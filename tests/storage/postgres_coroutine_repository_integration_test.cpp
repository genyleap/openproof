#include <gtest/gtest.h>
#include <boost/asio.hpp>

#include "coroutine_session_authenticator.hpp"
#include "coroutine_session_service.hpp"
#include <libpq-fe.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "coroutine_session_repository.hpp"

import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.security;
import openproof.session;
import openproof.storage.postgres;

namespace {
namespace asio = boost::asio;
namespace auth = openproof::authentication;
namespace fnd = openproof::foundation;
namespace ids = openproof::identity::core;
namespace idp = openproof::identity::provider;
namespace sec = openproof::security;
namespace ses = openproof::session;
namespace pg = openproof::storage::postgres;

using namespace std::chrono_literals;
constexpr std::string_view kDisposableDatabase =
    "postgresql://openproof_ci:ci_disposable_only@127.0.0.1:5432/openproof_coroutine_ci";
constexpr std::string_view kDisposableServerDatabase =
    "postgresql://openproof_ci:ci_disposable_only@127.0.0.1:55432/openproof_coroutine_ci";
constexpr fnd::Instant kNow{std::chrono::milliseconds{1770000000000}};

struct PqDeleter {
    void operator()(PGconn* connection) const noexcept {
        if (connection) PQfinish(connection);
    }
};
struct PqResultDeleter {
    void operator()(PGresult* result) const noexcept {
        if (result) PQclear(result);
    }
};

void seedOrganizationAndIdentities(std::string_view url)
{
    std::unique_ptr<PGconn, PqDeleter> connection{
        PQconnectdb(std::string{url}.c_str())};
    if (!connection || PQstatus(connection.get()) != CONNECTION_OK)
        throw std::runtime_error{"Cannot connect to isolated session test database"};
    constexpr std::array<const char*, 3U> statements{
        "INSERT INTO openproof.organizations(id,name,state,created_at_ms) "
        "VALUES('coroutine-org','Coroutine Test',0,1770000000000)",
        "INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) "
        "VALUES('coroutine-user-a','coroutine-org',0,0,1770000000000)",
        "INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) "
        "VALUES('coroutine-user-b','coroutine-org',0,0,1770000000000)"
    };
    for (const char* statement : statements) {
        std::unique_ptr<PGresult, PqResultDeleter> result{
            PQexec(connection.get(), statement)};
        if (!result || PQresultStatus(result.get()) != PGRES_COMMAND_OK)
            throw std::runtime_error{"Isolated PostgreSQL seed failed"};
    }
}

[[nodiscard]] ses::Session createSession(
    std::string id, std::string identity, unsigned char digestByte)
{
    sec::Sha256Digest digest{};
    digest.fill(std::byte{digestByte});
    const auto created = ses::Session::create(
        ses::SessionId{std::move(id)}, ids::IdentityId{std::move(identity)},
        idp::ProviderId{"test-oidc"}, idp::AssuranceLevel::Ial2,
        idp::AuthenticationStrength{
            idp::AuthenticationFactor::Knowledge |
            idp::AuthenticationFactor::Possession, false},
        kNow, ses::TokenDigest{digest}, kNow, 2h, 15min);
    if (!created) throw std::runtime_error{"Invalid domain test session"};
    return created.value();
}

[[nodiscard]] ses::TokenDigest digestOf(unsigned char digestByte)
{
    sec::Sha256Digest digest{};
    digest.fill(std::byte{digestByte});
    return ses::TokenDigest{digest};
}

asio::awaitable<void> verifyLegacySessionReadAndRevoke(
    pg::CoroutinePostgresSessionRepository& repository,
    bool& crossReadable, bool& crossRevoked)
{
    auto used = co_await repository.use(digestOf(0x51), kNow + 1min);
    crossReadable = used && used->id().value() == "legacy-interop"
        && used->lastSeenAt() == kNow + 1min;
    auto revoked = co_await repository.revoke(
        ses::SessionId{"legacy-interop"}, kNow + 2min);
    auto fromNew = co_await repository.find(ses::SessionId{"legacy-interop"});
    crossRevoked = revoked && fromNew && fromNew->has_value()
        && fromNew->value().state() == ses::SessionState::Revoked;
}

asio::awaitable<void> verifyNewRejectsLegacyRevocation(
    pg::CoroutinePostgresSessionRepository& repository, bool& denied)
{
    auto attempt = co_await repository.use(digestOf(0x61), kNow + 3min);
    denied = !attempt
        && attempt.error().code() == fnd::ErrorCode::AuthenticationFailed;
}

struct HmacResults {
    bool accepted{};
    bool wrongKeyDenied{};
    bool wrongBearerDenied{};
    bool revokedDenied{};
};

asio::awaitable<void> verifyRealBearerHmac(
    pg::CoroutinePostgresSessionRepository& repository, HmacResults& checks)
{
    // Test-only credentials are never used outside the throwaway database.
    const std::string rawBearer{"isolated-test-cookie-raw-value"};
    const fnd::SecretString signingKey{std::string(32, 'k')};
    auto fingerprint = sec::hmacSha256(signingKey, rawBearer);
    if (!fingerprint) co_return;
    auto issued = ses::Session::create(
        ses::SessionId{"hmac-real-session"},
        ids::IdentityId{"coroutine-user-a"},
        idp::ProviderId{"test-oidc"}, idp::AssuranceLevel::Ial2,
        idp::AuthenticationStrength{
            idp::AuthenticationFactor::Knowledge |
            idp::AuthenticationFactor::Possession, false},
        kNow, ses::TokenDigest{fingerprint.value()},
        kNow, 2h, 15min);
    if (!issued) co_return;
    const auto stored = co_await repository.add(std::move(issued).value());
    if (!stored) co_return;

    fnd::ManualClockSource clock{kNow + 1min};
    pg::CoroutineSessionAuthenticator authenticator{
        repository, clock, signingKey.clone()};
    auto accepted = co_await authenticator.authenticate(
        fnd::SecretString{rawBearer});
    checks.accepted = accepted
        && accepted->id().value() == "hmac-real-session"
        && accepted->lastSeenAt() == kNow + 1min;
    auto wrongBearer = co_await authenticator.authenticate(
        fnd::SecretString{"another-isolated-test-cookie"});
    checks.wrongBearerDenied = !wrongBearer
        && wrongBearer.error().code() == fnd::ErrorCode::AuthenticationFailed;

    pg::CoroutineSessionAuthenticator wrongKey{
        repository, clock, fnd::SecretString{std::string(32, 'w')}};
    auto wrongSigningKey = co_await wrongKey.authenticate(
        fnd::SecretString{rawBearer});
    checks.wrongKeyDenied = !wrongSigningKey
        && wrongSigningKey.error().code() == fnd::ErrorCode::AuthenticationFailed;

    auto revoked = co_await repository.revoke(
        ses::SessionId{"hmac-real-session"}, kNow + 2min);
    clock.set(kNow + 3min);
    auto denied = co_await authenticator.authenticate(
        fnd::SecretString{rawBearer});
    checks.revokedDenied = revoked && !denied
        && denied.error().code() == fnd::ErrorCode::AuthenticationFailed;
}

struct ServiceChecks final {
    bool authenticated{};
    bool ownerProtected{};
    bool listed{};
    bool rotated{};
    bool replayDenied{};
    bool revoked{};
    bool listEmptyAfterRevoke{};
};

asio::awaitable<void> verifyCoroutineServiceAuthorization(
    pg::CoroutinePostgresSessionRepository& repository,
    ServiceChecks& checks)
{
    const std::string bearer{"isolated-coroutine-service-token"};
    const fnd::SecretString key{std::string(32, 's')};
    const auto fingerprint = sec::hmacSha256(key, bearer);
    if (!fingerprint) co_return;
    auto session = ses::Session::create(
        ses::SessionId{"coroutine-service-session"},
        ids::IdentityId{"coroutine-user-a"},
        idp::ProviderId{"test-oidc"},
        idp::AssuranceLevel::Ial2,
        idp::AuthenticationStrength{
            idp::AuthenticationFactor::Knowledge |
            idp::AuthenticationFactor::Possession, false},
        kNow, ses::TokenDigest{fingerprint.value()}, kNow, 2h, 15min);
    if (!session) co_return;
    auto inserted = co_await repository.add(std::move(session).value());
    if (!inserted) co_return;

    fnd::ManualClockSource clock{kNow + 1min};
    auto policy = ses::SessionPolicy::create(2h, 15min);
    if (!policy) co_return;
    pg::CoroutinePostgresSessionService service{
        repository, clock, key.clone(), std::move(policy).value()};

    auto authenticated = co_await service.authenticate(fnd::SecretString{bearer});
    checks.authenticated = authenticated
        && authenticated->id().value() == "coroutine-service-session";
    auto listed = co_await service.list(ids::IdentityId{"coroutine-user-a"});
    checks.listed = listed && listed->size() == 1U
        && listed->front().id().value() == "coroutine-service-session";

    auto notOwner = co_await service.revokeOwned(
        ids::IdentityId{"coroutine-user-b"},
        ses::SessionId{"coroutine-service-session"});
    checks.ownerProtected = !notOwner
        && notOwner.error().code() == fnd::ErrorCode::NotFound;
    auto rotated = co_await service.rotate(fnd::SecretString{bearer});
    checks.rotated = rotated
        && rotated->id().value() == "coroutine-service-session";
    auto replay = co_await service.authenticate(fnd::SecretString{bearer});
    checks.replayDenied = !replay
        && replay.error().code() == fnd::ErrorCode::AuthenticationFailed;

    if (!rotated) co_return;
    auto newToken = co_await service.authenticate(rotated->token().clone());
    auto revoked = co_await service.revokeOwned(
        ids::IdentityId{"coroutine-user-a"},
        ses::SessionId{"coroutine-service-session"});
    auto after = co_await service.authenticate(rotated->token().clone());
    checks.revoked = newToken && revoked && !after
        && after.error().code() == fnd::ErrorCode::AuthenticationFailed;
    auto empty = co_await service.list(ids::IdentityId{"coroutine-user-a"});
    checks.listEmptyAfterRevoke = empty && empty->empty();
}

class CoroutineSessionProofProvider final : public idp::AuthenticationProvider {
public:
    [[nodiscard]] idp::ProviderId id() const override {
        return idp::ProviderId{"session-test"};
    }
    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override {
        return idp::InteractionModel::ChallengeResponse;
    }
    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override {
        return idp::AssuranceLevel::Ial3;
    }
    [[nodiscard]] fnd::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest&) override {
        return idp::AuthenticationChallenge{
            idp::ChallengeId{"coroutine-session-proof-challenge"}, kNow + 5min};
    }
    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse&) override {
        return idp::AuthenticationOutcome::create(
            id(), idp::ExternalSubject{"coroutine-user-a-external"},
            idp::VerifiedClaims{}, idp::AssuranceLevel::Ial3,
            idp::AuthenticationStrength{
                idp::AuthenticationFactor::Possession |
                idp::AuthenticationFactor::Inherence, true},
            idp::ProviderEvidence{}, kNow);
    }
};

[[nodiscard]] auth::VerifiedAuthentication verifiedCoroutineLogin()
{
    idp::ProviderRegistry providers;
    if (!providers.registerProvider(
            std::make_unique<CoroutineSessionProofProvider>())) {
        throw std::runtime_error{"Could not register test-only provider"};
    }
    idp::InMemoryAuthenticationTransactionStore transactions;
    ids::InMemoryExternalIdentityDirectory identities;
    auto link = ids::IdentityLink::request(
        ids::IdentityId{"coroutine-user-a"},
        ids::ExternalIdentityRef{
            idp::ProviderId{"session-test"},
            idp::ExternalSubject{"coroutine-user-a-external"}},
        kNow, 5min);
    if (!link || !link->requireVerification(kNow)
        || !link->markVerified(kNow) || !link->complete(kNow)
        || !identities.attach(*link)) {
        throw std::runtime_error{"Test identity linking was refused"};
    }
    auth::ProviderTrustPolicy trust;
    if (!trust.trust(idp::ProviderId{"session-test"},
                     idp::AssuranceLevel::Ial3)) {
        throw std::runtime_error{"Test provider trust was refused"};
    }
    fnd::ManualClockSource clock{kNow};
    auth::AuthenticationService authenticator{
        providers, transactions, identities, clock, std::move(trust), 5min};
    idp::AuthenticationRequest request{
        idp::ProviderId{"session-test"}, idp::ClientContext{}};
    request.setRequestedAssurance(idp::AssuranceLevel::Ial3);
    auto binding = sec::sha256("coroutine-test-bound-channel");
    if (!binding) throw std::runtime_error{"Binding digest generation failed"};
    auto started = authenticator.begin(
        request, binding.value(), fnd::CorrelationId{"coroutine-auth-correlation"});
    if (!started) throw std::runtime_error{"Test authentication begin failed"};
    idp::AuthenticationResponse response{
        started->challenge().id(), idp::ClientContext{}};
    auto completed = authenticator.complete(
        started->transactionId(), started->continuationToken(),
        binding.value(), response);
    if (!completed) throw std::runtime_error{"Test authentication completion failed"};
    return std::move(completed).value();
}

struct LoginChecks final {
    bool issued{};
    bool firstPartyAccepted{};
    bool metadataPreserved{};
    bool onlyOldRevoked{};
    bool staleCookieIgnored{};
    bool noCrossIdentityRevoke{};
};

asio::awaitable<void> verifyCoroutineLoginLifecycle(
    pg::CoroutinePostgresSessionRepository& repository,
    auth::VerifiedAuthentication trustedLogin,
    LoginChecks& checks)
{
    fnd::ManualClockSource clock{kNow};
    auto policy = ses::SessionPolicy::create(8h, 30min);
    if (!policy) co_return;
    pg::CoroutinePostgresSessionService service{
        repository, clock, fnd::SecretString{std::string(32, 'L')},
        std::move(policy).value()};
    idp::ClientContext client;
    client.setUserAgent("OpenProof coroutine browser test");
    client.setRemoteAddress("192.0.2.10");

    auto previous = co_await service.issue(trustedLogin, client);
    if (!previous) co_return;
    checks.issued = !previous->id().empty()
        && previous->token().size() == 43U;
    auto oldCookie = previous->token().clone();
    auto independent = co_await service.issue(trustedLogin, client);
    if (!independent) co_return;
    auto independentCookie = independent->token().clone();
    auto authenticated = co_await service.authenticate(oldCookie.clone());
    checks.firstPartyAccepted = authenticated
        && authenticated->identity() == ids::IdentityId{"coroutine-user-a"}
        && authenticated->assurance() == idp::AssuranceLevel::Ial3;
    checks.metadataPreserved = authenticated
        && authenticated->userAgent().has_value()
        && authenticated->userAgent().value() == "OpenProof coroutine browser test"
        && authenticated->remoteAddress().has_value()
        && authenticated->remoteAddress().value() == "192.0.2.10";

    auto replacement = co_await service.issueReplacing(
        trustedLogin, client, &oldCookie);
    if (!replacement) co_return;
    auto oldDenied = co_await service.authenticate(oldCookie.clone());
    auto newAccepted = co_await service.authenticate(replacement->token().clone());
    auto independentAccepted =
        co_await service.authenticate(independentCookie.clone());
    checks.onlyOldRevoked = !oldDenied && newAccepted && independentAccepted
        && oldDenied.error().code() == fnd::ErrorCode::AuthenticationFailed;

    const fnd::SecretString stale{"unknown-or-expired-cookie"};
    auto extra = co_await service.issueReplacing(trustedLogin, client, &stale);
    auto stillValid = co_await service.authenticate(replacement->token().clone());
    checks.staleCookieIgnored = extra && stillValid;
    auto unrelated = co_await service.revokeOwned(
        ids::IdentityId{"coroutine-user-b"}, replacement->id());
    checks.noCrossIdentityRevoke = !unrelated
        && unrelated.error().code() == fnd::ErrorCode::NotFound;

    auto revoked = co_await service.revokeAll(ids::IdentityId{"coroutine-user-a"});
    auto excluded = co_await service.list(ids::IdentityId{"coroutine-user-a"});
    if (!revoked || !excluded || !excluded->empty()) {
        checks.noCrossIdentityRevoke = false;
    }
}

asio::awaitable<void> verifyReplacementRefusesDatabaseOutage(
    pg::CoroutinePostgresSessionService& service,
    auth::VerifiedAuthentication trustedLogin,
    bool& replacementDenied,
    bool& initialIssuanceDenied)
{
    const fnd::SecretString priorCookie{"previous-test-browser-cookie"};
    const idp::ClientContext client{};
    auto replaced = co_await service.issueReplacing(
        trustedLogin, client, &priorCookie);
    replacementDenied = !replaced
        && replaced.error().code() == fnd::ErrorCode::Unavailable;
    auto issued = co_await service.issue(trustedLogin, client);
    initialIssuanceDenied = !issued
        && issued.error().code() == fnd::ErrorCode::Unavailable;
}

TEST(PostgresCoroutineDomainTest, DatabaseOutageNeverIssuesOrReplacesBearer)
{
    asio::io_context io;
    pg::CoroutinePostgresSessionRepository unavailable{
        io.get_executor(),
        fnd::SecretString{"openproof_invalid_connection_keyword=invalid"},
        1U, 100ms, 100ms, 100ms};
    const fnd::ManualClockSource clock{kNow};
    auto policy = ses::SessionPolicy::create(8h, 30min);
    ASSERT_TRUE(policy);
    pg::CoroutinePostgresSessionService service{
        unavailable, clock, fnd::SecretString{std::string(32, 'L')},
        std::move(policy).value()};
    bool deniedReplacement = false;
    bool deniedIssuance = false;
    auto tested = asio::co_spawn(
        io, verifyReplacementRefusesDatabaseOutage(
            service, verifiedCoroutineLogin(), deniedReplacement, deniedIssuance),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(tested.get());
    EXPECT_TRUE(deniedReplacement);
    EXPECT_TRUE(deniedIssuance);
}

struct Results {
    bool issued{};
    bool touched{};
    bool rotated{};
    bool replayDenied{};
    bool revoked{};
    bool identityScoped{};
    bool purged{};
};

asio::awaitable<void> verifyRealPostgresRepository(
    pg::CoroutinePostgresSessionRepository& repository, Results& r)
{
    auto first = co_await repository.add(
        createSession("coroutine-session-1", "coroutine-user-a", 0x11));
    auto count = co_await repository.size();
    auto found = co_await repository.find(ses::SessionId{"coroutine-session-1"});
    auto list = co_await repository.list(ids::IdentityId{"coroutine-user-a"});
    r.issued = first && count && *count == 1U && found
        && found->has_value() && list && list->size() == 1U;

    auto used = co_await repository.use(digestOf(0x11), kNow + 1min);
    r.touched = used && used->state() == ses::SessionState::Active
        && used->lastSeenAt() == kNow + 1min;

    auto rotation = co_await repository.rotate(
        ses::SessionId{"coroutine-session-1"},
        digestOf(0x11), digestOf(0x12), kNow + 2min);
    auto replay = co_await repository.use(digestOf(0x11), kNow + 3min);
    auto newToken = co_await repository.use(digestOf(0x12), kNow + 3min);
    r.rotated = rotation && newToken;
    r.replayDenied = !replay &&
        replay.error().code() == fnd::ErrorCode::AuthenticationFailed;

    auto revoked = co_await repository.revoke(
        ses::SessionId{"coroutine-session-1"}, kNow + 4min);
    auto duplicate = co_await repository.revoke(
        ses::SessionId{"coroutine-session-1"}, kNow + 5min);
    auto denied = co_await repository.use(digestOf(0x12), kNow + 6min);
    r.revoked = revoked && duplicate && !denied &&
        denied.error().code() == fnd::ErrorCode::AuthenticationFailed;

    auto second = co_await repository.add(
        createSession("coroutine-session-2", "coroutine-user-a", 0x21));
    auto other = co_await repository.add(
        createSession("coroutine-other-1", "coroutine-user-b", 0x31));
    auto affected = co_await repository.revokeAll(
        ids::IdentityId{"coroutine-user-a"}, kNow + 7min);
    auto unrelated = co_await repository.use(digestOf(0x31), kNow + 8min);
    r.identityScoped = second && other && affected && *affected == 1U
        && unrelated && unrelated->state() == ses::SessionState::Active;

    auto removed = co_await repository.purgeExpired(kNow + 3h);
    auto empty = co_await repository.size();
    r.purged = removed && *removed == 3U && empty && *empty == 0U;
}
} // namespace

TEST(PostgresCoroutineRealDatabaseTest, DomainRepositoryFullLifecycleAndIsolation)
{
    const char* uri = std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN");
    const char* ack = std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK");
    if (uri == nullptr || ack == nullptr) {
        // The generic CTest phase skips this fixture; the dedicated CI
        // step must explicitly supply the disposable database and ack.
        GTEST_SKIP() << "No explicitly acknowledged disposable coroutine database";
    }
    // This fixture applies schema migrations and inserts records. Only a
    // disposable GitHub runner OR a verified pg_virtualenv temporary cluster
    // on a non-production port may be accepted. Merely setting the ACK is
    // insufficient to authorize access to a real production database.
    ASSERT_STREQ(ack, "YES_EXCLUSIVE_DISPOSABLE_DATABASE");
    const bool hostedCi = std::getenv("GITHUB_ACTIONS") != nullptr
        && std::string_view{uri} == kDisposableDatabase;
    const bool localVirtualEnv = std::string_view{uri} == kDisposableServerDatabase
        && std::getenv("PG_CLUSTER_CONF_ROOT") != nullptr
        && std::string_view{std::getenv("PG_CLUSTER_CONF_ROOT")}
            .starts_with("/tmp/pg_virtualenv.");
    const char* localMode = std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_MODE");
    const bool localDocker = std::string_view{uri} == kDisposableServerDatabase
        && localMode != nullptr
        && std::string_view{localMode} == "isolated-docker-55432";
    ASSERT_TRUE(hostedCi || localVirtualEnv || localDocker)
        << "Not an explicitly permitted disposable PostgreSQL cluster";
    if (localDocker) {
        // A second, server-sourced assertion is required; an environment
        // variable and a localhost port alone never prove DB isolation.
        std::unique_ptr<PGconn, PqDeleter> isolation{PQconnectdb(uri)};
        ASSERT_TRUE(isolation && PQstatus(isolation.get()) == CONNECTION_OK);
        std::unique_ptr<PGresult, PqResultDeleter> identity{
            PQexec(isolation.get(), "SHOW cluster_name")};
        ASSERT_TRUE(identity && PQresultStatus(identity.get()) == PGRES_TUPLES_OK);
        ASSERT_EQ(PQntuples(identity.get()), 1);
        ASSERT_STREQ(PQgetvalue(identity.get(), 0, 0),
                    "openproof_disposable_coroutine_55432");
        std::unique_ptr<PGresult, PqResultDeleter> location{
            PQexec(isolation.get(), "SHOW data_directory")};
        ASSERT_TRUE(location && PQresultStatus(location.get()) == PGRES_TUPLES_OK);
        ASSERT_EQ(PQntuples(location.get()), 1);
        ASSERT_STREQ(PQgetvalue(location.get(), 0, 0),
                    "/var/lib/postgresql/data");
    }
    if (localVirtualEnv) {
        // Independently verify actual server storage, rather than trusting
        // environment variables or a socket on the expected port.
        std::unique_ptr<PGconn, PqDeleter> isolation{PQconnectdb(uri)};
        ASSERT_TRUE(isolation && PQstatus(isolation.get()) == CONNECTION_OK);
        std::unique_ptr<PGresult, PqResultDeleter> actual{
            PQexec(isolation.get(), "SHOW data_directory")};
        ASSERT_TRUE(actual && PQresultStatus(actual.get()) == PGRES_TUPLES_OK);
        ASSERT_EQ(PQntuples(actual.get()), 1);
        ASSERT_EQ(PQnfields(actual.get()), 1);
        ASSERT_TRUE(std::string_view{PQgetvalue(actual.get(), 0, 0)}
                        .starts_with("/tmp/pg_virtualenv."));
    }

    auto config = pg::PoolConfig::create(
        fnd::SecretString{uri}, 2U, 2s);
    ASSERT_TRUE(config);
    auto syncPool = pg::ConnectionPool::create(std::move(config).value());
    ASSERT_TRUE(syncPool);
    pg::Migrator migrator{*syncPool.value()};
    auto migration = migrator.applyDirectory(
        std::filesystem::path{OPENPROOF_SOURCE_DIR} / "migrations");
    ASSERT_TRUE(migration);
    ASSERT_NO_THROW(seedOrganizationAndIdentities(uri));

    asio::io_context io;
    pg::CoroutinePostgresSessionRepository repository{
        io.get_executor(), fnd::SecretString{uri},
        2U, 2s, 2s, 4s};
    Results results;
    auto completed = asio::co_spawn(
        io, verifyRealPostgresRepository(repository, results), asio::use_future);
    io.run();
    ASSERT_NO_THROW(completed.get());
    EXPECT_TRUE(results.issued);
    EXPECT_TRUE(results.touched);
    EXPECT_TRUE(results.rotated);
    EXPECT_TRUE(results.replayDenied);
    EXPECT_TRUE(results.revoked);
    EXPECT_TRUE(results.identityScoped);
    EXPECT_TRUE(results.purged);

    // Migration compatibility is bidirectional: a session written by the
    // deployed synchronous repository must still be valid to the new
    // nonblocking repository, and a revoke by the new path must be visible
    // immediately to the old one. All changes stay in this disposable DB.
    pg::PostgresSessionRepository legacy{*syncPool.value()};
    ASSERT_TRUE(legacy.add(
        createSession("legacy-interop", "coroutine-user-a", 0x51)));
    io.restart();
    bool crossReadable = false, crossRevoked = false;
    auto interoperability = asio::co_spawn(
        io, verifyLegacySessionReadAndRevoke(
            repository, crossReadable, crossRevoked), asio::use_future);
    io.run();
    ASSERT_NO_THROW(interoperability.get());
    EXPECT_TRUE(crossReadable);
    EXPECT_TRUE(crossRevoked);
    const auto deniedByOld = legacy.use(digestOf(0x51), kNow + 3min);
    EXPECT_FALSE(deniedByOld);
    if (!deniedByOld) {
        EXPECT_EQ(deniedByOld.error().code(),
                  fnd::ErrorCode::AuthenticationFailed);
    }
    io.restart();
    auto asyncInsert = asio::co_spawn(
        io, repository.add(createSession(
            "async-interop", "coroutine-user-b", 0x61)),
        asio::use_future);
    io.run();
    ASSERT_TRUE(asyncInsert.get());
    const auto acceptedByOld = legacy.use(digestOf(0x61), kNow + 1min);
    ASSERT_TRUE(acceptedByOld);
    EXPECT_EQ(acceptedByOld->id().value(), "async-interop");
    ASSERT_TRUE(legacy.revoke(
        ses::SessionId{"async-interop"}, kNow + 2min));
    io.restart();
    bool rejected = false;
    auto deniedByNew = asio::co_spawn(
        io, verifyNewRejectsLegacyRevocation(repository, rejected),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(deniedByNew.get());
    EXPECT_TRUE(rejected);
    EXPECT_EQ(legacy.purgeExpired(kNow + 3h), 2U);

    io.restart();
    HmacResults hmac;
    auto verifiedBearer = asio::co_spawn(
        io, verifyRealBearerHmac(repository, hmac), asio::use_future);
    io.run();
    ASSERT_NO_THROW(verifiedBearer.get());
    EXPECT_TRUE(hmac.accepted);
    EXPECT_TRUE(hmac.wrongBearerDenied);
    EXPECT_TRUE(hmac.wrongKeyDenied);
    EXPECT_TRUE(hmac.revokedDenied);
    EXPECT_EQ(legacy.purgeExpired(kNow + 3h), 1U);

    io.restart();
    ServiceChecks serviceChecks;
    auto serviceRun = asio::co_spawn(
        io, verifyCoroutineServiceAuthorization(repository, serviceChecks),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(serviceRun.get());
    EXPECT_TRUE(serviceChecks.authenticated);
    EXPECT_TRUE(serviceChecks.ownerProtected);
    EXPECT_TRUE(serviceChecks.listed);
    EXPECT_TRUE(serviceChecks.rotated);
    EXPECT_TRUE(serviceChecks.replayDenied);
    EXPECT_TRUE(serviceChecks.revoked);
    EXPECT_TRUE(serviceChecks.listEmptyAfterRevoke);
    EXPECT_EQ(legacy.purgeExpired(kNow + 3h), 1U);

    // Verify genuine trusted AuthenticationService outputs, not a forged
    // VerifiedAuthentication, and browser replacement semantics end-to-end.
    io.restart();
    LoginChecks loginChecks;
    auto login = asio::co_spawn(
        io, verifyCoroutineLoginLifecycle(
            repository, verifiedCoroutineLogin(), loginChecks), asio::use_future);
    io.run();
    ASSERT_NO_THROW(login.get());
    EXPECT_TRUE(loginChecks.issued);
    EXPECT_TRUE(loginChecks.firstPartyAccepted);
    EXPECT_TRUE(loginChecks.metadataPreserved);
    EXPECT_TRUE(loginChecks.onlyOldRevoked);
    EXPECT_TRUE(loginChecks.staleCookieIgnored);
    EXPECT_TRUE(loginChecks.noCrossIdentityRevoke);
    EXPECT_EQ(legacy.purgeExpired(kNow + 9h), 4U);
}

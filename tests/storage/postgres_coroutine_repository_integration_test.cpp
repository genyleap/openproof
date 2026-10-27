#include <gtest/gtest.h>
#include <boost/asio.hpp>

#include "coroutine_session_authenticator.hpp"
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

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.security;
import openproof.session;
import openproof.storage.postgres;

namespace {
namespace asio = boost::asio;
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
}

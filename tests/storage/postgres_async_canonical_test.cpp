#include <gtest/gtest.h>

#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <libpq-fe.h>

#include <chrono>
#include <cstdlib>
#include <initializer_list>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>
#include <utility>
#include <unistd.h>

#include "async_pool.hpp"
#include "coroutine_canonical_finalizer.hpp"

import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.profile;
import openproof.identity.provider;

namespace {
namespace asio = boost::asio;
namespace pg = openproof::storage::postgres;
namespace fnd = openproof::foundation;
namespace ids = openproof::identity::core;
namespace idp = openproof::identity::provider;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1770000000000LL}};
// A disposable-only Unix-domain socket. TCP URLs are rejected even when
// an operator accidentally exports a production database environment.
constexpr std::string_view kSocketPrefix =
    "host=/tmp/openproof-canonical-pg.";
constexpr std::string_view kSocketSuffix =
    " port=55418 user=postgres dbname=openproof_coroutine_ci";

struct PgConnDeleter final {
    void operator()(PGconn* value) const noexcept { if (value) PQfinish(value); }
};
struct PgResultDeleter final {
    void operator()(PGresult* value) const noexcept { if (value) PQclear(value); }
};
using Conn = std::unique_ptr<PGconn, PgConnDeleter>;
using Result = std::unique_ptr<PGresult, PgResultDeleter>;

[[nodiscard]] bool isolatedSocketDsn(std::string_view value)
{
    if (!value.starts_with(kSocketPrefix)
        || !value.ends_with(kSocketSuffix)
        || value.size() != kSocketPrefix.size() + 8U + kSocketSuffix.size())
        return false;
    const auto random = value.substr(kSocketPrefix.size(), 8U);
    for (const char symbol : random) {
        if (!((symbol >= 'A' && symbol <= 'Z')
            || (symbol >= 'a' && symbol <= 'z')
            || (symbol >= '0' && symbol <= '9')))
            return false;
    }
    return true;
}

[[nodiscard]] std::optional<std::string> disposableDsn()
{
    const char* dsn = std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN");
    if (dsn == nullptr) return std::nullopt;
    const char* acknowledged =
        std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK");
    // The runner creates one private socket directory with an mktemp
    // eight-character suffix; never connect to TCP or an arbitrary DB host.
    const std::string_view value{dsn};
    if (acknowledged == nullptr
        || std::string_view{acknowledged}
            != "YES_EXCLUSIVE_DISPOSABLE_DATABASE"
        || !isolatedSocketDsn(value))
        return std::nullopt;
    return std::string{value};
}

[[nodiscard]] Result execute(PGconn* connection, std::string_view sql,
                             std::initializer_list<std::string> parameters)
{
    std::vector<std::string> owned(parameters);
    std::vector<const char*> values;
    for (const auto& param : owned) values.push_back(param.c_str());
    Result result{PQexecParams(connection, std::string{sql}.c_str(),
        static_cast<int>(values.size()), nullptr, values.data(),
        nullptr, nullptr, 0)};
    if (!result || (PQresultStatus(result.get()) != PGRES_COMMAND_OK
                    && PQresultStatus(result.get()) != PGRES_TUPLES_OK)) {
        throw std::runtime_error{"Disposable PostgreSQL fixture query failed"};
    }
    return result;
}

[[nodiscard]] idp::AuthenticationOutcome verified(
    std::string subject, std::string preferredUsername = "native-user",
    std::optional<std::string> verifiedEmail = std::nullopt)
{
    idp::VerifiedClaims claims;
    claims.set(idp::ClaimName::PreferredUsername, std::move(preferredUsername));
    if (verifiedEmail) {
        claims.set(idp::ClaimName::Email, std::move(*verifiedEmail));
        claims.set(idp::ClaimName::EmailVerified, "true");
    }
    auto result = idp::AuthenticationOutcome::create(
        idp::ProviderId{"native-canonical-provider"},
        idp::ExternalSubject{std::move(subject)},
        std::move(claims), idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{idp::AuthenticationFactor::Possession, false},
        idp::ProviderEvidence{}, kNow);
    if (!result) throw std::runtime_error{"Invalid canonical test proof"};
    return std::move(result).value();
}

struct Seed final {
    std::string suffix = std::to_string(::getpid()) + "-"
        + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    std::string org = "nc-org-" + suffix;
    std::string foreignOrg = "nc-foreign-org-" + suffix;
    std::string suspendedOrg = "nc-suspended-org-" + suffix;
    std::string owner = "nc-owner-" + suffix;
    std::string secondOwner = "nc-second-" + suffix;
    std::string freshLoginOwner = "nc-fresh-login-" + suffix;
    std::string simultaneousOwner = "nc-simultaneous-" + suffix;
    std::string lockedOwner = "nc-locked-" + suffix;
    std::string foreignOwner = "nc-foreign-owner-" + suffix;
    std::string suspendedOwner = "nc-suspended-owner-" + suffix;
    std::string subject = "nc-existing-" + suffix;
    std::string freshLoginSubject = "nc-fresh-provider-" + suffix;
    std::string simultaneousSubjectA = "nc-sim-a-" + suffix;
    std::string simultaneousSubjectB = "nc-sim-b-" + suffix;
    std::string lockedSubject = "nc-locked-external-" + suffix;
    std::string foreignSubject = "nc-foreign-external-" + suffix;
    std::string suspendedSubject = "nc-suspended-external-" + suffix;
    std::string newSubject = "nc-new-" + suffix;
    std::string racingSubject = "nc-race-" + suffix;
    std::string invalidSubject = "nc-rollback-" + suffix;

    void install(PGconn* connection) const
    {
        for (const auto& id : {org, foreignOrg, suspendedOrg}) {
            static_cast<void>(execute(connection,
                "INSERT INTO openproof.organizations("
                "id,name,state,created_at_ms) VALUES($1,'Isolated Coroutine Test',$2,$3)",
                {id, id == suspendedOrg ? "1" : "0", "1770000000000"}));
        }
        for (const auto& [id, tenant, status] :
            {std::tuple{owner, org, "0"},
             std::tuple{secondOwner, org, "0"},
             std::tuple{freshLoginOwner, org, "0"},
             std::tuple{simultaneousOwner, org, "0"},
             std::tuple{lockedOwner, org, "2"},
             std::tuple{foreignOwner, foreignOrg, "0"},
             std::tuple{suspendedOwner, suspendedOrg, "0"}}) {
            static_cast<void>(execute(connection,
                "INSERT INTO openproof.identities("
                "id,organization_id,kind,status,created_at_ms) "
                "VALUES($1,$2,0,$3,$4)",
                {id, tenant, status, "1770000000000"}));
        }
        for (const auto& [subjectValue, linked] :
            {std::pair{subject, owner},
             std::pair{freshLoginSubject, freshLoginOwner},
             std::pair{simultaneousSubjectA, simultaneousOwner},
             std::pair{simultaneousSubjectB, simultaneousOwner},
             std::pair{lockedSubject, lockedOwner},
             std::pair{foreignSubject, foreignOwner},
             std::pair{suspendedSubject, suspendedOwner}}) {
            static_cast<void>(execute(connection,
                "INSERT INTO openproof.external_identities("
                "provider,external_subject,identity_id,linked_at_ms) "
                "VALUES('native-canonical-provider',$1,$2,$3)",
                {subjectValue, linked, "1770000000000"}));
        }
        static_cast<void>(execute(connection,
            "INSERT INTO openproof.identity_profiles("
            "identity_id,display_name,created_at_ms,updated_at_ms) "
            "VALUES($1,'User-chosen name',$2,$3)",
            {owner, "1770000000000", "1770000000000"}));
    }
};

struct IntegrationResult {
    bool login{};
    bool freshLogin{};
    bool repeatedLogin{};
    bool wrongTenantDenied{};
    bool inactiveDenied{};
    bool unlinkedDenied{};
    bool targetAuthorized{};
    bool inactiveTargetDenied{};
    bool foreignTargetDenied{};
    bool suspendedTenantLoginDenied{};
    bool suspendedTenantTargetDenied{};
    bool suspendedTenantLinkDenied{};
    bool connectionAttached{};
    bool ownerConflictDenied{};
    bool invalidProfileDenied{};
};

asio::awaitable<void> checkRealDatabase(
    pg::CoroutinePostgresCanonicalFinalizer& canonical,
    pg::CoroutinePostgresCanonicalFinalizer& wrongTenant,
    pg::CoroutinePostgresCanonicalFinalizer& suspendedTenant,
    const Seed& seed, IntegrationResult& checks)
{
    const auto owner = co_await canonical.finishLoginAsync(
        verified(seed.subject, "provider-proposed"), kNow);
    checks.login = owner && owner->value() == seed.owner;

    // The first login to a previously linked, profile-less identity may
    // persist provider-verified email. Subsequent logins must NOT replace it.
    auto fresh = co_await canonical.finishLoginAsync(
        verified(seed.freshLoginSubject, "initial-user", "first@example.test"), kNow);
    checks.freshLogin = fresh && fresh->value() == seed.freshLoginOwner;
    auto repeated = co_await canonical.finishLoginAsync(
        verified(seed.freshLoginSubject, "later-user", "second@example.test"), kNow);
    checks.repeatedLogin = repeated && repeated->value() == seed.freshLoginOwner;

    auto wrong = co_await wrongTenant.finishLoginAsync(
        verified(seed.subject), kNow);
    checks.wrongTenantDenied = !wrong
        && wrong.error().code() == fnd::ErrorCode::AuthenticationFailed;

    auto locked = co_await canonical.finishLoginAsync(
        verified(seed.lockedSubject), kNow);
    checks.inactiveDenied = !locked
        && locked.error().code() == fnd::ErrorCode::AuthenticationFailed;

    auto missing = co_await canonical.finishLoginAsync(
        verified("unlinked-canonical-proof"), kNow);
    checks.unlinkedDenied = !missing
        && missing.error().code() == fnd::ErrorCode::AuthenticationFailed;

    auto target = co_await canonical.authorizeConnectionTargetAsync(
        ids::IdentityId{seed.secondOwner});
    checks.targetAuthorized = target.has_value();
    auto inactive = co_await canonical.authorizeConnectionTargetAsync(
        ids::IdentityId{seed.lockedOwner});
    checks.inactiveTargetDenied = !inactive
        && inactive.error().code() == fnd::ErrorCode::AuthenticationFailed;
    auto foreign = co_await canonical.authorizeConnectionTargetAsync(
        ids::IdentityId{seed.foreignOwner});
    checks.foreignTargetDenied = !foreign
        && foreign.error().code() == fnd::ErrorCode::AuthenticationFailed;

    // An active identity inside a suspended organization cannot complete
    // authentication or linking. Test the three native entry points, not
    // just the read-only preflight.
    auto suspendedLogin = co_await suspendedTenant.finishLoginAsync(
        verified(seed.suspendedSubject), kNow);
    checks.suspendedTenantLoginDenied = !suspendedLogin
        && suspendedLogin.error().code() == fnd::ErrorCode::AuthenticationFailed;
    auto suspendedTarget = co_await suspendedTenant.authorizeConnectionTargetAsync(
        ids::IdentityId{seed.suspendedOwner});
    checks.suspendedTenantTargetDenied = !suspendedTarget
        && suspendedTarget.error().code() == fnd::ErrorCode::AuthenticationFailed;
    auto suspendedLink = co_await suspendedTenant.finishConnectionAsync(
        verified("nc-new-in-suspended-org"), ids::IdentityId{seed.suspendedOwner},
        kNow);
    checks.suspendedTenantLinkDenied = !suspendedLink
        && suspendedLink.error().code() == fnd::ErrorCode::AuthenticationFailed;

    auto connected = co_await canonical.finishConnectionAsync(
        verified(seed.newSubject, "linked-user", "untrusted-link@example.test"),
        ids::IdentityId{seed.secondOwner}, kNow);
    checks.connectionAttached = connected
        && connected->subject().value() == seed.newSubject;

    auto stolen = co_await canonical.finishConnectionAsync(
        verified(seed.newSubject), ids::IdentityId{seed.owner}, kNow);
    checks.ownerConflictDenied = !stolen
        && stolen.error().code() == fnd::ErrorCode::Conflict;

    // SQL INSERT of the external link succeeds first, but the existing
    // profile has no locale. The domain refresh accepts the new claim and
    // then rejects its oversized value, forcing the whole transaction
    // (including the successfully inserted link) to roll back.
    idp::VerifiedClaims invalidClaims;
    invalidClaims.set(idp::ClaimName::Locale, std::string(65U, 'x'));
    auto invalidProof = idp::AuthenticationOutcome::create(
        idp::ProviderId{"native-canonical-provider"},
        idp::ExternalSubject{seed.invalidSubject},
        std::move(invalidClaims), idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{
            idp::AuthenticationFactor::Possession, false},
        idp::ProviderEvidence{}, kNow);
    if (!invalidProof) co_return;
    auto refused = co_await canonical.finishConnectionAsync(
        invalidProof.value(), ids::IdentityId{seed.secondOwner}, kNow);
    checks.invalidProfileDenied = !refused
        && refused.error().code() == fnd::ErrorCode::Unavailable;
}

asio::awaitable<void> raceFirstCanonicalProfile(
    pg::CoroutinePostgresCanonicalFinalizer& canonical,
    std::string subject, std::string identity, bool& accepted)
{
    auto result = co_await canonical.finishLoginAsync(
        verified(std::move(subject)), kNow);
    accepted = result && result->value() == identity;
}

asio::awaitable<void> raceForSameExternalIdentity(
    pg::CoroutinePostgresCanonicalFinalizer& canonical,
    std::string subject, ids::IdentityId target,
    bool& accepted, bool& conflicted)
{
    auto linked = co_await canonical.finishConnectionAsync(
        verified(std::move(subject)), std::move(target), kNow);
    accepted = linked.has_value();
    conflicted = !linked && linked.error().code() == fnd::ErrorCode::Conflict;
}

TEST(PostgresCanonicalCoroutineTest, ConnectionPresentationCannotClaimVerifiedContactData)
{
    // This domain invariant must be exercised even when disposable SQL is
    // unavailable. The finalizer chooses the presentation-only operation
    // when a connection creates its first profile.
    idp::VerifiedClaims claims;
    claims.set(idp::ClaimName::PreferredUsername, "display-only");
    claims.set(idp::ClaimName::Email, "external-provider@example.test");
    claims.set(idp::ClaimName::EmailVerified, "true");
    claims.set(idp::ClaimName::PhoneNumber, "+12025550123");
    claims.set(idp::ClaimName::PhoneNumberVerified, "true");

    auto connected = openproof::identity::profile::IdentityProfile::create(
        ids::IdentityId{"connected-profile-test"}, kNow);
    ASSERT_TRUE(connected);
    ASSERT_TRUE(connected->refreshPresentationClaims(claims, kNow));
    ASSERT_TRUE(connected->preferredUsername().has_value());
    EXPECT_EQ(*connected->preferredUsername(), "display-only");
    EXPECT_FALSE(connected->email().has_value());
    EXPECT_FALSE(connected->emailVerified());
    EXPECT_FALSE(connected->phoneNumber().has_value());
    EXPECT_FALSE(connected->phoneNumberVerified());

    // A genuine first login on a pre-linked identity uses the distinct
    // verified-claims path, and may establish a verified contact credential.
    auto loggedIn = openproof::identity::profile::IdentityProfile::create(
        ids::IdentityId{"login-profile-test"}, kNow);
    ASSERT_TRUE(loggedIn);
    ASSERT_TRUE(loggedIn->applyVerifiedClaims(claims, kNow));
    ASSERT_TRUE(loggedIn->email().has_value());
    EXPECT_EQ(*loggedIn->email(), "external-provider@example.test");
    EXPECT_TRUE(loggedIn->emailVerified());
    ASSERT_TRUE(loggedIn->phoneNumber().has_value());
    EXPECT_EQ(*loggedIn->phoneNumber(), "+12025550123");
    EXPECT_TRUE(loggedIn->phoneNumberVerified());
}

TEST(PostgresCanonicalCoroutineTest, ExpiredPoolDeadlineDoesNotConsumeSlots)
{
    asio::io_context io;
    openproof::storage::postgres::async_detail::AsyncConnectionPool pool{
        io.get_executor(),
        "openproof_invalid_connection_keyword=invalid",
        1U, std::chrono::milliseconds{150},
        std::chrono::milliseconds{150}};
    std::size_t expiredCount = 0U;
    std::size_t subMillisecondCount = 0U;
    std::size_t physicalConnectAttempts = 0U;
    auto check = [&]() -> asio::awaitable<void> {
        for (int attempt = 0; attempt < 3; ++attempt) {
            try {
                auto lease = co_await pool.acquire(
                    std::chrono::steady_clock::now() - std::chrono::milliseconds{1});
                static_cast<void>(lease);
            } catch (const std::runtime_error& error) {
                if (std::string_view{error.what()}.contains(
                    "operation deadline expired")) {
                    ++expiredCount;
                }
            }
        }
        // The libpq connector uses millisecond deadlines. Remaining time
        // below 1 ms must be refused rather than rounded up to 1 ms: even
        // an immediately available permit cannot authorize network I/O
        // outside the caller's actual deadline.
        for (int attempt = 0; attempt < 3; ++attempt) {
            try {
                auto lease = co_await pool.acquire(
                    std::chrono::steady_clock::now()
                    + std::chrono::microseconds{100});
                static_cast<void>(lease);
            } catch (const std::runtime_error& error) {
                if (std::string_view{error.what()}.contains(
                    "operation deadline expired")) {
                    ++subMillisecondCount;
                }
            }
        }
        // Capacity() reports the *configured* limit, not the state of the
        // channel. Prove each slot token was returned by reaching libpq
        // twice after the expired operations. If permits leaked, acquire
        // would fail with a pool acquisition timeout instead.
        for (int attempt = 0; attempt < 2; ++attempt) {
            try {
                auto lease = co_await pool.acquire(
                    std::chrono::steady_clock::now() + std::chrono::seconds{1});
                static_cast<void>(lease);
            } catch (const std::runtime_error& error) {
                if (std::string_view{error.what()}.contains(
                    "PostgreSQL connection failed")) {
                    ++physicalConnectAttempts;
                }
            }
        }
    };
    auto operation = check();
    auto future = asio::co_spawn(io, std::move(operation), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_EQ(expiredCount, 3U);
    EXPECT_EQ(subMillisecondCount, 3U);
    EXPECT_EQ(physicalConnectAttempts, 2U);
    EXPECT_EQ(pool.capacity(), 1U);
}

TEST(PostgresCanonicalCoroutineTest, RejectsProductionOrUntrustedSqlEndpoints)
{
    EXPECT_FALSE(isolatedSocketDsn(
        "postgresql://openproof_ci:ci_disposable_only@127.0.0.1:5432/openproof_coroutine_ci"));
    EXPECT_FALSE(isolatedSocketDsn(
        "host=127.0.0.1 port=55418 user=postgres dbname=openproof_coroutine_ci"));
    EXPECT_FALSE(isolatedSocketDsn(
        "host=/var/run/postgresql port=55418 user=postgres dbname=openproof_coroutine_ci"));
    EXPECT_FALSE(isolatedSocketDsn(
        "host=/tmp/openproof-canonical-pg.BAD-X000 port=55418 user=postgres dbname=openproof_coroutine_ci"));
    EXPECT_FALSE(isolatedSocketDsn(
        "host=/tmp/openproof-canonical-pg.ABcd1234 port=5432 user=postgres dbname=openproof_coroutine_ci"));
    EXPECT_TRUE(isolatedSocketDsn(
        "host=/tmp/openproof-canonical-pg.ABcd1234 port=55418 user=postgres dbname=openproof_coroutine_ci"));
}

TEST(PostgresCanonicalCoroutineTest, SqlFailureReturnsUnavailable)
{
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer finalizer{
        io.get_executor(),
        fnd::SecretString{"openproof_invalid_connection_keyword=invalid"},
        ids::OrganizationId{"isolated-org"},
        1U, std::chrono::milliseconds{100},
        std::chrono::milliseconds{100},
        std::chrono::milliseconds{100}};
    bool loginDenied = false;
    bool targetDenied = false;
    bool linkDenied = false;
    auto run = [&]() -> asio::awaitable<void> {
        auto result = co_await finalizer.finishLoginAsync(
            verified("never-linked"), kNow);
        loginDenied = !result
            && result.error().code() == fnd::ErrorCode::Unavailable;
        auto target = co_await finalizer.authorizeConnectionTargetAsync(
            ids::IdentityId{"existing-id"});
        targetDenied = !target
            && target.error().code() == fnd::ErrorCode::Unavailable;
        auto link = co_await finalizer.finishConnectionAsync(
            verified("never-linked"), ids::IdentityId{"existing-id"}, kNow);
        linkDenied = !link
            && link.error().code() == fnd::ErrorCode::Unavailable;
    };
    auto operation = run();
    auto future = asio::co_spawn(io, std::move(operation), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(loginDenied);
    EXPECT_TRUE(targetDenied);
    EXPECT_TRUE(linkDenied);
}

TEST(PostgresCanonicalCoroutineTest, InvalidTenantConfigurationIsRejected)
{
    asio::io_context io;
    EXPECT_THROW(
        (pg::CoroutinePostgresCanonicalFinalizer{
            io.get_executor(),
            fnd::SecretString{"openproof_invalid_connection_keyword=invalid"},
            ids::OrganizationId{}, 1U,
            std::chrono::milliseconds{100},
            std::chrono::milliseconds{100},
            std::chrono::milliseconds{100}}),
        std::invalid_argument);
}

TEST(PostgresCanonicalCoroutineTest, RealDatabaseTimeoutDropsPoisonedConnection)
{
    const auto dsn = disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK") != nullptr)
            FAIL() << "A disposable SQL database was requested with an invalid DSN.";
        GTEST_SKIP() << "No explicitly acknowledged disposable PostgreSQL cluster.";
    }
    asio::io_context io;
    pg::async_detail::AsyncConnectionPool pool{
        io.get_executor(), *dsn, 1U, std::chrono::milliseconds{500},
        std::chrono::milliseconds{1000}};
    bool timedOut = false;
    bool recovered = false;
    auto run = [&]() -> asio::awaitable<void> {
        std::string firstBackend;
        {
            auto lease = co_await pool.acquire(
                std::chrono::steady_clock::now() + std::chrono::seconds{3});
            const auto original = co_await lease.connection().query(
                "SELECT pg_backend_pid()::text", {}, std::chrono::seconds{1});
            if (original.rows.size() != 1U
                || original.rows.front().size() != 1U
                || !original.rows.front().front()) co_return;
            firstBackend = *original.rows.front().front();
            try {
                // No SQL write: the only effect is holding this PGconn busy
                // beyond the same 25 ms query deadline.
                static_cast<void>(co_await lease.connection().query(
                    "SELECT pg_sleep(0.4)", {}, std::chrono::milliseconds{25}));
            } catch (const std::runtime_error&) {
                timedOut = !lease.connection().reusable();
            }
        }
        // The timed-out server query must never be returned to another
        // tenant. With one permit the next acquisition can only succeed
        // if the poisoned lease was returned as a fresh-connection slot.
        auto fresh = co_await pool.acquire(
            std::chrono::steady_clock::now() + std::chrono::seconds{3});
        const auto newBackend = co_await fresh.connection().query(
            "SELECT pg_backend_pid()::text", {}, std::chrono::seconds{1});
        recovered = newBackend.rows.size() == 1U
            && newBackend.rows.front().size() == 1U
            && newBackend.rows.front().front().has_value()
            && *newBackend.rows.front().front() != firstBackend;
    };
    auto future = asio::co_spawn(io, run(), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(timedOut);
    EXPECT_TRUE(recovered);
}

TEST(PostgresCanonicalCoroutineTest, RealDatabaseRecycledLeaseResetsSession)
{
    const auto dsn = disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK") != nullptr)
            FAIL() << "A disposable SQL database was requested with an invalid DSN.";
        GTEST_SKIP() << "No explicitly acknowledged disposable PostgreSQL cluster.";
    }
    asio::io_context io;
    pg::async_detail::AsyncConnectionPool pool{
        io.get_executor(), *dsn, 1U, std::chrono::milliseconds{500},
        std::chrono::milliseconds{1000}};
    bool cleaned = false;
    auto run = [&]() -> asio::awaitable<void> {
        {
            auto first = co_await pool.acquire(
                std::chrono::steady_clock::now() + std::chrono::seconds{3});
            static_cast<void>(co_await first.connection().query(
                "SET application_name TO 'canonical_private_prior_tenant'",
                {}, std::chrono::seconds{1}));
        }
        auto recycled = co_await pool.acquire(
            std::chrono::steady_clock::now() + std::chrono::seconds{3});
        const auto current = co_await recycled.connection().query(
            "SHOW application_name", {}, std::chrono::seconds{1});
        cleaned = current.rows.size() == 1U
            && current.rows.front().size() == 1U
            && current.rows.front().front().has_value()
            && *current.rows.front().front() != "canonical_private_prior_tenant";
    };
    auto future = asio::co_spawn(io, run(), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(cleaned);
}

TEST(PostgresCanonicalCoroutineTest, RealDatabaseTenantOwnershipLifecycleAndProfiles)
{
    const auto dsn = disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK") != nullptr)
            FAIL() << "Explicitly requested disposable database has an invalid socket DSN.";
        GTEST_SKIP() << "Only an explicitly acknowledged disposable database may be used.";
    }

    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get()) == CONNECTION_OK)
        << "Disposable database is unavailable";
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));

    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer canonical{
        io.get_executor(), fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org}, 2U,
        std::chrono::milliseconds{500}, std::chrono::milliseconds{1000},
        std::chrono::milliseconds{2000}};
    pg::CoroutinePostgresCanonicalFinalizer wrongTenant{
        io.get_executor(), fnd::SecretString{*dsn},
        ids::OrganizationId{seed.foreignOrg}, 1U,
        std::chrono::milliseconds{500}, std::chrono::milliseconds{1000},
        std::chrono::milliseconds{2000}};

    pg::CoroutinePostgresCanonicalFinalizer suspendedTenant{
        io.get_executor(), fnd::SecretString{*dsn},
        ids::OrganizationId{seed.suspendedOrg}, 1U,
        std::chrono::milliseconds{500}, std::chrono::milliseconds{1000},
        std::chrono::milliseconds{2000}};

    IntegrationResult checks;
    auto future = asio::co_spawn(io,
        checkRealDatabase(canonical, wrongTenant, suspendedTenant, seed, checks),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(checks.login);
    EXPECT_TRUE(checks.freshLogin);
    EXPECT_TRUE(checks.repeatedLogin);
    EXPECT_TRUE(checks.wrongTenantDenied);
    EXPECT_TRUE(checks.inactiveDenied);
    EXPECT_TRUE(checks.unlinkedDenied);
    EXPECT_TRUE(checks.targetAuthorized);
    EXPECT_TRUE(checks.inactiveTargetDenied);
    EXPECT_TRUE(checks.foreignTargetDenied);
    EXPECT_TRUE(checks.suspendedTenantLoginDenied);
    EXPECT_TRUE(checks.suspendedTenantTargetDenied);
    EXPECT_TRUE(checks.suspendedTenantLinkDenied);
    EXPECT_TRUE(checks.connectionAttached);
    EXPECT_TRUE(checks.ownerConflictDenied);
    EXPECT_TRUE(checks.invalidProfileDenied);

    const auto notCommitted = execute(fixture.get(),
        "SELECT COUNT(*)::text FROM openproof.external_identities "
        "WHERE provider='native-canonical-provider' AND external_subject=$1",
        {seed.invalidSubject});
    ASSERT_EQ(PQntuples(notCommitted.get()), 1);
    EXPECT_STREQ(PQgetvalue(notCommitted.get(), 0, 0), "0");

    // Connecting a new provider is a presentation-only operation. It must
    // never seed a second provider's email verification into a canonical
    // identity which had no profile before linking.
    const auto linkedProfile = execute(fixture.get(),
        "SELECT email IS NULL,email_verified,preferred_username "
        "FROM openproof.identity_profiles WHERE identity_id=$1",
        {seed.secondOwner});
    ASSERT_EQ(PQntuples(linkedProfile.get()), 1);
    EXPECT_STREQ(PQgetvalue(linkedProfile.get(), 0, 0), "t");
    EXPECT_STREQ(PQgetvalue(linkedProfile.get(), 0, 1), "f");
    EXPECT_STREQ(PQgetvalue(linkedProfile.get(), 0, 2), "linked-user");

    const auto loginProfile = execute(fixture.get(),
        "SELECT email,email_verified FROM openproof.identity_profiles "
        "WHERE identity_id=$1", {seed.freshLoginOwner});
    ASSERT_EQ(PQntuples(loginProfile.get()), 1);
    EXPECT_STREQ(PQgetvalue(loginProfile.get(), 0, 0), "first@example.test");
    EXPECT_STREQ(PQgetvalue(loginProfile.get(), 0, 1), "t");

    const auto profile = execute(fixture.get(),
        "SELECT display_name,preferred_username FROM openproof.identity_profiles "
        "WHERE identity_id=$1", {seed.owner});
    ASSERT_EQ(PQntuples(profile.get()), 1);
    EXPECT_STREQ(PQgetvalue(profile.get(), 0, 0), "User-chosen name");
    EXPECT_STREQ(PQgetvalue(profile.get(), 0, 1), "provider-proposed");

    const auto link = execute(fixture.get(),
        "SELECT identity_id FROM openproof.external_identities "
        "WHERE provider='native-canonical-provider' AND external_subject=$1",
        {seed.newSubject});
    ASSERT_EQ(PQntuples(link.get()), 1);
    EXPECT_STREQ(PQgetvalue(link.get(), 0, 0), seed.secondOwner.c_str());

    // Concurrent proof completions for the same provider subject must never
    // let two independently verified targets take ownership of one link.
    bool firstAccepted = false, secondAccepted = false;
    bool firstConflict = false, secondConflict = false;
    io.restart();
    auto first = asio::co_spawn(io, raceForSameExternalIdentity(
        canonical, seed.racingSubject, ids::IdentityId{seed.owner},
        firstAccepted, firstConflict), asio::use_future);
    auto second = asio::co_spawn(io, raceForSameExternalIdentity(
        canonical, seed.racingSubject, ids::IdentityId{seed.secondOwner},
        secondAccepted, secondConflict), asio::use_future);
    io.run();
    ASSERT_NO_THROW(first.get());
    ASSERT_NO_THROW(second.get());
    EXPECT_NE(firstAccepted, secondAccepted);
    EXPECT_NE(firstConflict, secondConflict);
    EXPECT_EQ(firstAccepted, secondConflict);
    EXPECT_EQ(secondAccepted, firstConflict);

    // Two distinct external accounts linked to the same profile-less
    // canonical identity must both authenticate, while exactly one initial
    // profile row is created under the canonical row's transaction lock.
    bool bothLoginA = false;
    bool bothLoginB = false;
    io.restart();
    auto loginA = asio::co_spawn(io, raceFirstCanonicalProfile(
        canonical, seed.simultaneousSubjectA, seed.simultaneousOwner, bothLoginA),
        asio::use_future);
    auto loginB = asio::co_spawn(io, raceFirstCanonicalProfile(
        canonical, seed.simultaneousSubjectB, seed.simultaneousOwner, bothLoginB),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(loginA.get());
    ASSERT_NO_THROW(loginB.get());
    EXPECT_TRUE(bothLoginA);
    EXPECT_TRUE(bothLoginB);
    const auto profiles = execute(fixture.get(),
        "SELECT COUNT(*)::text FROM openproof.identity_profiles "
        "WHERE identity_id=$1", {seed.simultaneousOwner});
    ASSERT_EQ(PQntuples(profiles.get()), 1);
    EXPECT_STREQ(PQgetvalue(profiles.get(), 0, 0), "1");

    const auto raced = execute(fixture.get(),
        "SELECT identity_id FROM openproof.external_identities "
        "WHERE provider='native-canonical-provider' AND external_subject=$1",
        {seed.racingSubject});
    ASSERT_EQ(PQntuples(raced.get()), 1);
    EXPECT_STREQ(PQgetvalue(raced.get(), 0, 0),
        firstAccepted ? seed.owner.c_str() : seed.secondOwner.c_str());

    // Repeating an already verified login with exactly the same trusted
    // presentation must not allocate a new canonical profile row version.
    // PostgreSQL's ctid/xmin pair observes the physical row and transaction.
    const auto beforeNoop = execute(fixture.get(),
        "SELECT ctid::text,xmin::text FROM openproof.identity_profiles "
        "WHERE identity_id=$1", {seed.owner});
    ASSERT_EQ(PQntuples(beforeNoop.get()), 1);
    const std::string beforeCtid{PQgetvalue(beforeNoop.get(), 0, 0)};
    const std::string beforeXmin{PQgetvalue(beforeNoop.get(), 0, 1)};

    io.restart();
    // The outcome must outlive the coroutine frame: finishLoginAsync takes
    // a const reference and co_spawn can suspend before reading the proof.
    auto stableOutcome = verified(seed.subject, "provider-proposed");
    auto noChangeFuture = asio::co_spawn(io, canonical.finishLoginAsync(
        stableOutcome, kNow), asio::use_future);
    io.run();
    auto noChange = noChangeFuture.get();
    ASSERT_TRUE(noChange);
    EXPECT_EQ(noChange->value(), seed.owner);

    const auto afterNoop = execute(fixture.get(),
        "SELECT ctid::text,xmin::text FROM openproof.identity_profiles "
        "WHERE identity_id=$1", {seed.owner});
    ASSERT_EQ(PQntuples(afterNoop.get()), 1);
    EXPECT_STREQ(PQgetvalue(afterNoop.get(), 0, 0), beforeCtid.c_str());
    EXPECT_STREQ(PQgetvalue(afterNoop.get(), 0, 1), beforeXmin.c_str());
}
} // namespace

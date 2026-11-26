#include <gtest/gtest.h>

#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <libpq-fe.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <future>
#include <initializer_list>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
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
import openproof.organization;

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
    std::string emptyConnectionsOwner = "nc-empty-connections-" + suffix;
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
             std::tuple{emptyConnectionsOwner, org, "0"},
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


// Own the physical connection throughout the query, including cancellation.
asio::awaitable<bool> queryOnNextExecutor(
    std::unique_ptr<pg::async_detail::AsyncConnection> connection)
{
    const auto rows = co_await connection->query(
        "SELECT 'executor-handoff'::text FROM pg_sleep(0.05)", {},
        std::chrono::seconds{1});
    co_return connection->reusable() && rows.rows.size() == 1U
        && rows.rows.front().size() == 1U
        && rows.rows.front().front() == "executor-handoff";
}

TEST(PostgresCanonicalCoroutineTest, RealDatabaseConnectionUsesCurrentExecutor)
{
    const auto dsn = disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK") != nullptr)
            FAIL() << "A disposable SQL database was requested with an invalid DSN.";
        GTEST_SKIP() << "No explicitly acknowledged disposable PostgreSQL cluster.";
    }
    // Keep the original context alive but stopped throughout the next
    // operation. A cached opening executor cannot service its socket.
    asio::io_context next;
    asio::io_context opening;
    auto connected = asio::co_spawn(opening,
        pg::async_detail::AsyncConnection::connect(*dsn,
            std::chrono::seconds{2}), asio::use_future);
    opening.run();
    auto connection = connected.get();
    ASSERT_TRUE(connection);
    ASSERT_TRUE(opening.stopped());

    auto result = asio::co_spawn(next,
        queryOnNextExecutor(std::move(connection)), asio::use_future);
    next.run_for(std::chrono::seconds{3});
    const bool ready = result.wait_for(std::chrono::seconds{0})
        == std::future_status::ready;
    EXPECT_TRUE(ready) << "Query did not complete on its current executor.";
    if (!ready) {
        // Drain a regressed implementation without destroying a context
        // while a coroutine still owns a descriptor on that context.
        opening.restart();
        opening.run_for(std::chrono::seconds{2});
        next.restart();
        next.run_for(std::chrono::seconds{2});
        return;
    }
    EXPECT_TRUE(result.get());
}

// The fixture is isolated by the same guarded Unix socket as every
// canonical SQL integration test. Never insert credentials on a live DB.
TEST(PostgresCanonicalCoroutineTest, RealDatabaseTotpStatusOnlyReadsOwnedBooleans)
{
    const auto dsn = disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK") != nullptr)
            FAIL() << "Explicitly requested disposable database has an invalid socket DSN.";
        GTEST_SKIP() << "Only an explicitly acknowledged disposable database may be used.";
    }
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get()) == CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
        "VALUES($1,'fixture-only-not-a-password-hash',1770000000000)", {seed.owner})));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.totp_credentials(identity_id,encrypted_seed,key_version,enrolled_at_ms) "
        "VALUES($1,decode('00','hex'),1,1770000000000)", {seed.owner})));
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer canonical{
        io.get_executor(), fnd::SecretString{*dsn}, ids::OrganizationId{seed.org}, 2U,
        std::chrono::milliseconds{500}, std::chrono::milliseconds{1000},
        std::chrono::milliseconds{2000}};
    pg::CoroutinePostgresCanonicalFinalizer suspended{
        io.get_executor(), fnd::SecretString{*dsn}, ids::OrganizationId{seed.suspendedOrg}, 1U,
        std::chrono::milliseconds{500}, std::chrono::milliseconds{1000},
        std::chrono::milliseconds{2000}};
    auto run = [&]() -> asio::awaitable<void> {
        const idp::ProviderId provider{"native-canonical-provider"};
        const auto enabled = co_await canonical.readTotpStatusAsync(ids::IdentityId{seed.owner}, provider);
        EXPECT_TRUE(enabled && enabled->first.value() == seed.owner && enabled->second == true);
        const auto disabled = co_await canonical.readTotpStatusAsync(ids::IdentityId{seed.freshLoginOwner}, provider);
        EXPECT_TRUE(disabled && disabled->second == false);
        const auto absent = co_await canonical.readTotpStatusAsync(ids::IdentityId{seed.emptyConnectionsOwner}, provider);
        EXPECT_TRUE(absent && !absent->second.has_value());
        const auto differentProvider = co_await canonical.readTotpStatusAsync(ids::IdentityId{seed.owner}, idp::ProviderId{"other-provider"});
        EXPECT_TRUE(differentProvider && !differentProvider->second.has_value());
        for (const auto& denied : {seed.foreignOwner, seed.lockedOwner, seed.suspendedOwner}) {
            const auto status = co_await canonical.readTotpStatusAsync(ids::IdentityId{denied}, provider);
            EXPECT_TRUE(!status && status.error().code() == fnd::ErrorCode::NotFound);
        }
        const auto inactiveTenant = co_await suspended.readTotpStatusAsync(ids::IdentityId{seed.suspendedOwner}, provider);
        EXPECT_TRUE(!inactiveTenant && inactiveTenant.error().code() == fnd::ErrorCode::NotFound);
    };
    auto done = asio::co_spawn(io, run(), asio::use_future);
    io.run();
    ASSERT_NO_THROW(done.get());
}

struct ProfileReadChecks final {
    bool activeProfile{};
    bool wrongTenantDenied{};
    bool foreignTenantDenied{};
    bool inactiveIdentityDenied{};
    bool inactiveOrganizationDenied{};
    bool activeConnections{};
    bool emptyConnections{};
    bool wrongTenantConnectionsDenied{};
    bool inactiveConnectionsDenied{};
    bool suspendedConnectionsDenied{};
};

asio::awaitable<ProfileReadChecks> verifyTenantScopedProfileRead(
    pg::CoroutinePostgresCanonicalFinalizer& canonical,
    pg::CoroutinePostgresCanonicalFinalizer& wrongTenant,
    pg::CoroutinePostgresCanonicalFinalizer& suspendedTenant,
    const Seed& seed)
{
    ProfileReadChecks checks;
    auto allowed = co_await canonical.readProfileAsync(ids::IdentityId{seed.owner});
    checks.activeProfile = allowed
        && allowed->identity().value() == seed.owner
        && allowed->displayName().has_value()
        && *allowed->displayName() == "User-chosen name";
    auto deniedTenant = co_await wrongTenant.readProfileAsync(
        ids::IdentityId{seed.owner});
    checks.wrongTenantDenied = !deniedTenant
        && deniedTenant.error().code() == fnd::ErrorCode::NotFound;
    auto foreign = co_await canonical.readProfileAsync(
        ids::IdentityId{seed.foreignOwner});
    checks.foreignTenantDenied = !foreign
        && foreign.error().code() == fnd::ErrorCode::NotFound;
    auto locked = co_await canonical.readProfileAsync(
        ids::IdentityId{seed.lockedOwner});
    checks.inactiveIdentityDenied = !locked
        && locked.error().code() == fnd::ErrorCode::NotFound;
    auto suspended = co_await suspendedTenant.readProfileAsync(
        ids::IdentityId{seed.suspendedOwner});
    checks.inactiveOrganizationDenied = !suspended
        && suspended.error().code() == fnd::ErrorCode::NotFound;

    auto linked = co_await canonical.readConnectionsAsync(ids::IdentityId{seed.owner});
    checks.activeConnections = linked
        && linked->first.value() == seed.owner && !linked->second.empty();
    auto emptyLinks = co_await canonical.readConnectionsAsync(
        ids::IdentityId{seed.emptyConnectionsOwner});
    checks.emptyConnections = emptyLinks
        && emptyLinks->first.value() == seed.emptyConnectionsOwner
        && emptyLinks->second.empty();
    auto wrongLinks = co_await wrongTenant.readConnectionsAsync(
        ids::IdentityId{seed.owner});
    checks.wrongTenantConnectionsDenied = !wrongLinks
        && wrongLinks.error().code() == fnd::ErrorCode::NotFound;
    auto inactiveLinks = co_await canonical.readConnectionsAsync(
        ids::IdentityId{seed.lockedOwner});
    checks.inactiveConnectionsDenied = !inactiveLinks
        && inactiveLinks.error().code() == fnd::ErrorCode::NotFound;
    auto suspendedLinks = co_await suspendedTenant.readConnectionsAsync(
        ids::IdentityId{seed.suspendedOwner});
    checks.suspendedConnectionsDenied = !suspendedLinks
        && suspendedLinks.error().code() == fnd::ErrorCode::NotFound;
    co_return checks;
}

// Exercise concurrent native readers on different io_context threads,
// including an active Identity with no external providers. No request may
// inherit another owner's linked account metadata through pool reuse.
asio::awaitable<bool> concurrentConnectionRead(
    pg::CoroutinePostgresCanonicalFinalizer& canonical,
    ids::IdentityId owner, bool emptyExpected)
{
    auto linked = co_await canonical.readConnectionsAsync(owner);
    co_return linked && linked->first == owner
        && linked->second.empty() == emptyExpected;
}

TEST(PostgresCanonicalCoroutineTest, RealDatabaseAuthorizationMembershipIsTenantBoundAndFresh)
{
    const auto dsn = disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK") != nullptr)
            FAIL() << "Explicitly requested disposable database has an invalid socket DSN.";
        GTEST_SKIP() << "Only an explicitly acknowledged disposable database may be used.";
    }
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get()) == CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    for (const auto& [tenant, subject, state] : {
         std::tuple{seed.org, seed.owner, "1"},
         std::tuple{seed.org, seed.secondOwner, "2"},
         std::tuple{seed.org, seed.freshLoginOwner, "0"},
         std::tuple{seed.org, seed.lockedOwner, "1"},
         std::tuple{seed.org, seed.emptyConnectionsOwner, "1"},
         std::tuple{seed.foreignOrg, seed.foreignOwner, "1"},
         std::tuple{seed.suspendedOrg, seed.suspendedOwner, "1"}}) {
        ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
            "INSERT INTO openproof.memberships(organization_id,identity_id,state,invited_at_ms) "
            "VALUES($1,$2,$3,1770000000000)", {tenant, subject, state})));
    }
    for (const auto& role : {"owner", "auditor"}) {
        ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
            "INSERT INTO openproof.membership_roles(organization_id,identity_id,role) VALUES($1,$2,$3)",
            {seed.org, seed.owner, role})));
    }
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer canonical{
        io.get_executor(), fnd::SecretString{*dsn}, ids::OrganizationId{seed.org}, 2U,
        std::chrono::milliseconds{500}, std::chrono::milliseconds{1000},
        std::chrono::milliseconds{2000}};
    pg::CoroutinePostgresCanonicalFinalizer suspended{
        io.get_executor(), fnd::SecretString{*dsn}, ids::OrganizationId{seed.suspendedOrg}, 1U,
        std::chrono::milliseconds{500}, std::chrono::milliseconds{1000},
        std::chrono::milliseconds{2000}};
    auto check = [&]() -> asio::awaitable<void> {
        auto allowed = co_await canonical.readAuthorizationMembershipAsync(
            ids::IdentityId{seed.owner}, ids::OrganizationId{seed.org});
        if (!allowed) {
            ADD_FAILURE() << "Expected active tenant membership";
            co_return;
        }
        EXPECT_EQ(allowed->identity().value(), seed.owner);
        EXPECT_EQ(allowed->organization().value(), seed.org);
        EXPECT_EQ(allowed->roles().size(), 2U);
        EXPECT_TRUE(allowed->hasRole(openproof::organization::Role{"owner"}));
        EXPECT_TRUE(allowed->hasRole(openproof::organization::Role{"auditor"}));
        auto empty = co_await canonical.readAuthorizationMembershipAsync(
            ids::IdentityId{seed.emptyConnectionsOwner}, ids::OrganizationId{seed.org});
        EXPECT_TRUE(empty && empty->roles().empty());
        for (const auto& subject : {seed.secondOwner, seed.freshLoginOwner, seed.lockedOwner,
                                    seed.foreignOwner, seed.simultaneousOwner}) {
            auto denied = co_await canonical.readAuthorizationMembershipAsync(
                ids::IdentityId{subject}, ids::OrganizationId{seed.org});
            EXPECT_TRUE(!denied && denied.error().code() == fnd::ErrorCode::PermissionDenied);
        }
        auto wrongTenant = co_await canonical.readAuthorizationMembershipAsync(
            ids::IdentityId{seed.owner}, ids::OrganizationId{seed.foreignOrg});
        EXPECT_TRUE(!wrongTenant && wrongTenant.error().code() == fnd::ErrorCode::PermissionDenied);
        auto inactiveTenant = co_await suspended.readAuthorizationMembershipAsync(
            ids::IdentityId{seed.suspendedOwner}, ids::OrganizationId{seed.suspendedOrg});
        EXPECT_TRUE(!inactiveTenant && inactiveTenant.error().code() == fnd::ErrorCode::PermissionDenied);
    };
    auto done = asio::co_spawn(io, check(), asio::use_future);
    io.run();
    ASSERT_NO_THROW(done.get());

    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "DELETE FROM openproof.membership_roles WHERE organization_id=$1 AND identity_id=$2 AND role='owner'",
        {seed.org, seed.owner})));
    io.restart();
    // Boost.Asio 1.88 co_spawn requires a default-constructible completion
    // value on exception. Membership intentionally has no default state.
    // Keep that invariant and transfer the result through a void coroutine.
    std::optional<fnd::Result<openproof::organization::Membership>> refreshedResult;
    auto refresh = [&]() -> asio::awaitable<void> {
        refreshedResult.emplace(co_await canonical.readAuthorizationMembershipAsync(
            ids::IdentityId{seed.owner}, ids::OrganizationId{seed.org}));
    };
    auto refreshed = asio::co_spawn(io, refresh(), asio::use_future);
    io.run();
    ASSERT_NO_THROW(refreshed.get());
    ASSERT_TRUE(refreshedResult);
    auto& member = *refreshedResult;
    ASSERT_TRUE(member);
    EXPECT_FALSE(member->hasRole(openproof::organization::Role{"owner"}));
    EXPECT_TRUE(member->hasRole(openproof::organization::Role{"auditor"}));

    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.membership_roles(organization_id,identity_id,role) "
        "SELECT $1,$2,'role-' || n::text FROM generate_series(1,257) AS n",
        {seed.org, seed.owner})));
    io.restart();
    refreshedResult.reset();
    auto overflow = asio::co_spawn(io, refresh(), asio::use_future);
    io.run();
    ASSERT_NO_THROW(overflow.get());
    ASSERT_TRUE(refreshedResult);
    auto& bounded = *refreshedResult;
    EXPECT_TRUE(!bounded && bounded.error().code() == fnd::ErrorCode::Unavailable);
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

    // Seed profile data even for forbidden identity states: the SQL reader
    // must not mistake "profile exists" for authorization to disclose it.
    for (const auto& forbidden : {
             seed.foreignOwner, seed.lockedOwner, seed.suspendedOwner}) {
        static_cast<void>(execute(fixture.get(),
            "INSERT INTO openproof.identity_profiles("
            "identity_id,display_name,created_at_ms,updated_at_ms) "
            "VALUES($1,'Do not disclose',1770000000000,1770000000000) "
            "ON CONFLICT(identity_id) DO UPDATE "
            "SET display_name=EXCLUDED.display_name", {forbidden}));
    }
    io.restart();
    auto profileReads = asio::co_spawn(io,
        verifyTenantScopedProfileRead(
            canonical, wrongTenant, suspendedTenant, seed), asio::use_future);
    io.run();
    const auto profileChecks = profileReads.get();
    EXPECT_TRUE(profileChecks.activeProfile);
    EXPECT_TRUE(profileChecks.wrongTenantDenied);
    EXPECT_TRUE(profileChecks.foreignTenantDenied);
    EXPECT_TRUE(profileChecks.inactiveIdentityDenied);
    EXPECT_TRUE(profileChecks.inactiveOrganizationDenied);
    EXPECT_TRUE(profileChecks.activeConnections);
    EXPECT_TRUE(profileChecks.emptyConnections);
    EXPECT_TRUE(profileChecks.wrongTenantConnectionsDenied);
    EXPECT_TRUE(profileChecks.inactiveConnectionsDenied);
    EXPECT_TRUE(profileChecks.suspendedConnectionsDenied);

    // Run more requests than the bounded connection-pool capacity on four
    // executor threads. A simple sequential SELECT would never exercise
    // the channel handoff and connection lifetime under real contention.
    // The normal runtime constructs a dedicated native PostgreSQL executor.
    // Do the same here: prior identity mutation/negative-timeout scenarios
    // have already stopped/restarted "io" repeatedly, and reusing their
    // reactor introduces unrelated stale cancellation state into this probe.
    // This is still the SAME disposable database, and all eight SQL requests
    // contend for two physical connections in four running OS threads.
    asio::io_context concurrentIo;
    pg::CoroutinePostgresCanonicalFinalizer concurrentCanonical{
        concurrentIo.get_executor(), fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org}, 2U,
        std::chrono::milliseconds{500}, std::chrono::milliseconds{1000},
        std::chrono::milliseconds{2000}};
    // Keep the independent executor alive until all eight completions fire.
    auto work = asio::make_work_guard(concurrentIo);
    std::atomic<std::size_t> completed{0U};
    std::atomic<std::size_t> failed{0U};
    std::promise<void> allCompleted;
    auto completion = allCompleted.get_future();
    for (std::size_t index = 0U; index < 8U; ++index) {
        const bool emptyExpected = index % 2U == 1U;
        asio::co_spawn(concurrentIo,
            concurrentConnectionRead(concurrentCanonical, ids::IdentityId{
                emptyExpected ? seed.emptyConnectionsOwner : seed.owner},
                emptyExpected),
            [&](std::exception_ptr exception, bool valid) {
                if (exception || !valid)
                    failed.fetch_add(1U, std::memory_order_relaxed);
                if (completed.fetch_add(1U, std::memory_order_acq_rel) + 1U == 8U)
                    allCompleted.set_value();
            });
    }
    std::vector<std::thread> workers;
    workers.reserve(4U);
    for (std::size_t index = 0U; index < 4U; ++index)
        workers.emplace_back([&concurrentIo] { concurrentIo.run(); });
    // A shared ten-second ceiling prevents deadlocks from hanging CI.
    const bool finished = completion.wait_for(std::chrono::seconds{10})
        == std::future_status::ready;
    work.reset();
    concurrentIo.stop();
    for (auto& worker : workers) worker.join();
    EXPECT_TRUE(finished);
    EXPECT_EQ(completed.load(std::memory_order_acquire), 8U);
    EXPECT_EQ(failed.load(std::memory_order_relaxed), 0U);
}
} // namespace

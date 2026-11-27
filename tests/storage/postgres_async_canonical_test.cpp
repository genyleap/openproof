#include <gtest/gtest.h>

#include "../../src/gateway/asio_service_ids_extern.hpp"
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <libpq-fe.h>

#include <algorithm>
#include <array>
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
#include "coroutine_auth_transaction_store.hpp"
#include "coroutine_canonical_finalizer.hpp"
#include "coroutine_consent_store.hpp"
#include "coroutine_session_authenticator.hpp"
#include "coroutine_authorization_audit.hpp"
#include "coroutine_verification_challenge_store.hpp"
#include "coroutine_local_credential_store.hpp"
#include "coroutine_recovery_code_repository.hpp"
#include "coroutine_local_proof_verifier.hpp"

import openproof.account;
import openproof.authentication;
import openproof.audit;
import openproof.consent;
import openproof.credentials;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.profile;
import openproof.identity.provider;
import openproof.organization;
import openproof.policy;
import openproof.session;
import openproof.security;
import openproof.token;
import openproof.client;
import openproof.oauth;

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
    std::string unlinkedSubject = "nc-unlinked-" + suffix;
    std::string matchingEmailSubject = "nc-email-match-" + suffix;

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
    bool matchingVerifiedEmailDenied{};
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
        verified(seed.unlinkedSubject), kNow);
    checks.unlinkedDenied = !missing
        && missing.error().code() == fnd::ErrorCode::AuthenticationFailed;

    // A verified email matching an existing native profile is not an
    // external identity link and cannot authorize implicit provisioning.
    auto matchingEmail = co_await canonical.finishLoginAsync(
        verified(seed.matchingEmailSubject, "must-not-update", "first@example.test"), kNow);
    checks.matchingVerifiedEmailDenied = !matchingEmail
        && matchingEmail.error().code() == fnd::ErrorCode::AuthenticationFailed;

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

TEST(PostgresCanonicalCoroutineTest, RealDatabaseNativeReadinessChecksActualPool)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{"readiness-fixture"},1U,500ms,1000ms,3000ms};
    auto first=asio::co_spawn(io,native.healthCheckAsync(),asio::use_future);
    auto second=asio::co_spawn(io,native.healthCheckAsync(),asio::use_future);
    io.run();
    EXPECT_TRUE(first.get());
    EXPECT_TRUE(second.get());
    io.restart();
    auto third=asio::co_spawn(io,native.healthCheckAsync(),asio::use_future);
    io.run();
    EXPECT_TRUE(third.get()); // the previous probes returned the only lease
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
    if (!connection->reusable() || rows.rows.size() != 1U
        || rows.rows.front().size() != 1U
        || rows.rows.front().front() != "executor-handoff") co_return false;
    // A bounded result much larger than one PostgreSQL protocol buffer
    // exercises repeated readiness waits on the current executor.
    const auto streamed = co_await connection->query(
        // Qualify the input column: unqualified ORDER BY i resolves to the
        // text output column i, which sorts 1, 10, 100 rather than numerically.
        "SELECT series.i::text, repeat('x', 1024) FROM generate_series(1, 512) AS series(i) ORDER BY series.i",
        {}, std::chrono::seconds{2});
    if (streamed.rows.size() != 512U) {
        ADD_FAILURE() << "Unexpected streamed row count: " << streamed.rows.size();
        co_return false;
    }
    const std::string payload(1024U, 'x');
    for (std::size_t index = 0U; index < streamed.rows.size(); ++index) {
        const auto& row = streamed.rows[index];
        if (row.size() != 2U || row[0] != std::to_string(index + 1U)
            || row[1] != payload) {
            ADD_FAILURE() << "Incorrect bounded stream row at index " << index;
            co_return false;
        }
    }
    const auto after = co_await connection->query(
        "SELECT 'reuse-after-stream'::text", {}, std::chrono::seconds{1});
    if (!connection->reusable() || after.rows.size() != 1U
        || after.rows.front().size() != 1U
        || after.rows.front().front() != "reuse-after-stream") co_return false;
    // A server error after emitting a large prefix of single-row results
    // must discard every partial row and poison the physical connection.
    try {
        static_cast<void>(co_await connection->query(
            "SELECT repeat('x', 1024), 1 / (512-i) FROM generate_series(1,512) AS series(i)",
            {}, std::chrono::seconds{2}));
    } catch (const std::runtime_error&) {
        co_return !connection->reusable();
    }
    co_return false;
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
    next.run_for(std::chrono::seconds{6});
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

TEST(PostgresCanonicalCoroutineTest, NativeEvidenceChallengesAndBatchesAreSessionBound)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace ev=openproof::evidence;
    namespace verify=ev::verification;
    using Op=verify::AccountOperation;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    const auto sessionName="evidence-session-"+seed.suffix;
    const auto digest=fnd::toHex(openproof::security::sha256(sessionName).value());
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.sessions(id,identity_id,provider,assurance,factors,phishing_resistant,state,"
        "token_digest,authenticated_at_ms,issued_at_ms,last_seen_at_ms,absolute_expires_at_ms,idle_timeout_ms) "
        "VALUES($1,$2,'local',2,3,false,0,decode($3,'hex'),1770000000000,1770000000000,1770000000000,1770003600000,600000)",
        {sessionName,seed.owner,digest})));
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    const auto provider=openproof::identity::provider::ProviderId{"signed-jwt-evidence"};
    const auto challenge=verify::ChallengeDigest{fnd::toHex(openproof::security::sha256(seed.suffix).value())};
    const auto task=[&](verify::AccountCommand command,std::string identity={},fnd::Instant when=kNow+1s){
        return native.evidenceAccountAsync(ids::IdentityId{identity.empty()?seed.owner:identity},
            openproof::session::SessionId{sessionName},when,std::move(command));
    };
    const auto run=[&](verify::AccountCommand command,std::string identity={},fnd::Instant when=kNow+1s){
        io.restart();
        auto done=asio::co_spawn(io,task(std::move(command),std::move(identity),when),asio::use_future);
        io.run();return done.get();
    };
    const verify::AccountCommand list{Op::List,openproof::identity::provider::ProviderId{""},verify::ChallengeDigest{""},{},{}};
    auto empty=run(list);
    ASSERT_TRUE(empty && empty->empty());
    EXPECT_FALSE(run(list,seed.foreignOwner));
    const verify::AccountCommand issue{Op::Issue,provider,challenge,kNow+300s,{}};
    const verify::AccountCommand consume{Op::Consume,provider,challenge,{},{}};
    ASSERT_TRUE(run(issue));
    EXPECT_FALSE(run(issue));
    auto wrong=consume;wrong.provider=openproof::identity::provider::ProviderId{"x509-evidence"};
    EXPECT_FALSE(run(wrong));
    EXPECT_FALSE(run(consume,seed.secondOwner));
    io.restart();
    auto first=asio::co_spawn(io,task(consume),asio::use_future);
    auto second=asio::co_spawn(io,task(consume),asio::use_future);
    io.run();
    auto a=first.get(),b=second.get();
    ASSERT_NE(a.has_value(),b.has_value());
    EXPECT_FALSE(run(consume));
    const auto evidenceId="native-evidence-"+seed.suffix;
    const auto record=[&](std::string id,std::string owner){
        return ev::Evidence::create(ev::EvidenceId{std::move(id)},ids::IdentityId{std::move(owner)},
            provider,"jwt.attestation","fixture.claim","fixture-value",85U,kNow+1s,kNow+200s).value();
    };
    auto item=record(evidenceId,seed.owner);
    auto foreign=record(evidenceId+"-foreign",seed.foreignOwner);
    EXPECT_FALSE(run({Op::Persist,provider,verify::ChallengeDigest{""},{},{foreign}}));
    // A duplicate in the batch must roll back the first insert as well.
    EXPECT_FALSE(run({Op::Persist,provider,verify::ChallengeDigest{""},{},{item,item}}));
    auto rolledBack=run(list);
    ASSERT_TRUE(rolledBack && rolledBack->empty());
    ASSERT_TRUE(run({Op::Persist,provider,verify::ChallengeDigest{""},{},{item}}));
    auto listed=run(list);
    ASSERT_TRUE(listed && listed->size()==1U);
    EXPECT_EQ(listed->front().id(),item.id());
    EXPECT_EQ(listed->front().confidence(),85U);
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "UPDATE openproof.sessions SET state=1,revoked_at_ms=1770000002000 WHERE id=$1",{sessionName})));
    EXPECT_FALSE(run(list));
    EXPECT_FALSE(run({Op::Persist,provider,verify::ChallengeDigest{""},{},{record(evidenceId+"-revoked",seed.owner)}}));
}

TEST(PostgresCanonicalCoroutineTest, NativeScimReadsPreserveTenantAndCanonicalState)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace scim=openproof::enterprise::scim;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    const auto group="scim-group-"+seed.suffix,foreignGroup="scim-foreign-"+seed.suffix;
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.scim_users(identity_id,organization_id,user_name,external_id,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,'alice','fixture-external',1770000000000,1770000000123),"
        "($3,$2,'bob',NULL,1770000000000,1770000000123),"
        "($4,$5,'alice','foreign-external',1770000000000,1770000000123)",
        {seed.owner,seed.org,seed.lockedOwner,seed.foreignOwner,seed.foreignOrg})));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.scim_groups(id,organization_id,display_name,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,'Engineering',1770000000000,1770000000123),"
        "($3,$4,'Engineering',1770000000000,1770000000123)",
        {group,seed.org,foreignGroup,seed.foreignOrg})));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.scim_group_members(organization_id,group_id,identity_id) VALUES($1,$2,$3),($1,$2,$4),($5,$6,$7)",
        {seed.org,group,seed.owner,seed.lockedOwner,seed.foreignOrg,foreignGroup,seed.foreignOwner})));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.identity_profiles(identity_id,display_name,email,email_verified,created_at_ms,updated_at_ms) "
        "VALUES($1,'Alice Fixture','alice@example.invalid',false,1770000000000,1770000000123) "
        "ON CONFLICT(identity_id) DO UPDATE SET display_name=EXCLUDED.display_name,email=EXCLUDED.email",
        {seed.owner})));
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    const auto read=[&](scim::ReadKind kind,scim::ReadSelector selector=scim::ReadSelector::All,
        std::optional<std::string> value=std::nullopt) {
        io.restart();
        auto done=asio::co_spawn(io,native.readScimAsync({kind,selector,std::move(value)}),asio::use_future);
        io.run();return done.get();
    };
    auto users=read(scim::ReadKind::Users);
    ASSERT_TRUE(users);
    ASSERT_EQ(users->rows.size(),2U);
    EXPECT_NE(users->rows[0].json.find(seed.owner),std::string::npos);
    EXPECT_NE(users->rows[0].json.find("Alice Fixture"),std::string::npos);
    EXPECT_NE(users->rows[0].json.find("alice@example.invalid"),std::string::npos);
    EXPECT_NE(users->rows[0].json.find(fnd::toIso8601(kNow+123ms)),std::string::npos);
    EXPECT_EQ(users->rows[0].updatedAt,kNow+123ms);
    EXPECT_EQ(users->rows[0].json.find("foreign-external"),std::string::npos);
    EXPECT_EQ(users->rows[1].json.find("externalId"),std::string::npos);
    EXPECT_NE(users->rows[1].json.find("false"),std::string::npos);
    auto matched=read(scim::ReadKind::Users,scim::ReadSelector::Name,"alice");
    ASSERT_TRUE(matched && matched->rows.size()==1U);
    EXPECT_NE(matched->rows.front().json.find(seed.owner),std::string::npos);
    auto absent=read(scim::ReadKind::Users,scim::ReadSelector::Name,"missing");
    ASSERT_TRUE(absent);
    EXPECT_TRUE(absent->rows.empty());
    auto foreign=read(scim::ReadKind::Users,scim::ReadSelector::Id,seed.foreignOwner);
    ASSERT_FALSE(foreign);
    EXPECT_EQ(foreign.error().code(),fnd::ErrorCode::NotFound);
    auto groups=read(scim::ReadKind::Groups,scim::ReadSelector::Name,"Engineering");
    ASSERT_TRUE(groups && groups->rows.size()==1U);
    EXPECT_NE(groups->rows.front().json.find(group),std::string::npos);
    EXPECT_NE(groups->rows.front().json.find(seed.owner),std::string::npos);
    EXPECT_NE(groups->rows.front().json.find(seed.lockedOwner),std::string::npos);
    EXPECT_EQ(groups->rows.front().json.find(seed.foreignOwner),std::string::npos);
    EXPECT_FALSE(read(scim::ReadKind::Groups,scim::ReadSelector::Id,foreignGroup));
    EXPECT_FALSE(read(scim::ReadKind::Users,scim::ReadSelector::All,"unexpected"));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "UPDATE openproof.organizations SET state=1 WHERE id=$1",{seed.org})));
    auto disabled=read(scim::ReadKind::Users);
    ASSERT_FALSE(disabled);
    EXPECT_EQ(disabled.error().code(),fnd::ErrorCode::PermissionDenied);
}

TEST(PostgresCanonicalCoroutineTest, NativeScimMutationsAreAtomicAndVersioned)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace scim=openproof::enterprise::scim;
    using Op=scim::MutationKind;
    using Kind=scim::ReadKind;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    const auto command=[](Kind kind,Op op,std::string id) {
        return scim::MutationRequest{kind,op,std::move(id),std::nullopt,
            std::nullopt,std::nullopt,std::nullopt,std::nullopt,std::nullopt,{}};
    };
    const auto run=[&](scim::MutationRequest input) {
        io.restart();
        auto done=asio::co_spawn(io,native.mutateScimAsync(std::move(input),kNow+1s),asio::use_future);
        io.run();return done.get();
    };
    const auto user="scim-user-"+seed.suffix,second=user+"-2",group="scim-group-"+seed.suffix;
    auto create=command(Kind::Users,Op::Create,user);
    create.name="fixture-user";create.displayName="Fixture User";create.email="fixture@example.invalid";
    auto created=run(create);
    ASSERT_TRUE(created && created->rows.size()==1U);
    EXPECT_EQ(created->rows.front().updatedAt,kNow+1s);
    auto duplicate=create;duplicate.id=second;
    auto denied=run(duplicate);
    ASSERT_FALSE(denied);
    EXPECT_EQ(denied.error().code(),fnd::ErrorCode::AlreadyExists);
    const auto missing=execute(fixture.get(),"SELECT count(*)::text FROM openproof.identities WHERE id=$1",{second});
    EXPECT_STREQ(PQgetvalue(missing.get(),0,0),"0");
    duplicate.name="fixture-second";
    ASSERT_TRUE(run(duplicate));
    EXPECT_FALSE(run(command(Kind::Users,Op::Remove,seed.owner)));
    EXPECT_FALSE(run(command(Kind::Users,Op::Remove,seed.foreignOwner)));
    auto newGroup=command(Kind::Groups,Op::Create,group);
    newGroup.name="Fixture Group";
    newGroup.memberChanges.push_back({scim::MemberAction::Replace,{ids::IdentityId{seed.foreignOwner}}});
    EXPECT_FALSE(run(newGroup));
    const auto absent=execute(fixture.get(),"SELECT count(*)::text FROM openproof.scim_groups WHERE id=$1",{group});
    EXPECT_STREQ(PQgetvalue(absent.get(),0,0),"0");
    newGroup.memberChanges.front().members={ids::IdentityId{user}};
    auto added=run(newGroup);
    ASSERT_TRUE(added && added->rows.size()==1U);
    auto groupPatch=command(Kind::Groups,Op::Patch,group);
    groupPatch.expectedVersion=added->rows.front().updatedAt;
    groupPatch.memberChanges.push_back({scim::MemberAction::Add,{ids::IdentityId{second}}});
    auto modified=run(groupPatch);
    ASSERT_TRUE(modified) << (modified ? "" : std::string{modified.error().internalDetail()});
    ASSERT_EQ(modified->rows.size(),1U);
    EXPECT_NE(modified->rows.front().json.find(second),std::string::npos);
    EXPECT_GT(modified->rows.front().updatedAt,added->rows.front().updatedAt);
    auto stale=run(groupPatch);
    ASSERT_FALSE(stale);
    EXPECT_EQ(stale.error().code(),fnd::ErrorCode::FailedPrecondition);
    auto groupRemove=command(Kind::Groups,Op::Patch,group);
    groupRemove.memberChanges.push_back({scim::MemberAction::Remove,{ids::IdentityId{second}}});
    auto reduced=run(groupRemove);
    ASSERT_TRUE(reduced && reduced->rows.size()==1U);
    EXPECT_EQ(reduced->rows.front().json.find(second),std::string::npos);
    const auto session="scim-session-"+seed.suffix;
    const auto digest=fnd::toHex(openproof::security::sha256(session).value());
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.sessions(id,identity_id,provider,assurance,factors,phishing_resistant,state,"
        "token_digest,authenticated_at_ms,issued_at_ms,last_seen_at_ms,absolute_expires_at_ms,idle_timeout_ms) "
        "VALUES($1,$2,'local',2,3,false,0,decode($3,'hex'),1770000000000,1770000000000,1770000000000,1770003600000,600000)",
        {session,user,digest})));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.membership_roles(organization_id,identity_id,role) VALUES($1,$2,'owner')",{seed.org,user})));
    auto disable=command(Kind::Users,Op::Patch,user);
    disable.active=false;
    auto protectedOwner=run(disable);
    ASSERT_FALSE(protectedOwner);
    EXPECT_EQ(protectedOwner.error().code(),fnd::ErrorCode::FailedPrecondition);
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.membership_roles(organization_id,identity_id,role) VALUES($1,$2,'owner')",{seed.org,second})));
    auto disabled=run(disable);
    ASSERT_TRUE(disabled && disabled->rows.size()==1U);
    EXPECT_NE(disabled->rows.front().json.find("false"),std::string::npos);
    const auto sessionState=execute(fixture.get(),"SELECT state::text FROM openproof.sessions WHERE id=$1",{session});
    EXPECT_STREQ(PQgetvalue(sessionState.get(),0,0),"1");
    disable.active=true;
    ASSERT_TRUE(run(disable));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),"UPDATE openproof.identities SET status=2 WHERE id=$1",{user})));
    EXPECT_FALSE(run(disable));
    disable.active=false;
    ASSERT_TRUE(run(disable));
    disable.active=true;
    EXPECT_FALSE(run(disable));
    ASSERT_TRUE(run(command(Kind::Users,Op::Remove,user)));
    const auto retired=execute(fixture.get(),
        "SELECT i.status::text,m.state::text,(SELECT count(*) FROM openproof.scim_users WHERE identity_id=$1)::text,"
        "(SELECT count(*) FROM openproof.scim_group_members WHERE identity_id=$1)::text "
        "FROM openproof.identities i JOIN openproof.memberships m ON m.identity_id=i.id WHERE i.id=$1",{user});
    ASSERT_EQ(PQntuples(retired.get()),1);
    EXPECT_STREQ(PQgetvalue(retired.get(),0,0),"3");
    EXPECT_STREQ(PQgetvalue(retired.get(),0,1),"3");
    EXPECT_STREQ(PQgetvalue(retired.get(),0,2),"0");
    EXPECT_STREQ(PQgetvalue(retired.get(),0,3),"0");
    EXPECT_FALSE(run(disable));
    auto oldGroupDelete=command(Kind::Groups,Op::Remove,group);
    oldGroupDelete.expectedVersion=reduced->rows.front().updatedAt;
    EXPECT_FALSE(run(oldGroupDelete));
    ASSERT_TRUE(run(command(Kind::Groups,Op::Remove,group)));
}

TEST(PostgresCanonicalCoroutineTest, NativePasskeyListingAndRegistrationChallengeAreSessionBound)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace pk=openproof::provider::passkey;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    const auto sessionName="passkey-session-"+seed.suffix;
    const auto credentialId="passkey-credential-"+seed.suffix;
    const auto otherCredential="passkey-other-"+seed.suffix;
    const auto digest=fnd::toHex(openproof::security::sha256(sessionName).value());
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.sessions(id,identity_id,provider,assurance,factors,phishing_resistant,state,"
        "token_digest,authenticated_at_ms,issued_at_ms,last_seen_at_ms,absolute_expires_at_ms,idle_timeout_ms) "
        "VALUES($1,$2,'local',2,3,false,0,decode($3,'hex'),1770000000000,1770000000000,1770000000000,1770003600000,600000)",
        {sessionName,seed.owner,digest})));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.passkey_credentials(credential_id,identity_id,public_key_x,public_key_y,sign_count,created_at_ms,last_used_at_ms) "
        "VALUES($1,$2,'fixture-x','fixture-y',7,1770000000000,1770000000000),"
        "($3,$4,'fixture-x','fixture-y',0,1770000000000,1770000000000)",
        {credentialId,seed.owner,otherCredential,seed.secondOwner})));
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    const auto read=[&](std::optional<pk::RegistrationCeremony> ceremony=std::nullopt,
        std::string identity={},fnd::Instant now=kNow+1s) {
        io.restart();
        auto task=native.readPasskeyAccountAsync(ids::IdentityId{identity.empty()?seed.owner:identity},
            openproof::session::SessionId{sessionName},now,std::move(ceremony));
        auto done=asio::co_spawn(io,std::move(task),asio::use_future);
        io.run(); return done.get();
    };
    const auto listed=read();
    ASSERT_TRUE(listed);
    ASSERT_EQ(listed->size(),1U);
    EXPECT_EQ(listed->front().credentialId,credentialId);
    EXPECT_EQ(listed->front().signCount,7U);
    EXPECT_FALSE(read(std::nullopt,seed.secondOwner));
    EXPECT_FALSE(read(std::nullopt,seed.owner,kNow+601s));
    auto ceremony=[&](std::string suffix,fnd::Instant expiry) {
        return pk::RegistrationCeremony{openproof::identity::provider::ChallengeId{"pkr_"+seed.suffix+suffix},
            ids::IdentityId{seed.owner},expiry};
    };
    const auto first=ceremony("-first",kNow+300s);
    const auto expired=ceremony("-expired",kNow);
    EXPECT_FALSE(read(expired));
    auto mismatch=first;
    mismatch.identity=ids::IdentityId{seed.secondOwner};
    EXPECT_FALSE(read(mismatch));
    ASSERT_TRUE(read(first));
    EXPECT_FALSE(read(first));
    const auto stored=execute(fixture.get(),
        "SELECT identity_id,expires_at_ms::text,consumed_at_ms IS NULL FROM openproof.passkey_registration_ceremonies WHERE id=$1",
        {std::string{first.id.value()}});
    ASSERT_EQ(PQntuples(stored.get()),1);
    EXPECT_EQ(std::string{PQgetvalue(stored.get(),0,0)},seed.owner);
    EXPECT_STREQ(PQgetvalue(stored.get(),0,1),"1770000300000");
    EXPECT_STREQ(PQgetvalue(stored.get(),0,2),"t");
    // The existing ceremony counts toward the bound; no unbounded creation.
    for (int n=1;n<32;++n) {
        const auto next=ceremony("-"+std::to_string(n),kNow+300s);
        ASSERT_TRUE(read(next));
    }
    auto capped=read(ceremony("-capped",kNow+300s));
    ASSERT_FALSE(capped);
    EXPECT_EQ(capped.error().code(),fnd::ErrorCode::RateLimited);
    // Passkey mutation rollback and last credential protection.
    const auto mutate=[&](std::string id,std::optional<pk::RegistrationCeremony> challenge=std::nullopt,
        std::string owner={},fnd::Instant now=kNow+2s) {
        auto identity=ids::IdentityId{owner.empty()?seed.owner:owner};
        std::optional<pk::PasskeyCredential> verified;
        std::optional<openproof::identity::provider::ChallengeId> cid;
        if (challenge) {
            cid=challenge->id;
            verified.emplace(pk::PasskeyCredential{id,identity,std::string(43,'A'),std::string(43,'B'),0U,now,now});
        }
        return native.mutatePasskeyAccountAsync(identity,openproof::session::SessionId{sessionName},now,
            std::move(id),std::move(cid),std::move(verified));
    };
    const auto runMutation=[&](auto task){
        io.restart();
        auto done=asio::co_spawn(io,std::move(task),asio::use_future);
        io.run(); return done.get();
    };
    EXPECT_FALSE(runMutation(mutate(otherCredential,first)));
    const auto unconsumed=execute(fixture.get(),
        "SELECT consumed_at_ms IS NULL FROM openproof.passkey_registration_ceremonies WHERE id=$1",
        {std::string{first.id.value()}});
    EXPECT_STREQ(PQgetvalue(unconsumed.get(),0,0),"t");
    const auto newCredential="native-new-"+seed.suffix;
    io.restart();
    auto one=asio::co_spawn(io,mutate(newCredential,first),asio::use_future);
    auto two=asio::co_spawn(io,mutate(newCredential+"-duplicate",first),asio::use_future);
    io.run();
    auto a=one.get(),b=two.get();
    ASSERT_NE(a.has_value(),b.has_value());
    const auto winner=a?newCredential:newCredential+"-duplicate";
    EXPECT_FALSE(runMutation(mutate(otherCredential)));
    EXPECT_FALSE(runMutation(mutate(winner,std::nullopt,seed.secondOwner)));
    io.restart();
    auto delA=asio::co_spawn(io,mutate(credentialId),asio::use_future);
    auto delB=asio::co_spawn(io,mutate(winner),asio::use_future);
    io.run();
    auto da=delA.get(),db=delB.get();
    ASSERT_NE(da.has_value(),db.has_value());
    EXPECT_EQ((da?db:da).error().code(),fnd::ErrorCode::FailedPrecondition);
    const auto remaining=read();
    ASSERT_TRUE(remaining);
    ASSERT_EQ(remaining->size(),1U);
    const auto link=execute(fixture.get(),
        "SELECT identity_id FROM openproof.external_identities WHERE provider='passkey' AND external_subject=$1",
        {seed.owner});
    ASSERT_EQ(PQntuples(link.get()),1);
    EXPECT_EQ(std::string{PQgetvalue(link.get(),0,0)},seed.owner);
    auto config=pk::PasskeyConfig::create("identity.example.test","Fixture","https://identity.example.test",
        fnd::SecretString{std::string(32U,'k')},5min);
    ASSERT_TRUE(config);
    auto options=pk::assertionOptions(config.value(),kNow+2s);
    ASSERT_TRUE(options);
    const auto assertProof=[&](std::string credential){
        io.restart();
        std::optional<fnd::Result<ids::IdentityId>> result;
        auto collect=[&]()->asio::awaitable<void>{
            result.emplace(co_await native.verifyPasskeyAssertionAsync(config.value(),options->id(),
                pk::AssertionResponse{std::move(credential),"invalid","invalid","invalid",std::nullopt},kNow+2s));
        };
        auto done=asio::co_spawn(io,collect(),asio::use_future);
        io.run(); done.get(); return std::move(result).value();
    };
    EXPECT_FALSE(assertProof(remaining->front().credentialId));
    EXPECT_FALSE(assertProof(otherCredential));
    const auto unchanged=read();
    ASSERT_TRUE(unchanged && unchanged->size()==1U);
    EXPECT_EQ(unchanged->front().signCount,remaining->front().signCount);
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "DELETE FROM openproof.external_identities WHERE provider='passkey' AND external_subject=$1",{seed.owner})));
    EXPECT_FALSE(assertProof(remaining->front().credentialId));
    ASSERT_TRUE(runMutation(mutate(remaining->front().credentialId)));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "UPDATE openproof.sessions SET state=1,revoked_at_ms=1770000002000 WHERE id=$1",{sessionName})));
    EXPECT_FALSE(read());
    EXPECT_FALSE(read(ceremony("-revoked",kNow+300s)));
}

TEST(PostgresCanonicalCoroutineTest, NativeApplicationReadsRequireCurrentOwnerSessionAndNeverProjectSecrets)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    using Read=openproof::application::ManagementRead;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    const auto app="read-app-"+seed.suffix, foreignApp="foreign-"+app, client="read-client-"+seed.suffix;
    const auto sessionName="read-session-"+seed.suffix, weakSession=sessionName+"-weak";
    auto sql=[&](std::string query,std::initializer_list<std::string> args) {
        static_cast<void>(execute(fixture.get(),query,args));
    };
    const auto digest=[&](std::string_view label) {
        return fnd::toHex(openproof::security::sha256(seed.suffix+std::string{label}).value());
    };
    ASSERT_NO_THROW(sql("INSERT INTO openproof.memberships(organization_id,identity_id,state,invited_at_ms) "
        "VALUES($1,$2,1,1770000000000),($1,$3,1,1770000000000)",{seed.org,seed.owner,seed.secondOwner}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.membership_roles(organization_id,identity_id,role) "
        "VALUES($1,$2,'owner'),($1,$3,'member')",{seed.org,seed.owner,seed.secondOwner}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.sessions(id,identity_id,provider,assurance,factors,phishing_resistant,state,"
        "token_digest,authenticated_at_ms,issued_at_ms,last_seen_at_ms,absolute_expires_at_ms,idle_timeout_ms) "
        "VALUES($1,$2,'local',2,3,false,0,decode($3,'hex'),1770000000000,1770000000000,1770000000000,1770003600000,600000),"
        "($4,$2,'local',1,1,false,0,decode($5,'hex'),1770000000000,1770000000000,1770000000000,1770003600000,600000)",
        {sessionName,seed.owner,digest("-session"),weakSession,digest("-weak")}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.applications(id,organization_id,identifier,display_name,environment,status,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,'read-fixture','Fixture',0,0,1770000000000,1770000000000),"
        "($3,$4,'foreign-fixture','Foreign',0,0,1770000000000,1770000000000)",{app,seed.org,foreignApp,seed.foreignOrg}));
    const auto secret=digest("-client-secret");
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_clients(id,application_id,display_name,kind,status,secret_digest,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,'Fixture',0,0,decode($3,'hex'),1770000000000,1770000000000)",{client,app,secret}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_client_redirect_uris(client_id,redirect_uri) "
        "VALUES($1,'https://fixture.example.invalid/callback')",{client}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_client_scopes(client_id,scope) VALUES($1,'openid')",{client}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_client_request_signing_keys(client_id,key_id,public_key_pem,updated_at_ms) "
        "VALUES($1,'fixture-key','fixture-public-material',1770000000000)",{client}));
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    const auto read=[&](Read op,std::optional<std::string> filter=std::nullopt,
        std::string actor={},std::string session={}) {
        io.restart();
        auto task=native.readApplicationManagementAsync(op,ids::IdentityId{actor.empty()?seed.owner:actor},
            openproof::session::SessionId{session.empty()?sessionName:session},std::move(filter),kNow+1s);
        auto done=asio::co_spawn(io,std::move(task),asio::use_future);
        io.run(); return done.get();
    };
    auto apps=read(Read::Applications);
    ASSERT_TRUE(apps);
    EXPECT_NE(apps->find(app),std::string::npos);
    EXPECT_EQ(apps->find(foreignApp),std::string::npos);
    EXPECT_FALSE(read(Read::Applications,std::nullopt,seed.secondOwner));
    auto weak=read(Read::Applications,std::nullopt,seed.owner,weakSession);
    ASSERT_FALSE(weak);
    EXPECT_EQ(weak.error().code(),fnd::ErrorCode::AssuranceInsufficient);
    auto console=read(Read::Console);
    ASSERT_TRUE(console);
    EXPECT_EQ(console.value(),"{}");
    EXPECT_FALSE(read(Read::Console,std::nullopt,seed.secondOwner));
    auto weakConsole=read(Read::Console,std::nullopt,seed.owner,weakSession);
    ASSERT_FALSE(weakConsole);
    EXPECT_EQ(weakConsole.error().code(),fnd::ErrorCode::AssuranceInsufficient);
    EXPECT_FALSE(read(Read::Clients,foreignApp));
    auto clients=read(Read::Clients,app);
    ASSERT_TRUE(clients);
    EXPECT_NE(clients->find(client),std::string::npos);
    EXPECT_NE(clients->find("https://fixture.example.invalid/callback"),std::string::npos);
    EXPECT_EQ(clients->find(secret),std::string::npos);
    EXPECT_EQ(clients->find("secret_digest"),std::string::npos);
    auto jar=read(Read::JarKey,client);
    ASSERT_TRUE(jar);
    EXPECT_NE(jar->find("fixture-public-material"),std::string::npos);
    EXPECT_TRUE(read(Read::Resources));
    EXPECT_FALSE(read(Read::ServiceIdentity,client));
    using Mutation=openproof::application::ApplicationMutation;
    using Command=openproof::application::ApplicationMutationCommand;
    using AppId=openproof::application::ApplicationId;
    using Status=openproof::application::ApplicationStatus;
    const auto mutate=[&](Command command,std::string actor={},std::string session={},fnd::Instant when=kNow+2s) {
        return native.mutateApplicationAsync(std::move(command),
            ids::IdentityId{actor.empty()?seed.owner:actor},
            openproof::session::SessionId{session.empty()?sessionName:session},when);
    };
    const auto collect=[](auto task,auto& output)->asio::awaitable<void> {
        output.emplace(co_await std::move(task));
    };
    const auto runMutation=[&](auto task) {
        io.restart();
        std::optional<typename decltype(task)::value_type> output;
        auto done=asio::co_spawn(io,collect(std::move(task),output),asio::use_future);
        io.run(); done.get();
        return std::move(output).value();
    };
    const auto createdId="native-created-"+seed.suffix;
    const auto create=[&](std::string id,std::string identifier) {
        return Command{Mutation::Create,AppId{std::move(id)},std::move(identifier),"Native fixture",
            openproof::application::Environment::Staging};
    };
    const auto change=[&](Mutation action,std::string id) {
        return Command{action,AppId{std::move(id)},{},{}};
    };
    EXPECT_FALSE(runMutation(mutate(create(createdId,"invalid identifier"))));
    EXPECT_FALSE(runMutation(mutate(create(createdId,"new-fixture"),seed.secondOwner)));
    EXPECT_FALSE(runMutation(mutate(create(createdId,"new-fixture"),seed.owner,weakSession)));
    auto foreign=runMutation(mutate(change(Mutation::Revoke,foreignApp)));
    ASSERT_FALSE(foreign);
    EXPECT_EQ(foreign.error().code(),fnd::ErrorCode::NotFound);
    auto created=runMutation(mutate(create(createdId,"new-fixture")));
    ASSERT_TRUE(created);
    EXPECT_EQ(created->id().value(),createdId);
    EXPECT_EQ(created->status(),Status::Active);
    auto duplicate=runMutation(mutate(create(createdId+"-duplicate","new-fixture")));
    ASSERT_FALSE(duplicate);
    EXPECT_EQ(duplicate.error().code(),fnd::ErrorCode::AlreadyExists);
    io.restart();
    std::optional<fnd::Result<openproof::application::Application>> resultA,resultB;
    auto suspendA=asio::co_spawn(io,collect(mutate(change(Mutation::Suspend,createdId)),resultA),asio::use_future);
    auto suspendB=asio::co_spawn(io,collect(mutate(change(Mutation::Suspend,createdId)),resultB),asio::use_future);
    io.run(); suspendA.get(); suspendB.get();
    auto a=std::move(resultA).value(),b=std::move(resultB).value();
    ASSERT_NE(a.has_value(),b.has_value());
    EXPECT_EQ((a?b:a).error().code(),fnd::ErrorCode::FailedPrecondition);
    auto activated=runMutation(mutate(change(Mutation::Activate,createdId)));
    ASSERT_TRUE(activated);
    EXPECT_EQ(activated->status(),Status::Active);
    auto revoked=runMutation(mutate(change(Mutation::Revoke,createdId)));
    ASSERT_TRUE(revoked);
    EXPECT_EQ(revoked->status(),Status::Revoked);
    EXPECT_FALSE(runMutation(mutate(change(Mutation::Activate,createdId))));
    EXPECT_FALSE(runMutation(mutate(change(Mutation::Revoke,createdId))));
    const auto durable=execute(fixture.get(),
        "SELECT status::text FROM openproof.applications WHERE id=$1",{createdId});
    ASSERT_EQ(PQntuples(durable.get()),1);
    EXPECT_STREQ(PQgetvalue(durable.get(),0,0),"2");
    namespace cli=openproof::client;
    using COp=cli::ManagementMutation;
    using CCommand=cli::ManagementMutationCommand;
    const auto clientDigest=[&](std::string_view label) {
        return cli::ClientSecretDigest{openproof::security::sha256(seed.suffix+std::string{label}).value()};
    };
    const auto createClient=[&](std::string id,std::string parent,cli::ClientKind kind) {
        std::vector<cli::RedirectUri> redirects;
        if (kind!=cli::ClientKind::Service)
            redirects.push_back(cli::RedirectUri::create("https://fixture.example.invalid/callback",kind).value());
        std::vector<cli::Scope> scopes;
        scopes.push_back(cli::Scope::create("openid").value());
        return CCommand{COp::Create,cli::ClientId{std::move(id)},AppId{std::move(parent)},"Client fixture",
            kind,std::move(redirects),std::move(scopes),
            cli::clientIsPublic(kind)?std::nullopt:std::optional<cli::ClientSecretDigest>{clientDigest("-initial")}};
    };
    const auto clientChange=[&](COp action,std::string id,std::optional<cli::ClientSecretDigest> next=std::nullopt) {
        return CCommand{action,cli::ClientId{std::move(id)},std::nullopt,{},cli::ClientKind::Web,{},{},next};
    };
    const auto clientTask=[&](CCommand command,std::string actor={},std::string session={}) {
        return native.mutateOAuthClientAsync(std::move(command),ids::IdentityId{actor.empty()?seed.owner:actor},
            openproof::session::SessionId{session.empty()?sessionName:session},kNow+3s);
    };
    const auto privateId="native-confidential-"+seed.suffix,publicId="native-public-"+seed.suffix;
    EXPECT_FALSE(runMutation(clientTask(createClient(privateId,foreignApp,cli::ClientKind::Web))));
    EXPECT_FALSE(runMutation(clientTask(createClient(privateId,createdId,cli::ClientKind::Web))));
    EXPECT_FALSE(runMutation(clientTask(createClient(privateId,app,cli::ClientKind::Web),seed.secondOwner)));
    EXPECT_FALSE(runMutation(clientTask(createClient(privateId,app,cli::ClientKind::Web),seed.owner,weakSession)));
    auto registered=runMutation(clientTask(createClient(privateId,app,cli::ClientKind::Web)));
    ASSERT_TRUE(registered);
    EXPECT_EQ(registered->status(),cli::ClientStatus::Active);
    EXPECT_EQ(registered->secretDigest(),std::optional<cli::ClientSecretDigest>{clientDigest("-initial")});
    EXPECT_FALSE(runMutation(clientTask(createClient(privateId,app,cli::ClientKind::Web))));
    auto publicClient=runMutation(clientTask(createClient(publicId,app,cli::ClientKind::Browser)));
    ASSERT_TRUE(publicClient);
    EXPECT_FALSE(publicClient->secretDigest());
    const auto next=clientDigest("-rotated");
    EXPECT_FALSE(runMutation(clientTask(clientChange(COp::RotateSecret,publicId,next))));
    auto rotated=runMutation(clientTask(clientChange(COp::RotateSecret,privateId,next)));
    ASSERT_TRUE(rotated);
    EXPECT_EQ(rotated->secretDigest(),std::optional<cli::ClientSecretDigest>{next});
    const auto persisted=execute(fixture.get(),
        "SELECT encode(secret_digest,'hex'),(SELECT count(*) FROM openproof.oauth_client_scopes WHERE client_id=$1)::text,"
        "(SELECT count(*) FROM openproof.oauth_client_redirect_uris WHERE client_id=$1)::text "
        "FROM openproof.oauth_clients WHERE id=$1",{privateId});
    ASSERT_EQ(PQntuples(persisted.get()),1);
    EXPECT_EQ(std::string{PQgetvalue(persisted.get(),0,0)},fnd::toHex(next.bytes()));
    EXPECT_STREQ(PQgetvalue(persisted.get(),0,1),"1");
    EXPECT_STREQ(PQgetvalue(persisted.get(),0,2),"1");
    io.restart();
    std::optional<fnd::Result<cli::Client>> clientResultA,clientResultB;
    auto clientA=asio::co_spawn(io,collect(clientTask(clientChange(COp::Suspend,privateId)),clientResultA),asio::use_future);
    auto clientB=asio::co_spawn(io,collect(clientTask(clientChange(COp::Suspend,privateId)),clientResultB),asio::use_future);
    io.run(); clientA.get(); clientB.get();
    auto ca=std::move(clientResultA).value(),cb=std::move(clientResultB).value();
    ASSERT_NE(ca.has_value(),cb.has_value());
    ASSERT_TRUE(runMutation(clientTask(clientChange(COp::Activate,privateId))));
    ASSERT_TRUE(runMutation(clientTask(clientChange(COp::Revoke,privateId))));
    EXPECT_FALSE(runMutation(clientTask(clientChange(COp::RotateSecret,privateId,next))));
    EXPECT_FALSE(runMutation(clientTask(clientChange(COp::Activate,privateId))));
    constexpr std::string_view kTestRsaPublicKey = R"PEM(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxQQ9mwfAEgVMWUY1rcqU
Q4YMPqUwXvppmoB2ffh5TXTN2YGR14AmL5wcCvxvA/LdmJ55vLWryzt6CBjp+1Ym
1pkT5jKpfKGPF+BC4PmqHo7SSR/Hr/e9lHHVQr1BHvxPHw8tC6jOWueB6HrZLUar
+xg6ix+x/mJmB85zL2C21LgKzLbiIOkPWpOE29CQ4RgnpFLtUegBFJTn+7op70O1
MfwasR7O/YMVe/Hq/LLhoVh64Il+6aLNgSSuU6wEvmAMRPJi6JYH4GhUsKaXvy+W
7D1jmGHYDJZCA2E/GuOinFTHuQIHt/dQtJ73GX2SH+TniwPrYZQmJbPS1QQxdJeb
2wIDAQAB
-----END PUBLIC KEY-----
)PEM";
    const auto keyTask=[&](std::string id,std::optional<std::string> kid,std::optional<std::string> pem,
        std::string actor={},std::string session={},fnd::Instant when=kNow+4s) {
        return native.mutateOAuthJarKeyAsync(cli::ClientId{std::move(id)},std::move(kid),std::move(pem),
            ids::IdentityId{actor.empty()?seed.owner:actor},
            openproof::session::SessionId{session.empty()?sessionName:session},when);
    };
    const std::string pem{kTestRsaPublicKey};
    EXPECT_FALSE(runMutation(keyTask(client,"bad","not a key")));
    EXPECT_FALSE(runMutation(keyTask(client,"bad",pem+pem)));
    EXPECT_FALSE(runMutation(keyTask(client,"bad",pem+"trailing material")));
    EXPECT_FALSE(runMutation(keyTask(client,"bad",std::nullopt)));
    EXPECT_FALSE(runMutation(keyTask(client,"denied",pem,seed.secondOwner)));
    EXPECT_FALSE(runMutation(keyTask(client,"denied",pem,seed.owner,weakSession)));
    EXPECT_FALSE(runMutation(keyTask(privateId,"revoked",pem)));
    EXPECT_FALSE(runMutation(keyTask("missing-client","missing",pem)));
    ASSERT_TRUE(runMutation(keyTask(client,"native-key",pem)));
    auto registeredJar=read(Read::JarKey,client);
    ASSERT_TRUE(registeredJar);
    EXPECT_NE(registeredJar->find("native-key"),std::string::npos);
    EXPECT_FALSE(runMutation(keyTask(client,"stale",pem,{}, {},kNow+3s)));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_jar_replays(client_id,jwt_id,expires_at_ms) "
        "VALUES($1,'fixture-replay',1770000600000)",{client}));
    ASSERT_TRUE(runMutation(keyTask(client,"rotated-key",pem)));
    ASSERT_TRUE(runMutation(keyTask(client,std::nullopt,std::nullopt)));
    ASSERT_TRUE(runMutation(keyTask(client,std::nullopt,std::nullopt)));
    EXPECT_FALSE(read(Read::JarKey,client));
    const auto replay=execute(fixture.get(),
        "SELECT count(*)::text FROM openproof.oauth_jar_replays WHERE client_id=$1 AND jwt_id='fixture-replay'",{client});
    ASSERT_EQ(PQntuples(replay.get()),1);
    EXPECT_STREQ(PQgetvalue(replay.get(),0,0),"1");
    namespace res=openproof::resource;
    using ROp=res::ResourceMutation;
    using RCommand=res::ResourceMutationCommand;
    const auto resourceId="native-resource-"+seed.suffix;
    const auto audience="urn:fixture:resource:"+seed.suffix;
    const auto resourceCreate=[&](std::string id,std::string target,std::vector<std::string> scopes) {
        return RCommand{ROp::Create,res::ResourceId{std::move(id)},std::move(target),"Resource fixture",std::move(scopes)};
    };
    const auto resourceChange=[&](ROp op) {
        return RCommand{op,res::ResourceId{""},audience,{},{}};
    };
    const auto resourceTask=[&](RCommand command,std::string actor={},std::string session={},
        fnd::Instant when=kNow+5s) {
        return native.mutateOAuthResourceAsync(std::move(command),ids::IdentityId{actor.empty()?seed.owner:actor},
            openproof::session::SessionId{session.empty()?sessionName:session},when);
    };
    EXPECT_FALSE(runMutation(resourceTask(resourceCreate(resourceId,"invalid audience",{"read"}))));
    EXPECT_FALSE(runMutation(resourceTask(resourceCreate(resourceId,audience,{}))));
    EXPECT_FALSE(runMutation(resourceTask(resourceCreate(resourceId,audience,{"read"}),seed.secondOwner)));
    EXPECT_FALSE(runMutation(resourceTask(resourceCreate(resourceId,audience,{"read"}),seed.owner,weakSession)));
    auto createdResource=runMutation(resourceTask(resourceCreate(resourceId,audience,{"write","read","read"})));
    ASSERT_TRUE(createdResource);
    EXPECT_EQ(createdResource->scopes(),(std::vector<std::string>{"read","write"}));
    EXPECT_EQ(createdResource->status(),res::ResourceStatus::Active);
    auto duplicateResource=runMutation(resourceTask(resourceCreate(resourceId+"-duplicate",audience,{"read"})));
    ASSERT_FALSE(duplicateResource);
    EXPECT_EQ(duplicateResource.error().code(),fnd::ErrorCode::AlreadyExists);
    auto suspendedResource=runMutation(resourceTask(resourceChange(ROp::Suspend),{}, {},kNow+6s));
    ASSERT_TRUE(suspendedResource);
    EXPECT_EQ(suspendedResource->status(),res::ResourceStatus::Suspended);
    auto staleResource=runMutation(resourceTask(resourceChange(ROp::Activate),{}, {},kNow+5s));
    ASSERT_FALSE(staleResource);
    EXPECT_EQ(staleResource.error().code(),fnd::ErrorCode::Conflict);
    io.restart();
    std::optional<fnd::Result<res::ResourceServer>> revokeResult,activateResult;
    auto revokeTask=asio::co_spawn(io,collect(resourceTask(resourceChange(ROp::Revoke),{}, {},kNow+7s),revokeResult),asio::use_future);
    auto activateTask=asio::co_spawn(io,collect(resourceTask(resourceChange(ROp::Activate),{}, {},kNow+7s),activateResult),asio::use_future);
    io.run(); revokeTask.get(); activateTask.get();
    ASSERT_TRUE(revokeResult && revokeResult->has_value());
    ASSERT_TRUE(activateResult.has_value());
    if (!activateResult->has_value()) {
        EXPECT_EQ(activateResult->error().code(),fnd::ErrorCode::FailedPrecondition);
    }
    EXPECT_FALSE(runMutation(resourceTask(resourceChange(ROp::Activate),{}, {},kNow+8s)));
    const auto resourceState=execute(fixture.get(),
        "SELECT status::text,(SELECT count(*) FROM openproof.oauth_resource_scopes WHERE resource_id=$1)::text "
        "FROM openproof.oauth_resources WHERE id=$1",{resourceId});
    ASSERT_EQ(PQntuples(resourceState.get()),1);
    EXPECT_STREQ(PQgetvalue(resourceState.get(),0,0),"2");
    EXPECT_STREQ(PQgetvalue(resourceState.get(),0,1),"2");

    using SOp=res::ServiceMutation;
    using SCommand=res::ServiceMutationCommand;
    const auto serviceClient="native-service-"+seed.suffix;
    const auto serviceResource="native-service-resource-"+seed.suffix;
    const auto serviceAudience="urn:fixture:service:"+seed.suffix;
    const auto serviceIdentity="native-service-identity-"+seed.suffix;
    ASSERT_TRUE(runMutation(clientTask(createClient(serviceClient,app,cli::ClientKind::Service))));
    ASSERT_TRUE(runMutation(resourceTask(resourceCreate(serviceResource,serviceAudience,{"openid","read"}))));
    const auto provision=[&](std::string id,std::string clientId,std::string target,std::vector<std::string> scopes) {
        return SCommand{SOp::Provision,cli::ClientId{std::move(clientId)},ids::IdentityId{std::move(id)},
            {std::move(target)},std::move(scopes)};
    };
    const auto serviceChange=[&](SOp op) {
        return SCommand{op,cli::ClientId{serviceClient},ids::IdentityId{""},{},{}};
    };
    const auto serviceTask=[&](SCommand command,std::string actor={},std::string session={},fnd::Instant when=kNow+9s) {
        return native.mutateServiceIdentityAsync(std::move(command),ids::IdentityId{actor.empty()?seed.owner:actor},
            openproof::session::SessionId{session.empty()?sessionName:session},when);
    };
    EXPECT_FALSE(runMutation(serviceTask(provision(serviceIdentity,publicId,serviceAudience,{"openid"}))));
    EXPECT_FALSE(runMutation(serviceTask(provision(serviceIdentity,serviceClient,audience,{"read"}))));
    EXPECT_FALSE(runMutation(serviceTask(provision(serviceIdentity,serviceClient,serviceAudience,{"forbidden"}))));
    EXPECT_FALSE(runMutation(serviceTask(provision(serviceIdentity,serviceClient,serviceAudience,{"openid"}),seed.secondOwner)));
    EXPECT_FALSE(runMutation(serviceTask(provision(serviceIdentity,serviceClient,serviceAudience,{"openid"}),seed.owner,weakSession)));
    EXPECT_FALSE(runMutation(serviceTask(provision(seed.owner,serviceClient,serviceAudience,{"openid"}))));
    const auto before=execute(fixture.get(),"SELECT count(*)::text FROM openproof.identities WHERE id=$1",{serviceIdentity});
    ASSERT_EQ(PQntuples(before.get()),1);
    EXPECT_STREQ(PQgetvalue(before.get(),0,0),"0");
    io.restart();
    std::optional<fnd::Result<res::ServiceIdentity>> serviceA,serviceB;
    auto sa=asio::co_spawn(io,collect(serviceTask(provision(serviceIdentity,serviceClient,serviceAudience,{"openid"})),serviceA),asio::use_future);
    auto sb=asio::co_spawn(io,collect(serviceTask(provision(serviceIdentity+"-duplicate",serviceClient,serviceAudience,{"openid"})),serviceB),asio::use_future);
    io.run(); sa.get(); sb.get();
    ASSERT_TRUE(serviceA && serviceB);
    ASSERT_NE(serviceA->has_value(),serviceB->has_value());
    const auto& registeredService=serviceA->has_value()?serviceA->value():serviceB->value();
    EXPECT_TRUE(registeredService.active());
    EXPECT_EQ(registeredService.scopes(),std::vector<std::string>{"openid"});
    const auto provisioned=execute(fixture.get(),
        "SELECT (SELECT count(*) FROM openproof.identities WHERE id IN ($1,$2) AND kind=1)::text,"
        "(SELECT count(*) FROM openproof.service_identities WHERE client_id=$3)::text",
        {serviceIdentity,serviceIdentity+"-duplicate",serviceClient});
    ASSERT_EQ(PQntuples(provisioned.get()),1);
    EXPECT_STREQ(PQgetvalue(provisioned.get(),0,0),"1");
    EXPECT_STREQ(PQgetvalue(provisioned.get(),0,1),"1");
    ASSERT_TRUE(read(Read::ServiceIdentity,serviceClient));
    auto inactive=runMutation(serviceTask(serviceChange(SOp::Deactivate),{}, {},kNow+10s));
    ASSERT_TRUE(inactive);
    EXPECT_FALSE(inactive->active());
    EXPECT_FALSE(runMutation(serviceTask(serviceChange(SOp::Activate),{}, {},kNow+9s)));
    ASSERT_TRUE(runMutation(serviceTask(serviceChange(SOp::Activate),{}, {},kNow+11s)));
    ASSERT_TRUE(runMutation(serviceTask(serviceChange(SOp::Deactivate),{}, {},kNow+12s)));
    const RCommand stopResource{ROp::Revoke,res::ResourceId{""},serviceAudience,{},{}};
    ASSERT_TRUE(runMutation(resourceTask(stopResource,{}, {},kNow+13s)));
    EXPECT_FALSE(runMutation(serviceTask(serviceChange(SOp::Activate),{}, {},kNow+14s)));
    const auto serviceState=execute(fixture.get(),
        "SELECT active::text,(SELECT count(*) FROM openproof.service_identity_audiences WHERE client_id=$1)::text,"
        "(SELECT count(*) FROM openproof.service_identity_scopes WHERE client_id=$1)::text "
        "FROM openproof.service_identities WHERE client_id=$1",{serviceClient});
    ASSERT_EQ(PQntuples(serviceState.get()),1);
    EXPECT_STREQ(PQgetvalue(serviceState.get(),0,0),"false");
    EXPECT_STREQ(PQgetvalue(serviceState.get(),0,1),"1");
    EXPECT_STREQ(PQgetvalue(serviceState.get(),0,2),"1");
    ASSERT_NO_THROW(sql("DELETE FROM openproof.membership_roles WHERE organization_id=$1 AND identity_id=$2 AND role='owner'",
        {seed.org,seed.owner}));
    EXPECT_FALSE(read(Read::Clients,app));
    EXPECT_FALSE(read(Read::Console));
    EXPECT_FALSE(runMutation(mutate(change(Mutation::Suspend,app))));
    EXPECT_FALSE(runMutation(clientTask(clientChange(COp::Revoke,publicId))));
    EXPECT_FALSE(runMutation(keyTask(client,"denied",pem)));
    EXPECT_FALSE(runMutation(resourceTask(resourceChange(ROp::Revoke),{}, {},kNow+8s)));
    EXPECT_FALSE(runMutation(serviceTask(serviceChange(SOp::Deactivate),{}, {},kNow+15s)));
}

TEST(PostgresCanonicalCoroutineTest, RealDatabaseAdminListingRequiresActiveTenantOwner)
{
    const auto dsn = disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK") != nullptr)
            FAIL() << "Explicitly requested disposable database has an invalid socket DSN.";
        GTEST_SKIP() << "Only an explicitly acknowledged disposable database may be used.";
    }
    Conn connection{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(connection && PQstatus(connection.get()) == CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(connection.get()));
    for (const auto& [tenant, identity, state, role] : {
         std::tuple{seed.org, seed.owner, "1", "owner"},
         std::tuple{seed.org, seed.secondOwner, "1", "member"},
         std::tuple{seed.org, seed.freshLoginOwner, "2", "owner"},
         std::tuple{seed.org, seed.lockedOwner, "1", "owner"},
         std::tuple{seed.org, seed.emptyConnectionsOwner, "3", ""},
         std::tuple{seed.foreignOrg, seed.foreignOwner, "1", "owner"},
         std::tuple{seed.suspendedOrg, seed.suspendedOwner, "1", "owner"}}) {
        ASSERT_NO_THROW(static_cast<void>(execute(connection.get(),
            "INSERT INTO openproof.memberships(organization_id,identity_id,state,invited_at_ms) "
            "VALUES($1,$2,$3,1770000000000)", {tenant, identity, state})));
        if (std::string_view{role}.size() != 0U) {
            ASSERT_NO_THROW(static_cast<void>(execute(connection.get(),
                "INSERT INTO openproof.membership_roles(organization_id,identity_id,role) VALUES($1,$2,$3)",
                {tenant, identity, role})));
        }
    }
    ASSERT_NO_THROW(static_cast<void>(execute(connection.get(),
        "INSERT INTO openproof.membership_roles(organization_id,identity_id,role) VALUES($1,$2,'auditor')",
        {seed.org, seed.owner})));
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
        const auto result = co_await canonical.readMembersAsync(ids::IdentityId{seed.owner});
        if (!result) {
            ADD_FAILURE() << "Owner membership projection failed";
            co_return;
        }
        EXPECT_EQ(result->actor.value(), seed.owner);
        EXPECT_EQ(result->members.size(), 5U);
        bool ownerSeen = false;
        bool removedSeen = false;
        bool suspendedSeen = false;
        for (const auto& member : result->members) {
            EXPECT_NE(member.identity.value(), seed.foreignOwner);
            EXPECT_NE(member.identity.value(), seed.suspendedOwner);
            if (member.identity.value() == seed.owner) {
                ownerSeen = true;
                EXPECT_EQ(member.roles.size(), 2U);
                if (member.roles.size() == 2U) {
                    EXPECT_EQ(member.roles[0].value(), "auditor");
                    EXPECT_EQ(member.roles[1].value(), "owner");
                }
            }
            if (member.identity.value() == seed.emptyConnectionsOwner) {
                removedSeen = true;
                EXPECT_EQ(member.membershipState, openproof::organization::MembershipState::Removed);
                EXPECT_TRUE(member.roles.empty());
            }
            if (member.identity.value() == seed.freshLoginOwner) {
                suspendedSeen = true;
                EXPECT_EQ(member.membershipState, openproof::organization::MembershipState::Suspended);
            }
        }
        EXPECT_TRUE(ownerSeen && removedSeen && suspendedSeen);
        for (const auto& actor : {seed.secondOwner, seed.freshLoginOwner, seed.lockedOwner,
                                  seed.foreignOwner, seed.simultaneousOwner}) {
            auto denied = co_await canonical.readMembersAsync(ids::IdentityId{actor});
            EXPECT_TRUE(!denied && denied.error().code() == fnd::ErrorCode::PermissionDenied);
        }
        auto inactive = co_await suspended.readMembersAsync(ids::IdentityId{seed.suspendedOwner});
        EXPECT_TRUE(!inactive && inactive.error().code() == fnd::ErrorCode::PermissionDenied);
    };
    auto done = asio::co_spawn(io, check(), asio::use_future);
    io.run();
    ASSERT_NO_THROW(done.get());
    // The first member is valid but the removed membership is deliberately
    // corrupted; no partial member list may be returned.
    ASSERT_NO_THROW(static_cast<void>(execute(connection.get(),
        "INSERT INTO openproof.membership_roles(organization_id,identity_id,role) VALUES($1,$2,'owner')",
        {seed.org, seed.emptyConnectionsOwner})));
    io.restart();
    auto malformed = asio::co_spawn(io, canonical.readMembersAsync(ids::IdentityId{seed.owner}), asio::use_future);
    io.run();
    auto denied = malformed.get();
    EXPECT_TRUE(!denied && denied.error().code() == fnd::ErrorCode::Unavailable);
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
    if (checks.activeConnections) {
        const auto external=linked->second.front();
        EXPECT_TRUE(co_await canonical.authorizeHandoffOwnerAsync(ids::IdentityId{seed.owner},external));
        EXPECT_FALSE(co_await wrongTenant.authorizeHandoffOwnerAsync(ids::IdentityId{seed.owner},external));
        EXPECT_FALSE(co_await canonical.authorizeHandoffOwnerAsync(ids::IdentityId{seed.secondOwner},external));
        EXPECT_FALSE(co_await canonical.authorizeHandoffOwnerAsync(ids::IdentityId{seed.lockedOwner},external));
    }
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
    if (linked && !linked->second.empty()) {
        const auto& link=linked->second.front();
        const ids::ExternalIdentityRef presentation{link.providerId(),link.subject(),
            std::string{"Wallet presentation"},std::nullopt,std::nullopt};
        EXPECT_FALSE(co_await wrongTenant.updatePresentationAsync(ids::IdentityId{seed.owner},presentation,kNow));
        EXPECT_FALSE(co_await canonical.updatePresentationAsync(ids::IdentityId{seed.secondOwner},presentation,kNow));
        EXPECT_TRUE(co_await canonical.updatePresentationAsync(ids::IdentityId{seed.owner},presentation,kNow));
        auto after=co_await canonical.readConnectionsAsync(ids::IdentityId{seed.owner});
        EXPECT_TRUE(after);
        if (after) {
            const auto found=std::ranges::find_if(after->second,[&](const auto& candidate){
                return candidate.providerId()==link.providerId() && candidate.subject()==link.subject();
            });
            EXPECT_NE(found,after->second.end());
            if (found!=after->second.end()) {
                EXPECT_EQ(found->displayName(),std::optional<std::string>{"Wallet presentation"});
            }
        }
    }
    const auto updatedAt=kNow+std::chrono::milliseconds{1000};
    auto changed=co_await canonical.updateProfileAsync(ids::IdentityId{seed.owner},
        std::string{"Native self-service"},std::nullopt,std::string{"fa-IR"},
        std::string{"https://example.invalid/avatar.png"},std::string{"profile"},updatedAt);
    EXPECT_TRUE(changed);
    if (changed && allowed) {
        EXPECT_EQ(changed->identity().value(),seed.owner);
        EXPECT_EQ(changed->displayName(),std::optional<std::string>{"Native self-service"});
        EXPECT_EQ(changed->email(),allowed->email());
        EXPECT_EQ(changed->emailVerified(),allowed->emailVerified());
        EXPECT_EQ(changed->createdAt(),allowed->createdAt());
        EXPECT_EQ(changed->avatarSource(),"profile");
    }
    auto denied=co_await canonical.updateProfileAsync(ids::IdentityId{seed.owner},
        std::string{"Must roll back"},std::nullopt,std::nullopt,std::nullopt,
        std::string{"missing-avatar-provider"},updatedAt);
    EXPECT_FALSE(denied);
    if (!denied) {
        EXPECT_EQ(denied.error().code(),fnd::ErrorCode::InvalidArgument);
    }
    auto persisted=co_await canonical.readProfileAsync(ids::IdentityId{seed.owner});
    EXPECT_TRUE(persisted);
    if (persisted) {
        EXPECT_EQ(persisted->displayName(),std::optional<std::string>{"Native self-service"});
    }
    auto deniedWrite=co_await wrongTenant.updateProfileAsync(ids::IdentityId{seed.owner},
        std::string{"foreign"},std::nullopt,std::nullopt,std::nullopt,std::nullopt,updatedAt);
    EXPECT_FALSE(deniedWrite);
    auto lockedWrite=co_await canonical.updateProfileAsync(ids::IdentityId{seed.lockedOwner},
        std::string{"locked"},std::nullopt,std::nullopt,std::nullopt,std::nullopt,updatedAt);
    EXPECT_FALSE(lockedWrite);
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

TEST(PostgresCanonicalCoroutineTest, IndependentNativeTransactionsShareOneTimeFederationState)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr) {
            FAIL()<<"Explicit disposable database has an invalid socket DSN.";
        }
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    asio::io_context io;
    pg::CoroutinePostgresAuthenticationTransactionStore peer{
        io.get_executor(),fnd::SecretString{*dsn},1U,500ms,1000ms,2000ms};
    pg::CoroutinePostgresAuthenticationTransactionStore native{
        io.get_executor(),fnd::SecretString{*dsn},2U,500ms,1000ms,2000ms};
    const Seed seed;
    const auto binding=openproof::security::sha256("fixture-browser-binding").value();
    const fnd::SecretString nonce{"fixture-continuation"};
    const auto pending=[&](const std::string& id) {
        auto tx=idp::AuthenticationTransaction::create(idp::TransactionId{id},
            idp::ProviderId{"fixture-provider"},idp::InteractionModel::Redirect,
            nonce.clone(),binding,fnd::CorrelationId{"native-legacy-cutover"},kNow,5min).value();
        tx.setMetadata("challenge_id","fixture-challenge");
        tx.setMetadata("connection_identity",seed.owner);
        tx.setMetadata("requested_assurance","1");
        return tx;
    };
    auto run=[&]<typename T>(asio::awaitable<T> task) {
        io.restart();
        std::optional<T> result;
        auto capture=[](asio::awaitable<T> operation,std::optional<T>& output)->asio::awaitable<void>{
            output.emplace(co_await std::move(operation));
        };
        auto completion=asio::co_spawn(io,capture(std::move(task),result),asio::use_future);
        io.run();
        completion.get();
        return std::move(result.value());
    };
    const auto first="legacy-to-native-"+seed.suffix;
    ASSERT_TRUE(run(peer.beginAsync(pending(first))));
    auto redeemed=run(native.consumeAsync(idp::TransactionId{first},nonce.clone(),binding,kNow+1s));
    ASSERT_TRUE(redeemed);
    EXPECT_EQ(redeemed->provider().value(),"fixture-provider");
    EXPECT_EQ(redeemed->metadata().at("challenge_id"),"fixture-challenge");
    EXPECT_EQ(redeemed->metadata().at("connection_identity"),seed.owner);
    EXPECT_EQ(redeemed->metadata().at("requested_assurance"),"1");
    EXPECT_FALSE(run(peer.consumeAsync(idp::TransactionId{first},nonce.clone(),binding,kNow+2s)));
    const auto second="native-to-legacy-"+seed.suffix;
    ASSERT_TRUE(run(native.beginAsync(pending(second))));
    auto legacyRedeemed=run(peer.consumeAsync(idp::TransactionId{second},nonce.clone(),binding,kNow+1s));
    ASSERT_TRUE(legacyRedeemed);
    EXPECT_EQ(legacyRedeemed->metadata().at("connection_identity"),seed.owner);
    EXPECT_FALSE(run(native.consumeAsync(idp::TransactionId{second},nonce.clone(),binding,kNow+2s)));
    const auto third="cross-store-burn-"+seed.suffix;
    ASSERT_TRUE(run(peer.beginAsync(pending(third))));
    EXPECT_FALSE(run(native.consumeAsync(idp::TransactionId{third},nonce.clone(),
        idp::BindingDigest{},kNow+1s)));
    EXPECT_FALSE(run(peer.consumeAsync(idp::TransactionId{third},nonce.clone(),binding,kNow+2s)));
}

TEST(PostgresCanonicalCoroutineTest, IndependentNativeAuthorizationAuditSharesChainAndRollsBack)
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
    namespace pol = openproof::policy;
    namespace ses = openproof::session;
    namespace aud = openproof::audit;
    using namespace std::chrono_literals;
    fnd::ManualClockSource clock{kNow};
    auto authenticated = ses::AuthenticatedSession::fromDelegatedAccess(
        ids::IdentityId{seed.owner}, idp::ProviderId{"native-canonical-provider"},
        idp::AssuranceLevel::Ial2,
        idp::AuthenticationStrength{idp::AuthenticationFactor::Possession, false},
        kNow, kNow, kNow + 1h);
    ASSERT_TRUE(authenticated);
    const auto makeKey = [] {
        return aud::AuditKey::create(fnd::SecretString{std::string(32U, 'A')}).value();
    };
    asio::io_context io;
    pg::CoroutineAuthorizationDecisionSink peer{
        io.get_executor(), fnd::SecretString{*dsn}, makeKey(), clock,
        1U, 500ms, 1000ms, 2000ms};
    pg::CoroutineAuthorizationDecisionSink native{
        io.get_executor(), fnd::SecretString{*dsn}, makeKey(), clock,
        2U, 500ms, 1000ms, 2000ms};
    const ids::OrganizationId tenant{seed.org};
    const pol::Action action{"protected.read"};
    const pol::Resource resource{"protected-resource"};
    const auto denial = pol::AuthorizationDecision::deny("fixture policy denied");
    const auto recordOn = [&](pg::CoroutineAuthorizationDecisionSink& sink,const std::string& correlation) {
        io.restart();
        auto completion = asio::co_spawn(io, sink.recordAsync(
            authenticated.value(), tenant, action, resource, denial,
            fnd::CorrelationId{correlation}), asio::use_future);
        io.run();
        return completion.get();
    };
    const auto record=[&](const std::string& correlation){return recordOn(native,correlation);};
    const std::string first = "peer-audit-" + seed.suffix;
    const std::string second = "native-audit-" + seed.suffix;
    const std::string third = "legacy-tail-" + seed.suffix;
    ASSERT_TRUE(recordOn(peer,first));
    ASSERT_TRUE(record(second));
    ASSERT_TRUE(recordOn(peer,third));
    auto chain = execute(fixture.get(),
        "SELECT a.sequence,a.event_id,a.correlation_id,encode(a.previous_hash,'hex'),"
        "encode(a.event_hash,'hex'),o.payload->>'type',o.payload->>'identity_id',"
        "o.payload->>'severity',o.payload->>'actor_identity_id',"
        "a.detail->>'reason',a.detail->>'action',a.detail->>'resource',a.detail->>'provider',"
        "a.detail->>'assurance' FROM openproof.audit_events a "
        "JOIN openproof.security_event_outbox o USING(event_id) "
        "WHERE a.identity_id=$1 ORDER BY a.sequence", {seed.owner});
    ASSERT_EQ(PQntuples(chain.get()), 3);
    EXPECT_EQ(std::string{PQgetvalue(chain.get(), 0, 2)}, first);
    EXPECT_EQ(std::string{PQgetvalue(chain.get(), 1, 2)}, second);
    EXPECT_EQ(std::string{PQgetvalue(chain.get(), 2, 2)}, third);
    EXPECT_STREQ(PQgetvalue(chain.get(), 0, 4), PQgetvalue(chain.get(), 1, 3));
    EXPECT_STREQ(PQgetvalue(chain.get(), 1, 4), PQgetvalue(chain.get(), 2, 3));
    for (int row = 0; row < 3; ++row) {
        EXPECT_STREQ(PQgetvalue(chain.get(), row, 5), "authorization.protected-route.denied");
        EXPECT_EQ(std::string{PQgetvalue(chain.get(), row, 6)}, seed.owner);
        EXPECT_STREQ(PQgetvalue(chain.get(), row, 7), "warning");
        EXPECT_EQ(std::string{PQgetvalue(chain.get(), row, 8)}, seed.owner);
        EXPECT_STREQ(PQgetvalue(chain.get(), row, 9), "fixture policy denied");
        EXPECT_STREQ(PQgetvalue(chain.get(), row, 10), "protected.read");
        EXPECT_STREQ(PQgetvalue(chain.get(), row, 11), "protected-resource");
        EXPECT_STREQ(PQgetvalue(chain.get(), row, 12), "native-canonical-provider");
        EXPECT_EQ(std::string{PQgetvalue(chain.get(), row, 13)},
                  idp::assuranceLevelName(idp::AssuranceLevel::Ial2));
        std::optional<openproof::security::Sha256Digest> previous;
        if (!PQgetisnull(chain.get(), row, 3)) {
            auto bytes = fnd::fromHex(PQgetvalue(chain.get(), row, 3));
            ASSERT_TRUE(bytes && bytes->size() == openproof::security::Sha256Digest{}.size());
            openproof::security::Sha256Digest digest{};
            std::copy(bytes->begin(), bytes->end(), digest.begin());
            previous = digest;
        }
        auto event = aud::AuditEvent::create(
            aud::AuditEventId{PQgetvalue(chain.get(), row, 1)}, kNow,
            fnd::CorrelationId{PQgetvalue(chain.get(), row, 2)}, tenant,
            ids::IdentityId{seed.owner}, "authorization", "protected-route.evaluate", "deny",
            aud::AuditFields{{"action", "protected.read"},
                {"assurance", std::string{idp::assuranceLevelName(idp::AssuranceLevel::Ial2)}},
                {"provider", "native-canonical-provider"}, {"reason", "fixture policy denied"},
                {"resource", "protected-resource"}});
        ASSERT_TRUE(event);
        auto hash = aud::computeAuditRecordHash(event.value(),
            std::stoull(PQgetvalue(chain.get(), row, 0)), previous, makeKey());
        ASSERT_TRUE(hash);
        EXPECT_EQ(fnd::toHex(hash.value()), PQgetvalue(chain.get(), row, 4));
    }

    // The constraint exists only in this explicitly disposable fixture.
    // Force failure AFTER the audit insert and HMAC update. No partial
    // audit record may survive, and subsequent writes must recover.
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "ALTER TABLE openproof.security_event_outbox ADD CONSTRAINT fixture_reject_warning "
        "CHECK ((payload->>'severity') <> 'warning') NOT VALID", {})));
    const std::string failed = "failed-audit-" + seed.suffix;
    auto rejected = record(failed);
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "ALTER TABLE openproof.security_event_outbox DROP CONSTRAINT fixture_reject_warning", {})));
    EXPECT_TRUE(!rejected && rejected.error().code() == fnd::ErrorCode::Unavailable);
    auto partial = execute(fixture.get(),
        "SELECT count(*) FROM openproof.audit_events WHERE correlation_id=$1", {failed});
    EXPECT_STREQ(PQgetvalue(partial.get(), 0, 0), "0");
    const std::string recovered = "recovered-audit-" + seed.suffix;
    ASSERT_TRUE(record(recovered));
    auto tail = execute(fixture.get(),
        "SELECT encode(previous_hash,'hex') FROM openproof.audit_events WHERE correlation_id=$1",
        {recovered});
    ASSERT_EQ(PQntuples(tail.get()), 1);
    EXPECT_STREQ(PQgetvalue(tail.get(), 0, 0), PQgetvalue(chain.get(), 2, 4));
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
    namespace pol = openproof::policy;
    namespace ses = openproof::session;
    fnd::ManualClockSource clock{kNow};
    const std::string bearer = "native-policy-fixture-" + seed.suffix;
    const fnd::SecretString key{std::string(32U, 'P')};
    pg::CoroutinePostgresSessionRepository sessionRepository{
        io.get_executor(), fnd::SecretString{*dsn}, 1U,
        std::chrono::milliseconds{500}, std::chrono::milliseconds{1000},
        std::chrono::milliseconds{2000}};
    pg::CoroutineSessionAuthenticator verifier{sessionRepository, clock, key.clone()};
    auto rule = pol::RolePolicyRule::create(pol::Action{"protected.read"},
        pol::Resource{"protected-resource"}, {pol::Role{"owner"}},
        pol::RoleMatchMode::All, idp::AssuranceLevel::Ial2);
    ASSERT_TRUE(rule);
    auto engine = pol::RolePolicyEngine::create({std::move(rule).value()});
    ASSERT_TRUE(engine);
    auto evaluate = [&]() -> asio::awaitable<void> {
        auto authenticated = co_await verifier.verifyAsync(fnd::SecretString{bearer});
        if (!authenticated) {
            ADD_FAILURE() << "Expected authoritative first-party session";
            co_return;
        }
        auto context = co_await canonical.readAuthorizationContextAsync(
            authenticated.value(), ids::OrganizationId{seed.org},
            pol::Action{"protected.read"}, pol::Resource{"protected-resource"});
        if (!context) {
            ADD_FAILURE() << "Expected active policy context";
            co_return;
        }
        EXPECT_EQ(context->subject().value(), seed.owner);
        EXPECT_EQ(context->organization().value(), seed.org);
        EXPECT_EQ(context->authentication().claimedAssurance(), idp::AssuranceLevel::Ial2);
        EXPECT_EQ(context->authentication().providerId().value(), "native-canonical-provider");
        EXPECT_TRUE(pol::evaluateProtected(engine->get(), context.value()).isPermitted());
        auto wrongTenant = co_await canonical.readAuthorizationContextAsync(
            authenticated.value(), ids::OrganizationId{seed.foreignOrg},
            pol::Action{"protected.read"}, pol::Resource{"protected-resource"});
        EXPECT_TRUE(!wrongTenant && wrongTenant.error().code() == fnd::ErrorCode::PermissionDenied);
        auto wrongAction = co_await canonical.readAuthorizationContextAsync(
            authenticated.value(), ids::OrganizationId{seed.org},
            pol::Action{"other.action"}, pol::Resource{"protected-resource"});
        EXPECT_TRUE(wrongAction && !pol::evaluateProtected(engine->get(), wrongAction.value()).isPermitted());
    };
    auto check = [&]() -> asio::awaitable<void> {
        auto digest = openproof::security::hmacSha256(key, bearer);
        if (!digest) { ADD_FAILURE() << "Fixture HMAC failed"; co_return; }
        auto value = ses::Session::create(ses::SessionId{"policy-" + seed.suffix},
            ids::IdentityId{seed.owner}, idp::ProviderId{"native-canonical-provider"},
            idp::AssuranceLevel::Ial2,
            idp::AuthenticationStrength{idp::AuthenticationFactor::Possession, false},
            kNow, ses::TokenDigest{digest.value()}, kNow,
            std::chrono::hours{2}, std::chrono::minutes{15});
        if (!value) { ADD_FAILURE() << "Fixture session failed"; co_return; }
        auto saved = co_await sessionRepository.add(std::move(value).value());
        if (!saved) { ADD_FAILURE() << "Fixture session storage failed"; co_return; }
        co_await evaluate();
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
    auto afterRevocation = [&]() -> asio::awaitable<void> {
        auto verified = co_await verifier.verifyAsync(fnd::SecretString{bearer});
        if (!verified) { ADD_FAILURE() << "Fixture session disappeared"; co_return; }
        auto context = co_await canonical.readAuthorizationContextAsync(
            std::move(verified).value(), ids::OrganizationId{seed.org},
            pol::Action{"protected.read"}, pol::Resource{"protected-resource"});
        EXPECT_TRUE(context && !pol::evaluateProtected(engine->get(), context.value()).isPermitted());
    };
    io.restart();
    auto decision = asio::co_spawn(io, afterRevocation(), asio::use_future);
    io.run();
    ASSERT_NO_THROW(decision.get());

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

TEST(PostgresCanonicalCoroutineTest, DelegatedAccountAuthorizationIsReadOnlyAndTenantBound)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr) {
            FAIL()<<"Explicit disposable database has invalid socket DSN.";
        }
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    const auto application="delegated-app-"+seed.suffix;
    const auto client="delegated-client-"+seed.suffix;
    const auto family="delegated-family-"+seed.suffix;
    const auto digest=fnd::toHex(openproof::security::sha256(family).value());
    auto sql=[&](const std::string& query,std::initializer_list<std::string> params){
        static_cast<void>(execute(fixture.get(),query,params));
    };
    ASSERT_NO_THROW(sql("INSERT INTO openproof.applications(id,organization_id,identifier,display_name,"
        "environment,status,created_at_ms,updated_at_ms) VALUES($1,$2,'delegated-fixture','Fixture',0,0,1770000000000,1770000000000)",
        {application,seed.org}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_clients(id,application_id,display_name,kind,status,"
        "created_at_ms,updated_at_ms) VALUES($1,$2,'Fixture client',1,0,1770000000000,1770000000000)",{client,application}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_token_families(id,client_id,identity_id,provider,"
        "assurance,factors,phishing_resistant,authenticated_at_ms) VALUES($1,$2,$3,'local',1,1,false,1770000000000)",
        {family,client,seed.owner}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_token_family_scopes(family_id,scope) VALUES($1,'account')",{family}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_access_tokens(token_digest,family_id,state,issued_at_ms,expires_at_ms)"
        " VALUES(decode($1,'hex'),$2,0,1770000000000,1770000060000)",{digest,family}));
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    pg::CoroutinePostgresCanonicalFinalizer foreign{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.foreignOrg},2U,500ms,1000ms,3000ms};
    const auto read=[&](pg::CoroutinePostgresCanonicalFinalizer& store,fnd::Instant now=kNow){
        std::optional<fnd::Result<openproof::session::Session>> result;
        auto capture=[](auto& adapter,std::string fingerprint,fnd::Instant time,auto& output)->asio::awaitable<void>{
            output.emplace(co_await adapter.authorizeDelegatedAccountAsync(std::move(fingerprint),time));
        };
        io.restart();
        auto done=asio::co_spawn(io,capture(store,digest,now,result),asio::use_future);
        io.run();
        done.get();
        return std::move(result.value());
    };
    const auto clientProof=fnd::toHex(openproof::security::sha256("confidential-fixture").value());
    const auto authenticateClient=[&](pg::CoroutinePostgresCanonicalFinalizer& store,std::string proof){
        io.restart();
        auto pending=asio::co_spawn(io,store.authenticateConfidentialClientAsync(client,std::move(proof)),asio::use_future);
        io.run(); return pending.get();
    };
    EXPECT_FALSE(authenticateClient(native,clientProof)); // public client
    ASSERT_NO_THROW(sql("UPDATE openproof.oauth_clients SET kind=0,secret_digest=decode($2,'hex') WHERE id=$1",{client,clientProof}));
    EXPECT_TRUE(authenticateClient(native,clientProof));
    EXPECT_FALSE(authenticateClient(foreign,clientProof));
    EXPECT_FALSE(authenticateClient(native,std::string(64U,'0')));
    const auto introspect=[&](pg::CoroutinePostgresCanonicalFinalizer& store,
        std::string proof,std::string token,fnd::Instant now=kNow) {
        fnd::Instant issued{};
        io.restart();
        fnd::ManualClockSource observedClock{now};
        auto done=asio::co_spawn(io,store.introspectAccessAsync(client,std::move(proof),
            std::move(token),observedClock,&issued),asio::use_future);
        io.run();
        auto result=done.get();
        if (result && result->has_value()) {
            EXPECT_EQ(issued,kNow);
        }
        return result;
    };
    const auto userInfo=[&](pg::CoroutinePostgresCanonicalFinalizer& store,std::string fingerprint,
        fnd::Instant now=kNow) {
        io.restart();
        auto pending=asio::co_spawn(io,store.readBearerUserInfoAsync(std::move(fingerprint),now),asio::use_future);
        io.run(); return pending.get();
    };
    auto accountOnly=userInfo(native,digest);
    ASSERT_TRUE(accountOnly);
    EXPECT_FALSE(accountOnly->second.has_value());
    EXPECT_FALSE(accountOnly->first.permits("openid"));
    EXPECT_FALSE(userInfo(foreign,digest));
    EXPECT_FALSE(userInfo(native,std::string(64U,'0')));
    EXPECT_FALSE(userInfo(native,digest,kNow+60s));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_token_family_scopes(family_id,scope) VALUES($1,'openid'),($1,'profile')",{family}));
    auto unbound=userInfo(native,digest);
    ASSERT_TRUE(unbound);
    EXPECT_TRUE(unbound->first.permits("openid"));
    EXPECT_TRUE(unbound->first.permits("profile"));
    // The seeded owner has a profile; match the independent live read.
    io.restart();
    auto expectedProfile=asio::co_spawn(io,native.readProfileAsync(ids::IdentityId{seed.owner}),asio::use_future);
    io.run();
    auto expected=expectedProfile.get();
    ASSERT_TRUE(expected);
    ASSERT_TRUE(unbound->second);
    EXPECT_EQ(unbound->second->identity(),expected->identity());
    EXPECT_EQ(unbound->second->displayName(),expected->displayName());
    ASSERT_NO_THROW(sql("UPDATE openproof.oauth_token_families SET sender_constraint_kind=0,"
        "sender_constraint_value='fixture' WHERE id=$1",{family}));
    auto senderBound=userInfo(native,digest);
    ASSERT_TRUE(senderBound);
    ASSERT_TRUE(senderBound->first.senderConstraint());
    EXPECT_FALSE(senderBound->second.has_value()); // Never read claims before sender proof.
    ASSERT_NO_THROW(sql("UPDATE openproof.oauth_token_families SET sender_constraint_kind=NULL,"
        "sender_constraint_value=NULL WHERE id=$1",{family}));
    ASSERT_NO_THROW(sql("UPDATE openproof.identities SET status=2 WHERE id=$1",{seed.owner}));
    EXPECT_FALSE(userInfo(native,digest));
    ASSERT_NO_THROW(sql("UPDATE openproof.identities SET status=0 WHERE id=$1",{seed.owner}));
    ASSERT_NO_THROW(sql("DELETE FROM openproof.oauth_token_family_scopes WHERE family_id=$1 AND scope IN ('openid','profile')",{family}));
    auto activeIntrospection=introspect(native,clientProof,digest);
    ASSERT_TRUE(activeIntrospection && activeIntrospection->has_value());
    EXPECT_EQ(activeIntrospection->value().clientId(),client);
    EXPECT_EQ(activeIntrospection->value().authenticated().session().identity().value(),seed.owner);
    auto badClient=introspect(native,std::string(64U,'0'),digest);
    ASSERT_FALSE(badClient);
    EXPECT_EQ(badClient.error().code(),fnd::ErrorCode::AuthenticationFailed);
    auto crossTenant=introspect(foreign,clientProof,digest);
    ASSERT_FALSE(crossTenant);
    EXPECT_EQ(crossTenant.error().code(),fnd::ErrorCode::AuthenticationFailed);
    auto unknown=introspect(native,clientProof,std::string(64U,'0'));
    ASSERT_TRUE(unknown);
    EXPECT_FALSE(unknown->has_value());
    auto expired=introspect(native,clientProof,digest,kNow+60s);
    ASSERT_TRUE(expired);
    EXPECT_FALSE(expired->has_value());
    ASSERT_NO_THROW(sql("UPDATE openproof.oauth_clients SET kind=1,secret_digest=NULL WHERE id=$1",{client}));
    auto publicDenied=introspect(native,clientProof,digest);
    ASSERT_FALSE(publicDenied);
    EXPECT_EQ(publicDenied.error().code(),fnd::ErrorCode::AuthenticationFailed);
    auto accepted=read(native);
    ASSERT_TRUE(accepted) << (accepted ? "" : std::string{fnd::errorCodeName(accepted.error().code())});
    EXPECT_EQ(accepted->identity().value(),seed.owner);
    EXPECT_EQ(accepted->id().value(),"delegated-access");
    const auto readContext=[&]{
        std::optional<fnd::Result<openproof::session::DelegatedAccess>> result;
        fnd::Instant issued{};
        auto capture=[](auto& adapter,std::string fingerprint,auto& output,fnd::Instant& observed)->asio::awaitable<void>{
            output.emplace(co_await adapter.readDelegatedAccessAsync(std::move(fingerprint),kNow,&observed));
        };
        io.restart();
        auto done=asio::co_spawn(io,capture(native,digest,result,issued),asio::use_future);
        io.run();
        done.get();
        if (result && *result) {
            EXPECT_EQ(issued,kNow);
        }
        return std::move(result.value());
    };
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_token_family_scopes(family_id,scope) VALUES($1,'gateway.read')",{family}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_token_family_audiences(family_id,audience)"
        " VALUES($1,'https://gateway.example.test'),($1,'https://other.example.test')",{family}));
    auto context=readContext();
    ASSERT_TRUE(context);
    EXPECT_EQ(context->clientId(),client);
    EXPECT_EQ(context->scopes().size(),2U);
    EXPECT_EQ(context->audiences().size(),2U);
    EXPECT_TRUE(context->permits("gateway.read"));
    EXPECT_TRUE(context->permitsAudience("https://gateway.example.test"));
    EXPECT_FALSE(context->permitsAudience("https://wrong.example.test"));
    EXPECT_FALSE(context->senderConstraint());
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_token_family_scopes(family_id,scope)"
        " SELECT $1,'bounded-'||n FROM generate_series(1,257) n",{family}));
    EXPECT_FALSE(readContext());
    ASSERT_NO_THROW(sql("DELETE FROM openproof.oauth_token_family_scopes"
        " WHERE family_id=$1 AND scope LIKE 'bounded-%'",{family}));
    EXPECT_FALSE(read(foreign));
    EXPECT_FALSE(read(native,kNow+60s));
    ASSERT_NO_THROW(sql("DELETE FROM openproof.oauth_token_family_scopes WHERE family_id=$1",{family}));
    auto scopeDenied=read(native);
    ASSERT_FALSE(scopeDenied);
    EXPECT_EQ(scopeDenied.error().code(),fnd::ErrorCode::PermissionDenied);
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_token_family_scopes(family_id,scope) VALUES($1,'account')",{family}));
    ASSERT_NO_THROW(sql("UPDATE openproof.oauth_token_families SET sender_constraint_kind=0,"
        "sender_constraint_value='fixture' WHERE id=$1",{family}));
    EXPECT_FALSE(read(native));
    auto constrained=readContext();
    ASSERT_TRUE(constrained);
    ASSERT_TRUE(constrained->senderConstraint());
    EXPECT_EQ(constrained->senderConstraint()->kind(),openproof::session::DelegatedSenderConstraintKind::Dpop);
    EXPECT_EQ(constrained->senderConstraint()->value(),"fixture");
    ASSERT_NO_THROW(sql("UPDATE openproof.oauth_token_families SET sender_constraint_kind=NULL,"
        "sender_constraint_value=NULL WHERE id=$1",{family}));
    ASSERT_NO_THROW(sql("UPDATE openproof.oauth_clients SET status=1 WHERE id=$1",{client}));
    EXPECT_FALSE(read(native));
    ASSERT_NO_THROW(sql("UPDATE openproof.oauth_clients SET status=0 WHERE id=$1",{client}));
    ASSERT_NO_THROW(sql("UPDATE openproof.applications SET status=1 WHERE id=$1",{application}));
    EXPECT_FALSE(read(native));
    ASSERT_NO_THROW(sql("UPDATE openproof.applications SET status=0 WHERE id=$1",{application}));
    const auto otherClient=client+"-other";
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_clients(id,application_id,display_name,kind,status,"
        "created_at_ms,updated_at_ms) VALUES($1,$2,'Other fixture',1,0,1770000000000,1770000000000)",{otherClient,application}));
    const auto refreshDigest=openproof::security::sha256(family+"-refresh").value();
    const auto refreshHex=fnd::toHex(refreshDigest);
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_refresh_tokens(token_digest,family_id,sequence,state,issued_at_ms,expires_at_ms) "
        "VALUES(decode($1,'hex'),$2,0,0,1770000000000,1770000060000)",{refreshHex,family}));
    auto revoke=[&](pg::CoroutinePostgresCanonicalFinalizer& store,std::string caller,
        std::optional<std::string> proof,std::string fingerprint){
        io.restart();
        auto pending=asio::co_spawn(io,store.revokeOAuthTokenAsync(std::move(caller),
            std::move(proof),std::move(fingerprint),kNow+1s),asio::use_future);
        io.run(); return pending.get();
    };
    EXPECT_FALSE(revoke(foreign,client,std::nullopt,refreshHex));
    EXPECT_FALSE(revoke(native,client,clientProof,refreshHex)); // public clients must not present a secret
    EXPECT_TRUE(revoke(native,otherClient,std::nullopt,refreshHex)); // foreign token, indistinguishable no-op
    EXPECT_TRUE(revoke(native,client,std::nullopt,std::string(64U,'0')));
    EXPECT_TRUE(read(native));
    EXPECT_TRUE(revoke(native,client,std::nullopt,digest)); // access only
    EXPECT_FALSE(read(native));
    auto liveFamily=execute(fixture.get(),
        "SELECT (revoked_at_ms IS NULL)::text FROM openproof.oauth_token_families WHERE id=$1",{family});
    ASSERT_EQ(PQntuples(liveFamily.get()),1);
    EXPECT_STREQ(PQgetvalue(liveFamily.get(),0,0),"true");
    // Race two independent native storage instances. Both possible orders
    // must leave no live successor after revocation.
    pg::CoroutinePostgresCanonicalFinalizer peer{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},1U,500ms,1000ms,3000ms};
    const auto nextAccess=fnd::toHex(openproof::security::sha256(family+"-next-access").value());
    const auto nextRefresh=fnd::toHex(openproof::security::sha256(family+"-next-refresh").value());
    io.restart();
    auto rotate=asio::co_spawn(io,peer.rotateOAuthRefreshAsync(client,std::nullopt,refreshHex,
        nextAccess,nextRefresh,std::nullopt,kNow+1s,30s),asio::use_future);
    auto revokeRace=asio::co_spawn(io,native.revokeOAuthTokenAsync(client,std::nullopt,refreshHex,kNow+1s),asio::use_future);
    io.run();
    const auto revoked=revokeRace.get();
    const auto rotated=rotate.get();
    ASSERT_TRUE(revoked);
    if (!rotated) {
        EXPECT_EQ(rotated.error().code(),fnd::ErrorCode::AuthenticationFailed);
    }
    const auto states=execute(fixture.get(),
        "SELECT (f.revoked_at_ms IS NOT NULL)::text,"
        "(SELECT count(*) FROM openproof.oauth_access_tokens t WHERE t.family_id=f.id AND t.state=0)::text,"
        "(SELECT count(*) FROM openproof.oauth_refresh_tokens r WHERE r.family_id=f.id AND r.state<>2)::text "
        "FROM openproof.oauth_token_families f WHERE f.id=$1",{family});
    ASSERT_EQ(PQntuples(states.get()),1);
    EXPECT_STREQ(PQgetvalue(states.get(),0,0),"true");
    EXPECT_STREQ(PQgetvalue(states.get(),0,1),"0");
    EXPECT_STREQ(PQgetvalue(states.get(),0,2),"0");
    EXPECT_TRUE(revoke(native,client,std::nullopt,refreshHex)); // idempotent
    EXPECT_FALSE(read(native));

    // Fresh family for native/native rotation: exactly one transaction
    // consumes the original token; the second detects reuse and commits
    // revocation of that transaction's newly issued successor.
    const auto rotatingFamily=family+"-native-rotation";
    const auto fingerprint=[&](std::string_view label) {
        return fnd::toHex(openproof::security::sha256(rotatingFamily+std::string{label}).value());
    };
    const auto original=fingerprint("-original");
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_token_families(id,client_id,identity_id,provider,"
        "assurance,factors,phishing_resistant,authenticated_at_ms) VALUES($1,$2,$3,'local',1,1,false,1770000000000)",
        {rotatingFamily,client,seed.owner}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_token_family_scopes(family_id,scope) VALUES($1,'account')",{rotatingFamily}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_refresh_tokens(token_digest,family_id,sequence,state,issued_at_ms,expires_at_ms) "
        "VALUES(decode($1,'hex'),$2,0,0,1770000000000,1770000060000)",{original,rotatingFamily}));
    using Sender=openproof::session::DelegatedSenderConstraint;
    auto attempt=[&](std::string caller,std::string suffix,std::optional<Sender> binding=std::nullopt){
        return native.rotateOAuthRefreshAsync(std::move(caller),std::nullopt,original,
            fingerprint("-access-"+suffix),fingerprint("-refresh-"+suffix),std::move(binding),kNow+2s,15min);
    };
    io.restart();
    auto denied=asio::co_spawn(io,attempt(otherClient,"foreign"),asio::use_future);
    auto wrongSender=asio::co_spawn(io,attempt(client,"sender",Sender{
        openproof::session::DelegatedSenderConstraintKind::Dpop,"fixture"}),asio::use_future);
    io.run();
    EXPECT_FALSE(denied.get());
    EXPECT_FALSE(wrongSender.get());
    io.restart();
    auto first=asio::co_spawn(io,attempt(client,"first"),asio::use_future);
    auto second=asio::co_spawn(io,attempt(client,"second"),asio::use_future);
    io.run();
    const auto a=first.get(),b=second.get();
    ASSERT_NE(a.has_value(),b.has_value());
    EXPECT_EQ((a?b:a).error().code(),fnd::ErrorCode::AuthenticationFailed);
    EXPECT_EQ((a?a:b).value(),std::vector<std::string>{"account"});
    const auto finalState=execute(fixture.get(),
        "SELECT (f.revoked_at_ms IS NOT NULL)::text,"
        "(SELECT count(*) FROM openproof.oauth_access_tokens t WHERE t.family_id=f.id AND t.state=0)::text,"
        "(SELECT count(*) FROM openproof.oauth_refresh_tokens r WHERE r.family_id=f.id AND r.state<>2)::text,"
        "(SELECT count(*) FROM openproof.oauth_refresh_tokens r WHERE r.family_id=f.id AND r.sequence=1 AND r.expires_at_ms=1770000060000)::text "
        "FROM openproof.oauth_token_families f WHERE f.id=$1",{rotatingFamily});
    ASSERT_EQ(PQntuples(finalState.get()),1);
    EXPECT_STREQ(PQgetvalue(finalState.get(),0,0),"true");
    EXPECT_STREQ(PQgetvalue(finalState.get(),0,1),"0");
    EXPECT_STREQ(PQgetvalue(finalState.get(),0,2),"0");
    EXPECT_STREQ(PQgetvalue(finalState.get(),0,3),"1");
}

TEST(PostgresCanonicalCoroutineTest, NativeParPreservesLoopbackAndCommitsJarReplayAtomically)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace oauth=openproof::oauth;
    namespace cli=openproof::client;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    const auto app="par-app-"+seed.suffix,client="par-client-"+seed.suffix;
    const auto fingerprint=[&](std::string_view suffix) {
        return fnd::toHex(openproof::security::sha256(client+std::string{suffix}).value());
    };
    auto sql=[&](std::string query,std::initializer_list<std::string> args) {
        static_cast<void>(execute(fixture.get(),query,args));
    };
    ASSERT_NO_THROW(sql("INSERT INTO openproof.applications(id,organization_id,identifier,display_name,environment,status,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,'par-fixture','Fixture',0,0,1770000000000,1770000000000)",{app,seed.org}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_clients(id,application_id,display_name,kind,status,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,'Fixture',1,0,1770000000000,1770000000000)",{client,app}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_client_redirect_uris(client_id,redirect_uri) "
        "VALUES($1,'http://127.0.0.1:1234/callback')",{client}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_client_scopes(client_id,scope) VALUES($1,'openid'),($1,'account')",{client}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_client_request_signing_keys(client_id,key_id,public_key_pem,updated_at_ms) "
        "VALUES($1,'fixture-key','fixture-public-material',1770000000000)",{client}));
    auto makeRequest=[&](std::string uri,std::string scope) {
        std::vector<cli::Scope> scopes;
        scopes.push_back(cli::Scope::create(std::move(scope)).value());
        return oauth::AuthorizationRequest::create(cli::ClientId{client},std::move(uri),std::move(scopes),
            oauth::PkceChallenge::create(std::string(43U,'a')).value(),"fixture-state","fixture-nonce",
            60s,std::nullopt,oauth::AuthorizationResponseMode::Jwt).value();
    };
    const auto redirect="http://127.0.0.1:4321/callback";
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    pg::CoroutinePostgresCanonicalFinalizer foreign{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.foreignOrg},2U,500ms,1000ms,3000ms};
    const auto capture=[](auto task,auto& output)->asio::awaitable<void> {
        output.emplace(co_await std::move(task));
    };
    const auto run=[&](auto task) {
        io.restart();
        std::optional<typename decltype(task)::value_type> result;
        auto done=asio::co_spawn(io,capture(std::move(task),result),asio::use_future);
        io.run(); done.get();
        return std::move(result).value();
    };
    auto push=[&](auto& store,std::string label,oauth::AuthorizationRequest request,
        std::optional<std::string> proof=std::nullopt) {
        return run(store.pushOAuthAuthorizationAsync(client,std::move(proof),fingerprint(label),
            std::move(request),{},kNow,90s));
    };
    EXPECT_FALSE(push(foreign,"-foreign",makeRequest(redirect,"openid")));
    EXPECT_FALSE(push(native,"-secret",makeRequest(redirect,"openid"),std::string(64U,'0')));
    EXPECT_FALSE(push(native,"-redirect",makeRequest("http://127.0.0.1:4321/wrong","openid")));
    EXPECT_FALSE(push(native,"-scope",makeRequest(redirect,"profile")));
    ASSERT_TRUE(push(native,"-direct",makeRequest(redirect,"openid")));
    int verified=0;
    const auto verifier=[&](std::string_view kid,std::string_view pem,fnd::Instant observed)
        ->fnd::Result<oauth::NativeJarAuthorization> {
        ++verified;
        EXPECT_EQ(kid,"fixture-key");
        EXPECT_EQ(pem,"fixture-public-material");
        EXPECT_EQ(observed,kNow);
        return oauth::NativeJarAuthorization{makeRequest(redirect,"account"),"fixture-jti",kNow-1s,kNow+60s};
    };
    auto jar=[&](std::string label) {
        return native.pushOAuthAuthorizationAsync(client,std::nullopt,fingerprint(label),std::nullopt,
            verifier,kNow,90s);
    };
    // Deliberately collide with the direct request. Its failed INSERT must
    // roll back JTI consumption so the correct subsequent push can succeed.
    EXPECT_FALSE(run(jar("-direct")));
    io.restart();
    auto first=asio::co_spawn(io,jar("-jar-first"),asio::use_future);
    auto second=asio::co_spawn(io,jar("-jar-second"),asio::use_future);
    io.run();
    auto a=first.get(),b=second.get();
    ASSERT_NE(a.has_value(),b.has_value());
    EXPECT_EQ(verified,3);
    const auto rows=execute(fixture.get(),
        "SELECT (SELECT count(*) FROM openproof.oauth_pushed_authorization_requests WHERE client_id=$1 "
        "AND redirect_uri=$2 AND response_mode=1 AND expires_at_ms=1770000090000)::text,"
        "(SELECT count(*) FROM openproof.oauth_jar_replays WHERE client_id=$1 AND jwt_id='fixture-jti')::text",
        {client,redirect});
    ASSERT_EQ(PQntuples(rows.get()),1);
    EXPECT_STREQ(PQgetvalue(rows.get(),0,0),"2");
    EXPECT_STREQ(PQgetvalue(rows.get(),0,1),"1");

    // Exercise the actual PAR consumer, including consent and JARM failure.
    const auto sessionName="par-session-"+seed.suffix;
    ASSERT_NO_THROW(sql("INSERT INTO openproof.sessions(id,identity_id,provider,assurance,factors,phishing_resistant,state,"
        "token_digest,authenticated_at_ms,issued_at_ms,last_seen_at_ms,absolute_expires_at_ms,idle_timeout_ms) "
        "VALUES($1,$2,'local',1,1,false,0,decode($3,'hex'),1770000000000,1770000000000,1770000000000,1770003600000,600000)",
        {sessionName,seed.owner,fingerprint("-session")}));
    using Decision=oauth::NativeAuthorizationDecision;
    bool failSign=false;
    int signedCalls=0;
    const auto sign=[&](const oauth::AuthorizationRequest& request,bool denied)->fnd::Result<std::string>{
        ++signedCalls;
        EXPECT_EQ(request.redirectUri(),redirect);
        EXPECT_EQ(request.state(),std::optional<std::string>{"fixture-state"});
        if (failSign) return fnd::fail(fnd::ErrorCode::Unavailable);
        return std::string{denied?"fixture-denial":"fixture-response"};
    };
    auto complete=[&](auto& store,std::string par,std::string suffix,Decision decision,
        fnd::Instant now=kNow+1s,std::string owner={}) {
        return store.completeOAuthAuthorizationAsync(client,fingerprint(par),std::nullopt,
            ids::IdentityId{owner.empty()?seed.owner:owner},openproof::session::SessionId{sessionName},
            decision,client+suffix,fingerprint("-code"+suffix),now,5min,sign);
    };
    EXPECT_FALSE(run(complete(foreign,"-direct","-foreign",Decision::Approve)));
    EXPECT_FALSE(run(complete(native,"-direct","-wrong-owner",Decision::Approve,kNow+1s,seed.secondOwner)));
    EXPECT_FALSE(run(complete(native,"-direct","-stale",Decision::Approve,kNow+61s)));
    auto preview=run(complete(native,"-direct","-preview",Decision::ExistingConsent));
    ASSERT_TRUE(preview);
    EXPECT_TRUE(preview->consentRequired);
    EXPECT_EQ(signedCalls,0);
    failSign=true;
    EXPECT_FALSE(run(complete(native,"-direct","-sign-failed",Decision::Approve)));
    failSign=false;
    auto afterFailure=run(complete(native,"-direct","-preview-after",Decision::ExistingConsent));
    ASSERT_TRUE(afterFailure);
    EXPECT_TRUE(afterFailure->consentRequired);
    io.restart();
    std::optional<fnd::Result<oauth::NativeAuthorizationResult>> resultA,resultB;
    auto approveA=asio::co_spawn(io,capture(complete(native,"-direct","-approve-a",Decision::Approve),resultA),asio::use_future);
    auto approveB=asio::co_spawn(io,capture(complete(native,"-direct","-approve-b",Decision::Approve),resultB),asio::use_future);
    io.run();approveA.get();approveB.get();
    auto approvedA=std::move(resultA).value(),approvedB=std::move(resultB).value();
    ASSERT_NE(approvedA.has_value(),approvedB.has_value());
    const auto& approved=approvedA?approvedA.value():approvedB.value();
    ASSERT_TRUE(approved.signedResponse);
    EXPECT_EQ(approved.signedResponse->expose(),"fixture-response");
    EXPECT_FALSE(approved.consentRequired);
    ASSERT_TRUE(push(native,"-covered",makeRequest(redirect,"openid")));
    auto covered=run(complete(native,"-covered","-covered",Decision::ExistingConsent));
    ASSERT_TRUE(covered);
    EXPECT_FALSE(covered->consentRequired);
    const std::string jarPar=a?"-jar-first":"-jar-second";
    auto denied=run(complete(native,jarPar,"-denied",Decision::Deny));
    ASSERT_TRUE(denied);
    ASSERT_TRUE(denied->signedResponse);
    EXPECT_EQ(denied->signedResponse->expose(),"fixture-denial");
    EXPECT_FALSE(run(complete(native,jarPar,"-replay-denied",Decision::Approve)));
    const auto finalState=execute(fixture.get(),
        "SELECT (SELECT count(*) FROM openproof.oauth_pushed_authorization_requests WHERE client_id=$1)::text,"
        "(SELECT count(*) FROM openproof.oauth_authorization_codes WHERE client_id=$1)::text,"
        "(SELECT count(*) FROM openproof.oauth_consents WHERE client_id=$1 AND revoked_at_ms IS NULL)::text",
        {client});
    ASSERT_EQ(PQntuples(finalState.get()),1);
    EXPECT_STREQ(PQgetvalue(finalState.get(),0,0),"0");
    EXPECT_STREQ(PQgetvalue(finalState.get(),0,1),"2");
    EXPECT_STREQ(PQgetvalue(finalState.get(),0,2),"1");
}

TEST(PostgresCanonicalCoroutineTest, NativeCodeExchangeConsumesExactlyOnceAndRollsBackFailedSigning)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace oauth=openproof::oauth;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    const auto app="code-app-"+seed.suffix;
    const auto client="code-client-"+seed.suffix;
    const auto family="code-family-"+seed.suffix;
    const auto fingerprint=[&](std::string_view suffix) {
        return fnd::toHex(openproof::security::sha256(family+std::string{suffix}).value());
    };
    const auto code=fingerprint("-code");
    const std::string challenge(43U,'a'),redirect="https://client.example.invalid/callback";
    const auto sql=[&](std::string query,std::initializer_list<std::string> args) {
        static_cast<void>(execute(fixture.get(),query,args));
    };
    ASSERT_NO_THROW(sql("INSERT INTO openproof.applications(id,organization_id,identifier,display_name,environment,status,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,'code-fixture','Fixture',0,0,1770000000000,1770000000000)",{app,seed.org}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_clients(id,application_id,display_name,kind,status,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,'Fixture',1,0,1770000000000,1770000000000)",{client,app}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_authorization_codes "
        "(code_digest,client_id,identity_id,redirect_uri,code_challenge,nonce,provider,assurance,factors,phishing_resistant,authenticated_at_ms,issued_at_ms,expires_at_ms,resource) "
        "VALUES(decode($1,'hex'),$2,$3,$4,$5,'fixture-nonce','local',1,1,false,1770000000000,1770000000000,1770000060000,'urn:fixture')",
        {code,client,seed.owner,redirect,challenge}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_authorization_code_scopes(code_digest,scope) "
        "VALUES(decode($1,'hex'),'openid'),(decode($1,'hex'),'account')",{code}));
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    pg::CoroutinePostgresCanonicalFinalizer foreign{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.foreignOrg},2U,500ms,1000ms,3000ms};
    int signCalls=0;
    bool failSigning=false;
    const auto signer=[&](const oauth::AuthorizationCode& grant)->fnd::Result<std::string> {
        ++signCalls;
        EXPECT_EQ(grant.clientId().value(),client);
        EXPECT_EQ(grant.identity().value(),seed.owner);
        EXPECT_EQ(grant.nonce(),std::optional<std::string>{"fixture-nonce"});
        EXPECT_EQ(grant.resource(),std::optional<std::string>{"urn:fixture"});
        if (failSigning) return fnd::fail(fnd::ErrorCode::Unavailable);
        return std::string{"fixture-signed-result"};
    };
    const auto attempt=[&](pg::CoroutinePostgresCanonicalFinalizer& store,std::string suffix,
        std::string proof,std::string uri,std::optional<std::string> clientProof=std::nullopt){
        return store.exchangeOAuthCodeAsync(client,std::move(clientProof),code,std::move(uri),std::move(proof),
            family+suffix,fingerprint("-access"+suffix),fingerprint("-refresh"+suffix),std::nullopt,
            kNow+1s,15min,24h*30,signer);
    };
    const auto run=[&](auto task){
        io.restart();
        auto done=asio::co_spawn(io,std::move(task),asio::use_future);
        io.run();
        return done.get();
    };
    EXPECT_FALSE(run(attempt(foreign,"-foreign",challenge,redirect)));
    EXPECT_FALSE(run(attempt(native,"-pkce",std::string(43U,'b'),redirect)));
    EXPECT_FALSE(run(attempt(native,"-redirect",challenge,redirect+"/wrong")));
    EXPECT_FALSE(run(attempt(native,"-secret",challenge,redirect,std::string(64U,'0'))));
    EXPECT_EQ(signCalls,0);
    failSigning=true;
    EXPECT_FALSE(run(attempt(native,"-sign-failed",challenge,redirect)));
    failSigning=false;
    EXPECT_EQ(signCalls,1);
    io.restart();
    auto first=asio::co_spawn(io,attempt(native,"-first",challenge,redirect),asio::use_future);
    auto second=asio::co_spawn(io,attempt(native,"-second",challenge,redirect),asio::use_future);
    io.run();
    auto a=first.get();
    auto b=second.get();
    ASSERT_NE(a.has_value(),b.has_value());
    EXPECT_EQ((a?b:a).error().code(),fnd::ErrorCode::AuthenticationFailed);
    const auto& accepted=a?a.value():b.value();
    EXPECT_EQ(accepted.scopes,(std::vector<std::string>{"account","openid"}));
    ASSERT_TRUE(accepted.idToken);
    EXPECT_EQ(accepted.idToken->expose(),"fixture-signed-result");
    EXPECT_EQ(signCalls,2);
    const auto persisted=execute(fixture.get(),
        "SELECT (SELECT count(*) FROM openproof.oauth_authorization_codes WHERE code_digest=decode($1,'hex'))::text,"
        "(SELECT count(*) FROM openproof.oauth_token_families WHERE client_id=$2)::text,"
        "(SELECT count(*) FROM openproof.oauth_access_tokens t JOIN openproof.oauth_token_families f ON f.id=t.family_id WHERE f.client_id=$2 AND t.state=0)::text,"
        "(SELECT count(*) FROM openproof.oauth_refresh_tokens r JOIN openproof.oauth_token_families f ON f.id=r.family_id WHERE f.client_id=$2 AND r.state=0)::text",
        {code,client});
    ASSERT_EQ(PQntuples(persisted.get()),1);
    EXPECT_STREQ(PQgetvalue(persisted.get(),0,0),"0");
    EXPECT_STREQ(PQgetvalue(persisted.get(),0,1),"1");
    EXPECT_STREQ(PQgetvalue(persisted.get(),0,2),"1");
    EXPECT_STREQ(PQgetvalue(persisted.get(),0,3),"1");
}

TEST(PostgresCanonicalCoroutineTest, NativeMachineGrantsCannotWidenScopeAudienceOrLifetime)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    const auto app="machine-app-"+seed.suffix,client="machine-client-"+seed.suffix;
    const auto service="machine-identity-"+seed.suffix,resource="machine-resource-"+seed.suffix;
    const auto audience="urn:machine:"+seed.suffix,otherAudience=audience+":other";
    const auto fingerprint=[&](std::string_view suffix) {
        return fnd::toHex(openproof::security::sha256(client+std::string{suffix}).value());
    };
    const auto clientProof=fingerprint("-client");
    auto sql=[&](std::string query,std::initializer_list<std::string> args) {
        static_cast<void>(execute(fixture.get(),query,args));
    };
    ASSERT_NO_THROW(sql("INSERT INTO openproof.applications(id,organization_id,identifier,display_name,environment,status,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,'machine-fixture','Fixture',0,0,1770000000000,1770000000000)",{app,seed.org}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_clients(id,application_id,display_name,kind,status,secret_digest,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,'Fixture',3,0,decode($3,'hex'),1770000000000,1770000000000)",{client,app,clientProof}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) VALUES($1,$2,1,0,1770000000000)",{service,seed.org}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.service_identities(client_id,identity_id,active,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,true,1770000000000,1770000000000)",{client,service}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_resources(id,audience,display_name,status,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,'Fixture',0,1770000000000,1770000000000),($3,$4,'Other',0,1770000000000,1770000000000)",
        {resource,audience,resource+"-other",otherAudience}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_resource_scopes(resource_id,scope) VALUES($1,'read'),($1,'write'),($2,'read')",
        {resource,resource+"-other"}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.service_identity_audiences(client_id,audience) VALUES($1,$2)",{client,audience}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.service_identity_scopes(client_id,scope) VALUES($1,'read')",{client}));
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    pg::CoroutinePostgresCanonicalFinalizer foreign{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.foreignOrg},2U,500ms,1000ms,3000ms};
    using Sender=openproof::session::DelegatedSenderConstraint;
    const auto issue=[&](pg::CoroutinePostgresCanonicalFinalizer& store,std::string suffix,
        std::optional<std::string> proof,std::optional<std::string> subject,std::string target,
        std::vector<std::string> scopes,fnd::Instant now=kNow,std::optional<Sender> sender=std::nullopt) {
        io.restart();
        auto task=store.issueOAuthMachineGrantAsync(client,std::move(proof),std::move(subject),
            std::move(target),std::move(scopes),client+suffix,fingerprint(suffix),std::move(sender),now,15min);
        auto done=asio::co_spawn(io,std::move(task),asio::use_future);
        io.run();
        return done.get();
    };
    EXPECT_FALSE(issue(foreign,"-foreign",clientProof,std::nullopt,audience,{"read"}));
    EXPECT_FALSE(issue(native,"-secret",std::string(64U,'0'),std::nullopt,audience,{"read"}));
    EXPECT_FALSE(issue(native,"-wide",clientProof,std::nullopt,audience,{"write"}));
    EXPECT_FALSE(issue(native,"-target",clientProof,std::nullopt,otherAudience,{"read"}));
    auto issued=issue(native,"-initial",clientProof,std::nullopt,audience,{});
    ASSERT_TRUE(issued);
    EXPECT_EQ(issued->scopes,std::vector<std::string>{"read"});
    EXPECT_EQ(issued->expiresIn,15min);
    const auto source=fingerprint("-initial");
    EXPECT_FALSE(issue(native,"-exchange-wide",clientProof,source,audience,{"write"}));
    EXPECT_FALSE(issue(native,"-exchange-target",clientProof,source,otherAudience,{"read"}));
    EXPECT_FALSE(issue(native,"-exchange-sender",clientProof,source,audience,{"read"},kNow,
        Sender{openproof::session::DelegatedSenderConstraintKind::Dpop,"fixture"}));
    auto exchanged=issue(native,"-exchanged",clientProof,source,audience,{"read"},kNow+10min);
    ASSERT_TRUE(exchanged);
    EXPECT_EQ(exchanged->expiresIn,5min);
    EXPECT_EQ(exchanged->scopes,std::vector<std::string>{"read"});
    ASSERT_NO_THROW(sql("UPDATE openproof.oauth_access_tokens SET state=1,revoked_at_ms=1770000600000 "
        "WHERE token_digest=decode($1,'hex')",{source}));
    EXPECT_FALSE(issue(native,"-revoked",clientProof,source,audience,{"read"},kNow+10min));
    ASSERT_NO_THROW(sql("UPDATE openproof.service_identities SET active=false WHERE client_id=$1",{client}));
    EXPECT_FALSE(issue(native,"-disabled",clientProof,std::nullopt,audience,{"read"}));
    const auto rows=execute(fixture.get(),
        "SELECT (SELECT count(*) FROM openproof.oauth_token_families WHERE client_id=$1)::text,"
        "(SELECT count(*) FROM openproof.oauth_refresh_tokens r JOIN openproof.oauth_token_families f ON f.id=r.family_id WHERE f.client_id=$1)::text,"
        "(SELECT count(*) FROM openproof.oauth_access_tokens t JOIN openproof.oauth_token_families f ON f.id=t.family_id WHERE f.client_id=$1 AND f.identity_id=$2)::text",
        {client,service});
    ASSERT_EQ(PQntuples(rows.get()),1);
    EXPECT_STREQ(PQgetvalue(rows.get(),0,0),"2");
    EXPECT_STREQ(PQgetvalue(rows.get(),0,1),"0");
    EXPECT_STREQ(PQgetvalue(rows.get(),0,2),"2");
}

TEST(PostgresCanonicalCoroutineTest, NativeDevicePollingCommitsThrottleAndConsumesApprovedCodeExactlyOnce)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    const auto app="device-app-"+seed.suffix,client="device-client-"+seed.suffix;
    const auto family="device-family-"+seed.suffix;
    const auto fingerprint=[&](std::string_view suffix) {
        return fnd::toHex(openproof::security::sha256(family+std::string{suffix}).value());
    };
    const auto device=fingerprint("-device"),user=fingerprint("-user");
    auto sql=[&](std::string query,std::initializer_list<std::string> args) {
        static_cast<void>(execute(fixture.get(),query,args));
    };
    ASSERT_NO_THROW(sql("INSERT INTO openproof.applications(id,organization_id,identifier,display_name,environment,status,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,'device-fixture','Fixture',0,0,1770000000000,1770000000000)",{app,seed.org}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_clients(id,application_id,display_name,kind,status,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,'Fixture',1,0,1770000000000,1770000000000)",{client,app}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_client_scopes(client_id,scope) VALUES($1,'account'),($1,'read'),($1,'write')",{client}));
    const auto resource="device-resource-"+seed.suffix;
    const auto audience="urn:device:"+seed.suffix;
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_resources(id,audience,display_name,status,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,'Fixture',0,1770000000000,1770000000000)",{resource,audience}));
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_resource_scopes(resource_id,scope) VALUES($1,'read')",{resource}));
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    pg::CoroutinePostgresCanonicalFinalizer foreign{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.foreignOrg},2U,500ms,1000ms,3000ms};
    using State=openproof::oauth::NativeDevicePollState;
    const auto attempt=[&](pg::CoroutinePostgresCanonicalFinalizer& store,std::string suffix,fnd::Instant now,
        std::optional<std::string> proof=std::nullopt) {
        return store.pollOAuthDeviceAsync(client,std::move(proof),device,family+suffix,
            fingerprint("-access"+suffix),fingerprint("-refresh"+suffix),std::nullopt,now,15min,24h*30);
    };
    const auto run=[&](auto task) {
        io.restart();
        auto done=asio::co_spawn(io,std::move(task),asio::use_future);
        io.run(); return done.get();
    };
    const auto begin=[&](pg::CoroutinePostgresCanonicalFinalizer& store,std::string digest,
        std::string human,std::vector<std::string> scopes,std::optional<std::string> target=std::nullopt,
        std::optional<std::string> proof=std::nullopt) {
        return run(store.beginOAuthDeviceAsync(client,std::move(proof),std::move(digest),
            std::move(human),std::move(scopes),std::move(target),kNow,10min,5s));
    };
    EXPECT_FALSE(begin(foreign,device,user,{"account"}));
    EXPECT_FALSE(begin(native,device,user,{"account"},std::nullopt,std::string(64U,'0')));
    EXPECT_FALSE(begin(native,device,user,{"forbidden"}));
    EXPECT_FALSE(begin(native,device,user,{"read"})); // API scope requires target
    EXPECT_FALSE(begin(native,device,user,{"write"},audience)); // resource excludes write
    EXPECT_FALSE(begin(native,device,user,{"account","account"}));
    ASSERT_TRUE(begin(native,device,user,{"account"},audience));
    const auto duplicate=begin(native,fingerprint("-other-device"),user,{"account"});
    ASSERT_FALSE(duplicate);
    EXPECT_EQ(duplicate.error().code(),fnd::ErrorCode::Conflict);
    const auto persisted=execute(fixture.get(),
        "SELECT count(*)::text FROM openproof.oauth_device_authorizations WHERE client_id=$1",{client});
    ASSERT_EQ(PQntuples(persisted.get()),1);
    EXPECT_STREQ(PQgetvalue(persisted.get(),0,0),"1");
    EXPECT_FALSE(run(attempt(foreign,"-foreign",kNow)));
    EXPECT_FALSE(run(attempt(native,"-wrong-secret",kNow,std::string(64U,'0'))));
    auto pending=run(attempt(native,"-pending",kNow));
    ASSERT_TRUE(pending); EXPECT_EQ(pending->state,State::Pending);
    auto slow=run(attempt(native,"-slow",kNow+1s));
    ASSERT_TRUE(slow); EXPECT_EQ(slow->state,State::SlowDown);
    const auto throttle=execute(fixture.get(),
        "SELECT poll_interval_ms::text,last_poll_at_ms::text FROM openproof.oauth_device_authorizations WHERE device_digest=decode($1,'hex')",{device});
    ASSERT_EQ(PQntuples(throttle.get()),1);
    EXPECT_STREQ(PQgetvalue(throttle.get(),0,0),"10000");
    EXPECT_STREQ(PQgetvalue(throttle.get(),0,1),"1770000001000");
    const auto sessionName="device-session-"+seed.suffix;
    ASSERT_NO_THROW(sql("INSERT INTO openproof.sessions(id,identity_id,provider,assurance,factors,phishing_resistant,state,"
        "token_digest,authenticated_at_ms,issued_at_ms,last_seen_at_ms,absolute_expires_at_ms,idle_timeout_ms) "
        "VALUES($1,$2,'local',1,1,false,0,decode($3,'hex'),1770000001000,1770000001000,1770000001000,1770003600000,600000)",
        {sessionName,seed.owner,fingerprint("-session")}));
    auto readApproval=[&](auto& store, std::string owner) {
        return run(store.readOAuthDeviceApprovalAsync(user,ids::IdentityId{std::move(owner)},kNow+1s));
    };
    EXPECT_FALSE(readApproval(foreign,seed.owner));
    const auto preview=readApproval(native,seed.owner);
    ASSERT_TRUE(preview);
    EXPECT_EQ(preview->clientName,"Fixture");
    EXPECT_EQ(preview->resource,std::optional<std::string>{audience});
    EXPECT_EQ(preview->scopes,std::vector<std::string>{"account"});
    const auto decide=[&](auto& store,std::string owner,bool approve,std::string consent){
        return run(store.decideOAuthDeviceAsync(user,ids::IdentityId{std::move(owner)},
            openproof::session::SessionId{sessionName},approve,std::move(consent),kNow+1s));
    };
    EXPECT_FALSE(decide(foreign,seed.owner,true,family+"-foreign"));
    EXPECT_FALSE(decide(native,seed.secondOwner,true,family+"-wrong-owner"));
    // Force a consent collision; the device must remain pending.
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_consents(id,identity_id,client_id,audience,granted_at_ms) "
        "VALUES($1,$2,$3,$4,1770000000000)",{family+"-consent-collision",seed.owner,client,audience}));
    EXPECT_FALSE(decide(native,seed.owner,true,family+"-consent-collision"));
    EXPECT_TRUE(readApproval(native,seed.owner));
    ASSERT_TRUE(decide(native,seed.owner,true,family+"-consent"));
    EXPECT_FALSE(decide(native,seed.owner,false,""));
    EXPECT_FALSE(readApproval(native,seed.owner));
    const auto consents=execute(fixture.get(),
        "SELECT count(*)::text FROM openproof.oauth_consents c JOIN openproof.oauth_consent_scopes s ON s.consent_id=c.id "
        "WHERE c.identity_id=$1 AND c.client_id=$2 AND c.revoked_at_ms IS NULL AND s.scope='account'",{seed.owner,client});
    ASSERT_EQ(PQntuples(consents.get()),1);
    EXPECT_STREQ(PQgetvalue(consents.get(),0,0),"1");
    // A duplicate family insertion must roll back without consuming approval.
    ASSERT_NO_THROW(sql("INSERT INTO openproof.oauth_token_families "
        "(id,client_id,identity_id,provider,assurance,factors,phishing_resistant,authenticated_at_ms) "
        "VALUES($1,$2,$3,'local',1,1,false,1770000001000)",{family+"-collision",client,seed.owner}));
    EXPECT_FALSE(run(attempt(native,"-collision",kNow+11s)));
    io.restart();
    auto first=asio::co_spawn(io,attempt(native,"-first",kNow+11s),asio::use_future);
    auto second=asio::co_spawn(io,attempt(native,"-second",kNow+11s),asio::use_future);
    io.run();
    auto a=first.get(),b=second.get();
    ASSERT_NE(a.has_value(),b.has_value());
    EXPECT_EQ((a?b:a).error().code(),fnd::ErrorCode::AuthenticationFailed);
    const auto& accepted=a?a.value():b.value();
    EXPECT_EQ(accepted.state,State::Issued);
    EXPECT_EQ(accepted.scopes,std::vector<std::string>{"account"});
    const auto state=execute(fixture.get(),
        "SELECT d.status::text,(SELECT count(*) FROM openproof.oauth_access_tokens t JOIN openproof.oauth_token_families f ON f.id=t.family_id WHERE f.client_id=$2)::text,"
        "(SELECT count(*) FROM openproof.oauth_refresh_tokens r JOIN openproof.oauth_token_families f ON f.id=r.family_id WHERE f.client_id=$2)::text "
        "FROM openproof.oauth_device_authorizations d WHERE d.device_digest=decode($1,'hex')",{device,client});
    ASSERT_EQ(PQntuples(state.get()),1);
    EXPECT_STREQ(PQgetvalue(state.get(),0,0),"3");
    EXPECT_STREQ(PQgetvalue(state.get(),0,1),"1");
    EXPECT_STREQ(PQgetvalue(state.get(),0,2),"1");
}

TEST(PostgresCanonicalCoroutineTest, SenderReplayConsumptionIsAtomicAcrossTenantsAndLegacy)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN.";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    using Kind=openproof::session::DelegatedSenderConstraintKind;
    Seed seed;
    const std::string thumbprint="replay-"+seed.suffix;
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    pg::CoroutinePostgresCanonicalFinalizer foreign{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.foreignOrg},2U,500ms,1000ms,3000ms};
    auto run=[&](asio::awaitable<fnd::Status> task) {
        io.restart();
        auto done=asio::co_spawn(io,std::move(task),asio::use_future);
        io.run();
        return done.get();
    };
    for (const auto kind:{Kind::Dpop,Kind::Mtls}) {
        io.restart();
        auto first=asio::co_spawn(io,native.consumeSenderReplayAsync(kind,thumbprint,"concurrent",kNow+60s,kNow),asio::use_future);
        auto second=asio::co_spawn(io,foreign.consumeSenderReplayAsync(kind,thumbprint,"concurrent",kNow+60s,kNow),asio::use_future);
        io.run();
        const auto a=first.get(),b=second.get();
        ASSERT_NE(a.has_value(),b.has_value());
        const auto& rejected=a?b:a;
        EXPECT_EQ(rejected.error().code(),fnd::ErrorCode::AuthenticationFailed);
        EXPECT_FALSE(run(native.consumeSenderReplayAsync(kind,thumbprint,"concurrent",kNow+60s,kNow)));
        EXPECT_TRUE(run(native.consumeSenderReplayAsync(kind,thumbprint,"concurrent",kNow+120s,kNow+60s)));
        EXPECT_FALSE(run(native.consumeSenderReplayAsync(kind,thumbprint,"expired",kNow,kNow)));
        EXPECT_FALSE(run(native.consumeSenderReplayAsync(kind,thumbprint,std::string{"a\0b",3U},kNow+60s,kNow)));
        EXPECT_FALSE(run(native.consumeSenderReplayAsync(kind,thumbprint,"long",kNow+13min,kNow)));
    }
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.oauth_dpop_replays(jwk_thumbprint,jwt_id,expires_at_ms) VALUES($1,'legacy',1770000060000)",{thumbprint})));
    EXPECT_FALSE(run(native.consumeSenderReplayAsync(Kind::Dpop,thumbprint,"legacy",kNow+60s,kNow)));
    EXPECT_TRUE(run(native.consumeSenderReplayAsync(Kind::Dpop,thumbprint,"legacy",kNow+120s,kNow+60s)));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.oauth_mtls_forwarding_replays(certificate_thumbprint,nonce,expires_at_ms) VALUES($1,'legacy',1770000060000)",{thumbprint})));
    EXPECT_FALSE(run(native.consumeSenderReplayAsync(Kind::Mtls,thumbprint,"legacy",kNow+60s,kNow)));
}

TEST(PostgresCanonicalCoroutineTest, NativeConsentListAndRevokeAreTenantScopedAndBounded)
{
    const auto dsn = disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK") != nullptr)
            FAIL() << "Explicitly requested disposable database has an invalid socket DSN.";
        GTEST_SKIP() << "Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace consent = openproof::consent;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get()) == CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    const auto app = "consent-app-" + seed.suffix;
    const auto client = "consent-client-" + seed.suffix;
    const auto foreignApp = "foreign-app-" + seed.suffix;
    const auto foreignClient = "foreign-client-" + seed.suffix;
    for (const auto& [application, tenant, clientId] :
         {std::tuple{app, seed.org, client}, std::tuple{foreignApp, seed.foreignOrg, foreignClient}}) {
        ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
            "INSERT INTO openproof.applications(id,organization_id,identifier,display_name,"
            "environment,status,created_at_ms,updated_at_ms) VALUES($1,$2,'consent-fixture','Fixture',0,0,$3,$3)",
            {application, tenant, "1770000000000"})));
        ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
            "INSERT INTO openproof.oauth_clients(id,application_id,display_name,kind,status,"
            "created_at_ms,updated_at_ms) VALUES($1,$2,'Fixture client',1,0,$3,$3)",
            {clientId, application, "1770000000000"})));
    }
    const auto active = "consent-active-" + seed.suffix;
    const auto expired = "consent-expired-" + seed.suffix;
    const auto revoked = "consent-revoked-" + seed.suffix;
    const auto other = "consent-other-" + seed.suffix;
    auto insert = [&](const std::string& id, const std::string& owner,
                      const std::string& clientId, const std::string& grantedAt) {
        static_cast<void>(execute(fixture.get(),
            "INSERT INTO openproof.oauth_consents(id,identity_id,client_id,audience,granted_at_ms)"
            " VALUES($1,$2,$3,'urn:fixture:resource',$4)", {id, owner, clientId, grantedAt}));
        static_cast<void>(execute(fixture.get(),
            "INSERT INTO openproof.oauth_consent_scopes(consent_id,scope) VALUES($1,'write'),($1,'read')",
            {id}));
    };
    ASSERT_NO_THROW(insert(active, seed.owner, client, "1769999999999"));
    ASSERT_NO_THROW(insert(expired, seed.owner, client, "1769999999998"));
    ASSERT_NO_THROW(insert(revoked, seed.owner, client, "1769999999997"));
    ASSERT_NO_THROW(insert(other, seed.secondOwner, client, "1769999999999"));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "UPDATE openproof.oauth_consents SET expires_at_ms=1770000000000 WHERE id=$1", {expired})));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "UPDATE openproof.oauth_consents SET revoked_at_ms=1769999999999 WHERE id=$1", {revoked})));

    asio::io_context io;
    pg::CoroutineConsentStore store{io.get_executor(), fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org}, 2U, 500ms, 1000ms, 3000ms};
    const ids::IdentityId owner{seed.owner};
    auto list = [&](const ids::IdentityId& identity) {
        io.restart();
        auto pending = asio::co_spawn(io, store.listAsync(identity), asio::use_future);
        io.run();
        return pending.get();
    };
    auto revoke = [&](const std::string& grant, const ids::IdentityId& identity,
                      fnd::Instant now = kNow) {
        io.restart();
        auto pending = asio::co_spawn(io, store.revokeAsync(consent::ConsentId{grant}, identity, now),
            asio::use_future);
        io.run();
        return pending.get();
    };
    auto result = list(owner);
    ASSERT_TRUE(result);
    ASSERT_EQ(result->size(), 3U);
    EXPECT_EQ(result->at(0).id().value(), active);
    EXPECT_EQ(result->at(0).identity(), owner);
    EXPECT_EQ(result->at(0).scopes(), (std::vector<std::string>{"read", "write"}));
    EXPECT_TRUE(result->at(0).activeAt(kNow));
    EXPECT_EQ(result->at(1).id().value(), expired);
    EXPECT_FALSE(result->at(1).activeAt(kNow));
    EXPECT_EQ(result->at(2).id().value(), revoked);
    EXPECT_FALSE(result->at(2).activeAt(kNow));
    auto empty = list(ids::IdentityId{seed.emptyConnectionsOwner});
    ASSERT_TRUE(empty);
    EXPECT_TRUE(empty->empty());
    for (const auto& deniedOwner : {seed.lockedOwner, seed.foreignOwner, seed.suspendedOwner}) {
        auto denied = list(ids::IdentityId{deniedOwner});
        EXPECT_TRUE(!denied && denied.error().code() == fnd::ErrorCode::PermissionDenied);
        auto deniedRevoke = revoke(active, ids::IdentityId{deniedOwner});
        EXPECT_TRUE(!deniedRevoke && deniedRevoke.error().code() == fnd::ErrorCode::PermissionDenied);
    }
    auto wrongOwner = revoke(other, owner);
    EXPECT_TRUE(!wrongOwner && wrongOwner.error().code() == fnd::ErrorCode::NotFound);
    ASSERT_TRUE(revoke(active, owner));
    ASSERT_TRUE(revoke(active, owner, kNow + 1h));
    result = list(owner);
    ASSERT_TRUE(result && result->size() == 3U);
    EXPECT_EQ(result->at(0).revokedAt(), std::optional<fnd::Instant>{kNow});
    auto otherResult = list(ids::IdentityId{seed.secondOwner});
    ASSERT_TRUE(otherResult && otherResult->size() == 1U);
    EXPECT_TRUE(otherResult->at(0).activeAt(kNow));

    // An inconsistent cross-tenant grant must never be serialized or mutated.
    const auto malformed = "consent-cross-tenant-" + seed.suffix;
    ASSERT_NO_THROW(insert(malformed, seed.owner, foreignClient, "1769999999999"));
    auto crossTenant = list(owner);
    EXPECT_TRUE(!crossTenant && crossTenant.error().code() == fnd::ErrorCode::Unavailable);
    auto crossRevoke = revoke(malformed, owner);
    EXPECT_TRUE(!crossRevoke && crossRevoke.error().code() == fnd::ErrorCode::NotFound);
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "DELETE FROM openproof.oauth_consents WHERE id=$1", {malformed})));

    // Oversized or scope-less grants fail closed instead of truncating.
    const auto overflow = "consent-overflow-" + seed.suffix;
    ASSERT_NO_THROW(insert(overflow, seed.owner, client, "1769999999999"));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.oauth_consent_scopes(consent_id,scope) "
        "SELECT $1,'scope-' || n FROM generate_series(1,257) AS n", {overflow})));
    auto bounded = list(owner);
    EXPECT_TRUE(!bounded && bounded.error().code() == fnd::ErrorCode::Unavailable);
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "DELETE FROM openproof.oauth_consent_scopes WHERE consent_id=$1", {overflow})));
    auto malformedScope = list(owner);
    EXPECT_TRUE(!malformedScope && malformedScope.error().code() == fnd::ErrorCode::Unavailable);
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "DELETE FROM openproof.oauth_consents WHERE id=$1", {overflow})));
    ASSERT_TRUE(list(owner));
}

TEST(PostgresCanonicalCoroutineTest, SignupProvisioningIsAtomicAndNeverCreatesDuplicateVerifiedOwner)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN.";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace acc=openproof::account;
    namespace cred=openproof::credentials;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    asio::io_context io;
    pg::CoroutineVerificationChallengeStore store{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    pg::CoroutineVerificationChallengeStore disabled{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.suspendedOrg},1U,500ms,1000ms,3000ms};
    const auto policy=cred::PasswordPolicy::create(1024U,8U,1U,16U,32U,2U*1024U*1024U);
    ASSERT_TRUE(policy);
    auto hasher=cred::PasswordHasher::create(fnd::SecretString{std::string(32U,'p')},policy.value());
    ASSERT_TRUE(hasher);
    auto password=hasher->hash(fnd::SecretString{"fixture-password"});
    ASSERT_TRUE(password);
    auto key=acc::VerificationKey::create(fnd::SecretString{std::string(32U,'v')});
    ASSERT_TRUE(key);
    const idp::ProviderId provider{"signup-"+seed.suffix};
    const auto email="fresh-"+seed.suffix+"@example.test";
    const auto existing="existing-"+seed.suffix+"@example.test";
    const auto ambiguous="ambiguous-"+seed.suffix+"@example.test";
    const auto broken="rollback-"+seed.suffix+"@example.test";
    using SignupResult=fnd::Result<pg::CoroutineVerificationChallengeStore::PendingSignup>;
    auto capture=[&](pg::CoroutineVerificationChallengeStore& adapter,std::string destination,
        std::optional<SignupResult>& result)->asio::awaitable<void> {
        result.emplace(co_await adapter.provisionSignupAsync(provider,std::move(destination),
            password.value(),std::string{"Fixture signup"},key.value(),kNow,24h));
    };
    auto run=[&](pg::CoroutineVerificationChallengeStore& adapter,std::string destination){
        std::optional<SignupResult> result;
        io.restart();
        auto done=asio::co_spawn(io,capture(adapter,std::move(destination),result),asio::use_future);
        io.run();
        done.get();
        return std::move(result.value());
    };
    auto query=[&](std::string_view sql,std::initializer_list<std::string> params){
        return execute(fixture.get(),sql,params);
    };
    auto count=[&](std::string_view sql,std::initializer_list<std::string> params){
        auto rows=query(sql,params);
        return std::string{PQgetvalue(rows.get(),0,0)};
    };
    std::optional<SignupResult> first,second;
    io.restart();
    auto a=asio::co_spawn(io,capture(store,email,first),asio::use_future);
    auto b=asio::co_spawn(io,capture(store,email,second),asio::use_future);
    io.run();
    ASSERT_NO_THROW(a.get());
    ASSERT_NO_THROW(b.get());
    ASSERT_TRUE(first && second);
    ASSERT_NE(first->has_value(),second->has_value());
    auto& winner=first->has_value()?first.value():second.value();
    auto& loser=first->has_value()?second.value():first.value();
    EXPECT_EQ(loser.error().code(),fnd::ErrorCode::AlreadyExists);
    ASSERT_TRUE(winner->createdIdentity);
    const std::string owner{winner->dispatch.identity().value()};
    EXPECT_EQ(count("SELECT count(*) FROM openproof.identities i JOIN openproof.identity_profiles p ON p.identity_id=i.id "
        "WHERE i.organization_id=$1 AND p.email=$2 AND i.status=3 AND NOT p.email_verified",{seed.org,email}),"1");
    EXPECT_EQ(count("SELECT count(*) FROM openproof.password_credentials WHERE identity_id=$1",{owner}),"1");
    EXPECT_EQ(count("SELECT count(*) FROM openproof.pending_external_identity_reservations "
        "WHERE provider=$1 AND external_subject=$2 AND identity_id=$3 AND verification_id IS NULL",
        {std::string{provider.value()},email,owner}),"1");
    const auto digest=acc::VerificationPreparation::digest(key.value(),winner->dispatch.id(),winner->dispatch.secret());
    ASSERT_TRUE(digest);
    EXPECT_EQ(count("SELECT count(*) FROM openproof.account_verification_challenges "
        "WHERE id=$1 AND identity_id=$2 AND purpose=0 AND secret_digest=decode($3,'hex')",
        {std::string{winner->dispatch.id().value()},owner,fnd::toHex(digest->bytes())}),"1");
    EXPECT_EQ(count("SELECT count(*) FROM openproof.external_identities WHERE identity_id=$1",{owner}),"0");
    using Activated=fnd::Result<pg::CoroutineVerificationChallengeStore::ActivatedSignup>;
    pg::CoroutineVerificationChallengeStore foreign{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.foreignOrg},1U,500ms,1000ms,3000ms};
    const auto activate=[&](pg::CoroutineVerificationChallengeStore& adapter,acc::VerificationId id,
        acc::VerificationDigest proof,fnd::Instant now,std::optional<Activated>& result)->asio::awaitable<void>{
        result.emplace(co_await adapter.activateSignupAsync(provider,std::move(id),proof,now,3U));
    };
    const auto redeem=[&](pg::CoroutineVerificationChallengeStore& adapter,acc::VerificationId id,
        acc::VerificationDigest proof,fnd::Instant now=kNow){
        std::optional<Activated> result;
        io.restart();
        auto done=asio::co_spawn(io,activate(adapter,std::move(id),proof,now,result),asio::use_future);
        io.run();
        done.get();
        return std::move(result.value());
    };
    const auto proofId=winner->dispatch.id();
    const std::string proofName{proofId.value()};
    EXPECT_FALSE(redeem(foreign,proofId,digest.value()));
    EXPECT_EQ(count("SELECT attempts FROM openproof.account_verification_challenges WHERE id=$1",{proofName}),"0");
    EXPECT_FALSE(redeem(store,proofId,acc::VerificationDigest{std::array<std::byte,32>{}}));
    EXPECT_EQ(count("SELECT attempts FROM openproof.account_verification_challenges WHERE id=$1",{proofName}),"1");
    EXPECT_EQ(count("SELECT status FROM openproof.identities WHERE id=$1",{owner}),"3");
    ASSERT_NO_THROW(static_cast<void>(query("UPDATE openproof.identities SET status=2 WHERE id=$1",{owner})));
    EXPECT_FALSE(redeem(store,proofId,digest.value()));
    ASSERT_NO_THROW(static_cast<void>(query("UPDATE openproof.identities SET status=3 WHERE id=$1",{owner})));
    // A failure after writing the local link must restore the entire proof
    // and pending state; a subsequent correct retry may still succeed.
    ASSERT_NO_THROW(static_cast<void>(query("ALTER TABLE openproof.identity_profiles ADD CONSTRAINT "
        "native_signup_fixture_activation CHECK(NOT email_verified) NOT VALID",{})));
    EXPECT_FALSE(redeem(store,proofId,digest.value()));
    ASSERT_NO_THROW(static_cast<void>(query("ALTER TABLE openproof.identity_profiles "
        "DROP CONSTRAINT native_signup_fixture_activation",{})));
    EXPECT_EQ(count("SELECT count(*) FROM openproof.external_identities WHERE identity_id=$1",{owner}),"0");
    EXPECT_EQ(count("SELECT count(*) FROM openproof.account_verification_challenges WHERE id=$1",{proofName}),"1");
    std::optional<Activated> one,two;
    io.restart();
    auto redeemOne=asio::co_spawn(io,activate(store,proofId,digest.value(),kNow,one),asio::use_future);
    auto redeemTwo=asio::co_spawn(io,activate(store,proofId,digest.value(),kNow,two),asio::use_future);
    io.run();
    ASSERT_NO_THROW(redeemOne.get());
    ASSERT_NO_THROW(redeemTwo.get());
    ASSERT_TRUE(one && two);
    ASSERT_NE(one->has_value(),two->has_value());
    EXPECT_EQ(count("SELECT status FROM openproof.identities WHERE id=$1",{owner}),"0");
    EXPECT_EQ(count("SELECT email_verified::text FROM openproof.identity_profiles WHERE identity_id=$1",{owner}),"true");
    EXPECT_EQ(count("SELECT count(*) FROM openproof.external_identities WHERE identity_id=$1",{owner}),"1");
    EXPECT_EQ(count("SELECT count(*) FROM openproof.account_verification_challenges WHERE id=$1",{proofName}),"0");
    EXPECT_EQ(count("SELECT count(*) FROM openproof.pending_external_identity_reservations WHERE identity_id=$1",{owner}),"0");
    EXPECT_FALSE(redeem(store,proofId,digest.value()));
    ASSERT_NO_THROW(static_cast<void>(query("UPDATE openproof.identity_profiles SET email=$2,email_verified=true WHERE identity_id=$1",
        {seed.owner,existing})));
    auto linked=run(store,existing);
    ASSERT_TRUE(linked);
    EXPECT_FALSE(linked->createdIdentity);
    EXPECT_EQ(linked->dispatch.identity().value(),seed.owner);
    EXPECT_EQ(count("SELECT display_name FROM openproof.identity_profiles WHERE identity_id=$1",{seed.owner}),"User-chosen name");
    const auto failedId=linked->dispatch.id();
    const auto replacement=acc::VerificationPreparation::prepare(key.value(),ids::IdentityId{seed.owner},
        acc::VerificationPurpose::SignupEmail,acc::VerificationChannel::Email,existing,kNow,24h);
    ASSERT_TRUE(replacement);
    auto runStatus=[&](asio::awaitable<fnd::Status> task) {
        io.restart();
        auto done=asio::co_spawn(io,std::move(task),asio::use_future);
        io.run();
        return done.get();
    };
    ASSERT_TRUE(runStatus(store.replacePublicEmailAsync(replacement->first,provider)));
    ASSERT_TRUE(runStatus(store.discardAsync(failedId,ids::IdentityId{seed.owner},acc::VerificationPurpose::SignupEmail)));
    EXPECT_EQ(count("SELECT count(*) FROM openproof.account_verification_challenges WHERE id=$1",
        {std::string{replacement->first.id().value()}}),"1");
    EXPECT_EQ(count("SELECT count(*) FROM openproof.pending_external_identity_reservations WHERE identity_id=$1 AND verification_id IS NULL",
        {seed.owner}),"1");
    // Discarding the latest failed delivery leaves the pending enrollment
    // available for explicit resend but no usable proof.
    ASSERT_TRUE(runStatus(store.discardAsync(replacement->first.id(),ids::IdentityId{seed.owner},acc::VerificationPurpose::SignupEmail)));
    EXPECT_EQ(count("SELECT count(*) FROM openproof.account_verification_challenges WHERE identity_id=$1 AND purpose=0",{seed.owner}),"0");
    EXPECT_EQ(count("SELECT count(*) FROM openproof.pending_external_identity_reservations WHERE identity_id=$1 AND verification_id IS NULL",{seed.owner}),"1");
    EXPECT_EQ(count("SELECT count(*) FROM openproof.password_credentials WHERE identity_id=$1",{seed.owner}),"1");
    EXPECT_EQ(count("SELECT display_name FROM openproof.identity_profiles WHERE identity_id=$1",{seed.owner}),"User-chosen name");
    // A live reservation cannot replace the previous hash, even if its
    // notification failed. Only a fully expired, exact pending enrollment
    // may be retried with a different password.
    auto retryPassword=hasher->hash(fnd::SecretString{"replacement-password"});
    ASSERT_TRUE(retryPassword);
    const auto retry=[&](fnd::Instant now){
        std::optional<SignupResult> result;
        auto retryCapture=[&]()->asio::awaitable<void>{
            result.emplace(co_await store.provisionSignupAsync(provider,existing,
                retryPassword.value(),std::string{"Ignored profile name"},key.value(),now,24h));
        };
        io.restart();
        auto done=asio::co_spawn(io,retryCapture(),asio::use_future);
        io.run();
        done.get();
        return std::move(result.value());
    };
    const std::string initialHash{password->encoded()};
    EXPECT_FALSE(retry(kNow+23h));
    EXPECT_EQ(count("SELECT password_hash FROM openproof.password_credentials WHERE identity_id=$1",{seed.owner}),initialHash);
    // A live proof forbids replacement even when the reservation has expired.
    const auto futureProof=acc::VerificationPreparation::prepare(key.value(),ids::IdentityId{seed.owner},
        acc::VerificationPurpose::SignupEmail,acc::VerificationChannel::Email,existing,kNow+23h,24h);
    ASSERT_TRUE(futureProof);
    ASSERT_TRUE(runStatus(store.replacePublicEmailAsync(futureProof->first,provider)));
    EXPECT_FALSE(retry(kNow+24h));
    ASSERT_TRUE(runStatus(store.discardAsync(futureProof->first.id(),ids::IdentityId{seed.owner},acc::VerificationPurpose::SignupEmail)));
    // A bare credential must not be treated as a pending enrollment.
    ASSERT_NO_THROW(static_cast<void>(query("DELETE FROM openproof.pending_external_identity_reservations WHERE identity_id=$1",{seed.owner})));
    EXPECT_FALSE(retry(kNow+24h));
    ASSERT_NO_THROW(static_cast<void>(query("INSERT INTO openproof.pending_external_identity_reservations"
        "(provider,external_subject,identity_id,expires_at_ms) VALUES($1,$2,$3,1770086400000)",
        {std::string{provider.value()},existing,seed.owner})));
    auto retried=retry(kNow+24h);
    ASSERT_TRUE(retried);
    EXPECT_FALSE(retried->createdIdentity);
    EXPECT_EQ(retried->dispatch.identity().value(),seed.owner);
    EXPECT_EQ(count("SELECT password_hash FROM openproof.password_credentials WHERE identity_id=$1",{seed.owner}),
        std::string{retryPassword->encoded()});
    EXPECT_EQ(count("SELECT display_name FROM openproof.identity_profiles WHERE identity_id=$1",{seed.owner}),"User-chosen name");
    EXPECT_EQ(count("SELECT status FROM openproof.identities WHERE id=$1",{seed.owner}),"0");
    EXPECT_EQ(count("SELECT count(*) FROM openproof.account_verification_challenges WHERE identity_id=$1 AND purpose=0",{seed.owner}),"1");
    EXPECT_FALSE(retry(kNow+25h));
    const auto retryDigest=acc::VerificationPreparation::digest(key.value(),retried->dispatch.id(),retried->dispatch.secret());
    ASSERT_TRUE(retryDigest);
    ASSERT_TRUE(redeem(store,retried->dispatch.id(),retryDigest.value(),kNow+24h));
    EXPECT_FALSE(retry(kNow+48h));
    ASSERT_NO_THROW(static_cast<void>(query("INSERT INTO openproof.identity_profiles(identity_id,email,email_verified,created_at_ms,updated_at_ms)"
        " VALUES($1,$3,true,1770000000000,1770000000000),($2,$3,true,1770000000000,1770000000000)",
        {seed.secondOwner,seed.emptyConnectionsOwner,ambiguous})));
    auto conflict=run(store,ambiguous);
    ASSERT_FALSE(conflict);
    EXPECT_EQ(conflict.error().code(),fnd::ErrorCode::Conflict);
    EXPECT_FALSE(run(disabled,"disabled-"+seed.suffix+"@example.test"));
    // Inject a late insertion failure, after identity/profile/reservation/
    // password writes, using an isolated fixture-only CHECK constraint.
    // suffix is generated by Seed; use a fixed name in the disposable runner
    // and quote the fixture email with libpq to avoid interpolating SQL data.
    const auto quoted=PQescapeLiteral(fixture.get(),broken.data(),broken.size());
    ASSERT_NE(quoted,nullptr);
    const std::string escaped{quoted};
    PQfreemem(quoted);
    ASSERT_NO_THROW(static_cast<void>(query("ALTER TABLE openproof.account_verification_challenges ADD CONSTRAINT "
        "native_signup_fixture_rollback CHECK(destination<>"+escaped+")",{})));
    auto failed=run(store,broken);
    ASSERT_NO_THROW(static_cast<void>(query("ALTER TABLE openproof.account_verification_challenges "
        "DROP CONSTRAINT native_signup_fixture_rollback",{})));
    EXPECT_FALSE(failed);
    EXPECT_EQ(count("SELECT count(*) FROM openproof.identity_profiles WHERE email=$1",{broken}),"0");
    EXPECT_EQ(count("SELECT count(*) FROM openproof.pending_external_identity_reservations WHERE external_subject=$1",{broken}),"0");
    EXPECT_EQ(count("SELECT count(*) FROM openproof.account_verification_challenges WHERE destination=$1",{broken}),"0");
}

TEST(PostgresCanonicalCoroutineTest, PasswordResetCommitsHashProofAndSessionRevocationTogether)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN.";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace acc=openproof::account;
    namespace cred=openproof::credentials;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    const idp::ProviderId provider{"reset-"+seed.suffix};
    const std::string destination="reset-"+seed.suffix+"@example.test";
    auto policy=cred::PasswordPolicy::create(1024U,8U,1U,16U,32U,2U*1024U*1024U);
    ASSERT_TRUE(policy);
    auto hasher=cred::PasswordHasher::create(fnd::SecretString{std::string(32U,'p')},policy.value());
    ASSERT_TRUE(hasher);
    auto original=hasher->hash(fnd::SecretString{"original-password"});
    auto replacement=hasher->hash(fnd::SecretString{"replacement-password"});
    ASSERT_TRUE(original && replacement);
    auto key=acc::VerificationKey::create(fnd::SecretString{std::string(32U,'v')});
    ASSERT_TRUE(key);
    auto query=[&](std::string_view sql,std::initializer_list<std::string> params){
        return execute(fixture.get(),sql,params);
    };
    auto scalar=[&](std::string_view sql,std::initializer_list<std::string> params){
        auto rows=query(sql,params);
        return std::string{PQgetvalue(rows.get(),0,0)};
    };
    ASSERT_NO_THROW(static_cast<void>(query(
        "INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms)"
        " VALUES($1,$2,$3,1770000000000)",{std::string{provider.value()},destination,seed.owner})));
    ASSERT_NO_THROW(static_cast<void>(query(
        "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms)"
        " VALUES($1,$2,1770000000000)",{seed.owner,std::string{original->encoded()}})));
    const auto sessionId="reset-session-"+seed.suffix;
    const auto otherId="other-session-"+seed.suffix;
    for (const auto& [sessionName,ownerName,hashByte]:
        {std::tuple{sessionId,seed.owner,"11"},std::tuple{otherId,seed.secondOwner,"22"}}) {
        ASSERT_NO_THROW(static_cast<void>(query(
            "INSERT INTO openproof.sessions(id,identity_id,provider,assurance,factors,phishing_resistant,state,"
            "token_digest,authenticated_at_ms,issued_at_ms,last_seen_at_ms,absolute_expires_at_ms,idle_timeout_ms)"
            " VALUES($1,$2,$3,1,1,false,0,decode($4,'hex'),1770000000000,1770000000000,"
            "1770000000000,1770003600000,600000)",
            {sessionName,ownerName,std::string{provider.value()},
            fnd::toHex(openproof::security::sha256(seed.suffix+hashByte).value())})));
    }
    asio::io_context io;
    pg::CoroutineVerificationChallengeStore store{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    pg::CoroutineVerificationChallengeStore foreign{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.foreignOrg},1U,500ms,1000ms,3000ms};
    auto run=[&](asio::awaitable<fnd::Status> task){
        io.restart();
        auto done=asio::co_spawn(io,std::move(task),asio::use_future);
        io.run();
        return done.get();
    };
    auto proof=acc::VerificationPreparation::prepare(key.value(),ids::IdentityId{seed.owner},
        acc::VerificationPurpose::PasswordReset,acc::VerificationChannel::Email,destination,kNow,30min);
    ASSERT_TRUE(proof);
    ASSERT_TRUE(run(store.replacePublicEmailAsync(proof->first,provider)));
    const auto id=proof->first.id();
    const auto idText=std::string{id.value()};
    const auto digest=proof->first.digest();
    auto reset=[&](pg::CoroutineVerificationChallengeStore& adapter,acc::VerificationDigest value){
        return adapter.resetPasswordAsync(provider,id,value,replacement.value(),kNow+1s,3U);
    };
    EXPECT_FALSE(run(reset(foreign,digest)));
    EXPECT_FALSE(run(reset(store,acc::VerificationDigest{std::array<std::byte,32>{}})));
    EXPECT_EQ(scalar("SELECT attempts FROM openproof.account_verification_challenges WHERE id=$1",{idText}),"1");
    ASSERT_NO_THROW(static_cast<void>(query(
        "UPDATE openproof.password_credentials SET changed_at_ms=1770000000001 WHERE identity_id=$1",{seed.owner})));
    EXPECT_FALSE(run(reset(store,digest)));
    ASSERT_NO_THROW(static_cast<void>(query(
        "UPDATE openproof.password_credentials SET changed_at_ms=1770000000000 WHERE identity_id=$1",{seed.owner})));
    ASSERT_NO_THROW(static_cast<void>(query(
        "ALTER TABLE openproof.sessions ADD CONSTRAINT native_reset_fixture_rollback CHECK(state<>1) NOT VALID",{})));
    EXPECT_FALSE(run(reset(store,digest)));
    ASSERT_NO_THROW(static_cast<void>(query(
        "ALTER TABLE openproof.sessions DROP CONSTRAINT native_reset_fixture_rollback",{})));
    EXPECT_EQ(scalar("SELECT password_hash FROM openproof.password_credentials WHERE identity_id=$1",{seed.owner}),
        std::string{original->encoded()});
    EXPECT_EQ(scalar("SELECT state FROM openproof.sessions WHERE id=$1",{sessionId}),"0");
    EXPECT_EQ(scalar("SELECT count(*) FROM openproof.account_verification_challenges WHERE id=$1",{idText}),"1");
    io.restart();
    auto first=asio::co_spawn(io,reset(store,digest),asio::use_future);
    auto second=asio::co_spawn(io,reset(store,digest),asio::use_future);
    io.run();
    const auto firstResult=first.get(),secondResult=second.get();
    ASSERT_NE(firstResult.has_value(),secondResult.has_value());
    EXPECT_EQ(scalar("SELECT password_hash FROM openproof.password_credentials WHERE identity_id=$1",{seed.owner}),
        std::string{replacement->encoded()});
    EXPECT_EQ(scalar("SELECT state FROM openproof.sessions WHERE id=$1",{sessionId}),"1");
    EXPECT_EQ(scalar("SELECT state FROM openproof.sessions WHERE id=$1",{otherId}),"0");
    EXPECT_EQ(scalar("SELECT count(*) FROM openproof.account_verification_challenges WHERE id=$1",{idText}),"0");
    EXPECT_FALSE(run(reset(store,digest)));

    // Simulate a login proof captured before reset, then persisted after it.
    namespace ses=openproof::session;
    pg::CoroutinePostgresSessionRepository repository{io.get_executor(),fnd::SecretString{*dsn},
        2U,500ms,1000ms,3000ms};
    const auto makeSession=[&](const std::string& name){
        return ses::Session::create(ses::SessionId{name},ids::IdentityId{seed.owner},provider,
            idp::AssuranceLevel::Ial1,
            idp::AuthenticationStrength{idp::AuthenticationFactor::Knowledge,false},
            kNow,ses::TokenDigest{openproof::security::sha256(name).value()},kNow+1s,2h,15min);
    };
    const auto staleName="stale-"+seed.suffix;
    const auto currentName="current-"+seed.suffix;
    const auto staleReplacement="stale-replacement-"+seed.suffix;
    using Fence=pg::CoroutinePostgresSessionRepository::PasswordFence;
    auto stale=run(repository.addFenced(makeSession(staleName).value(),
        Fence{idp::ExternalSubject{destination},kNow}));
    ASSERT_FALSE(stale);
    EXPECT_EQ(stale.error().code(),fnd::ErrorCode::AuthenticationFailed);
    ASSERT_TRUE(run(repository.addFenced(makeSession(currentName).value(),
        Fence{idp::ExternalSubject{destination},kNow+1s})));
    auto deniedReplacement=run(repository.replace(makeSession(staleReplacement).value(),
        ses::SessionId{currentName},ses::TokenDigest{openproof::security::sha256(currentName).value()},
        kNow+1s,Fence{idp::ExternalSubject{destination},kNow}));
    ASSERT_FALSE(deniedReplacement);
    EXPECT_EQ(deniedReplacement.error().code(),fnd::ErrorCode::AuthenticationFailed);
    EXPECT_EQ(scalar("SELECT state FROM openproof.sessions WHERE id=$1",{currentName}),"0");
    EXPECT_EQ(scalar("SELECT count(*) FROM openproof.sessions WHERE id IN ($1,$2)",
        {staleName,staleReplacement}),"0");
    EXPECT_FALSE(run(repository.addFenced(makeSession(staleName).value(),
        Fence{idp::ExternalSubject{"different-subject"},kNow+1s})));
    const auto nextName="next-"+seed.suffix;
    ASSERT_TRUE(run(repository.replace(makeSession(nextName).value(),
        ses::SessionId{currentName},ses::TokenDigest{openproof::security::sha256(currentName).value()},
        kNow+1s,Fence{idp::ExternalSubject{destination},kNow+1s})));
    EXPECT_EQ(scalar("SELECT state FROM openproof.sessions WHERE id=$1",{currentName}),"1");
    EXPECT_EQ(scalar("SELECT state FROM openproof.sessions WHERE id=$1",{nextName}),"0");
}

TEST(PostgresCanonicalCoroutineTest, ReapOnlyExpiredUntouchedNativeSignupOwners)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN.";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    asio::io_context io;
    pg::CoroutineVerificationChallengeStore store{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    const auto make=[&](std::string owner,std::string tenant,std::string status,std::string expiry) {
        const std::string email=owner+"@example.test";
        static_cast<void>(execute(fixture.get(),
            "INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) "
            "VALUES($1,$2,0,$3,1770000000000)",{owner,tenant,status}));
        static_cast<void>(execute(fixture.get(),
            "INSERT INTO openproof.identity_profiles(identity_id,email,email_verified,created_at_ms,updated_at_ms) "
            "VALUES($1,$2,false,1770000000000,1770000000000)",{owner,email}));
        static_cast<void>(execute(fixture.get(),
            "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
            "VALUES($1,'fixture-hash',1770000000000)",{owner}));
        static_cast<void>(execute(fixture.get(),
            "INSERT INTO openproof.pending_external_identity_reservations(provider,external_subject,identity_id,expires_at_ms) "
            "VALUES('local',$2,$1,$3)",{owner,email,expiry}));
    };
    const auto nativeId=[&](char suffix) {
        std::string id=seed.suffix;
        id.resize(31U,'x');
        return "opi_signup_"+id+suffix;
    };
    const auto expired="1770086400000",live="1770300000000";
    const auto ordinary="opi_legacy-"+seed.suffix;
    const auto foreign=nativeId('f'),active=nativeId('a'),unexpired=nativeId('u'),
        changed=nativeId('c'),linked=nativeId('l'),member=nativeId('m'),audited=nativeId('e');
    ASSERT_NO_THROW(make(ordinary,seed.org,"3",expired));
    ASSERT_NO_THROW(make(foreign,seed.foreignOrg,"3",expired));
    ASSERT_NO_THROW(make(active,seed.org,"0",expired));
    ASSERT_NO_THROW(make(unexpired,seed.org,"3",live));
    ASSERT_NO_THROW(make(changed,seed.org,"3",expired));
    ASSERT_NO_THROW(make(linked,seed.org,"3",expired));
    ASSERT_NO_THROW(make(member,seed.org,"3",expired));
    ASSERT_NO_THROW(make(audited,seed.org,"3",expired));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "UPDATE openproof.identity_profiles SET updated_at_ms=1770000000001 WHERE identity_id=$1",{changed})));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms)"
        " VALUES('fixture',$1,$1,1770000000000)",{linked})));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.memberships(organization_id,identity_id,state,invited_at_ms)"
        " VALUES($1,$2,0,1770000000000)",{seed.org,member})));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.audit_events(event_id,occurred_at_ms,correlation_id,identity_id,category,action,outcome,event_hash)"
        " VALUES($1,1770000000000,$1,$2,'fixture','fixture','fixture',decode(repeat('00',32),'hex'))",
        {"event-"+seed.suffix,audited})));
    for (char suffix='0';suffix<='8';++suffix)
        ASSERT_NO_THROW(make(nativeId(suffix),seed.org,"3",expired));
    const auto run=[&](fnd::Instant now){
        io.restart();
        auto done=asio::co_spawn(io,store.reapExpiredSignupsAsync(now),asio::use_future);
        io.run();
        return done.get();
    };
    const auto early=run(kNow+47h);
    ASSERT_TRUE(early);
    EXPECT_EQ(early.value(),0U);
    const auto first=run(kNow+48h);
    ASSERT_TRUE(first);
    EXPECT_EQ(first.value(),8U);
    const auto second=run(kNow+48h);
    ASSERT_TRUE(second);
    EXPECT_EQ(second.value(),1U);
    const auto none=run(kNow+48h);
    ASSERT_TRUE(none);
    EXPECT_EQ(none.value(),0U);
    for (const auto& owner:{ordinary,foreign,active,unexpired,changed,linked,member,audited}) {
        auto result=execute(fixture.get(),"SELECT count(*) FROM openproof.identities WHERE id=$1",{owner});
        EXPECT_STREQ(PQgetvalue(result.get(),0,0),"1");
    }
    for (char suffix='0';suffix<='8';++suffix) {
        auto result=execute(fixture.get(),
            "SELECT (SELECT count(*) FROM openproof.identities WHERE id=$1)"
            "+(SELECT count(*) FROM openproof.identity_profiles WHERE identity_id=$1)"
            "+(SELECT count(*) FROM openproof.password_credentials WHERE identity_id=$1)"
            "+(SELECT count(*) FROM openproof.pending_external_identity_reservations WHERE identity_id=$1)",
            {nativeId(suffix)});
        EXPECT_STREQ(PQgetvalue(result.get(),0,0),"0");
    }
}

TEST(PostgresCanonicalCoroutineTest, EmailChangePreservesOwnerAndExistingPasswordAndSupportsFirstEnrollment)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN.";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace acc=openproof::account;
    namespace cred=openproof::credentials;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    asio::io_context io;
    pg::CoroutineVerificationChallengeStore store{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    const idp::ProviderId provider{"email-change-"+seed.suffix};
    auto key=acc::VerificationKey::create(fnd::SecretString{std::string(32U,'v')});
    ASSERT_TRUE(key);
    auto policy=cred::PasswordPolicy::create(1024U,8U,1U,16U,32U,2U*1024U*1024U);
    ASSERT_TRUE(policy);
    auto hasher=cred::PasswordHasher::create(fnd::SecretString{std::string(32U,'p')},policy.value());
    ASSERT_TRUE(hasher);
    auto initial=hasher->hash(fnd::SecretString{"original-password"});
    auto replacement=hasher->hash(fnd::SecretString{"replacement-password"});
    ASSERT_TRUE(initial && replacement);
    auto run=[&](asio::awaitable<fnd::Status> task) {
        io.restart();
        auto done=asio::co_spawn(io,std::move(task),asio::use_future);
        io.run();
        return done.get();
    };
    auto query=[&](std::string_view sql,std::initializer_list<std::string> params){
        return execute(fixture.get(),sql,params);
    };
    auto scalar=[&](std::string_view sql,std::initializer_list<std::string> params){
        auto result=query(sql,params);
        return std::string{PQgetvalue(result.get(),0,0)};
    };
    const auto prepare=[&](std::string email){
        return acc::VerificationPreparation::prepare(key.value(),ids::IdentityId{seed.owner},
            acc::VerificationPurpose::ChangeEmail,acc::VerificationChannel::Email,std::move(email),kNow,10min);
    };
    auto profileOnly=prepare("profile-"+seed.suffix+"@example.test");
    ASSERT_TRUE(profileOnly);
    ASSERT_TRUE(run(store.reserveAndReplaceAsync(profileOnly->first,provider)));
    ASSERT_TRUE(run(store.changeEmailAsync(provider,ids::IdentityId{seed.owner},profileOnly->first.id(),
        profileOnly->first.digest(),std::nullopt,kNow,3U)));
    EXPECT_EQ(scalar("SELECT count(*) FROM openproof.password_credentials WHERE identity_id=$1",{seed.owner}),"0");
    EXPECT_EQ(scalar("SELECT count(*) FROM openproof.external_identities WHERE provider=$1",{std::string{provider.value()}}),"0");
    const std::string firstEmail="first-"+seed.suffix+"@example.test";
    auto enroll=prepare(firstEmail);
    ASSERT_TRUE(enroll);
    ASSERT_TRUE(run(store.reserveAndReplaceAsync(enroll->first,provider)));
    ASSERT_TRUE(run(store.changeEmailAsync(provider,ids::IdentityId{seed.owner},enroll->first.id(),
        enroll->first.digest(),initial.value(),kNow,3U)));
    const std::string nextEmail="next-"+seed.suffix+"@example.test";
    auto rebind=prepare(nextEmail);
    ASSERT_TRUE(rebind);
    ASSERT_TRUE(run(store.reserveAndReplaceAsync(rebind->first,provider)));
    auto complete=[&] {
        return store.changeEmailAsync(provider,ids::IdentityId{seed.owner},rebind->first.id(),
            rebind->first.digest(),replacement.value(),kNow,3U);
    };
    ASSERT_NO_THROW(static_cast<void>(query("ALTER TABLE openproof.identity_profiles ADD CONSTRAINT native_email_fixture_rollback "
        "CHECK(NOT email_verified) NOT VALID",{})));
    EXPECT_FALSE(run(complete()));
    ASSERT_NO_THROW(static_cast<void>(query("ALTER TABLE openproof.identity_profiles DROP CONSTRAINT native_email_fixture_rollback",{})));
    EXPECT_EQ(scalar("SELECT external_subject FROM openproof.external_identities WHERE provider=$1",{std::string{provider.value()}}),firstEmail);
    EXPECT_EQ(scalar("SELECT changed_at_ms FROM openproof.password_credentials WHERE identity_id=$1",{seed.owner}),"1770000000000");
    io.restart();
    auto first=asio::co_spawn(io,complete(),asio::use_future);
    auto second=asio::co_spawn(io,complete(),asio::use_future);
    io.run();
    const auto a=first.get(),b=second.get();
    ASSERT_NE(a.has_value(),b.has_value());
    EXPECT_EQ(scalar("SELECT external_subject FROM openproof.external_identities WHERE provider=$1",{std::string{provider.value()}}),nextEmail);
    EXPECT_EQ(scalar("SELECT password_hash FROM openproof.password_credentials WHERE identity_id=$1",{seed.owner}),std::string{initial->encoded()});
    EXPECT_EQ(scalar("SELECT changed_at_ms FROM openproof.password_credentials WHERE identity_id=$1",{seed.owner}),"1770000000001");
    EXPECT_EQ(scalar("SELECT email||':'||email_verified::text FROM openproof.identity_profiles WHERE identity_id=$1",{seed.owner}),nextEmail+":true");
    EXPECT_EQ(scalar("SELECT display_name FROM openproof.identity_profiles WHERE identity_id=$1",{seed.owner}),"User-chosen name");
    EXPECT_FALSE(run(complete()));
}

TEST(PostgresCanonicalCoroutineTest, PhoneProofCommitsOwnerLinkProfileAndReservationTogether)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN.";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace acc=openproof::account;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    asio::io_context io;
    pg::CoroutineVerificationChallengeStore store{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,500ms,1000ms,3000ms};
    pg::CoroutineVerificationChallengeStore foreign{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.foreignOrg},1U,500ms,1000ms,3000ms};
    const idp::ProviderId provider{"phone-"+seed.suffix};
    const std::string number="+12025550123";
    const auto key=acc::VerificationKey::create(fnd::SecretString{std::string(32U,'v')});
    ASSERT_TRUE(key);
    auto proof=acc::VerificationPreparation::prepare(key.value(),ids::IdentityId{seed.owner},
        acc::VerificationPurpose::VerifyPhone,acc::VerificationChannel::Sms,number,kNow,10min);
    ASSERT_TRUE(proof);
    const auto generation=proof->first.id();
    const auto digest=proof->first.digest();
    const std::string generationName{generation.value()};
    auto run=[&](asio::awaitable<fnd::Status> task) {
        io.restart();
        auto done=asio::co_spawn(io,std::move(task),asio::use_future);
        io.run();
        return done.get();
    };
    auto query=[&](std::string_view sql,std::initializer_list<std::string> params){
        return execute(fixture.get(),sql,params);
    };
    auto scalar=[&](std::string_view sql,std::initializer_list<std::string> params){
        auto result=query(sql,params);
        return std::string{PQgetvalue(result.get(),0,0)};
    };
    ASSERT_TRUE(run(store.reserveAndReplaceAsync(proof->first,provider)));
    EXPECT_FALSE(run(foreign.verifyPhoneAsync(provider,ids::IdentityId{seed.owner},generation,digest,kNow,3U)));
    EXPECT_FALSE(run(store.verifyPhoneAsync(provider,ids::IdentityId{seed.secondOwner},generation,digest,kNow,3U)));
    EXPECT_EQ(scalar("SELECT attempts FROM openproof.account_verification_challenges WHERE id=$1",{generationName}),"0");
    EXPECT_FALSE(run(store.verifyPhoneAsync(provider,ids::IdentityId{seed.owner},generation,
        acc::VerificationDigest{std::array<std::byte,32>{}},kNow,3U)));
    EXPECT_EQ(scalar("SELECT attempts FROM openproof.account_verification_challenges WHERE id=$1",{generationName}),"1");
    const auto verify=[&](){
        return store.verifyPhoneAsync(provider,ids::IdentityId{seed.owner},generation,digest,kNow,3U);
    };
    ASSERT_NO_THROW(static_cast<void>(query(
        "ALTER TABLE openproof.identity_profiles ADD CONSTRAINT native_phone_fixture_rollback "
        "CHECK(NOT phone_number_verified) NOT VALID",{})));
    EXPECT_FALSE(run(verify()));
    ASSERT_NO_THROW(static_cast<void>(query(
        "ALTER TABLE openproof.identity_profiles DROP CONSTRAINT native_phone_fixture_rollback",{})));
    EXPECT_EQ(scalar("SELECT count(*) FROM openproof.external_identities WHERE provider=$1",
        {std::string{provider.value()}}),"0");
    EXPECT_EQ(scalar("SELECT count(*) FROM openproof.account_verification_challenges WHERE id=$1",{generationName}),"1");
    io.restart();
    auto first=asio::co_spawn(io,verify(),asio::use_future);
    auto second=asio::co_spawn(io,verify(),asio::use_future);
    io.run();
    const auto a=first.get(),b=second.get();
    ASSERT_NE(a.has_value(),b.has_value());
    EXPECT_EQ(scalar("SELECT identity_id FROM openproof.external_identities WHERE provider=$1 AND external_subject=$2",
        {std::string{provider.value()},number}),seed.owner);
    EXPECT_EQ(scalar("SELECT phone_number||':'||phone_number_verified::text FROM openproof.identity_profiles WHERE identity_id=$1",
        {seed.owner}),number+":true");
    EXPECT_EQ(scalar("SELECT count(*) FROM openproof.account_verification_challenges WHERE id=$1",{generationName}),"0");
    EXPECT_EQ(scalar("SELECT count(*) FROM openproof.pending_external_identity_reservations WHERE verification_id=$1",{generationName}),"0");
    EXPECT_FALSE(run(verify()));
}

TEST(PostgresCanonicalCoroutineTest, VerificationReplacementAndCompensationPreserveLatestOwnerChallenge)
{
    const auto dsn = disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK") != nullptr)
            FAIL() << "Explicitly requested disposable database has an invalid socket DSN.";
        GTEST_SKIP() << "Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace acc = openproof::account;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get()) == CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    asio::io_context io;
    pg::CoroutineVerificationChallengeStore store{io.get_executor(),
        fnd::SecretString{*dsn}, ids::OrganizationId{seed.org}, 2U, 500ms, 1000ms, 3000ms};
    pg::CoroutineVerificationChallengeStore foreign{io.get_executor(),
        fnd::SecretString{*dsn}, ids::OrganizationId{seed.foreignOrg}, 1U, 500ms, 1000ms, 3000ms};
    pg::CoroutineVerificationChallengeStore peer{io.get_executor(),
        fnd::SecretString{*dsn}, ids::OrganizationId{seed.org}, 1U, 500ms, 1000ms, 3000ms};
    const idp::ProviderId localProvider{"fixture-local-" + seed.suffix};
    const auto scalar=[&](std::string_view sql,std::initializer_list<std::string> args){
        auto result=execute(fixture.get(),sql,args);
        if (PQntuples(result.get())!=1 || PQnfields(result.get())!=1 || PQgetisnull(result.get(),0,0))
            throw std::runtime_error{"Invalid verification fixture scalar"};
        return std::string{PQgetvalue(result.get(),0,0)};
    };
    const auto purpose = acc::VerificationPurpose::ChangeEmail;
    std::array<std::byte, 32> digest{};
    digest[0] = std::byte{42};
    auto challenge = [&](const std::string& id, const std::string& owner,
                         acc::VerificationPurpose p = acc::VerificationPurpose::ChangeEmail) {
        return acc::VerificationChallenge::create(acc::VerificationId{id},
            ids::IdentityId{owner}, p, acc::VerificationChannel::Email,
            "contact@example.test", acc::VerificationDigest{digest}, kNow, 10min).value();
    };
    auto run = [&](asio::awaitable<fnd::Status> pending) {
        io.restart();
        auto complete = asio::co_spawn(io, std::move(pending), asio::use_future);
        io.run();
        return complete.get();
    };
    const auto first = "verification-first-" + seed.suffix;
    const auto second = "verification-second-" + seed.suffix;
    const auto third = "verification-third-" + seed.suffix;
    const auto last = "verification-last-" + seed.suffix;
    // Independent native issuers share the same owner/purpose lock.
    // Concurrent first issuance cannot leave two redeemable challenges.
    io.restart();
    auto peerWrite = asio::co_spawn(io,peer.replaceAsync(challenge(first,seed.owner)),asio::use_future);
    auto a = asio::co_spawn(io, store.replaceAsync(challenge(second, seed.owner)), asio::use_future);
    auto b = asio::co_spawn(io, store.replaceAsync(challenge(third, seed.owner)), asio::use_future);
    io.run();
    ASSERT_TRUE(peerWrite.get());
    ASSERT_TRUE(a.get());
    ASSERT_TRUE(b.get());
    auto count = execute(fixture.get(),
        "SELECT count(*) FROM openproof.account_verification_challenges WHERE identity_id=$1 AND purpose=1",
        {seed.owner});
    EXPECT_STREQ(PQgetvalue(count.get(), 0, 0), "1");

    ASSERT_TRUE(run(store.reserveAndReplaceAsync(challenge(last, seed.owner),localProvider)));
    for (const auto& previous : {first, second, third})
        EXPECT_TRUE(run(store.discardAsync(acc::VerificationId{previous},
            ids::IdentityId{seed.owner}, purpose)));
    EXPECT_TRUE(run(foreign.discardAsync(acc::VerificationId{last},
        ids::IdentityId{seed.owner}, purpose)));
    EXPECT_TRUE(run(store.discardAsync(acc::VerificationId{last},
        ids::IdentityId{seed.secondOwner}, purpose)));
    EXPECT_TRUE(run(store.discardAsync(acc::VerificationId{last},
        ids::IdentityId{seed.owner}, acc::VerificationPurpose::VerifyPhone)));
    auto denied = run(store.replaceAsync(challenge("foreign-" + seed.suffix, seed.foreignOwner)));
    EXPECT_TRUE(!denied && denied.error().code() == fnd::ErrorCode::PermissionDenied);
    auto locked = run(store.replaceAsync(challenge("locked-" + seed.suffix, seed.lockedOwner)));
    EXPECT_TRUE(!locked && locked.error().code() == fnd::ErrorCode::PermissionDenied);
    auto signup = run(store.replaceAsync(challenge("signup-" + seed.suffix,
        seed.owner, acc::VerificationPurpose::SignupEmail)));
    EXPECT_TRUE(!signup && signup.error().code() == fnd::ErrorCode::InvalidArgument);
    // Wrong-purpose, wrong-owner and foreign-tenant requests must not
    // consume or exhaust a valid native proof.
    const ids::IdentityId expectedOwner{seed.owner};
    for (int attempt=0;attempt<10;++attempt) {
        auto wrong=run(peer.verifyPhoneAsync(localProvider,expectedOwner,acc::VerificationId{last},
            acc::VerificationDigest{std::array<std::byte,32>{}},kNow,8U));
        EXPECT_TRUE(!wrong && wrong.error().code()==fnd::ErrorCode::AuthenticationFailed);
    }
    EXPECT_FALSE(run(peer.verifyPhoneAsync(localProvider,expectedOwner,acc::VerificationId{last},
        acc::VerificationDigest{digest},kNow,8U)));
    EXPECT_FALSE(run(peer.changeEmailAsync(localProvider,ids::IdentityId{seed.secondOwner},
        acc::VerificationId{last},acc::VerificationDigest{digest},std::nullopt,kNow,8U)));
    EXPECT_FALSE(run(foreign.changeEmailAsync(localProvider,expectedOwner,
        acc::VerificationId{last},acc::VerificationDigest{digest},std::nullopt,kNow,8U)));
    EXPECT_EQ(scalar("SELECT attempts::text FROM openproof.account_verification_challenges WHERE id=$1",{last}),"0");
    ASSERT_TRUE(run(peer.changeEmailAsync(localProvider,expectedOwner,acc::VerificationId{last},
        acc::VerificationDigest{digest},std::nullopt,kNow,8U)));
    EXPECT_EQ(scalar("SELECT email||':'||email_verified::text FROM openproof.identity_profiles WHERE identity_id=$1",{seed.owner}),
        "contact@example.test:true");
    EXPECT_FALSE(run(store.changeEmailAsync(localProvider,expectedOwner,acc::VerificationId{last},
        acc::VerificationDigest{digest},std::nullopt,kNow,8U)));
    const auto failed = "verification-failed-" + seed.suffix;
    ASSERT_TRUE(run(store.replaceAsync(challenge(failed, seed.owner))));
    ASSERT_TRUE(run(store.discardAsync(acc::VerificationId{failed},
        ids::IdentityId{seed.owner}, purpose)));
    EXPECT_FALSE(run(peer.changeEmailAsync(localProvider,expectedOwner,acc::VerificationId{failed},
        acc::VerificationDigest{digest},std::nullopt,kNow,8U)));
    EXPECT_TRUE(run(store.discardAsync(acc::VerificationId{failed},
        ids::IdentityId{seed.owner}, purpose)));

    const auto reservedId = "reserved-" + seed.suffix;
    ASSERT_TRUE(run(store.reserveAndReplaceAsync(challenge(reservedId, seed.owner), localProvider)));
    auto reservation = execute(fixture.get(),
        "SELECT identity_id FROM openproof.pending_external_identity_reservations "
        "WHERE provider=$1 AND external_subject='contact@example.test'", {std::string{localProvider.value()}});
    ASSERT_EQ(PQntuples(reservation.get()), 1);
    EXPECT_EQ(std::string{PQgetvalue(reservation.get(), 0, 0)}, seed.owner);
    auto noProfile = run(store.reserveAndReplaceAsync(
        challenge("no-profile-" + seed.suffix, seed.secondOwner), localProvider));
    EXPECT_TRUE(!noProfile && noProfile.error().code() == fnd::ErrorCode::NotFound);
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.identity_profiles(identity_id,created_at_ms,updated_at_ms) VALUES($1,$2,$2)",
        {seed.secondOwner, "1770000000000"})));
    auto contested = run(store.reserveAndReplaceAsync(
        challenge("contested-" + seed.suffix, seed.secondOwner), localProvider));
    EXPECT_TRUE(!contested && contested.error().code() == fnd::ErrorCode::AlreadyExists);
    auto deniedCount = execute(fixture.get(),
        "SELECT count(*) FROM openproof.account_verification_challenges WHERE identity_id=$1",
        {seed.secondOwner});
    EXPECT_STREQ(PQgetvalue(deniedCount.get(), 0, 0), "0");
    // Failed challenge insertion must not commit its alias reservation.
    const idp::ProviderId rollbackProvider{"rollback-local-" + seed.suffix};
    auto collision = run(store.reserveAndReplaceAsync(
        challenge(reservedId, seed.secondOwner), rollbackProvider));
    EXPECT_TRUE(!collision && collision.error().code() == fnd::ErrorCode::Conflict);
    auto rolledBack = execute(fixture.get(),
        "SELECT count(*) FROM openproof.pending_external_identity_reservations WHERE provider=$1",
        {std::string{rollbackProvider.value()}});
    EXPECT_STREQ(PQgetvalue(rolledBack.get(), 0, 0), "0");
    // Force an insert failure after reservation to test actual rollback.
    const auto impossibleId = "rejected-insert-" + seed.suffix;
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "ALTER TABLE openproof.account_verification_challenges ADD CONSTRAINT fixture_reject_insert "
        "CHECK (id NOT LIKE 'rejected-insert-%') NOT VALID", {})));
    auto rejectedInsert = run(store.reserveAndReplaceAsync(
        challenge(impossibleId, seed.secondOwner), rollbackProvider));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "ALTER TABLE openproof.account_verification_challenges DROP CONSTRAINT fixture_reject_insert", {})));
    EXPECT_TRUE(!rejectedInsert && rejectedInsert.error().code() == fnd::ErrorCode::Unavailable);
    auto afterInsertFailure = execute(fixture.get(),
        "SELECT count(*) FROM openproof.pending_external_identity_reservations WHERE provider=$1",
        {std::string{rollbackProvider.value()}});
    EXPECT_STREQ(PQgetvalue(afterInsertFailure.get(), 0, 0), "0");
    const ids::IdentityId ownerId{seed.owner};
    const std::string providerName{localProvider.value()};
    const auto generation=[&](){
        return scalar("SELECT COALESCE((SELECT verification_id FROM openproof.pending_external_identity_reservations "
            "WHERE provider=$1 AND external_subject='contact@example.test' AND identity_id=$2),'none')",
            {providerName,seed.owner});
    };
    const auto reservationCount=[&](){
        return scalar("SELECT count(*)::text FROM openproof.pending_external_identity_reservations "
            "WHERE provider=$1 AND external_subject='contact@example.test'",{providerName});
    };
    EXPECT_EQ(generation(),reservedId);
    const auto renewedId="renewed-"+seed.suffix;
    ASSERT_TRUE(run(peer.reserveAndReplaceAsync(challenge(renewedId,seed.owner),localProvider)));
    ASSERT_TRUE(run(store.discardAsync(acc::VerificationId{reservedId},ownerId,purpose)));
    EXPECT_EQ(generation(),renewedId);
    EXPECT_FALSE(run(peer.changeEmailAsync(localProvider,ownerId,acc::VerificationId{reservedId},
        acc::VerificationDigest{digest},std::nullopt,kNow,8U)));
    EXPECT_EQ(generation(),renewedId);
    ASSERT_TRUE(run(store.discardAsync(acc::VerificationId{renewedId},ownerId,purpose)));
    EXPECT_FALSE(run(peer.changeEmailAsync(localProvider,ownerId,acc::VerificationId{renewedId},
        acc::VerificationDigest{digest},std::nullopt,kNow,8U)));
    EXPECT_EQ(reservationCount(),"0");

    // Native completion is atomic: no intermediate consumed-but-reserved
    // state is published. Late delivery compensation cannot undo the profile.
    const auto completingId="completing-"+seed.suffix;
    ASSERT_TRUE(run(store.reserveAndReplaceAsync(challenge(completingId,seed.owner),localProvider)));
    ASSERT_TRUE(run(peer.changeEmailAsync(localProvider,ownerId,acc::VerificationId{completingId},
        acc::VerificationDigest{digest},std::nullopt,kNow,8U)));
    ASSERT_TRUE(run(store.discardAsync(acc::VerificationId{completingId},ownerId,purpose)));
    EXPECT_EQ(reservationCount(),"0");
    EXPECT_EQ(scalar("SELECT email||':'||email_verified::text FROM openproof.identity_profiles WHERE identity_id=$1",
        {seed.owner}),"contact@example.test:true");
    EXPECT_FALSE(run(peer.changeEmailAsync(localProvider,ownerId,acc::VerificationId{completingId},
        acc::VerificationDigest{digest},std::nullopt,kNow,8U)));

    // Historical interrupted completion: a tagged reservation without its
    // challenge is never accepted as proof; stale compensation is harmless.
    const auto orphanId="orphan-"+seed.suffix;
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.pending_external_identity_reservations(provider,external_subject,identity_id,expires_at_ms,verification_id)"
        " VALUES($1,'contact@example.test',$2,1770000600000,$3)",{providerName,seed.owner,orphanId})));
    EXPECT_FALSE(run(peer.changeEmailAsync(localProvider,ownerId,acc::VerificationId{orphanId},
        acc::VerificationDigest{digest},std::nullopt,kNow,8U)));
    ASSERT_TRUE(run(store.discardAsync(acc::VerificationId{orphanId},ownerId,purpose)));
    EXPECT_EQ(generation(),orphanId);
    const auto supersededId="superseded-"+seed.suffix;
    ASSERT_TRUE(run(store.reserveAndReplaceAsync(challenge(supersededId,seed.owner),localProvider)));
    ASSERT_TRUE(run(peer.replaceAsync(challenge("peer-replacement-"+seed.suffix,seed.owner))));
    EXPECT_EQ(reservationCount(),"0");

    // A historical untagged signup reservation cannot be taken over by a
    // contact-change ceremony, even by its own owner.
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.pending_external_identity_reservations(provider,external_subject,identity_id,expires_at_ms)"
        " VALUES($1,'contact@example.test',$2,1770000600000)",{providerName,seed.owner})));
    auto untagged=run(peer.reserveAndReplaceAsync(challenge("untagged-"+seed.suffix,seed.owner),localProvider));
    EXPECT_TRUE(!untagged && untagged.error().code()==fnd::ErrorCode::AlreadyExists);
    EXPECT_EQ(reservationCount(),"1");
    EXPECT_EQ(scalar("SELECT count(*)::text FROM openproof.pending_external_identity_reservations "
        "WHERE provider=$1 AND verification_id IS NULL",{providerName}),"1");
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "DELETE FROM openproof.pending_external_identity_reservations WHERE provider=$1 AND verification_id IS NULL",
        {providerName})));
}

TEST(PostgresCanonicalCoroutineTest, NativeLocalCredentialsRejectStaleProofsAndTotpReplay)
{
    const auto dsn = disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK") != nullptr)
            FAIL() << "Explicitly requested disposable database has an invalid socket DSN.";
        GTEST_SKIP() << "Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get()) == CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    // These are opaque test markers, not actual password hashes or TOTP keys.
    // The storage adapter must not perform cryptographic verification.
    for (const auto& owner : {seed.owner, seed.foreignOwner, seed.lockedOwner, seed.suspendedOwner}) {
        ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
            "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
            "VALUES($1,'fixture-hash',1770000000000)", {owner})));
    }
    asio::io_context io;
    const idp::ProviderId provider{"native-canonical-provider"};
    pg::CoroutineLocalCredentialStore store{io.get_executor(), fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org}, provider, 2U, 500ms, 1000ms, 3000ms};
    pg::CoroutineLocalCredentialStore foreign{io.get_executor(), fnd::SecretString{*dsn},
        ids::OrganizationId{seed.foreignOrg}, provider, 1U, 500ms, 1000ms, 3000ms};
    pg::CoroutineLocalCredentialStore suspended{io.get_executor(), fnd::SecretString{*dsn},
        ids::OrganizationId{seed.suspendedOrg}, provider, 1U, 500ms, 1000ms, 3000ms};
    auto run = [&]<typename T>(asio::awaitable<T> pending) {
        io.restart();
        auto complete = asio::co_spawn(io, std::move(pending), asio::use_future);
        io.run();
        return complete.get();
    };
    const idp::ExternalSubject subject{seed.subject};
    auto initial = run(store.readAsync(subject));
    ASSERT_TRUE(initial && initial->has_value());
    EXPECT_EQ(initial->value().owner, ids::IdentityId{seed.owner});
    EXPECT_EQ(initial->value().passwordHash, "fixture-hash");
    EXPECT_FALSE(initial->value().encryptedTotpHex);
    EXPECT_TRUE(run(store.confirmPasswordOnlyAsync(subject, initial->value())));
    EXPECT_FALSE(run(foreign.confirmPasswordOnlyAsync(subject, initial->value())));
    for (const auto& missing : {seed.foreignSubject, seed.lockedSubject, seed.unlinkedSubject}) {
        auto result = run(store.readAsync(idp::ExternalSubject{missing}));
        ASSERT_TRUE(result);
        EXPECT_FALSE(result->has_value());
    }
    auto disabled = run(suspended.readAsync(idp::ExternalSubject{seed.suspendedSubject}));
    ASSERT_TRUE(disabled);
    EXPECT_FALSE(disabled->has_value());

    // Password generation changes invalidate an in-flight verification.
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "UPDATE openproof.password_credentials SET password_hash='replacement-hash',"
        "changed_at_ms=1770000000001 WHERE identity_id=$1", {seed.owner})));
    EXPECT_FALSE(run(store.confirmPasswordOnlyAsync(subject, initial->value())));
    auto current = run(store.readAsync(subject));
    ASSERT_TRUE(current && current->has_value());
    EXPECT_TRUE(run(store.confirmPasswordOnlyAsync(subject, current->value())));

    // An MFA enrollment between reading and confirming a password must
    // not result in a password-only success.
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.totp_credentials(identity_id,encrypted_seed,key_version,enrolled_at_ms) "
        "VALUES($1,decode('010203','hex'),1,1770000000002)", {seed.owner})));
    EXPECT_FALSE(run(store.confirmPasswordOnlyAsync(subject, current->value())));
    auto mfa = run(store.readAsync(subject));
    ASSERT_TRUE(mfa && mfa->has_value());
    ASSERT_TRUE(mfa->value().encryptedTotpHex);
    EXPECT_EQ(*mfa->value().encryptedTotpHex, "010203");
    EXPECT_FALSE(run(store.confirmPasswordOnlyAsync(subject, mfa->value())));
    EXPECT_FALSE(run(foreign.consumeTotpAsync(subject, mfa->value(), 100U)));

    // Two independent native SQL leases race for the same verified step.
    io.restart();
    auto first = asio::co_spawn(io, store.consumeTotpAsync(subject, mfa->value(), 100U), asio::use_future);
    auto second = asio::co_spawn(io, store.consumeTotpAsync(subject, mfa->value(), 100U), asio::use_future);
    io.run();
    const auto one = first.get();
    const auto two = second.get();
    EXPECT_NE(static_cast<bool>(one), static_cast<bool>(two));
    EXPECT_FALSE(run(store.consumeTotpAsync(subject, mfa->value(), 99U)));
    EXPECT_TRUE(run(store.consumeTotpAsync(subject, mfa->value(), 101U)));

    // Re-enrollment changes the exact credential generation, even if the
    // encrypted bytes are unchanged. A stale snapshot must not consume it.
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "UPDATE openproof.totp_credentials SET enrolled_at_ms=1770000000003,"
        "last_accepted_step=NULL WHERE identity_id=$1", {seed.owner})));
    EXPECT_FALSE(run(store.consumeTotpAsync(subject, mfa->value(), 102U)));
    auto renewed = run(store.readAsync(subject));
    ASSERT_TRUE(renewed && renewed->has_value());
    EXPECT_TRUE(run(store.consumeTotpAsync(subject, renewed->value(), 102U)));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "UPDATE openproof.identities SET status=2 WHERE id=$1", {seed.owner})));
    EXPECT_FALSE(run(store.consumeTotpAsync(subject, renewed->value(), 103U)));
    auto locked = run(store.readAsync(subject));
    ASSERT_TRUE(locked);
    EXPECT_FALSE(locked->has_value());
}

TEST(PostgresCanonicalCoroutineTest, NativeTotpCeremonyVerifiesActualSeedAndBurnsEnrollment)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN.";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace cred=openproof::credentials;
    namespace sec=openproof::security;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    auto policy=cred::PasswordPolicy::create(1024U,8U,1U,16U,32U,2U*1024U*1024U);
    ASSERT_TRUE(policy);
    auto maker=cred::PasswordHasher::create(fnd::SecretString{std::string(32U,'p')},policy.value());
    auto worker=cred::PasswordHasher::create(fnd::SecretString{std::string(32U,'p')},policy.value());
    ASSERT_TRUE(maker && worker);
    auto hash=maker->hash(fnd::SecretString{"fixture-password"});
    ASSERT_TRUE(hash);
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms)"
        " VALUES($1,$2,1770000000000)",{seed.owner,std::string{hash->encoded()}})));
    auto passwords=cred::BoundedPasswordExecutor::create(std::move(worker).value(),1U);
    auto key=sec::AeadKey::create(fnd::SecretString{std::string(32U,'k')});
    auto readerKey=sec::AeadKey::create(fnd::SecretString{std::string(32U,'k')});
    ASSERT_TRUE(passwords && key && readerKey);
    asio::io_context io;
    fnd::ManualClockSource clock{kNow};
    pg::CoroutineLocalCredentialStore store{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},idp::ProviderId{"native-canonical-provider"},2U,500ms,1000ms,3000ms};
    pg::CoroutineTotpEnrollment ceremony{store,*passwords.value(),std::move(key).value(),1U,clock};
    auto run=[&]<typename T>(asio::awaitable<T> pending){
        io.restart();
        std::optional<T> output;
        auto capture=[](asio::awaitable<T> task,std::optional<T>& target)->asio::awaitable<void>{
            target.emplace(co_await std::move(task));
        };
        auto done=asio::co_spawn(io,capture(std::move(pending),output),asio::use_future);
        io.run();
        done.get();
        return std::move(output.value());
    };
    const ids::IdentityId owner{seed.owner};
    constexpr auto ial1=idp::AssuranceLevel::Ial1,ial2=idp::AssuranceLevel::Ial2;
    auto begin=[&](idp::AssuranceLevel assurance=idp::AssuranceLevel::Ial1){
        return run(ceremony.beginAsync(owner,fnd::SecretString{"fixture-password"},assurance));
    };
    // Decode the actual enrollment response, as an authenticator would.
    // The raw seed is neither fixed nor logged by the test.
    auto codeAt=[](const pg::CoroutineTotpEnrollment::Start& started,fnd::Instant instant)->fnd::Result<std::string>{
        constexpr std::string_view alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::string bytes;
        std::uint32_t bits=0U,accumulator=0U;
        for (const char ch:std::get<1>(started).expose()) {
            const auto index=alphabet.find(ch);
            if (index==std::string_view::npos) return fnd::fail(fnd::ErrorCode::InvalidArgument);
            accumulator=(accumulator<<5U)|static_cast<std::uint32_t>(index);
            bits+=5U;
            if (bits>=8U) {
                bits-=8U;
                bytes.push_back(static_cast<char>((accumulator>>bits)&0xffU));
            }
        }
        auto secret=cred::TotpSecret::create(fnd::SecretString{std::move(bytes)});
        if (!secret) return fnd::fail(secret.error());
        return cred::totpAt(secret.value(),cred::TotpPolicy::recommended(),instant);
    };
    auto codeFor=[&](const pg::CoroutineTotpEnrollment::Start& started){return codeAt(started,clock.now());};
    EXPECT_FALSE(run(ceremony.beginAsync(owner,fnd::SecretString{"wrong-password"},ial1)));
    EXPECT_FALSE(run(ceremony.beginAsync(ids::IdentityId{seed.foreignOwner},fnd::SecretString{"fixture-password"},ial1)));
    auto expired=begin();
    ASSERT_TRUE(expired);
    clock.advance(10min);
    auto expiredCode=codeFor(expired.value());
    ASSERT_TRUE(expiredCode);
    EXPECT_FALSE(run(ceremony.completeAsync(owner,std::get<0>(*expired),fnd::SecretString{expiredCode.value()},ial1)));
    auto exhausted=begin();
    ASSERT_TRUE(exhausted);
    auto correct=codeFor(exhausted.value());
    ASSERT_TRUE(correct);
    auto earlier=codeAt(exhausted.value(),clock.now()-30s);
    auto later=codeAt(exhausted.value(),clock.now()+30s);
    ASSERT_TRUE(earlier && later);
    std::string incorrect="000000";
    for (char digit='0';digit<='3';++digit) {
        incorrect.front()=digit;
        if (incorrect!=correct.value() && incorrect!=earlier.value() && incorrect!=later.value()) break;
    }
    for (unsigned int attempt=0;attempt<5U;++attempt) {
        EXPECT_FALSE(run(ceremony.completeAsync(owner,std::get<0>(*exhausted),fnd::SecretString{incorrect},ial1)));
    }
    EXPECT_FALSE(run(ceremony.completeAsync(owner,std::get<0>(*exhausted),fnd::SecretString{correct.value()},ial1)));
    auto first=begin();
    ASSERT_TRUE(first);
    auto newest=begin();
    ASSERT_TRUE(newest);
    auto firstCode=codeFor(first.value());
    auto newestCode=codeFor(newest.value());
    ASSERT_TRUE(firstCode && newestCode);
    EXPECT_FALSE(run(ceremony.completeAsync(owner,std::get<0>(*first),fnd::SecretString{firstCode.value()},ial1)));
    EXPECT_FALSE(run(ceremony.completeAsync(ids::IdentityId{seed.secondOwner},std::get<0>(*newest),
        fnd::SecretString{newestCode.value()},ial1)));
    EXPECT_FALSE(std::get<3>(*newest));
    ASSERT_TRUE(run(ceremony.completeAsync(owner,std::get<0>(*newest),fnd::SecretString{newestCode.value()},ial1)));
    EXPECT_FALSE(run(ceremony.completeAsync(owner,std::get<0>(*newest),fnd::SecretString{newestCode.value()},ial1)));
    auto snapshot=run(store.readAsync(idp::ExternalSubject{seed.subject}));
    ASSERT_TRUE(snapshot && snapshot->has_value() && snapshot->value().encryptedTotpHex);
    auto ciphertext=fnd::fromHex(*snapshot->value().encryptedTotpHex);
    ASSERT_TRUE(ciphertext);
    auto decrypted=sec::openAes256Gcm(readerKey.value(),ciphertext.value(),"openproof/totp/v1:"+seed.owner);
    ASSERT_TRUE(decrypted);
    auto installed=cred::TotpSecret::create(std::move(decrypted).value());
    ASSERT_TRUE(installed);
    EXPECT_TRUE(installed->enrollmentBase32().expose()==std::get<1>(*newest).expose());
    EXPECT_FALSE(begin(ial1));
    EXPECT_FALSE(run(ceremony.disableAsync(owner,fnd::SecretString{"fixture-password"},ial1)));
    auto replacement=begin(ial2);
    ASSERT_TRUE(replacement);
    EXPECT_TRUE(std::get<3>(*replacement));
    auto replacementCode=codeFor(replacement.value());
    ASSERT_TRUE(replacementCode);
    EXPECT_FALSE(run(ceremony.completeAsync(owner,std::get<0>(*replacement),fnd::SecretString{replacementCode.value()},ial1)));
    ASSERT_TRUE(run(ceremony.completeAsync(owner,std::get<0>(*replacement),fnd::SecretString{replacementCode.value()},ial2)));
    ASSERT_TRUE(run(ceremony.disableAsync(owner,fnd::SecretString{"fixture-password"},ial2)));
    auto removed=run(store.readAsync(idp::ExternalSubject{seed.subject}));
    ASSERT_TRUE(removed && removed->has_value());
    EXPECT_FALSE(removed->value().encryptedTotpHex);
}

TEST(PostgresCanonicalCoroutineTest, RecoveryIssuanceFenceRejectsChangedFactorWithoutDeletingNewBatch)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN.";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace cred=openproof::credentials;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    auto query=[&](std::string_view sql,std::initializer_list<std::string> params){
        return execute(fixture.get(),sql,params);
    };
    ASSERT_NO_THROW(static_cast<void>(query(
        "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
        "VALUES($1,'fixture-hash',1770000000000)",{seed.owner})));
    ASSERT_NO_THROW(static_cast<void>(query(
        "INSERT INTO openproof.totp_credentials(identity_id,encrypted_seed,key_version,last_accepted_step,enrolled_at_ms) "
        "VALUES($1,decode('010203','hex'),1,100,1770000000000)",{seed.owner})));
    asio::io_context io;
    const idp::ProviderId provider{"native-canonical-provider"};
    const ids::IdentityId owner{seed.owner};
    pg::CoroutinePostgresRecoveryCodeRepository repo{io.get_executor(),fnd::SecretString{*dsn},
        2U,500ms,1000ms,3000ms,ids::OrganizationId{seed.org},provider};
    pg::CoroutinePostgresRecoveryCodeRepository foreign{io.get_executor(),fnd::SecretString{*dsn},
        1U,500ms,1000ms,3000ms,ids::OrganizationId{seed.foreignOrg},provider};
    pg::CoroutineLocalCredentialStore store{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},provider,2U,500ms,1000ms,3000ms};
    auto run=[&]<typename T>(asio::awaitable<T> pending){
        io.restart();
        std::optional<T> output;
        auto capture=[](asio::awaitable<T> task,std::optional<T>& target)->asio::awaitable<void>{
            target.emplace(co_await std::move(task));
        };
        auto done=asio::co_spawn(io,capture(std::move(pending),output),asio::use_future);
        io.run();
        done.get();
        return std::move(output.value());
    };
    EXPECT_FALSE(run(foreign.captureIssuanceAsync(owner)));
    auto stale=run(repo.captureIssuanceAsync(owner));
    ASSERT_TRUE(stale);
    const auto firstDigest=openproof::security::sha256("fixture-first").value();
    const auto nextDigest=openproof::security::sha256("fixture-next").value();
    const auto rejectedDigest=openproof::security::sha256("fixture-stale").value();
    EXPECT_FALSE(run(repo.replaceAsync(owner,{firstDigest})));
    ASSERT_TRUE(run(repo.replaceFencedAsync(owner,{firstDigest},stale.value())));
    const idp::ExternalSubject subject{seed.subject};
    auto before=run(store.readAsync(subject));
    ASSERT_TRUE(before && before->has_value());
    using Owner=pg::CoroutineLocalCredentialStore::OwnerCredential;
    using Enrollment=pg::CoroutineLocalCredentialStore::EncryptedTotpEnrollment;
    ASSERT_TRUE(run(store.changeTotpAsync(Owner{subject,before->value()},Enrollment{"040506",1U,101U},kNow)));
    auto current=run(repo.captureIssuanceAsync(owner));
    ASSERT_TRUE(current);
    EXPECT_NE(current->credentialGeneration,stale->credentialGeneration);
    ASSERT_TRUE(run(repo.replaceFencedAsync(owner,{nextDigest},current.value())));
    EXPECT_FALSE(run(repo.replaceFencedAsync(owner,{rejectedDigest},stale.value())));
    EXPECT_FALSE(run(foreign.replaceFencedAsync(owner,{rejectedDigest},current.value())));
    EXPECT_FALSE(run(repo.consumeAsync(owner,rejectedDigest)));
    EXPECT_FALSE(run(repo.consumeAsync(owner,firstDigest)));
    EXPECT_TRUE(run(repo.consumeAsync(owner,nextDigest)));
    auto after=run(store.readAsync(subject));
    ASSERT_TRUE(after && after->has_value());
    ASSERT_TRUE(run(store.changeTotpAsync(Owner{subject,after->value()},std::nullopt,kNow)));
    EXPECT_FALSE(run(repo.captureIssuanceAsync(owner)));
    EXPECT_FALSE(run(repo.replaceFencedAsync(owner,{rejectedDigest},current.value())));
}

TEST(PostgresCanonicalCoroutineTest, NativeMfaMutationFencesOldLoginAndRecoveryGenerations)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Explicit disposable database has invalid socket DSN.";
        GTEST_SKIP()<<"Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    auto query=[&](std::string_view sql,std::initializer_list<std::string> params){
        return execute(fixture.get(),sql,params);
    };
    auto scalar=[&](std::string_view sql,std::initializer_list<std::string> params){
        auto rows=query(sql,params);
        return std::string{PQgetvalue(rows.get(),0,0)};
    };
    ASSERT_NO_THROW(static_cast<void>(query(
        "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
        "VALUES($1,'fixture-hash',1770000000000)",{seed.owner})));
    asio::io_context io;
    const idp::ProviderId provider{"native-canonical-provider"};
    pg::CoroutineLocalCredentialStore store{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},provider,2U,500ms,1000ms,3000ms};
    pg::CoroutineLocalCredentialStore foreign{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.foreignOrg},provider,1U,500ms,1000ms,3000ms};
    auto run=[&]<typename T>(asio::awaitable<T> pending){
        io.restart();
        auto done=asio::co_spawn(io,std::move(pending),asio::use_future);
        io.run();
        return done.get();
    };
    const idp::ExternalSubject subject{seed.subject};
    auto initial=run(store.readAsync(subject));
    ASSERT_TRUE(initial && initial->has_value());
    using OwnerCredential=pg::CoroutineLocalCredentialStore::OwnerCredential;
    using Enrollment=pg::CoroutineLocalCredentialStore::EncryptedTotpEnrollment;
    const OwnerCredential captured{subject,initial->value()};
    EXPECT_FALSE(run(foreign.changeTotpAsync(captured,Enrollment{"010203",1U,100U},kNow)));
    EXPECT_FALSE(run(store.changeTotpAsync(captured,std::nullopt,kNow)));
    auto enroll=[&]{
        return store.changeTotpAsync(captured,Enrollment{"010203",1U,100U},kNow);
    };
    io.restart();
    auto first=asio::co_spawn(io,enroll(),asio::use_future);
    auto second=asio::co_spawn(io,enroll(),asio::use_future);
    io.run();
    const auto a=first.get(),b=second.get();
    ASSERT_NE(a.has_value(),b.has_value());
    EXPECT_FALSE(run(store.confirmPasswordOnlyAsync(subject,captured.second)));
    auto current=run(store.readAsync(subject));
    ASSERT_TRUE(current && current->has_value());
    EXPECT_EQ(current->value().passwordChangedAt,"1770000000001");
    EXPECT_EQ(current->value().lastAcceptedStep,std::optional<std::string>{"100"});
    EXPECT_FALSE(run(store.consumeTotpAsync(subject,current->value(),100U)));
    const OwnerCredential enrolled{subject,current->value()};
    ASSERT_NO_THROW(static_cast<void>(query(
        "INSERT INTO openproof.recovery_codes(identity_id,code_digest,issued_at_ms) "
        "VALUES($1,decode(repeat('11',32),'hex'),1770000000000)",{seed.owner})));
    // Force a failure at the final generation advance after the factor
    // and recovery mutations; the entire transaction must roll back.
    ASSERT_NO_THROW(static_cast<void>(query(
        "ALTER TABLE openproof.password_credentials ADD CONSTRAINT native_mfa_fixture_rollback "
        "CHECK(changed_at_ms<=1770000000001) NOT VALID",{})));
    EXPECT_FALSE(run(store.changeTotpAsync(enrolled,Enrollment{"040506",1U,101U},kNow)));
    ASSERT_NO_THROW(static_cast<void>(query(
        "ALTER TABLE openproof.password_credentials DROP CONSTRAINT native_mfa_fixture_rollback",{})));
    EXPECT_EQ(scalar("SELECT encode(encrypted_seed,'hex') FROM openproof.totp_credentials WHERE identity_id=$1",{seed.owner}),"010203");
    EXPECT_EQ(scalar("SELECT count(*) FROM openproof.recovery_codes WHERE identity_id=$1",{seed.owner}),"1");
    ASSERT_TRUE(run(store.changeTotpAsync(enrolled,Enrollment{"040506",1U,101U},kNow)));
    EXPECT_FALSE(run(store.changeTotpAsync(enrolled,std::nullopt,kNow)));
    EXPECT_FALSE(run(store.consumeTotpAsync(subject,enrolled.second,102U)));
    EXPECT_EQ(scalar("SELECT count(*) FROM openproof.recovery_codes WHERE identity_id=$1",{seed.owner}),"0");
    auto rotated=run(store.readAsync(subject));
    ASSERT_TRUE(rotated && rotated->has_value());
    EXPECT_EQ(rotated->value().passwordChangedAt,"1770000000002");
    EXPECT_EQ(rotated->value().totpEnrolledAt,std::optional<std::string>{"1770000000001"});
    ASSERT_TRUE(run(store.changeTotpAsync(OwnerCredential{subject,rotated->value()},std::nullopt,kNow)));
    auto removed=run(store.readAsync(subject));
    ASSERT_TRUE(removed && removed->has_value());
    EXPECT_FALSE(removed->value().encryptedTotpHex);
    EXPECT_EQ(removed->value().passwordHash,"fixture-hash");
    EXPECT_EQ(removed->value().passwordChangedAt,"1770000000003");
    EXPECT_FALSE(run(store.confirmPasswordOnlyAsync(subject,captured.second)));
    EXPECT_TRUE(run(store.confirmPasswordOnlyAsync(subject,removed->value())));
}

TEST(PostgresCanonicalCoroutineTest, NativeLocalRecoveryAndRehashRejectChangedCredentialGeneration)
{
    const auto dsn = disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK") != nullptr)
            FAIL() << "Explicitly requested disposable database has an invalid socket DSN.";
        GTEST_SKIP() << "Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace cred = openproof::credentials;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get()) == CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
        "VALUES($1,'fixture-hash',1770000000000)", {seed.owner})));
    cred::RecoveryCodeDigest digest{}, secondDigest{};
    digest[0] = std::byte{42};
    secondDigest[0] = std::byte{43};
    for (const auto& code : {digest, secondDigest}) {
        ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
            "INSERT INTO openproof.recovery_codes(identity_id,code_digest,issued_at_ms) "
            "VALUES($1,decode($2,'hex'),1770000000000)", {seed.owner, fnd::toHex(code)})));
    }

    asio::io_context io;
    const idp::ProviderId provider{"native-canonical-provider"};
    const idp::ExternalSubject subject{seed.subject};
    pg::CoroutineLocalCredentialStore store{io.get_executor(), fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org}, provider, 2U, 500ms, 1000ms, 3000ms};
    pg::CoroutineLocalCredentialStore foreign{io.get_executor(), fnd::SecretString{*dsn},
        ids::OrganizationId{seed.foreignOrg}, provider, 1U, 500ms, 1000ms, 3000ms};
    auto run = [&]<typename T>(asio::awaitable<T> pending) {
        io.restart();
        auto complete = asio::co_spawn(io, std::move(pending), asio::use_future);
        io.run();
        return complete.get();
    };
    auto remaining = [&] {
        auto count = execute(fixture.get(),
            "SELECT count(*)::text FROM openproof.recovery_codes WHERE identity_id=$1", {seed.owner});
        return std::string{PQgetvalue(count.get(), 0, 0)};
    };
    auto noMfa = run(store.readAsync(subject));
    ASSERT_TRUE(noMfa && noMfa->has_value());
    EXPECT_FALSE(run(store.consumeRecoveryAsync(subject, noMfa->value(), digest)));
    EXPECT_EQ(remaining(), "2");
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.totp_credentials(identity_id,encrypted_seed,key_version,enrolled_at_ms) "
        "VALUES($1,decode('010203','hex'),1,1770000000000)", {seed.owner})));
    auto initial = run(store.readAsync(subject));
    ASSERT_TRUE(initial && initial->has_value());
    EXPECT_FALSE(run(foreign.consumeRecoveryAsync(subject, initial->value(), digest)));
    EXPECT_FALSE(run(store.consumeRecoveryAsync(idp::ExternalSubject{seed.unlinkedSubject},
                                                initial->value(), digest)));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "UPDATE openproof.password_credentials SET changed_at_ms=1770000000001 WHERE identity_id=$1",
        {seed.owner})));
    EXPECT_FALSE(run(store.consumeRecoveryAsync(subject, initial->value(), digest)));
    auto verified = run(store.readAsync(subject));
    ASSERT_TRUE(verified && verified->has_value());
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "UPDATE openproof.totp_credentials SET enrolled_at_ms=1770000000001 WHERE identity_id=$1",
        {seed.owner})));
    EXPECT_FALSE(run(store.consumeRecoveryAsync(subject, verified->value(), digest)));
    EXPECT_EQ(remaining(), "2");
    auto current = run(store.readAsync(subject));
    ASSERT_TRUE(current && current->has_value());

    // Same digest concurrently redeemed on separate leases: exactly one
    // success, other codes unaffected.
    io.restart();
    auto first = asio::co_spawn(io, store.consumeRecoveryAsync(subject, current->value(), digest), asio::use_future);
    auto second = asio::co_spawn(io, store.consumeRecoveryAsync(subject, current->value(), digest), asio::use_future);
    io.run();
    const auto one = first.get();
    const auto two = second.get();
    EXPECT_NE(static_cast<bool>(one), static_cast<bool>(two));
    EXPECT_FALSE(run(store.consumeRecoveryAsync(subject, current->value(), digest)));
    EXPECT_EQ(remaining(), "1");

    // Rehash uses a real encoded hash, preserves the password-change
    // timestamp, and cannot overwrite a concurrently changed password.
    auto policy = cred::PasswordPolicy::create(1024U, 8U, 1U, 16U, 32U, 2U * 1024U * 1024U);
    ASSERT_TRUE(policy);
    auto hasher = cred::PasswordHasher::create(fnd::SecretString{std::string(32U, 'p')}, policy.value());
    ASSERT_TRUE(hasher);
    auto replacement = hasher->hash(fnd::SecretString{"disposable-fixture-password"});
    ASSERT_TRUE(replacement);
    auto stale = run(store.rehashAsync(subject, initial->value(), replacement.value()));
    ASSERT_TRUE(stale);
    EXPECT_FALSE(stale.value());
    auto otherTenant = run(foreign.rehashAsync(subject, current->value(), replacement.value()));
    ASSERT_TRUE(otherTenant);
    EXPECT_FALSE(otherTenant.value());
    auto upgraded = run(store.rehashAsync(subject, current->value(), replacement.value()));
    ASSERT_TRUE(upgraded && upgraded.value());
    auto updated = run(store.readAsync(subject));
    ASSERT_TRUE(updated && updated->has_value());
    EXPECT_EQ(updated->value().passwordHash, replacement->encoded());
    EXPECT_EQ(updated->value().passwordChangedAt, current->value().passwordChangedAt);
    EXPECT_FALSE(run(store.consumeRecoveryAsync(subject, current->value(), secondDigest)));
    EXPECT_EQ(remaining(), "1");
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "UPDATE openproof.identities SET status=2 WHERE id=$1", {seed.owner})));
    EXPECT_FALSE(run(store.consumeRecoveryAsync(subject, updated->value(), secondDigest)));
    EXPECT_EQ(remaining(), "1");
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "UPDATE openproof.identities SET status=0 WHERE id=$1", {seed.owner})));
    EXPECT_TRUE(run(store.consumeRecoveryAsync(subject, updated->value(), secondDigest)));
    EXPECT_EQ(remaining(), "0");
}

TEST(PostgresCanonicalCoroutineTest, NativeLocalProofVerifiesRealPasswordTotpAndRecovery)
{
    const auto dsn = disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK") != nullptr)
            FAIL() << "Explicitly requested disposable database has an invalid socket DSN.";
        GTEST_SKIP() << "Only an explicitly acknowledged disposable database may be used.";
    }
    using namespace std::chrono_literals;
    namespace cred = openproof::credentials;
    namespace sec = openproof::security;
    namespace local = openproof::provider::local;
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get()) == CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    auto policy = cred::PasswordPolicy::create(1024U, 8U, 1U, 16U, 32U, 2U * 1024U * 1024U);
    ASSERT_TRUE(policy);
    auto maker = cred::PasswordHasher::create(fnd::SecretString{std::string(32U, 'p')}, policy.value());
    auto worker = cred::PasswordHasher::create(fnd::SecretString{std::string(32U, 'p')}, policy.value());
    ASSERT_TRUE(maker && worker);
    auto hash = maker->hash(fnd::SecretString{"fixture-password"});
    ASSERT_TRUE(hash);
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
        "VALUES($1,$2,1770000000000)", {seed.owner, std::string{hash->encoded()}})));
    auto passwords = cred::BoundedPasswordExecutor::create(std::move(worker).value(), 1U);
    ASSERT_TRUE(passwords);
    auto key = sec::AeadKey::create(fnd::SecretString{std::string(32U, 'k')});
    auto fixtureKey = sec::AeadKey::create(fnd::SecretString{std::string(32U, 'k')});
    ASSERT_TRUE(key && fixtureKey);
    fnd::SecretString pepper{std::string(32U, 'r')};
    auto digest = sec::hmacSha256(pepper, "fixture-recovery-code");
    ASSERT_TRUE(digest);
    asio::io_context io;
    fnd::ManualClockSource clock{kNow};
    const idp::ProviderId id{"native-canonical-provider"};
    pg::CoroutineLocalCredentialStore store{io.get_executor(), fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org}, id, 2U, 500ms, 1000ms, 3000ms};
    pg::CoroutinePostgresLocalProofVerifier verifier{store, *passwords.value(),
        cred::TotpPolicy::recommended(), std::move(key).value(), 1U, std::move(pepper)};
    local::CoroutineLocalAuthenticationProvider provider{id, verifier, clock, 5min};
    auto run = [&]<typename T>(asio::awaitable<T> pending) {
        io.restart();
        std::optional<T> value;
        auto capture = [](asio::awaitable<T> task, std::optional<T>& output) -> asio::awaitable<void> {
            output.emplace(co_await std::move(task));
        };
        auto complete = asio::co_spawn(io, capture(std::move(pending), value), asio::use_future);
        io.run();
        complete.get();
        return std::move(value.value());
    };
    const auto currentStatus = run(store.readPasswordUpgradeStatusAsync(
        ids::IdentityId{seed.owner}, *passwords.value()));
    ASSERT_TRUE(currentStatus);
    EXPECT_EQ(currentStatus->first.value(), seed.owner);
    ASSERT_TRUE(currentStatus->second.has_value());
    EXPECT_FALSE(*currentStatus->second);
    const auto absentStatus = run(store.readPasswordUpgradeStatusAsync(
        ids::IdentityId{seed.emptyConnectionsOwner}, *passwords.value()));
    ASSERT_TRUE(absentStatus);
    EXPECT_FALSE(absentStatus->second.has_value());
    EXPECT_FALSE(run(store.readPasswordUpgradeStatusAsync(
        ids::IdentityId{seed.foreignOwner}, *passwords.value())));
    EXPECT_FALSE(run(store.readPasswordUpgradeStatusAsync(
        ids::IdentityId{seed.lockedOwner}, *passwords.value())));
    if (cred::PasswordHasher::supportsArgon2id()) {
        auto upgradeHasher = cred::PasswordHasher::create(
            fnd::SecretString{std::string(32U, 'p')}, policy.value(), "argon2id");
        ASSERT_TRUE(upgradeHasher);
        auto upgradeWorker = cred::BoundedPasswordExecutor::create(
            std::move(upgradeHasher).value(), 1U);
        ASSERT_TRUE(upgradeWorker);
        const auto needed = run(store.readPasswordUpgradeStatusAsync(
            ids::IdentityId{seed.owner}, *upgradeWorker.value()));
        ASSERT_TRUE(needed);
        ASSERT_TRUE(needed->second.has_value());
        EXPECT_TRUE(*needed->second);
        auto bad = run(store.confirmPasswordUpgradeAsync(ids::IdentityId{seed.owner},
            fnd::SecretString{"wrong-password"}, *upgradeWorker.value()));
        ASSERT_FALSE(bad);
        EXPECT_EQ(bad.error().code(), fnd::ErrorCode::AuthenticationFailed);
        EXPECT_FALSE(run(store.confirmPasswordUpgradeAsync(ids::IdentityId{seed.foreignOwner},
            fnd::SecretString{"fixture-password"}, *upgradeWorker.value())));
        auto upgraded = run(store.confirmPasswordUpgradeAsync(ids::IdentityId{seed.owner},
            fnd::SecretString{"fixture-password"}, *upgradeWorker.value()));
        ASSERT_TRUE(upgraded);
        EXPECT_EQ(upgraded->first.value(),seed.owner);
        EXPECT_TRUE(upgraded->second);
        auto snapshot = run(store.readAsync(idp::ExternalSubject{seed.subject}));
        ASSERT_TRUE(snapshot && snapshot->has_value());
        EXPECT_TRUE(snapshot->value().passwordHash.starts_with("$argon2id$"));
        EXPECT_EQ(snapshot->value().passwordChangedAt,"1770000000000");
        EXPECT_FALSE(run(store.confirmPasswordUpgradeAsync(ids::IdentityId{seed.owner},
            fnd::SecretString{"wrong-password"}, *upgradeWorker.value())));
        auto unchanged = run(store.confirmPasswordUpgradeAsync(ids::IdentityId{seed.owner},
            fnd::SecretString{"fixture-password"}, *upgradeWorker.value()));
        ASSERT_TRUE(unchanged);
        EXPECT_FALSE(unchanged->second);
        // Restore the original fixture for the separate scrypt login proofs.
        ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
            "UPDATE openproof.password_credentials SET password_hash=$2 WHERE identity_id=$1",
            {seed.owner,std::string{hash->encoded()}})));
    }
    auto proof = [&](std::string password, std::optional<std::string> totp = std::nullopt,
                     std::optional<std::string> recovery = std::nullopt,
                     std::optional<std::string> subject = std::nullopt) {
        idp::AuthenticationResponse response{idp::ChallengeId{"disposable-provider-proof"}, idp::ClientContext{}};
        response.setParameter("subject", idp::CredentialValue{subject.value_or(seed.subject)});
        response.setParameter("password", idp::CredentialValue{std::move(password)});
        if (totp) response.setParameter("totp", idp::CredentialValue{std::move(*totp)});
        if (recovery) response.setParameter("recovery_code", idp::CredentialValue{std::move(*recovery)});
        return run(provider.completeAuthenticationAsync(std::move(response)));
    };
    auto first = proof("fixture-password");
    ASSERT_TRUE(first);
    EXPECT_EQ(first->claimedAssurance(), idp::AssuranceLevel::Ial1);
    ASSERT_TRUE(first->requiredCanonicalOwner());
    EXPECT_EQ(*first->requiredCanonicalOwner(), seed.owner);
    pg::CoroutinePostgresCanonicalFinalizer finalizer{io.get_executor(), fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org}, 1U, 500ms, 1000ms, 3000ms};
    auto owner = run(finalizer.finishLoginAsync(first.value(), kNow));
    ASSERT_TRUE(owner);
    EXPECT_EQ(owner->value(), seed.owner);
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "UPDATE openproof.external_identities SET identity_id=$2 WHERE provider='native-canonical-provider' "
        "AND external_subject=$1", {seed.subject, seed.secondOwner})));
    EXPECT_FALSE(run(finalizer.finishLoginAsync(first.value(), kNow)));
    EXPECT_FALSE(run(finalizer.finishConnectionAsync(first.value(), ids::IdentityId{seed.secondOwner}, kNow)));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "UPDATE openproof.external_identities SET identity_id=$2 WHERE provider='native-canonical-provider' "
        "AND external_subject=$1", {seed.subject, seed.owner})));
    EXPECT_FALSE(proof("incorrect-password"));
    EXPECT_FALSE(proof("fixture-password", {}, {}, seed.unlinkedSubject));
    EXPECT_FALSE(proof("fixture-password", {}, {}, seed.foreignSubject));
    EXPECT_FALSE(proof("fixture-password", {}, "fixture-recovery-code"));

    fnd::SecretString rawSeed{std::string(20U, 't')};
    auto envelope = sec::sealAes256Gcm(fixtureKey.value(), rawSeed,
        "openproof/totp/v1:" + seed.owner);
    ASSERT_TRUE(envelope);
    auto totpSecret = cred::TotpSecret::create(std::move(rawSeed));
    ASSERT_TRUE(totpSecret);
    auto code = cred::totpAt(totpSecret.value(), cred::TotpPolicy::recommended(), kNow);
    ASSERT_TRUE(code);
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.totp_credentials(identity_id,encrypted_seed,key_version,enrolled_at_ms) "
        "VALUES($1,decode($2,'hex'),1,1770000000000)", {seed.owner, fnd::toHex(envelope.value())})));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.recovery_codes(identity_id,code_digest,issued_at_ms) "
        "VALUES($1,decode($2,'hex'),1770000000000)", {seed.owner, fnd::toHex(digest.value())})));
    EXPECT_FALSE(proof("fixture-password"));
    EXPECT_FALSE(proof("incorrect-password", code.value()));
    EXPECT_FALSE(proof("fixture-password", code.value(), "fixture-recovery-code"));
    auto mfa = proof("fixture-password", code.value());
    ASSERT_TRUE(mfa);
    EXPECT_EQ(mfa->claimedAssurance(), idp::AssuranceLevel::Ial2);
    EXPECT_TRUE(mfa->strength().isMultiFactor());
    EXPECT_FALSE(proof("fixture-password", code.value()));
    EXPECT_FALSE(proof("incorrect-password", {}, "fixture-recovery-code"));
    auto recovered = proof("fixture-password", {}, "fixture-recovery-code");
    ASSERT_TRUE(recovered);
    EXPECT_EQ(recovered->claimedAssurance(), idp::AssuranceLevel::Ial2);
    EXPECT_FALSE(proof("fixture-password", {}, "fixture-recovery-code"));
}

TEST(PostgresCanonicalCoroutineTest, RealDatabaseDisconnectPreservesLastRegisteredMethodUnderRace)
{
    const auto dsn=disposableDsn();
    if (!dsn) {
        if (std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK")!=nullptr)
            FAIL()<<"Invalid disposable socket DSN";
        GTEST_SKIP()<<"Explicit disposable database required";
    }
    Conn fixture{PQconnectdb(dsn->c_str())};
    ASSERT_TRUE(fixture && PQstatus(fixture.get())==CONNECTION_OK);
    Seed seed;
    ASSERT_NO_THROW(seed.install(fixture.get()));
    const std::string provider="native-canonical-provider";
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) "
        "VALUES('verification-only',$1,$2,1770000000000)",{seed.newSubject,seed.owner})));
    ASSERT_NO_THROW(static_cast<void>(execute(fixture.get(),
        "INSERT INTO openproof.identity_profiles(identity_id,display_name,created_at_ms,updated_at_ms,avatar_source) "
        "VALUES($1,'Concurrent detach',1770000000000,1770000000000,$2)",{seed.simultaneousOwner,provider})));
    asio::io_context io;
    pg::CoroutinePostgresCanonicalFinalizer store{io.get_executor(),fnd::SecretString{*dsn},
        ids::OrganizationId{seed.org},2U,std::chrono::milliseconds{500},
        std::chrono::milliseconds{1000},std::chrono::milliseconds{3000}};
    const std::vector<idp::ProviderId> registered{idp::ProviderId{provider}};
    const auto detach=[&](const std::string& owner,const std::string& subject) {
        return store.disconnectAsync(ids::IdentityId{owner},
            ids::ExternalIdentityRef{idp::ProviderId{provider},idp::ExternalSubject{subject}},
            registered,kNow);
    };
    auto last=asio::co_spawn(io,detach(seed.owner,seed.subject),asio::use_future);
    auto foreign=asio::co_spawn(io,detach(seed.owner,seed.foreignSubject),asio::use_future);
    io.run();
    auto lastStatus=last.get();
    ASSERT_FALSE(lastStatus);
    EXPECT_EQ(lastStatus.error().code(),fnd::ErrorCode::FailedPrecondition);
    auto foreignStatus=foreign.get();
    ASSERT_FALSE(foreignStatus);
    EXPECT_EQ(foreignStatus.error().code(),fnd::ErrorCode::PermissionDenied);
    io.restart();
    auto a=asio::co_spawn(io,detach(seed.simultaneousOwner,seed.simultaneousSubjectA),asio::use_future);
    auto b=asio::co_spawn(io,detach(seed.simultaneousOwner,seed.simultaneousSubjectB),asio::use_future);
    io.run();
    auto first=a.get();
    auto second=b.get();
    ASSERT_NE(static_cast<bool>(first),static_cast<bool>(second));
    EXPECT_EQ((first ? second : first).error().code(),fnd::ErrorCode::FailedPrecondition);
    const auto remaining=execute(fixture.get(),
        "SELECT count(*)::text FROM openproof.external_identities WHERE identity_id=$1 AND provider=$2",
        {seed.simultaneousOwner,provider});
    ASSERT_EQ(PQntuples(remaining.get()),1);
    EXPECT_STREQ(PQgetvalue(remaining.get(),0,0),"1");
    const auto avatar=execute(fixture.get(),
        "SELECT avatar_source FROM openproof.identity_profiles WHERE identity_id=$1",
        {seed.simultaneousOwner});
    ASSERT_EQ(PQntuples(avatar.get()),1);
    EXPECT_STREQ(PQgetvalue(avatar.get(),0,0),"auto");
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

    const auto identitiesBefore = execute(fixture.get(),
        "SELECT COUNT(*)::text FROM openproof.identities WHERE organization_id=$1",
        {seed.org});
    ASSERT_EQ(PQntuples(identitiesBefore.get()), 1);
    const std::string initialIdentityCount{PQgetvalue(identitiesBefore.get(), 0, 0)};

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
    EXPECT_TRUE(checks.matchingVerifiedEmailDenied);
    EXPECT_TRUE(checks.targetAuthorized);
    EXPECT_TRUE(checks.inactiveTargetDenied);
    EXPECT_TRUE(checks.foreignTargetDenied);
    EXPECT_TRUE(checks.suspendedTenantLoginDenied);
    EXPECT_TRUE(checks.suspendedTenantTargetDenied);
    EXPECT_TRUE(checks.suspendedTenantLinkDenied);
    EXPECT_TRUE(checks.connectionAttached);
    EXPECT_TRUE(checks.ownerConflictDenied);
    EXPECT_TRUE(checks.invalidProfileDenied);

    const auto identitiesAfter = execute(fixture.get(),
        "SELECT COUNT(*)::text FROM openproof.identities WHERE organization_id=$1",
        {seed.org});
    ASSERT_EQ(PQntuples(identitiesAfter.get()), 1);
    EXPECT_STREQ(PQgetvalue(identitiesAfter.get(), 0, 0), initialIdentityCount.c_str());

    const auto implicitLinks = execute(fixture.get(),
        "SELECT COUNT(*)::text FROM openproof.external_identities "
        "WHERE provider='native-canonical-provider' AND external_subject IN ($1,$2)",
        {seed.unlinkedSubject, seed.matchingEmailSubject});
    ASSERT_EQ(PQntuples(implicitLinks.get()), 1);
    EXPECT_STREQ(PQgetvalue(implicitLinks.get(), 0, 0), "0");

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
        "SELECT email,email_verified,preferred_username FROM openproof.identity_profiles "
        "WHERE identity_id=$1", {seed.freshLoginOwner});
    ASSERT_EQ(PQntuples(loginProfile.get()), 1);
    EXPECT_STREQ(PQgetvalue(loginProfile.get(), 0, 0), "first@example.test");
    EXPECT_STREQ(PQgetvalue(loginProfile.get(), 0, 1), "t");
    // Presentation refresh fills missing fields; it never overwrites the
    // preferred username established by the first linked login.
    EXPECT_STREQ(PQgetvalue(loginProfile.get(), 0, 2), "initial-user");

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

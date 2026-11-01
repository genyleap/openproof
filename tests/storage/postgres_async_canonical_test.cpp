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

#include "coroutine_canonical_finalizer.hpp"

import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

namespace {
namespace asio = boost::asio;
namespace pg = openproof::storage::postgres;
namespace fnd = openproof::foundation;
namespace ids = openproof::identity::core;
namespace idp = openproof::identity::provider;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1770000000000LL}};
constexpr std::string_view kCiDatabase =
    "postgresql://openproof_ci:ci_disposable_only@127.0.0.1:5432/openproof_coroutine_ci";
constexpr std::string_view kLocalDatabase =
    "postgresql://openproof_ci:ci_disposable_only@127.0.0.1:55432/openproof_coroutine_ci";

struct PgConnDeleter final {
    void operator()(PGconn* value) const noexcept { if (value) PQfinish(value); }
};
struct PgResultDeleter final {
    void operator()(PGresult* value) const noexcept { if (value) PQclear(value); }
};
using Conn = std::unique_ptr<PGconn, PgConnDeleter>;
using Result = std::unique_ptr<PGresult, PgResultDeleter>;

[[nodiscard]] std::optional<std::string> disposableDsn()
{
    const char* dsn = std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN");
    if (dsn == nullptr) return std::nullopt;
    const char* acknowledged =
        std::getenv("OPENPROOF_TEST_POSTGRES_DOMAIN_ACK");
    // A deliberately strict allow-list: never use arbitrary credentials
    // supplied by an environment or a URL pointing to the live database.
    if (acknowledged == nullptr
        || std::string_view{acknowledged}
            != "YES_EXCLUSIVE_DISPOSABLE_DATABASE"
        || (std::string_view{dsn} != kCiDatabase
            && std::string_view{dsn} != kLocalDatabase)) {
        return std::nullopt;
    }
    return std::string{dsn};
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
    std::string subject, std::string preferredUsername = "native-user")
{
    idp::VerifiedClaims claims;
    claims.set(idp::ClaimName::PreferredUsername, std::move(preferredUsername));
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
    std::string owner = "nc-owner-" + suffix;
    std::string secondOwner = "nc-second-" + suffix;
    std::string lockedOwner = "nc-locked-" + suffix;
    std::string foreignOwner = "nc-foreign-owner-" + suffix;
    std::string subject = "nc-existing-" + suffix;
    std::string lockedSubject = "nc-locked-external-" + suffix;
    std::string foreignSubject = "nc-foreign-external-" + suffix;
    std::string newSubject = "nc-new-" + suffix;
    std::string invalidSubject = "nc-rollback-" + suffix;

    void install(PGconn* connection) const
    {
        for (const auto& id : {org, foreignOrg}) {
            static_cast<void>(execute(connection,
                "INSERT INTO openproof.organizations("
                "id,name,state,created_at_ms) VALUES($1,'Isolated Coroutine Test',0,$2)",
                {id, "1770000000000"}));
        }
        for (const auto& [id, tenant, status] :
            {std::tuple{owner, org, "0"},
             std::tuple{secondOwner, org, "0"},
             std::tuple{lockedOwner, org, "2"},
             std::tuple{foreignOwner, foreignOrg, "0"}}) {
            static_cast<void>(execute(connection,
                "INSERT INTO openproof.identities("
                "id,organization_id,kind,status,created_at_ms) "
                "VALUES($1,$2,0,$3,$4)",
                {id, tenant, status, "1770000000000"}));
        }
        for (const auto& [subjectValue, linked] :
            {std::pair{subject, owner},
             std::pair{lockedSubject, lockedOwner},
             std::pair{foreignSubject, foreignOwner}}) {
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
    bool wrongTenantDenied{};
    bool inactiveDenied{};
    bool unlinkedDenied{};
    bool targetAuthorized{};
    bool inactiveTargetDenied{};
    bool foreignTargetDenied{};
    bool connectionAttached{};
    bool ownerConflictDenied{};
    bool invalidProfileDenied{};
};

asio::awaitable<void> checkRealDatabase(
    pg::CoroutinePostgresCanonicalFinalizer& canonical,
    pg::CoroutinePostgresCanonicalFinalizer& wrongTenant,
    const Seed& seed, IntegrationResult& checks)
{
    const auto owner = co_await canonical.finishLoginAsync(
        verified(seed.subject, "provider-proposed"), kNow);
    checks.login = owner && owner->value() == seed.owner;

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

    auto connected = co_await canonical.finishConnectionAsync(
        verified(seed.newSubject), ids::IdentityId{seed.secondOwner}, kNow);
    checks.connectionAttached = connected
        && connected->subject().value() == seed.newSubject;

    auto stolen = co_await canonical.finishConnectionAsync(
        verified(seed.newSubject), ids::IdentityId{seed.owner}, kNow);
    checks.ownerConflictDenied = !stolen
        && stolen.error().code() == fnd::ErrorCode::Conflict;

    // SQL INSERT of the external link succeeds first, but canonical domain
    // validation of this oversized email must abort the whole transaction.
    idp::VerifiedClaims invalidClaims;
    invalidClaims.set(idp::ClaimName::Email, std::string(321U, 'x'));
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
    bool denied = false;
    auto run = [&]() -> asio::awaitable<void> {
        auto result = co_await finalizer.finishLoginAsync(
            verified("never-linked"), kNow);
        denied = !result && result.error().code() == fnd::ErrorCode::Unavailable;
    };
    auto operation = run();
    auto future = asio::co_spawn(io, std::move(operation), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(denied);
}

TEST(PostgresCanonicalCoroutineTest, RealDatabaseTenantOwnershipLifecycleAndProfiles)
{
    const auto dsn = disposableDsn();
    if (!dsn) GTEST_SKIP() << "Only an explicitly acknowledged disposable database may be used.";

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

    IntegrationResult checks;
    auto future = asio::co_spawn(io,
        checkRealDatabase(canonical, wrongTenant, seed, checks), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(checks.login);
    EXPECT_TRUE(checks.wrongTenantDenied);
    EXPECT_TRUE(checks.inactiveDenied);
    EXPECT_TRUE(checks.unlinkedDenied);
    EXPECT_TRUE(checks.targetAuthorized);
    EXPECT_TRUE(checks.inactiveTargetDenied);
    EXPECT_TRUE(checks.foreignTargetDenied);
    EXPECT_TRUE(checks.connectionAttached);
    EXPECT_TRUE(checks.ownerConflictDenied);
    EXPECT_TRUE(checks.invalidProfileDenied);

    const auto notCommitted = execute(fixture.get(),
        "SELECT COUNT(*)::text FROM openproof.external_identities "
        "WHERE provider='native-canonical-provider' AND external_subject=$1",
        {seed.invalidSubject});
    ASSERT_EQ(PQntuples(notCommitted.get()), 1);
    EXPECT_STREQ(PQgetvalue(notCommitted.get(), 0, 0), "0");

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
}
} // namespace

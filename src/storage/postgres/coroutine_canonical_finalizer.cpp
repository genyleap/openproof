#include "async_pool.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

// Include every textual Boost/STL dependency before GCC16 module imports.
#include "coroutine_canonical_finalizer.hpp"

import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.profile;
import openproof.identity.provider;

namespace openproof::storage::postgres {
namespace asio = boost::asio;
namespace core = identity::core;
namespace idp = identity::provider;
namespace profile = identity::profile;
namespace {
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;
using Row = std::vector<std::optional<std::string>>;
using Params = std::vector<std::optional<std::string>>;

[[nodiscard]] std::chrono::milliseconds remaining(Deadline deadline)
{
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - Clock::now());
    if (duration <= std::chrono::milliseconds::zero())
        throw std::runtime_error{"Canonical SQL deadline exceeded"};
    return duration;
}

[[nodiscard]] std::string required(const std::optional<std::string>& field)
{
    if (!field) throw std::runtime_error{"Malformed canonical identity row"};
    return *field;
}

[[nodiscard]] std::int64_t milliseconds(const std::optional<std::string>& field)
{
    const auto value = required(field);
    std::int64_t parsed{};
    const auto [end, error] = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size()
        || parsed < 0)
        throw std::runtime_error{"Malformed canonical profile timestamp"};
    return parsed;
}

[[nodiscard]] bool boolean(const std::optional<std::string>& field)
{
    const auto value = required(field);
    if (value == "t") return true;
    if (value == "f") return false;
    throw std::runtime_error{"Malformed canonical profile boolean"};
}

[[nodiscard]] std::optional<std::string> claim(
    const idp::VerifiedClaims& claims, idp::ClaimName name)
{
    const auto value = claims.get(name);
    if (!value) return std::nullopt;
    return std::string{*value};
}

[[nodiscard]] std::optional<std::string> text(const Row& row, std::size_t index)
{
    return row.at(index);
}

[[nodiscard]] std::string optionalText(const std::optional<std::string>& value)
{
    return value.value_or(std::string{});
}

enum class ProfilePurpose {
    Login,
    Connection
};

[[nodiscard]] core::ExternalIdentityRef externalRef(
    const idp::AuthenticationOutcome& outcome)
{
    return core::ExternalIdentityRef{
        outcome.provider(), outcome.subject(),
        claim(outcome.claims(), idp::ClaimName::DisplayName),
        claim(outcome.claims(), idp::ClaimName::PreferredUsername),
        claim(outcome.claims(), idp::ClaimName::PictureUrl)};
}

asio::awaitable<void> saveProfile(
    async_detail::AsyncConnection& connection,
    core::IdentityId identity,
    const idp::VerifiedClaims& claims,
    foundation::Instant completedAt,
    Deadline deadline,
    ProfilePurpose purpose)
{
    // Lock a profile across read, domain validation and write. The same
    // physical lease also holds the identity lifecycle lock until COMMIT.
    Params readParams{std::string{identity.value()}};
    const auto rows = co_await connection.query(
        "SELECT display_name,preferred_username,email,email_verified,"
        "phone_number,phone_number_verified,locale,picture_url,avatar_source,"
        "created_at_ms,updated_at_ms "
        "FROM openproof.identity_profiles WHERE identity_id=$1 FOR UPDATE",
        std::move(readParams), remaining(deadline));
    if (rows.rows.size() > 1U)
        throw std::runtime_error{"Duplicate canonical profile rows"};

    foundation::Result<profile::IdentityProfile> value =
        foundation::fail(foundation::ErrorCode::Unavailable);
    if (rows.rows.empty()) {
        value = profile::IdentityProfile::create(identity, completedAt);
        if (!value) throw std::runtime_error{"Cannot create canonical profile"};
        // A new pre-linked login can seed verified contact data, matching
        // the synchronous login flow. Adding a second login method must
        // NEVER transfer that provider's contact claims into a previously
        // profile-less canonical identity: connection is presentation-only.
        const auto applied = purpose == ProfilePurpose::Login
            ? value->applyVerifiedClaims(claims, completedAt)
            : value->refreshPresentationClaims(claims, completedAt);
        if (!applied) throw std::runtime_error{"Invalid verified profile claims"};
    } else {
        const auto& fields = rows.rows.front();
        if (fields.size() != 11U)
            throw std::runtime_error{"Invalid canonical profile shape"};
        value = profile::IdentityProfile::restore(
            identity, text(fields, 0), text(fields, 1), text(fields, 2),
            boolean(fields[3]), text(fields, 4), boolean(fields[5]),
            text(fields, 6), text(fields, 7),
            foundation::Instant{foundation::Duration{milliseconds(fields[9])}},
            foundation::Instant{foundation::Duration{milliseconds(fields[10])}},
            required(fields[8]));
        if (!value) throw std::runtime_error{"Invalid canonical profile"};
        const auto refreshed = value->refreshPresentationClaims(
            claims, completedAt);
        if (!refreshed) throw std::runtime_error{"Invalid presentation refresh"};
    }

    // All updates are committed together with the owner/lifecycle check.
    // The upsert is needed for the first sign-in of a pre-linked identity.
    Params writeParams{
        std::string{identity.value()}, optionalText(value->displayName()),
        optionalText(value->preferredUsername()), optionalText(value->email()),
        value->emailVerified() ? "true" : "false",
        optionalText(value->phoneNumber()),
        value->phoneNumberVerified() ? "true" : "false",
        optionalText(value->locale()), optionalText(value->pictureUrl()),
        std::string{value->avatarSource()},
        std::to_string(value->createdAt().time_since_epoch().count()),
        std::to_string(value->updatedAt().time_since_epoch().count())};
    static_cast<void>(co_await connection.query(
        "INSERT INTO openproof.identity_profiles("
        "identity_id,display_name,preferred_username,email,email_verified,"
        "phone_number,phone_number_verified,locale,picture_url,avatar_source,"
        "created_at_ms,updated_at_ms) "
        "VALUES($1,NULLIF($2,''),NULLIF($3,''),NULLIF($4,''),$5,"
        "NULLIF($6,''),$7,NULLIF($8,''),NULLIF($9,''),$10,$11,$12) "
        "ON CONFLICT(identity_id) DO UPDATE SET "
        "display_name=EXCLUDED.display_name,"
        "preferred_username=EXCLUDED.preferred_username,"
        "email=EXCLUDED.email,email_verified=EXCLUDED.email_verified,"
        "phone_number=EXCLUDED.phone_number,"
        "phone_number_verified=EXCLUDED.phone_number_verified,"
        "locale=EXCLUDED.locale,picture_url=EXCLUDED.picture_url,"
        "avatar_source=EXCLUDED.avatar_source,"
        "updated_at_ms=EXCLUDED.updated_at_ms "
        // An unchanged login profile should not allocate another heap tuple
        // or generate unnecessary WAL/replication churn on every login.
        "WHERE ROW(openproof.identity_profiles.display_name,"
        "openproof.identity_profiles.preferred_username,"
        "openproof.identity_profiles.email,"
        "openproof.identity_profiles.email_verified,"
        "openproof.identity_profiles.phone_number,"
        "openproof.identity_profiles.phone_number_verified,"
        "openproof.identity_profiles.locale,"
        "openproof.identity_profiles.picture_url,"
        "openproof.identity_profiles.avatar_source,"
        "openproof.identity_profiles.updated_at_ms) "
        "IS DISTINCT FROM ROW(EXCLUDED.display_name,"
        "EXCLUDED.preferred_username,EXCLUDED.email,EXCLUDED.email_verified,"
        "EXCLUDED.phone_number,EXCLUDED.phone_number_verified,"
        "EXCLUDED.locale,EXCLUDED.picture_url,EXCLUDED.avatar_source,"
        "EXCLUDED.updated_at_ms)",
        std::move(writeParams), remaining(deadline)));
}

asio::awaitable<void> rollback(
    async_detail::AsyncConnection& connection, Deadline deadline)
{
    // Return a known-idle PGconn to the pool after an ordinary denied proof.
    // If ROLLBACK itself fails, the query adapter poisons the connection.
    static_cast<void>(co_await connection.query(
        "ROLLBACK", {}, remaining(deadline)));
}

asio::awaitable<bool> activeTarget(
    async_detail::AsyncConnection& connection,
    std::string identity, std::string organization, Deadline deadline,
    bool mutationLock)
{
    // Lock the canonical row during writes, even if there is not yet a
    // profile row to lock. This serializes concurrent first-time profile
    // initialization, owner linking and lifecycle transitions per identity.
    // Preflight authorization is read-only and does not retain this lock.
    Params params{std::move(identity), std::move(organization)};
    const auto rows = co_await connection.query(
        std::string{"SELECT i.id FROM openproof.identities i "
                    "JOIN openproof.organizations o ON o.id=i.organization_id "
                    "WHERE i.id=$1 AND i.organization_id=$2 "
                    "AND i.status=0 AND o.state=0"}
            + (mutationLock ? " FOR UPDATE OF i FOR SHARE OF o" : ""),
        std::move(params), remaining(deadline));
    if (rows.rows.size() > 1U)
        throw std::runtime_error{"Duplicate canonical identities"};
    co_return !rows.rows.empty();
}

asio::awaitable<bool> refreshExternal(
    async_detail::AsyncConnection& connection,
    const core::ExternalIdentityRef& external,
    std::string owner,
    Deadline deadline)
{
    Params params{
        std::string{external.providerId().value()},
        std::string{external.subject().value()}, std::move(owner),
        optionalText(external.displayName()),
        optionalText(external.preferredUsername()),
        optionalText(external.pictureUrl())};
    const auto rows = co_await connection.query(
        "UPDATE openproof.external_identities SET "
        "display_name=COALESCE(NULLIF($4,''),display_name),"
        "preferred_username=COALESCE(NULLIF($5,''),preferred_username),"
        "picture_url=COALESCE(NULLIF($6,''),picture_url) "
        "WHERE provider=$1 AND external_subject=$2 AND identity_id=$3 "
        "RETURNING identity_id",
        std::move(params), remaining(deadline));
    if (rows.rows.size() > 1U)
        throw std::runtime_error{"Duplicate external account ownership"};
    co_return rows.rows.size() == 1U;
}
} // namespace

class CoroutinePostgresCanonicalFinalizer::Impl final {
public:
    Impl(asio::any_io_executor executor, std::string connectionString,
         core::OrganizationId organizationValue, std::size_t capacity,
         foundation::Duration acquireTimeout,
         foundation::Duration connectTimeout,
         foundation::Duration queryTimeoutValue)
        : pool(std::move(executor), std::move(connectionString),
               capacity, acquireTimeout, connectTimeout),
          organization(std::move(organizationValue)),
          queryTimeout(queryTimeoutValue) {}
    async_detail::AsyncConnectionPool pool;
    core::OrganizationId organization;
    foundation::Duration queryTimeout;
};

CoroutinePostgresCanonicalFinalizer::CoroutinePostgresCanonicalFinalizer(
    asio::any_io_executor executor,
    foundation::SecretString connectionString,
    core::OrganizationId organization,
    std::size_t maxConnections,
    foundation::Duration acquireTimeout,
    foundation::Duration connectTimeout,
    foundation::Duration queryTimeout)
{
    if (organization.empty() || organization.value().size() > 200U
        || queryTimeout <= foundation::Duration::zero())
        throw std::invalid_argument{"Invalid canonical PostgreSQL finalizer configuration"};
    m_impl = std::make_unique<Impl>(
        std::move(executor), std::string{connectionString.expose()},
        std::move(organization), maxConnections, acquireTimeout,
        connectTimeout, queryTimeout);
}

CoroutinePostgresCanonicalFinalizer::~CoroutinePostgresCanonicalFinalizer() = default;

asio::awaitable<foundation::Result<core::IdentityId>>
CoroutinePostgresCanonicalFinalizer::finishLoginAsync(
    const idp::AuthenticationOutcome& outcome, foundation::Instant completedAt)
{
    if (outcome.provider().empty() || outcome.subject().empty()) {
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    }
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire();
        auto& connection = lease.connection();
        static_cast<void>(co_await connection.query("BEGIN", {}, remaining(deadline)));
        Params ownerParams{
            std::string{outcome.provider().value()},
            std::string{outcome.subject().value()},
            std::string{m_impl->organization.value()}};
        const auto owner = co_await connection.query(
            "SELECT i.id FROM openproof.external_identities e "
            "JOIN openproof.identities i ON i.id=e.identity_id "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "WHERE e.provider=$1 AND e.external_subject=$2 "
            "AND i.organization_id=$3 AND i.status=0 AND o.state=0 "
            "FOR UPDATE OF i FOR SHARE OF o",
            std::move(ownerParams), remaining(deadline));
        if (owner.rows.empty()) {
            co_await rollback(connection, deadline);
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                "The verified external account is not linked to an active identity.");
        }
        if (owner.rows.size() != 1U || owner.rows.front().size() != 1U)
            throw std::runtime_error{"Malformed canonical owner result"};
        core::IdentityId identity{required(owner.rows.front().front())};
        const auto external = externalRef(outcome);
        if (!(co_await refreshExternal(
                connection, external, std::string{identity.value()}, deadline))) {
            co_await rollback(connection, deadline);
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                "Canonical identity ownership changed.");
        }
        co_await saveProfile(
            connection, identity, outcome.claims(), completedAt,
            deadline, ProfilePurpose::Login);
        static_cast<void>(co_await connection.query(
            "COMMIT", {}, remaining(deadline)));
        co_return identity;
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native canonical identity persistence is unavailable.");
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresCanonicalFinalizer::authorizeConnectionTargetAsync(
    core::IdentityId target)
{
    if (target.empty())
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire();
        const bool active = co_await activeTarget(
            lease.connection(), std::string{target.value()},
            std::string{m_impl->organization.value()}, deadline, false);
        if (!active)
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                "This canonical identity cannot link accounts.");
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native canonical identity authorization unavailable.");
    }
}

asio::awaitable<foundation::Result<core::ExternalIdentityRef>>
CoroutinePostgresCanonicalFinalizer::finishConnectionAsync(
    const idp::AuthenticationOutcome& outcome,
    core::IdentityId target,
    foundation::Instant completedAt)
{
    if (target.empty() || outcome.provider().empty() || outcome.subject().empty()) {
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire();
        auto& connection = lease.connection();
        static_cast<void>(co_await connection.query("BEGIN", {}, remaining(deadline)));
        if (!(co_await activeTarget(
                connection, std::string{target.value()},
                std::string{m_impl->organization.value()}, deadline, true))) {
            co_await rollback(connection, deadline);
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                "The target canonical identity is not active.");
        }
        const auto external = externalRef(outcome);
        Params linkParams{
            std::string{outcome.provider().value()},
            std::string{outcome.subject().value()}, std::string{target.value()},
            std::to_string(completedAt.time_since_epoch().count()),
            optionalText(external.displayName()),
            optionalText(external.preferredUsername()),
            optionalText(external.pictureUrl())};
        const auto linked = co_await connection.query(
            "INSERT INTO openproof.external_identities("
            "provider,external_subject,identity_id,linked_at_ms,"
            "display_name,preferred_username,picture_url) "
            "VALUES($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),NULLIF($7,'')) "
            "ON CONFLICT(provider,external_subject) DO UPDATE SET "
            "identity_id=EXCLUDED.identity_id,"
            "display_name=COALESCE(EXCLUDED.display_name,openproof.external_identities.display_name),"
            "preferred_username=COALESCE(EXCLUDED.preferred_username,openproof.external_identities.preferred_username),"
            "picture_url=COALESCE(EXCLUDED.picture_url,openproof.external_identities.picture_url) "
            "WHERE openproof.external_identities.identity_id=EXCLUDED.identity_id "
            "RETURNING identity_id",
            std::move(linkParams), remaining(deadline));
        if (linked.rows.empty()) {
            co_await rollback(connection, deadline);
            co_return foundation::fail(foundation::ErrorCode::Conflict,
                "This external account already belongs to another identity.");
        }
        if (linked.rows.size() != 1U || linked.rows.front().size() != 1U
            || required(linked.rows.front().front()) != target.value())
            throw std::runtime_error{"Invalid canonical ownership write result"};
        co_await saveProfile(
            connection, target, outcome.claims(), completedAt,
            deadline, ProfilePurpose::Connection);
        static_cast<void>(co_await connection.query(
            "COMMIT", {}, remaining(deadline)));
        co_return external;
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native canonical connection persistence unavailable.");
    }
}

} // namespace openproof::storage::postgres

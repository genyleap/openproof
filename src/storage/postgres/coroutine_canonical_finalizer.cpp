#include "async_pool.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
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
import openproof.organization;
import openproof.policy;
import openproof.session;
import openproof.security;
import openproof.client;

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
        auto lease = co_await m_impl->pool.acquire(deadline);
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
        if (outcome.requiredCanonicalOwner() && *outcome.requiredCanonicalOwner() != identity.value()) {
            co_await rollback(connection, deadline);
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                "The credential owner no longer owns the verified subject.");
        }
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

asio::awaitable<foundation::Result<profile::IdentityProfile>>
CoroutinePostgresCanonicalFinalizer::readProfileAsync(core::IdentityId owner)
{
    if (owner.empty()) {
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    // The authenticated session supplies owner; SQL independently checks
    // both active identity and configured tenant to prevent cross-tenant
    // profile disclosure when a caller or repository is misconfigured.
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        Params params{
            std::string{owner.value()},
            std::string{m_impl->organization.value()}};
        const auto result = co_await lease.connection().query(
            "SELECT p.display_name,p.preferred_username,p.email,p.email_verified,"
            "p.phone_number,p.phone_number_verified,p.locale,p.picture_url,"
            "p.avatar_source,p.created_at_ms,p.updated_at_ms "
            "FROM openproof.identity_profiles p "
            "JOIN openproof.identities i ON i.id=p.identity_id "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "WHERE p.identity_id=$1 AND i.organization_id=$2 "
            "AND i.status=0 AND o.state=0 LIMIT 2",
            std::move(params), remaining(deadline));
        if (result.rows.empty()) {
            co_return foundation::fail(foundation::ErrorCode::NotFound);
        }
        if (result.rows.size() != 1U || result.rows.front().size() != 11U) {
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        }
        const auto& fields = result.rows.front();
        auto value = profile::IdentityProfile::restore(
            std::move(owner), text(fields, 0), text(fields, 1), text(fields, 2),
            boolean(fields[3]), text(fields, 4), boolean(fields[5]),
            text(fields, 6), text(fields, 7),
            foundation::Instant{foundation::Duration{milliseconds(fields[9])}},
            foundation::Instant{foundation::Duration{milliseconds(fields[10])}},
            required(fields[8]));
        if (!value) {
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        }
        co_return value;
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native account profile lookup is unavailable.");
    }
}

asio::awaitable<foundation::Result<profile::IdentityProfile>>
CoroutinePostgresCanonicalFinalizer::updateProfileAsync(core::IdentityId owner,
    std::optional<std::string> displayName, std::optional<std::string> username,
    std::optional<std::string> locale, std::optional<std::string> picture,
    std::optional<std::string> avatarSource, foundation::Instant now)
{
    if (owner.empty() || owner.value().size()>200U)
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const Deadline deadline = Clock::now()+m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        auto& connection = lease.connection();
        static_cast<void>(co_await connection.query("BEGIN",{},remaining(deadline)));
        if (!(co_await activeTarget(connection,std::string{owner.value()},
                std::string{m_impl->organization.value()},deadline,true))) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(foundation::ErrorCode::NotFound);
        }
        Params params{std::string{owner.value()}};
        const auto rows = co_await connection.query(
            "SELECT display_name,preferred_username,email,email_verified,"
            "phone_number,phone_number_verified,locale,picture_url,avatar_source,"
            "created_at_ms,updated_at_ms FROM openproof.identity_profiles "
            "WHERE identity_id=$1 FOR UPDATE",std::move(params),remaining(deadline));
        if (rows.rows.empty()) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(foundation::ErrorCode::NotFound);
        }
        if (rows.rows.size()!=1U || rows.rows.front().size()!=11U)
            throw std::runtime_error{"Malformed profile update snapshot"};
        const auto& row=rows.rows.front();
        auto value=profile::IdentityProfile::restore(owner,text(row,0),text(row,1),text(row,2),
            boolean(row[3]),text(row,4),boolean(row[5]),text(row,6),text(row,7),
            foundation::Instant{foundation::Duration{milliseconds(row[9])}},
            foundation::Instant{foundation::Duration{milliseconds(row[10])}},required(row[8]));
        if (!value) throw std::runtime_error{"Invalid stored profile"};
        auto updated=value->updateSelfService(std::move(displayName),std::move(username),
            std::move(locale),std::move(picture),now);
        if (!updated) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(updated.error());
        }
        if (avatarSource) {
            bool allowed=*avatarSource=="auto";
            if (*avatarSource=="profile") allowed=value->pictureUrl().has_value();
            else if (!allowed && !avatarSource->empty() && avatarSource->size()<=128U
                && avatarSource->find('\0')==std::string::npos) {
                Params avatarParams{std::string{owner.value()},*avatarSource};
                const auto eligible=co_await connection.query(
                    "SELECT 1 FROM openproof.external_identities WHERE identity_id=$1 "
                    "AND provider=$2 AND picture_url IS NOT NULL AND picture_url<>'' "
                    "LIMIT 1 FOR SHARE",std::move(avatarParams),remaining(deadline));
                allowed=!eligible.rows.empty();
            }
            if (!allowed) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
            }
            auto selected=value->setAvatarSource(std::move(*avatarSource),now);
            if (!selected) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(selected.error());
            }
        }
        Params write{std::string{owner.value()},value->displayName(),value->preferredUsername(),
            value->locale(),value->pictureUrl(),std::string{value->avatarSource()},
            std::to_string(value->updatedAt().time_since_epoch().count())};
        // Never rewrite verified contacts, created_at or any credential.
        const auto persisted=co_await connection.query(
            "UPDATE openproof.identity_profiles SET display_name=$2,preferred_username=$3,"
            "locale=$4,picture_url=$5,avatar_source=$6,updated_at_ms=$7::bigint "
            "WHERE identity_id=$1 RETURNING identity_id",std::move(write),remaining(deadline));
        if (persisted.rows.size()!=1U || persisted.rows.front().size()!=1U
            || required(persisted.rows.front().front())!=owner.value())
            throw std::runtime_error{"Profile update owner mismatch"};
        static_cast<void>(co_await connection.query("COMMIT",{},remaining(deadline)));
        co_return value;
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native account profile update is unavailable.");
    }
}

// The active identity row anchors the LEFT JOIN, so a legitimate account
// with no linked providers returns an empty list without confusing a missing
// or cross-tenant identity with an empty result.
asio::awaitable<foundation::Result<std::pair<core::IdentityId,
    std::vector<core::ExternalIdentityRef>>>>
CoroutinePostgresCanonicalFinalizer::readConnectionsAsync(core::IdentityId owner)
{
    using Output = std::pair<core::IdentityId, std::vector<core::ExternalIdentityRef>>;
    if (owner.empty())
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        Params params{std::string{owner.value()},
                      std::string{m_impl->organization.value()}};
        const auto result = co_await lease.connection().query(
            "SELECT i.id,e.provider,e.external_subject,e.display_name,"
            "e.preferred_username,e.picture_url "
            "FROM openproof.identities i "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "LEFT JOIN openproof.external_identities e ON e.identity_id=i.id "
            "WHERE i.id=$1 AND i.organization_id=$2 "
            "AND i.status=0 AND o.state=0 "
            "ORDER BY e.provider,e.external_subject LIMIT 257",
            std::move(params), remaining(deadline));
        if (result.rows.empty())
            co_return foundation::fail(foundation::ErrorCode::NotFound);
        // A bounded output prevents an unexpected SQL cardinality explosion
        // from becoming an unbounded sensitive HTTP response.
        if (result.rows.size() > 256U)
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        std::vector<core::ExternalIdentityRef> values;
        values.reserve(result.rows.size());
        for (const auto& row : result.rows) {
            if (row.size() != 6U || required(row[0]) != owner.value())
                co_return foundation::fail(foundation::ErrorCode::Unavailable);
            if (!row[1] && !row[2]) {
                if (result.rows.size() != 1U || row[3] || row[4] || row[5])
                    co_return foundation::fail(foundation::ErrorCode::Unavailable);
                continue;
            }
            if (!row[1] || !row[2] || row[1]->empty() || row[2]->empty()
                || row[1]->size() > 200U || row[2]->size() > 1000U)
                co_return foundation::fail(foundation::ErrorCode::Unavailable);
            values.emplace_back(idp::ProviderId{*row[1]},
                idp::ExternalSubject{*row[2]}, row[3], row[4], row[5]);
        }
        co_return Output{std::move(owner), std::move(values)};
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native external connections lookup is unavailable.");
    }
}

asio::awaitable<foundation::Result<std::pair<core::IdentityId, std::optional<bool>>>>
CoroutinePostgresCanonicalFinalizer::readTotpStatusAsync(
    core::IdentityId owner, idp::ProviderId localProvider)
{
    using Output = std::pair<core::IdentityId, std::optional<bool>>;
    if (owner.empty() || localProvider.empty() || localProvider.value().size() > 200U)
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        Params params{std::string{owner.value()}, std::string{m_impl->organization.value()},
                      std::string{localProvider.value()}};
        // The one-statement snapshot binds both eligibility and enrollment
        // to the current active identity, tenant and configured provider.
        // Do not fetch password hashes, encrypted seeds or recovery codes.
        const auto rows = co_await lease.connection().query(
            "SELECT i.id,"
            "EXISTS(SELECT 1 FROM openproof.external_identities e "
            "WHERE e.identity_id=i.id AND e.provider=$3),"
            "EXISTS(SELECT 1 FROM openproof.external_identities e "
            "JOIN openproof.password_credentials p ON p.identity_id=e.identity_id "
            "JOIN openproof.totp_credentials t ON t.identity_id=e.identity_id "
            "WHERE e.identity_id=i.id AND e.provider=$3) "
            "FROM openproof.identities i "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "WHERE i.id=$1 AND i.organization_id=$2 AND i.status=0 AND o.state=0 LIMIT 2",
            std::move(params), remaining(deadline));
        if (rows.rows.empty())
            co_return foundation::fail(foundation::ErrorCode::NotFound);
        if (rows.rows.size() != 1U || rows.rows.front().size() != 3U
            || required(rows.rows.front()[0]) != owner.value())
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        const bool available = boolean(rows.rows.front()[1]);
        const bool enabled = boolean(rows.rows.front()[2]);
        if (enabled && !available)
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        co_return Output{std::move(owner), available ? std::optional<bool>{enabled}
                                                     : std::nullopt};
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native TOTP status lookup is unavailable.");
    }
}

asio::awaitable<foundation::Result<organization::Membership>>
CoroutinePostgresCanonicalFinalizer::readAuthorizationMembershipAsync(
    core::IdentityId subject, core::OrganizationId tenant)
{
    constexpr std::size_t maxRoles = 256U;
    if (subject.empty() || subject.value().size() > 200U || tenant.empty())
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    if (tenant != m_impl->organization)
        co_return foundation::fail(foundation::ErrorCode::PermissionDenied);
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        Params params{std::string{subject.value()}, std::string{tenant.value()}};
        // Keep identity, organization, membership lifecycle and assigned
        // roles in the SAME statement snapshot. Do not infer membership
        // from the identity's existence or reuse previously cached roles.
        const auto rows = co_await lease.connection().query(
            "SELECT m.identity_id,m.organization_id,m.invited_at_ms,r.role "
            "FROM openproof.memberships m "
            "JOIN openproof.identities i ON i.id=m.identity_id "
            "AND i.organization_id=m.organization_id "
            "JOIN openproof.organizations o ON o.id=m.organization_id "
            "LEFT JOIN openproof.membership_roles r ON r.organization_id=m.organization_id "
            "AND r.identity_id=m.identity_id "
            "WHERE m.identity_id=$1 AND m.organization_id=$2 "
            "AND m.state=1 AND i.status=0 AND o.state=0 "
            "ORDER BY r.role COLLATE \"C\" NULLS FIRST LIMIT 257",
            std::move(params), remaining(deadline));
        if (rows.rows.empty())
            co_return foundation::fail(foundation::ErrorCode::PermissionDenied);
        if (rows.rows.size() > maxRoles || rows.rows.front().size() != 4U)
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        const auto invitedAt = milliseconds(rows.rows.front()[2]);
        auto membership = organization::Membership::invite(
            tenant, subject, foundation::Instant{foundation::Duration{invitedAt}});
        if (!membership || !membership->accept())
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        for (const auto& row : rows.rows) {
            if (row.size() != 4U || required(row[0]) != subject.value()
                || required(row[1]) != tenant.value()
                || milliseconds(row[2]) != invitedAt)
                co_return foundation::fail(foundation::ErrorCode::Unavailable);
            if (!row[3]) {
                // A legitimate active membership may hold zero roles.
                if (rows.rows.size() != 1U)
                    co_return foundation::fail(foundation::ErrorCode::Unavailable);
                continue;
            }
            const auto& role = *row[3];
            if (role.empty() || role.size() > 200U
                || std::any_of(role.begin(), role.end(), [](char c) {
                    const auto byte = static_cast<unsigned char>(c);
                    return byte < 0x20U || byte == 0x7fU;
                })
                || membership->hasRole(organization::Role{role}))
                co_return foundation::fail(foundation::ErrorCode::Unavailable);
            if (!membership->grantRole(organization::Role{role}))
                co_return foundation::fail(foundation::ErrorCode::Unavailable);
        }
        co_return std::move(membership).value();
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native authorization membership lookup is unavailable.");
    }
}

asio::awaitable<foundation::Result<administration::MemberListing>>
CoroutinePostgresCanonicalFinalizer::readMembersAsync(core::IdentityId actor)
{
    constexpr std::size_t maxMembers = 256U;
    constexpr std::size_t maxRoles = 16U;
    constexpr std::size_t maxRows = maxMembers * maxRoles;
    if (actor.empty() || actor.value().size() > 200U)
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        // Owner authorization is part of the same statement/snapshot as
        // enumeration. No data is returned if actor, membership or tenant
        // is inactive or the owner role was absent in this snapshot.
        const auto rows = co_await lease.connection().query(
            "WITH permitted AS (SELECT a.identity_id FROM openproof.memberships a "
            "JOIN openproof.identities ai ON ai.id=a.identity_id "
            "AND ai.organization_id=a.organization_id "
            "JOIN openproof.organizations o ON o.id=a.organization_id "
            "WHERE a.identity_id=$1 AND a.organization_id=$2 "
            "AND a.state=1 AND ai.status=0 AND o.state=0 "
            "AND EXISTS(SELECT 1 FROM openproof.membership_roles ar "
            "WHERE ar.organization_id=a.organization_id AND ar.identity_id=a.identity_id "
            "AND ar.role='owner')) "
            "SELECT p.identity_id,i.id,i.status,m.state,r.role "
            "FROM permitted p JOIN openproof.memberships m ON m.organization_id=$2 "
            "JOIN openproof.identities i ON i.id=m.identity_id AND i.organization_id=m.organization_id "
            "LEFT JOIN openproof.membership_roles r ON r.organization_id=m.organization_id "
            "AND r.identity_id=m.identity_id "
            "ORDER BY i.id COLLATE \"C\",r.role COLLATE \"C\" NULLS FIRST LIMIT 4097",
            {std::string{actor.value()}, std::string{m_impl->organization.value()}},
            remaining(deadline));
        if (rows.rows.empty())
            co_return foundation::fail(foundation::ErrorCode::PermissionDenied);
        if (rows.rows.size() > maxRows)
            co_return foundation::fail(foundation::ErrorCode::Unavailable,
                "Native membership listing exceeds its bounded result.");
        const auto statusValue = [](const std::optional<std::string>& field,
                                    unsigned int maximum) {
            const auto value = required(field);
            unsigned int parsed{};
            const auto [end, error] = std::from_chars(
                value.data(), value.data() + value.size(), parsed);
            if (error != std::errc{} || end != value.data() + value.size()
                || parsed > maximum)
                throw std::runtime_error{"Malformed membership status"};
            return parsed;
        };
        const auto validText = [](std::string_view value) {
            return !value.empty() && value.size() <= 200U
                && std::all_of(value.begin(), value.end(), [](char c) {
                    const auto byte = static_cast<unsigned char>(c);
                    return byte >= 0x20U && byte != 0x7fU;
                });
        };
        administration::MemberListing result{actor, {}};
        bool ownerSeen = false;
        for (const auto& row : rows.rows) {
            if (row.size() != 5U || required(row[0]) != actor.value())
                throw std::runtime_error{"Invalid owner-bound member row"};
            const auto identity = required(row[1]);
            if (!validText(identity)) throw std::runtime_error{"Invalid member identity"};
            const auto identityStatus = static_cast<core::IdentityStatus>(statusValue(row[2], 5U));
            const auto membershipState = static_cast<organization::MembershipState>(statusValue(row[3], 3U));
            if (result.members.empty() || result.members.back().identity.value() != identity) {
                if (result.members.size() >= maxMembers)
                    throw std::runtime_error{"Native member count exceeds bound"};
                if (!result.members.empty() && result.members.back().identity.value() >= identity)
                    throw std::runtime_error{"Member rows are not strictly ordered"};
                result.members.push_back(administration::MemberSummary{
                    core::IdentityId{identity}, identityStatus, membershipState, {}});
            }
            auto& member = result.members.back();
            if (member.identityStatus != identityStatus || member.membershipState != membershipState)
                throw std::runtime_error{"Inconsistent member projection"};
            if (row[4]) {
                const auto& role = *row[4];
                if (!validText(role) || member.roles.size() >= maxRoles
                    || member.membershipState == organization::MembershipState::Removed
                    || (!member.roles.empty() && member.roles.back().value() >= role))
                    throw std::runtime_error{"Invalid member role projection"};
                member.roles.emplace_back(role);
                if (member.identity == actor && role == "owner"
                    && identityStatus == core::IdentityStatus::Active
                    && membershipState == organization::MembershipState::Active)
                    ownerSeen = true;
            } else if (!member.roles.empty()) {
                throw std::runtime_error{"Unexpected missing membership role"};
            }
        }
        if (!ownerSeen)
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        co_return std::move(result);
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native tenant membership listing is unavailable.");
    }
}

asio::awaitable<foundation::Result<policy::AuthorizationRequest>>
CoroutinePostgresCanonicalFinalizer::readAuthorizationContextAsync(
    session::AuthenticatedSession authenticated, core::OrganizationId tenant,
    policy::Action action, policy::Resource resource)
{
    if (tenant.empty() || action.empty() || resource.empty())
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    auto membership = co_await readAuthorizationMembershipAsync(
        authenticated.session().identity(), tenant);
    if (!membership) co_return foundation::fail(membership.error());
    co_return fromActiveMembership(authenticated, tenant, membership.value(),
                                   std::move(action), std::move(resource));
}

asio::awaitable<foundation::Status>
CoroutinePostgresCanonicalFinalizer::authorizeConnectionTargetAsync(
    core::IdentityId target)
{
    if (target.empty())
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
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

asio::awaitable<foundation::Result<session::Session>>
CoroutinePostgresCanonicalFinalizer::authorizeDelegatedAccountAsync(
    std::string digestHex,foundation::Instant now)
{
    auto access=co_await readDelegatedAccessAsync(std::move(digestHex),now);
    if (!access) co_return foundation::fail(access.error());
    // Account endpoints do not have a sender-proof verification boundary.
    if (access->senderConstraint())
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    if (!access->permits("account"))
        co_return foundation::fail(foundation::ErrorCode::PermissionDenied);
    co_return access->authenticated().session();
}

asio::awaitable<foundation::Result<session::DelegatedAccess>>
CoroutinePostgresCanonicalFinalizer::readDelegatedAccessAsync(
    std::string digestHex,foundation::Instant now,foundation::Instant* issuedAt)
{
    constexpr std::size_t maximumGrants=256U;
    if (digestHex.size()!=64U || !std::ranges::all_of(digestHex,[](char ch){
        return (ch>='0' && ch<='9') || (ch>='a' && ch<='f');
    })) co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    try {
        const Deadline deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        Params params{std::move(digestHex),std::to_string(now.time_since_epoch().count()),
            std::string{m_impl->organization.value()}};
        // One statement snapshot: never assemble a grant from separately
        // observed token, lifecycle, scope or audience state. The lateral
        // union avoids the scope/audience Cartesian product.
        const auto result=co_await lease.connection().query(
            "SELECT f.identity_id,f.provider,f.assurance,f.factors,f.phishing_resistant,"
            "f.authenticated_at_ms,t.expires_at_ms,c.id,"
            "f.sender_constraint_kind,f.sender_constraint_value,g.kind,g.value,t.issued_at_ms "
            "FROM openproof.oauth_access_tokens t "
            "JOIN openproof.oauth_token_families f ON f.id=t.family_id "
            "JOIN openproof.oauth_clients c ON c.id=f.client_id "
            "JOIN openproof.applications a ON a.id=c.application_id "
            "JOIN openproof.identities i ON i.id=f.identity_id "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "LEFT JOIN LATERAL ("
            "SELECT 0 AS kind,s.scope AS value FROM openproof.oauth_token_family_scopes s WHERE s.family_id=f.id "
            "UNION ALL "
            "SELECT 1 AS kind,u.audience AS value FROM openproof.oauth_token_family_audiences u WHERE u.family_id=f.id "
            "ORDER BY kind,value LIMIT 257) g ON true "
            "WHERE t.token_digest=decode($1,'hex') AND t.state=0 "
            "AND t.revoked_at_ms IS NULL AND t.issued_at_ms<=$2 AND t.expires_at_ms>$2 "
            "AND f.revoked_at_ms IS NULL AND f.authenticated_at_ms<=$2 "
            "AND c.status=0 AND a.status=0 AND i.status=0 AND o.state=0 "
            "AND i.organization_id=$3 AND a.organization_id=$3 "
            "ORDER BY g.kind,g.value",
            std::move(params),remaining(deadline));
        if (result.rows.empty())
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        if (result.rows.size()>maximumGrants || result.rows.front().size()!=13U)
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        const auto& row=result.rows.front();
        const auto assurance=milliseconds(row[2]);
        const auto factors=milliseconds(row[3]);
        if (assurance>4 || factors>7 || row[8].has_value()!=row[9].has_value())
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        std::optional<session::DelegatedSenderConstraint> sender;
        if (row[8]) {
            const auto kind=milliseconds(row[8]);
            if (kind>1 || row[9]->empty() || row[9]->size()>256U)
                co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
            sender.emplace(kind==0?session::DelegatedSenderConstraintKind::Dpop
                :session::DelegatedSenderConstraintKind::Mtls,*row[9]);
        }
        std::vector<std::string> scopes,audiences;
        for (const auto& grant:result.rows) {
            if (grant.size()!=13U || !std::equal(row.begin(),row.begin()+10,grant.begin())
                || grant[12]!=row[12])
                co_return foundation::fail(foundation::ErrorCode::Unavailable);
            if (!grant[10] && !grant[11]) {
                if (result.rows.size()!=1U) co_return foundation::fail(foundation::ErrorCode::Unavailable);
                continue;
            }
            if (!grant[10] || !grant[11])
                co_return foundation::fail(foundation::ErrorCode::Unavailable);
            const auto kind=milliseconds(grant[10]);
            const auto& value=*grant[11];
            if (kind==0 && !value.empty() && value.size()<=128U
                && std::ranges::all_of(value,[](char ch){
                    const auto byte=static_cast<unsigned char>(ch);
                    return byte==0x21U || (byte>=0x23U && byte<=0x5BU)
                        || (byte>=0x5DU && byte<=0x7EU);
                })) {
                scopes.push_back(value);
            } else if (kind==1 && !value.empty() && value.size()<=2048U
                && std::ranges::none_of(value,[](char ch){
                    const auto byte=static_cast<unsigned char>(ch);
                    return byte<0x20U || byte==0x7fU;
                })) {
                audiences.push_back(value);
            } else co_return foundation::fail(foundation::ErrorCode::Unavailable);
        }
        auto authorized=session::AuthenticatedSession::fromDelegatedAccess(
            core::IdentityId{required(row[0])},idp::ProviderId{required(row[1])},
            static_cast<idp::AssuranceLevel>(assurance),
            idp::AuthenticationStrength{static_cast<idp::AuthenticationFactor>(factors),boolean(row[4])},
            foundation::Instant{foundation::Duration{milliseconds(row[5])}},now,
            foundation::Instant{foundation::Duration{milliseconds(row[6])}});
        if (!authorized) co_return foundation::fail(authorized.error());
        const auto issued=foundation::Instant{foundation::Duration{milliseconds(row[12])}};
        if (issued>now || issued>=foundation::Instant{foundation::Duration{milliseconds(row[6])}})
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        if (issuedAt) *issuedAt=issued;
        co_return session::DelegatedAccess{std::move(authorized).value(),required(row[7]),
            std::move(scopes),std::move(audiences),std::move(sender)};
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable);
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresCanonicalFinalizer::consumeSenderReplayAsync(
    session::DelegatedSenderConstraintKind kind,std::string thumbprint,
    std::string identifier,foundation::Instant expiresAt,foundation::Instant now)
{
    const auto valid=[](const std::string& value,std::size_t maximum) {
        return !value.empty() && value.size()<=maximum
            && std::ranges::none_of(value,[](char ch){
                const auto byte=static_cast<unsigned char>(ch);
                return byte<0x20U || byte==0x7fU;
            });
    };
    if ((kind!=session::DelegatedSenderConstraintKind::Dpop
            && kind!=session::DelegatedSenderConstraintKind::Mtls)
        || !valid(thumbprint,128U) || !valid(identifier,256U)
        || now.time_since_epoch().count()<0 || expiresAt<=now
        || expiresAt-now>std::chrono::minutes{12})
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    try {
        const Deadline deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        // Replay keys are GLOBAL, matching the legacy tables. A token proof
        // must not become redeemable again merely by changing tenants.
        // Bounded cleanup excludes the inserted key and skips locked rows.
        // Conflict handling is atomic even across native/legacy connections.
        constexpr auto dpopSql=
            "WITH expired AS (SELECT jwk_thumbprint,jwt_id FROM openproof.oauth_dpop_replays "
            "WHERE expires_at_ms<=$4 AND (jwk_thumbprint,jwt_id)<>($1,$2) "
            "ORDER BY expires_at_ms LIMIT 64 FOR UPDATE SKIP LOCKED),"
            "purged AS (DELETE FROM openproof.oauth_dpop_replays r USING expired e "
            "WHERE r.jwk_thumbprint=e.jwk_thumbprint AND r.jwt_id=e.jwt_id) "
            "INSERT INTO openproof.oauth_dpop_replays AS r(jwk_thumbprint,jwt_id,expires_at_ms) "
            "VALUES($1,$2,$3) ON CONFLICT(jwk_thumbprint,jwt_id) DO UPDATE "
            "SET expires_at_ms=EXCLUDED.expires_at_ms WHERE r.expires_at_ms<=$4 RETURNING 1";
        constexpr auto mtlsSql=
            "WITH expired AS (SELECT certificate_thumbprint,nonce FROM openproof.oauth_mtls_forwarding_replays "
            "WHERE expires_at_ms<=$4 AND (certificate_thumbprint,nonce)<>($1,$2) "
            "ORDER BY expires_at_ms LIMIT 64 FOR UPDATE SKIP LOCKED),"
            "purged AS (DELETE FROM openproof.oauth_mtls_forwarding_replays r USING expired e "
            "WHERE r.certificate_thumbprint=e.certificate_thumbprint AND r.nonce=e.nonce) "
            "INSERT INTO openproof.oauth_mtls_forwarding_replays AS r(certificate_thumbprint,nonce,expires_at_ms) "
            "VALUES($1,$2,$3) ON CONFLICT(certificate_thumbprint,nonce) DO UPDATE "
            "SET expires_at_ms=EXCLUDED.expires_at_ms WHERE r.expires_at_ms<=$4 RETURNING 1";
        Params params{std::move(thumbprint),std::move(identifier),
            std::to_string(expiresAt.time_since_epoch().count()),
            std::to_string(now.time_since_epoch().count())};
        const auto result=co_await lease.connection().query(
            kind==session::DelegatedSenderConstraintKind::Dpop?dpopSql:mtlsSql,
            std::move(params),remaining(deadline));
        if (result.rows.empty())
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        if (result.rows.size()!=1U || result.rows.front().size()!=1U
            || required(result.rows.front().front())!="1")
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable);
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresCanonicalFinalizer::authorizeHandoffOwnerAsync(
    core::IdentityId owner,core::ExternalIdentityRef external)
{
    if (owner.empty() || owner.value().size()>200U
        || external.providerId().empty() || external.providerId().value().size()>128U
        || external.subject().empty() || external.subject().value().size()>1000U)
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const Deadline deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        Params params{std::string{owner.value()},std::string{external.providerId().value()},
            std::string{external.subject().value()},std::string{m_impl->organization.value()}};
        const auto rows=co_await lease.connection().query(
            "SELECT i.id FROM openproof.external_identities e "
            "JOIN openproof.identities i ON i.id=e.identity_id "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "WHERE i.id=$1 AND e.provider=$2 AND e.external_subject=$3 "
            "AND i.organization_id=$4 AND i.status=0 AND o.state=0",
            std::move(params),remaining(deadline));
        if (rows.rows.size()!=1U || rows.rows.front().size()!=1U
            || required(rows.rows.front().front())!=owner.value())
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable);
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresCanonicalFinalizer::updatePresentationAsync(
    core::IdentityId owner,core::ExternalIdentityRef external,foundation::Instant now)
{
    if (owner.empty() || owner.value().size()>200U
        || external.providerId().empty() || external.providerId().value().size()>128U
        || external.subject().empty() || external.subject().value().size()>1000U)
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    const auto safe=[](const auto& field,std::size_t maximum) {
        return !field || (field->size()<=maximum && field->find('\0')==std::string::npos);
    };
    if (!safe(external.displayName(),256U) || !safe(external.preferredUsername(),128U)
        || !safe(external.pictureUrl(),2048U))
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const Deadline deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        static_cast<void>(co_await connection.query("BEGIN",{},remaining(deadline)));
        if (!(co_await activeTarget(connection,std::string{owner.value()},
                std::string{m_impl->organization.value()},deadline,true))) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        Params params{std::string{owner.value()},std::string{external.providerId().value()},
            std::string{external.subject().value()},optionalText(external.displayName()),
            optionalText(external.preferredUsername()),optionalText(external.pictureUrl())};
        const auto updated=co_await connection.query(
            "UPDATE openproof.external_identities SET "
            "display_name=COALESCE(NULLIF($4,''),display_name),"
            "preferred_username=COALESCE(NULLIF($5,''),preferred_username),"
            "picture_url=COALESCE(NULLIF($6,''),picture_url) "
            "WHERE identity_id=$1 AND provider=$2 AND external_subject=$3 RETURNING identity_id",
            std::move(params),remaining(deadline));
        if (updated.rows.size()!=1U || updated.rows.front().size()!=1U
            || required(updated.rows.front().front())!=owner.value()) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        idp::VerifiedClaims presentation;
        if (external.displayName()) presentation.set(idp::ClaimName::DisplayName,std::string{*external.displayName()});
        if (external.preferredUsername()) presentation.set(idp::ClaimName::PreferredUsername,std::string{*external.preferredUsername()});
        if (external.pictureUrl()) presentation.set(idp::ClaimName::PictureUrl,std::string{*external.pictureUrl()});
        if (!presentation.empty())
            co_await saveProfile(connection,owner,presentation,now,deadline,ProfilePurpose::Connection);
        static_cast<void>(co_await connection.query("COMMIT",{},remaining(deadline)));
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable);
    }
}

asio::awaitable<foundation::Result<core::ExternalIdentityRef>>
CoroutinePostgresCanonicalFinalizer::finishConnectionAsync(
    const idp::AuthenticationOutcome& outcome,
    core::IdentityId target,
    foundation::Instant completedAt)
{
    if (outcome.requiredCanonicalOwner())
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
            "Owner-bound credentials cannot authorize a link ceremony.");
    if (target.empty() || outcome.provider().empty() || outcome.subject().empty()) {
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
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

asio::awaitable<foundation::Status>
CoroutinePostgresCanonicalFinalizer::disconnectAsync(core::IdentityId owner,
    core::ExternalIdentityRef external,std::vector<idp::ProviderId> authenticationProviders,
    foundation::Instant now)
{
    using E=foundation::ErrorCode;
    if (owner.empty() || owner.value().size()>200U || external.providerId().empty()
        || external.providerId().value().size()>128U || external.subject().empty()
        || external.subject().value().size()>512U || authenticationProviders.empty()
        || authenticationProviders.size()>256U
        || std::find(authenticationProviders.begin(),authenticationProviders.end(),
            external.providerId())==authenticationProviders.end())
        co_return foundation::fail(E::InvalidArgument);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        static_cast<void>(co_await connection.query("BEGIN",{},remaining(deadline)));
        // Match the legacy detach/merge advisory lock BEFORE taking row locks,
        // then share the canonical identity lock with linking/profile writes.
        Params lockParams{std::string{owner.value()}};
        static_cast<void>(co_await connection.query(
            "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 684271993))",
            std::move(lockParams),remaining(deadline)));
        if (!(co_await activeTarget(connection,std::string{owner.value()},
                std::string{m_impl->organization.value()},deadline,true))) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationFailed);
        }
        Params ownedParams{std::string{external.providerId().value()},std::string{external.subject().value()}};
        const auto linked=co_await connection.query(
            "SELECT identity_id FROM openproof.external_identities "
            "WHERE provider=$1 AND external_subject=$2 FOR UPDATE",
            std::move(ownedParams),remaining(deadline));
        if (linked.rows.empty()) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::NotFound);
        }
        if (linked.rows.size()!=1U || linked.rows.front().size()!=1U)
            throw std::runtime_error{"Malformed connection ownership"};
        if (required(linked.rows.front().front())!=owner.value()) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::PermissionDenied);
        }
        // Lock one different registered authentication connection, excluding
        // verification-only providers and the exact target. SQL parameters
        // remain separate from the dynamically generated placeholder list.
        Params survivorParams{std::string{owner.value()},std::string{external.providerId().value()},
            std::string{external.subject().value()}};
        std::string survivorSql=
            "SELECT identity_id FROM openproof.external_identities WHERE identity_id=$1 "
            "AND NOT (provider=$2 AND external_subject=$3) AND provider IN (";
        for (const auto& provider:authenticationProviders) {
            if (provider.empty() || provider.value().size()>200U)
                throw std::runtime_error{"Invalid authentication provider snapshot"};
            if (survivorParams.size()>3U) survivorSql.push_back(',');
            survivorSql.append("$"+std::to_string(survivorParams.size()+1U));
            survivorParams.emplace_back(std::string{provider.value()});
        }
        survivorSql.append(") ORDER BY provider,external_subject LIMIT 1 FOR UPDATE");
        const auto survivor=co_await connection.query(std::move(survivorSql),
            std::move(survivorParams),remaining(deadline));
        if (survivor.rows.empty()) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::FailedPrecondition);
        }
        if (survivor.rows.size()!=1U || survivor.rows.front().size()!=1U
            || required(survivor.rows.front().front())!=owner.value())
            throw std::runtime_error{"Invalid surviving authentication method"};
        Params detachParams{std::string{external.providerId().value()},
            std::string{external.subject().value()},std::string{owner.value()}};
        const auto removed=co_await connection.query(
            "DELETE FROM openproof.external_identities WHERE provider=$1 AND external_subject=$2 "
            "AND identity_id=$3 RETURNING identity_id",std::move(detachParams),remaining(deadline));
        if (removed.rows.size()!=1U || removed.rows.front().size()!=1U
            || required(removed.rows.front().front())!=owner.value())
            throw std::runtime_error{"Connection detach owner mismatch"};
        Params avatarParams{std::string{owner.value()},std::string{external.providerId().value()},
            std::to_string(now.time_since_epoch().count())};
        static_cast<void>(co_await connection.query(
            "UPDATE openproof.identity_profiles SET avatar_source='auto',"
            "updated_at_ms=GREATEST(updated_at_ms,$3::bigint) "
            "WHERE identity_id=$1 AND avatar_source=$2",std::move(avatarParams),remaining(deadline)));
        static_cast<void>(co_await connection.query("COMMIT",{},remaining(deadline)));
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native account disconnection is unavailable.");
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresCanonicalFinalizer::authenticateConfidentialClientAsync(
    std::string clientId,std::string digestHex)
{
    using E=foundation::ErrorCode;
    if (clientId.empty() || clientId.size()>256U || digestHex.size()!=64U)
        co_return foundation::fail(E::AuthenticationFailed);
    auto presented=foundation::fromHex(digestHex);
    if (!presented || presented->size()!=32U) co_return foundation::fail(E::AuthenticationFailed);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        Params params{std::move(clientId),std::string{m_impl->organization.value()}};
        const auto result=co_await lease.connection().query(
            "SELECT encode(c.secret_digest,'hex') FROM openproof.oauth_clients c "
            "JOIN openproof.applications a ON a.id=c.application_id "
            "JOIN openproof.organizations o ON o.id=a.organization_id "
            "WHERE c.id=$1 AND a.organization_id=$2 AND o.state=0 "
            "AND c.status=0 AND a.status=0 AND c.kind IN (0,3) LIMIT 2",
            std::move(params),remaining(deadline));
        if (result.rows.empty()) co_return foundation::fail(E::AuthenticationFailed);
        if (result.rows.size()!=1U || result.rows.front().size()!=1U)
            co_return foundation::fail(E::Unavailable);
        auto stored=foundation::fromHex(required(result.rows.front().front()));
        if (!stored || stored->size()!=32U) co_return foundation::fail(E::Unavailable);
        if (!security::constantTimeEquals(*presented,*stored))
            co_return foundation::fail(E::AuthenticationFailed);
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable);
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresCanonicalFinalizer::revokeOAuthTokenAsync(std::string clientId,
    std::optional<std::string> clientDigest,std::string tokenDigest,foundation::Instant now)
{
    using E=foundation::ErrorCode;
    const auto validDigest=[](std::string_view digest) {
        return digest.size()==64U && std::ranges::all_of(digest,[](char ch) {
            return (ch>='0' && ch<='9') || (ch>='a' && ch<='f');
        });
    };
    if (clientId.empty() || clientId.size()>256U || !validDigest(tokenDigest)
        || (clientDigest && !validDigest(*clientDigest)))
        co_return foundation::fail(E::InvalidArgument);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params params) {
            return connection.query(std::move(sql),std::move(params),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        const std::string tenant{m_impl->organization.value()};
        Params callerParams{clientId,tenant};
        const auto caller=co_await execute(
            "SELECT c.kind,encode(c.secret_digest,'hex') FROM openproof.oauth_clients c "
            "JOIN openproof.applications a ON a.id=c.application_id "
            "JOIN openproof.organizations o ON o.id=a.organization_id "
            "WHERE c.id=$1 AND a.organization_id=$2 AND o.state=0 "
            "AND c.status=0 AND a.status=0 FOR SHARE OF c,a,o",std::move(callerParams));
        bool authenticated=false;
        if (caller.rows.size()==1U && caller.rows.front().size()==2U) {
            const auto& row=caller.rows.front();
            const auto kind=milliseconds(row[0]);
            if ((kind==1 || kind==2) && !row[1] && !clientDigest) authenticated=true;
            if ((kind==0 || kind==3) && row[1] && clientDigest) {
                auto presented=foundation::fromHex(*clientDigest);
                auto stored=foundation::fromHex(*row[1]);
                authenticated=presented && stored && presented->size()==32U
                    && stored->size()==32U && security::constantTimeEquals(*presented,*stored);
            }
        }
        if (!authenticated) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationFailed);
        }
        // Locate without locking token rows; acquire the family lock FIRST.
        // All rotation and family-revocation writers use the same order.
        // Authorization is bound to the authenticated client and tenant.
        Params familyParams{tokenDigest,clientId,tenant};
        const auto found=co_await execute(
            "WITH candidates AS ("
            "SELECT family_id,true AS access FROM openproof.oauth_access_tokens WHERE token_digest=decode($1,'hex') "
            "UNION ALL SELECT family_id,false AS access FROM openproof.oauth_refresh_tokens WHERE token_digest=decode($1,'hex')) "
            "SELECT f.id,t.access FROM candidates t JOIN openproof.oauth_token_families f ON f.id=t.family_id "
            "JOIN openproof.identities i ON i.id=f.identity_id "
            "WHERE f.client_id=$2 AND i.organization_id=$3 "
            "ORDER BY f.id LIMIT 2 FOR UPDATE OF f",std::move(familyParams));
        if (found.rows.empty()) {
            static_cast<void>(co_await execute("COMMIT",{}));
            co_return foundation::ok();
        }
        if (found.rows.size()!=1U || found.rows.front().size()!=2U)
            throw std::runtime_error{"Ambiguous OAuth token family"};
        const auto family=required(found.rows.front()[0]);
        const auto access=boolean(found.rows.front()[1]);
        const auto timestamp=std::to_string(now.time_since_epoch().count());
        if (access) {
            Params args{tokenDigest,family,timestamp};
            const auto revoked=co_await execute(
                "UPDATE openproof.oauth_access_tokens SET state=1,revoked_at_ms=COALESCE(revoked_at_ms,$3) "
                "WHERE token_digest=decode($1,'hex') AND family_id=$2 RETURNING family_id",std::move(args));
            if (revoked.rows.size()!=1U || required(revoked.rows.front().front())!=family)
                throw std::runtime_error{"OAuth access revocation mismatch"};
        } else {
            // A refresh credential revokes the entire family, including all
            // successors minted before acquiring the family lock.
            Params args{family,timestamp};
            const auto revoked=co_await execute(
                "UPDATE openproof.oauth_token_families SET revoked_at_ms=COALESCE(revoked_at_ms,$2) "
                "WHERE id=$1 RETURNING id",std::move(args));
            if (revoked.rows.size()!=1U || required(revoked.rows.front().front())!=family)
                throw std::runtime_error{"OAuth family revocation mismatch"};
            Params accessArgs{family,timestamp};
            static_cast<void>(co_await execute(
                "UPDATE openproof.oauth_access_tokens SET state=1,revoked_at_ms=COALESCE(revoked_at_ms,$2) "
                "WHERE family_id=$1 AND state=0",std::move(accessArgs)));
            Params refreshArgs{family,timestamp};
            static_cast<void>(co_await execute(
                "UPDATE openproof.oauth_refresh_tokens SET state=2,changed_at_ms=COALESCE(changed_at_ms,$2) "
                "WHERE family_id=$1 AND state<>2",std::move(refreshArgs)));
        }
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native OAuth token revocation is unavailable.");
    }
}

asio::awaitable<foundation::Result<std::vector<std::string>>>
CoroutinePostgresCanonicalFinalizer::rotateOAuthRefreshAsync(
    std::string clientId,std::optional<std::string> clientDigest,std::string presentedDigest,
    std::string accessDigest,std::string refreshDigest,
    std::optional<session::DelegatedSenderConstraint> sender,foundation::Instant now,
    foundation::Duration accessLifetime)
{
    using E=foundation::ErrorCode;
    const auto validDigest=[](std::string_view digest) {
        return digest.size()==64U && std::ranges::all_of(digest,[](char ch) {
            return (ch>='0' && ch<='9') || (ch>='a' && ch<='f');
        });
    };
    if (clientId.empty() || clientId.size()>256U || !validDigest(presentedDigest)
        || !validDigest(accessDigest) || !validDigest(refreshDigest)
        || presentedDigest==accessDigest || presentedDigest==refreshDigest || accessDigest==refreshDigest
        || (clientDigest && !validDigest(*clientDigest))
        || accessLifetime<=foundation::Duration::zero() || accessLifetime>std::chrono::hours{1}
        || now.time_since_epoch().count()<0
        || now.time_since_epoch().count()>foundation::Duration::max().count()-accessLifetime.count())
        co_return foundation::fail(E::InvalidArgument);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params params) {
            return connection.query(std::move(sql),std::move(params),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        const std::string tenant{m_impl->organization.value()};
        Params callerParams{clientId,tenant};
        const auto caller=co_await execute(
            "SELECT c.kind,encode(c.secret_digest,'hex') FROM openproof.oauth_clients c "
            "JOIN openproof.applications a ON a.id=c.application_id "
            "JOIN openproof.organizations o ON o.id=a.organization_id "
            "WHERE c.id=$1 AND a.organization_id=$2 AND o.state=0 "
            "AND c.status=0 AND a.status=0 FOR SHARE OF c,a,o",std::move(callerParams));
        bool authenticated=false;
        if (caller.rows.size()==1U && caller.rows.front().size()==2U) {
            const auto& row=caller.rows.front();
            const auto kind=milliseconds(row[0]);
            if ((kind==1 || kind==2) && !row[1] && !clientDigest) authenticated=true;
            if ((kind==0 || kind==3) && row[1] && clientDigest) {
                auto presented=foundation::fromHex(*clientDigest);
                auto stored=foundation::fromHex(*row[1]);
                authenticated=presented && stored && presented->size()==32U
                    && stored->size()==32U && security::constantTimeEquals(*presented,*stored);
            }
        }
        if (!authenticated) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationRequired);
        }
        // Client -> identity -> family -> token lock order. Share the family
        // lock with revocation and legacy rotation; take a fresh token snapshot
        // after admission so a concurrent successor cannot escape revocation.
        Params familyParams{presentedDigest,clientId,tenant};
        const auto locked=co_await execute(
            "SELECT f.id,f.revoked_at_ms,f.sender_constraint_kind,f.sender_constraint_value "
            "FROM openproof.oauth_refresh_tokens r JOIN openproof.oauth_token_families f ON f.id=r.family_id "
            "JOIN openproof.identities i ON i.id=f.identity_id "
            "WHERE r.token_digest=decode($1,'hex') AND f.client_id=$2 AND i.organization_id=$3 "
            "AND i.status=0 FOR UPDATE OF f FOR SHARE OF i",std::move(familyParams));
        if (locked.rows.empty()) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationFailed);
        }
        if (locked.rows.size()!=1U || locked.rows.front().size()!=4U)
            throw std::runtime_error{"Malformed refresh family"};
        const auto& binding=locked.rows.front();
        const auto family=required(binding[0]);
        const bool senderMatches=(!sender && !binding[2] && !binding[3])
            || (sender && binding[2] && binding[3]
                && milliseconds(binding[2])==static_cast<int>(sender->kind())
                && *binding[3]==sender->value());
        if (binding[1] || !senderMatches) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationFailed);
        }
        Params tokenParams{presentedDigest,family};
        const auto current=co_await execute(
            "SELECT sequence,state,issued_at_ms,expires_at_ms FROM openproof.oauth_refresh_tokens "
            "WHERE token_digest=decode($1,'hex') AND family_id=$2 FOR UPDATE",std::move(tokenParams));
        if (current.rows.size()!=1U || current.rows.front().size()!=4U)
            throw std::runtime_error{"Malformed refresh token"};
        const auto& row=current.rows.front();
        const auto sequence=milliseconds(row[0]),state=milliseconds(row[1]);
        const auto issued=milliseconds(row[2]),expires=milliseconds(row[3]);
        const auto observed=now.time_since_epoch().count();
        const auto timestamp=std::to_string(observed);
        if (state!=0 || expires<=observed) {
            Params familyArgs{family,timestamp};
            static_cast<void>(co_await execute(
                "UPDATE openproof.oauth_token_families SET revoked_at_ms=COALESCE(revoked_at_ms,$2) WHERE id=$1",
                std::move(familyArgs)));
            Params accessArgs{family,timestamp};
            static_cast<void>(co_await execute(
                "UPDATE openproof.oauth_access_tokens SET state=1,revoked_at_ms=COALESCE(revoked_at_ms,$2) "
                "WHERE family_id=$1 AND state=0",std::move(accessArgs)));
            Params refreshArgs{family,timestamp};
            static_cast<void>(co_await execute(
                "UPDATE openproof.oauth_refresh_tokens SET state=2,changed_at_ms=COALESCE(changed_at_ms,$2) "
                "WHERE family_id=$1 AND state<>2",std::move(refreshArgs)));
            // Reuse detection must commit the revocation, not roll it back.
            static_cast<void>(co_await execute("COMMIT",{}));
            co_return foundation::fail(E::AuthenticationFailed);
        }
        if (issued>observed || sequence==std::numeric_limits<std::int64_t>::max())
            throw std::runtime_error{"Invalid refresh token chronology"};
        Params scopeParams{family};
        const auto grants=co_await execute(
            "SELECT scope FROM openproof.oauth_token_family_scopes WHERE family_id=$1 "
            "ORDER BY scope COLLATE \"C\" LIMIT 257",std::move(scopeParams));
        if (grants.rows.size()>256U) throw std::runtime_error{"Oversized refresh scope set"};
        std::vector<std::string> scopes;
        for (const auto& grant:grants.rows) {
            if (grant.size()!=1U) throw std::runtime_error{"Invalid refresh scope"};
            const auto scope=required(grant[0]);
            if (scope.empty() || scope.size()>128U || !std::ranges::all_of(scope,[](char ch){
                const auto byte=static_cast<unsigned char>(ch);
                return byte==0x21U || (byte>=0x23U && byte<=0x5BU) || (byte>=0x5DU && byte<=0x7EU);
            })) throw std::runtime_error{"Invalid refresh scope"};
            scopes.push_back(scope);
        }
        Params consumeArgs{presentedDigest,family,timestamp};
        const auto used=co_await execute(
            "UPDATE openproof.oauth_refresh_tokens SET state=1,changed_at_ms=$3 "
            "WHERE token_digest=decode($1,'hex') AND family_id=$2 AND state=0 RETURNING family_id",
            std::move(consumeArgs));
        if (used.rows.size()!=1U || used.rows.front().size()!=1U || required(used.rows.front()[0])!=family)
            throw std::runtime_error{"Refresh consumption mismatch"};
        Params accessArgs{accessDigest,family,timestamp,std::to_string(observed+accessLifetime.count())};
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.oauth_access_tokens(token_digest,family_id,state,issued_at_ms,expires_at_ms) "
            "VALUES(decode($1,'hex'),$2,0,$3,$4)",std::move(accessArgs)));
        Params refreshArgs{refreshDigest,family,std::to_string(sequence+1),timestamp,std::to_string(expires)};
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.oauth_refresh_tokens(token_digest,family_id,sequence,state,issued_at_ms,expires_at_ms) "
            "VALUES(decode($1,'hex'),$2,$3,0,$4,$5)",std::move(refreshArgs)));
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return scopes;
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native OAuth refresh rotation is unavailable.");
    }
}

asio::awaitable<foundation::Result<oauth::NativeCodeExchangeResult>>
CoroutinePostgresCanonicalFinalizer::exchangeOAuthCodeAsync(
    std::string clientId,std::optional<std::string> clientDigest,
    std::string codeDigest,std::string redirectUri,std::string challenge,
    std::string family,std::string accessDigest,std::string refreshDigest,
    std::optional<session::DelegatedSenderConstraint> sender,foundation::Instant now,
    foundation::Duration accessLifetime,foundation::Duration refreshLifetime,
    SignCodeIdToken signIdToken)
{
    using E=foundation::ErrorCode;
    const auto validDigest=[](std::string_view digest) {
        return digest.size()==64U && std::ranges::all_of(digest,[](char ch) {
            return (ch>='0' && ch<='9') || (ch>='a' && ch<='f');
        });
    };
    if (clientId.empty() || clientId.size()>256U || !validDigest(codeDigest)
        || !validDigest(accessDigest) || !validDigest(refreshDigest) || accessDigest==refreshDigest
        || (clientDigest && !validDigest(*clientDigest)) || family.empty() || family.size()>200U
        || redirectUri.empty() || redirectUri.size()>2048U || challenge.size()!=43U
        || accessLifetime<=foundation::Duration::zero() || accessLifetime>std::chrono::hours{1}
        || refreshLifetime<=accessLifetime || refreshLifetime>std::chrono::hours{24*365}
        || now.time_since_epoch().count()<0
        || now.time_since_epoch().count()>foundation::Duration::max().count()-refreshLifetime.count()
        || (sender && (sender->value().empty() || sender->value().size()>256U)))
        co_return foundation::fail(E::InvalidArgument);
    try {
        auto challengeValue=oauth::PkceChallenge::create(challenge);
        auto digestBytes=foundation::fromHex(codeDigest);
        if (!challengeValue || !digestBytes || digestBytes->size()!=32U)
            co_return foundation::fail(E::InvalidArgument);
        std::array<std::byte,32> codeBytes{};
        std::copy(digestBytes->begin(),digestBytes->end(),codeBytes.begin());
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params params) {
            return connection.query(std::move(sql),std::move(params),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        const std::string tenant{m_impl->organization.value()};
        Params callerParams{clientId,tenant};
        const auto caller=co_await execute(
            "SELECT c.kind,encode(c.secret_digest,'hex') FROM openproof.oauth_clients c "
            "JOIN openproof.applications a ON a.id=c.application_id "
            "JOIN openproof.organizations o ON o.id=a.organization_id "
            "WHERE c.id=$1 AND a.organization_id=$2 AND o.state=0 "
            "AND c.status=0 AND a.status=0 FOR SHARE OF c,a,o",std::move(callerParams));
        bool authenticated=false;
        if (caller.rows.size()==1U && caller.rows.front().size()==2U) {
            const auto& row=caller.rows.front();
            const auto kind=milliseconds(row[0]);
            if ((kind==1 || kind==2) && !row[1] && !clientDigest) authenticated=true;
            if ((kind==0 || kind==3) && row[1] && clientDigest) {
                auto presented=foundation::fromHex(*clientDigest);
                auto stored=foundation::fromHex(*row[1]);
                authenticated=presented && stored && presented->size()==32U
                    && stored->size()==32U && security::constantTimeEquals(*presented,*stored);
            }
        }
        if (!authenticated) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationRequired);
        }
        const auto timestamp=std::to_string(now.time_since_epoch().count());
        Params codeArgs{codeDigest,clientId,tenant,redirectUri,challenge,timestamp};
        // All binding and lifecycle checks precede any destructive write.
        // The same code row is locked by the old consumeBound implementation.
        const auto locked=co_await execute(
            "SELECT g.identity_id,g.provider,g.assurance,g.factors,g.phishing_resistant,"
            "g.authenticated_at_ms,g.issued_at_ms,g.expires_at_ms,g.nonce,g.resource "
            "FROM openproof.oauth_authorization_codes g "
            "JOIN openproof.identities i ON i.id=g.identity_id "
            "WHERE g.code_digest=decode($1,'hex') AND g.client_id=$2 AND i.organization_id=$3 "
            "AND g.redirect_uri=$4 AND g.code_challenge=$5 "
            "AND g.issued_at_ms<=$6 AND g.expires_at_ms>$6 AND i.status=0 "
            "FOR UPDATE OF g FOR SHARE OF i",std::move(codeArgs));
        if (locked.rows.empty()) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationFailed);
        }
        if (locked.rows.size()!=1U || locked.rows.front().size()!=10U)
            throw std::runtime_error{"Malformed authorization code"};
        const auto& row=locked.rows.front();
        const auto assurance=milliseconds(row[2]),factors=milliseconds(row[3]);
        if (assurance>4 || factors>7) throw std::runtime_error{"Malformed authentication context"};
        Params scopeArgs{codeDigest};
        const auto grantRows=co_await execute(
            "SELECT scope FROM openproof.oauth_authorization_code_scopes WHERE code_digest=decode($1,'hex') "
            "ORDER BY scope COLLATE \"C\" LIMIT 257 FOR SHARE",std::move(scopeArgs));
        if (grantRows.rows.empty() || grantRows.rows.size()>256U)
            throw std::runtime_error{"Invalid authorization code scope set"};
        std::vector<client::Scope> parsedScopes;
        oauth::NativeCodeExchangeResult result;
        bool openid=false;
        for (const auto& grant:grantRows.rows) {
            if (grant.size()!=1U) throw std::runtime_error{"Malformed authorization code scope"};
            auto parsed=client::Scope::create(required(grant[0]));
            if (!parsed) throw std::runtime_error{"Invalid authorization code scope"};
            openid=openid || parsed->value()=="openid";
            result.scopes.emplace_back(parsed->value());
            parsedScopes.emplace_back(std::move(parsed).value());
        }
        auto code=oauth::AuthorizationCode::restore(oauth::CodeDigest{codeBytes},
            client::ClientId{clientId},core::IdentityId{required(row[0])},redirectUri,
            std::move(parsedScopes),std::move(challengeValue).value(),row[8],
            idp::ProviderId{required(row[1])},static_cast<idp::AssuranceLevel>(assurance),
            idp::AuthenticationStrength{static_cast<idp::AuthenticationFactor>(factors),boolean(row[4])},
            foundation::Instant{foundation::Duration{milliseconds(row[5])}},
            foundation::Instant{foundation::Duration{milliseconds(row[6])}},
            foundation::Instant{foundation::Duration{milliseconds(row[7])}},row[9]);
        if (!code) throw std::runtime_error{"Invalid stored authorization code"};
        if (openid) {
            // Signing is pure local CPU work. Keep the JWT in a wiping owner
            // until COMMIT, so a signing failure cannot consume the code.
            if (!signIdToken) co_return foundation::fail(E::Unavailable);
            auto signedToken=signIdToken(code.value());
            if (!signedToken) co_return foundation::fail(E::Unavailable);
            result.idToken.emplace(std::move(signedToken).value());
        }
        Params familyArgs{family,clientId,std::string{code->identity().value()},
            std::string{code->provider().value()},std::to_string(assurance),std::to_string(factors),
            boolean(row[4])?"true":"false",required(row[5]),
            sender?std::optional<std::string>{std::to_string(static_cast<int>(sender->kind()))}:std::nullopt,
            sender?std::optional<std::string>{std::string{sender->value()}}:std::nullopt};
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.oauth_token_families "
            "(id,client_id,identity_id,provider,assurance,factors,phishing_resistant,authenticated_at_ms,sender_constraint_kind,sender_constraint_value) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",std::move(familyArgs)));
        for (const auto& scope:result.scopes) {
            Params args{family,scope};
            static_cast<void>(co_await execute(
                "INSERT INTO openproof.oauth_token_family_scopes(family_id,scope) VALUES($1,$2)",std::move(args)));
        }
        if (code->resource()) {
            Params args{family,*code->resource()};
            static_cast<void>(co_await execute(
                "INSERT INTO openproof.oauth_token_family_audiences(family_id,audience) VALUES($1,$2)",std::move(args)));
        }
        Params accessArgs{accessDigest,family,timestamp,std::to_string((now+accessLifetime).time_since_epoch().count())};
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.oauth_access_tokens(token_digest,family_id,state,issued_at_ms,expires_at_ms) "
            "VALUES(decode($1,'hex'),$2,0,$3,$4)",std::move(accessArgs)));
        Params refreshArgs{refreshDigest,family,timestamp,std::to_string((now+refreshLifetime).time_since_epoch().count())};
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.oauth_refresh_tokens(token_digest,family_id,sequence,state,issued_at_ms,expires_at_ms) "
            "VALUES(decode($1,'hex'),$2,0,0,$3,$4)",std::move(refreshArgs)));
        Params consumedArgs{codeDigest,clientId};
        const auto consumed=co_await execute(
            "DELETE FROM openproof.oauth_authorization_codes WHERE code_digest=decode($1,'hex') "
            "AND client_id=$2 RETURNING client_id",std::move(consumedArgs));
        if (consumed.rows.size()!=1U || consumed.rows.front().size()!=1U || required(consumed.rows.front()[0])!=clientId)
            throw std::runtime_error{"Authorization code consumption mismatch"};
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return std::move(result);
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native OAuth code exchange is unavailable.");
    }
}

asio::awaitable<foundation::Result<oauth::NativeMachineGrantResult>>
CoroutinePostgresCanonicalFinalizer::issueOAuthMachineGrantAsync(
    std::string clientId,std::optional<std::string> clientDigest,
    std::optional<std::string> subjectDigest,std::string audience,
    std::vector<std::string> requestedScopes,std::string family,std::string accessDigest,
    std::optional<session::DelegatedSenderConstraint> sender,foundation::Instant now,
    foundation::Duration accessLifetime)
{
    using E=foundation::ErrorCode;
    const auto validDigest=[](std::string_view digest) {
        return digest.size()==64U && std::ranges::all_of(digest,[](char ch) {
            return (ch>='0' && ch<='9') || (ch>='a' && ch<='f');
        });
    };
    if (clientId.empty() || clientId.size()>256U || audience.empty() || audience.size()>2048U
        || family.empty() || family.size()>200U || !validDigest(accessDigest)
        || (clientDigest && !validDigest(*clientDigest))
        || (subjectDigest && (!validDigest(*subjectDigest) || *subjectDigest==accessDigest))
        || requestedScopes.size()>256U
        || accessLifetime<=foundation::Duration::zero() || accessLifetime>std::chrono::hours{1}
        || now.time_since_epoch().count()<0
        || now.time_since_epoch().count()>foundation::Duration::max().count()-accessLifetime.count()
        || (sender && (sender->value().empty() || sender->value().size()>256U)))
        co_return foundation::fail(E::InvalidArgument);
    for (const auto& scope:requestedScopes)
        if (!client::Scope::create(scope)) co_return foundation::fail(E::InvalidArgument);
    std::ranges::sort(requestedScopes);
    requestedScopes.erase(std::unique(requestedScopes.begin(),requestedScopes.end()),requestedScopes.end());
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params params) {
            return connection.query(std::move(sql),std::move(params),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        const std::string tenant{m_impl->organization.value()};
        const auto observed=now.time_since_epoch().count();
        const auto timestamp=std::to_string(observed);
        Params callerParams{clientId,tenant};
        const auto caller=co_await execute(
            "SELECT c.kind,encode(c.secret_digest,'hex') FROM openproof.oauth_clients c "
            "JOIN openproof.applications a ON a.id=c.application_id "
            "JOIN openproof.organizations o ON o.id=a.organization_id "
            "WHERE c.id=$1 AND a.organization_id=$2 AND o.state=0 "
            "AND c.status=0 AND a.status=0 FOR SHARE OF c,a,o",std::move(callerParams));
        bool authenticated=false;
        std::int64_t kind=-1;
        if (caller.rows.size()==1U && caller.rows.front().size()==2U) {
            const auto& row=caller.rows.front();
            kind=milliseconds(row[0]);
            if ((kind==1 || kind==2) && !row[1] && !clientDigest) authenticated=true;
            if ((kind==0 || kind==3) && row[1] && clientDigest) {
                auto presented=foundation::fromHex(*clientDigest);
                auto stored=foundation::fromHex(*row[1]);
                authenticated=presented && stored && presented->size()==32U
                    && stored->size()==32U && security::constantTimeEquals(*presented,*stored);
            }
        }
        if (!authenticated) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationRequired);
        }
        if (!subjectDigest && kind!=3) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::FailedPrecondition);
        }
        // Parent row locks serialize resource and service scope replacement.
        Params resourceArgs{audience};
        const auto resource=co_await execute(
            "SELECT id FROM openproof.oauth_resources WHERE audience=$1 AND status=0 FOR SHARE",
            std::move(resourceArgs));
        if (resource.rows.empty()) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::NotFound);
        }
        if (resource.rows.size()!=1U || resource.rows.front().size()!=1U)
            throw std::runtime_error{"Malformed resource"};
        Params resourceScopeArgs{required(resource.rows.front()[0])};
        const auto resourceScopes=co_await execute(
            "SELECT scope FROM openproof.oauth_resource_scopes WHERE resource_id=$1 ORDER BY scope COLLATE \"C\" LIMIT 257 FOR SHARE",
            std::move(resourceScopeArgs));
        const auto scopesFrom=[](const auto& rows) {
            if (rows.size()>256U) throw std::runtime_error{"Oversized machine grant scopes"};
            std::vector<std::string> values;
            for (const auto& row:rows) {
                if (row.size()!=1U || !client::Scope::create(required(row[0])))
                    throw std::runtime_error{"Invalid machine grant scope"};
                values.push_back(required(row[0]));
            }
            return values;
        };
        const auto allowedResource=scopesFrom(resourceScopes.rows);
        std::vector<std::string> sourceScopes;
        std::string identityId,provider="client_credentials",assurance="1",factors="1",phishing="false",authenticatedAt=timestamp;
        auto expires=observed+accessLifetime.count();
        if (subjectDigest) {
            // The source family lock precedes the token lock, matching native
            // revocation and rotation. Read the source only after admission.
            Params args{*subjectDigest,clientId,tenant};
            const auto source=co_await execute(
                "SELECT f.id,f.identity_id,f.provider,f.assurance,f.factors,f.phishing_resistant,"
                "f.authenticated_at_ms,f.sender_constraint_kind,f.sender_constraint_value "
                "FROM openproof.oauth_access_tokens t JOIN openproof.oauth_token_families f ON f.id=t.family_id "
                "JOIN openproof.identities i ON i.id=f.identity_id "
                "WHERE t.token_digest=decode($1,'hex') AND f.client_id=$2 AND i.organization_id=$3 "
                "AND i.status=0 AND f.revoked_at_ms IS NULL FOR SHARE OF f,i",std::move(args));
            if (source.rows.empty()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::AuthenticationFailed);
            }
            if (source.rows.size()!=1U || source.rows.front().size()!=9U)
                throw std::runtime_error{"Malformed exchange subject"};
            const auto& row=source.rows.front();
            const auto sourceFamily=required(row[0]);
            const bool senderMatches=(!sender && !row[7] && !row[8])
                || (sender && row[7] && row[8] && milliseconds(row[7])==static_cast<int>(sender->kind())
                    && *row[8]==sender->value());
            if (!senderMatches || milliseconds(row[6])>observed) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::AuthenticationFailed);
            }
            Params liveArgs{*subjectDigest,sourceFamily,timestamp};
            const auto live=co_await execute(
                "SELECT expires_at_ms FROM openproof.oauth_access_tokens WHERE token_digest=decode($1,'hex') "
                "AND family_id=$2 AND state=0 AND revoked_at_ms IS NULL AND issued_at_ms<=$3 AND expires_at_ms>$3 FOR SHARE",
                std::move(liveArgs));
            if (live.rows.empty()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::AuthenticationFailed);
            }
            if (live.rows.size()!=1U || live.rows.front().size()!=1U)
                throw std::runtime_error{"Malformed source expiry"};
            expires=std::min(expires,milliseconds(live.rows.front()[0]));
            Params audienceArgs{sourceFamily,audience};
            const auto permitted=co_await execute(
                "SELECT audience FROM openproof.oauth_token_family_audiences WHERE family_id=$1 AND audience=$2 FOR SHARE",
                std::move(audienceArgs));
            if (permitted.rows.size()!=1U) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::AuthenticationFailed);
            }
            Params scopeArgs{sourceFamily};
            const auto grants=co_await execute(
                "SELECT scope FROM openproof.oauth_token_family_scopes WHERE family_id=$1 ORDER BY scope COLLATE \"C\" LIMIT 257 FOR SHARE",
                std::move(scopeArgs));
            sourceScopes=scopesFrom(grants.rows);
            identityId=required(row[1]); provider=required(row[2]);
            assurance=required(row[3]); factors=required(row[4]);
            phishing=boolean(row[5])?"true":"false"; authenticatedAt=required(row[6]);
        } else {
            Params args{clientId,tenant};
            const auto service=co_await execute(
                "SELECT s.identity_id FROM openproof.service_identities s "
                "JOIN openproof.identities i ON i.id=s.identity_id "
                "WHERE s.client_id=$1 AND i.organization_id=$2 AND s.active AND i.kind=1 AND i.status=0 "
                "FOR SHARE OF s,i",std::move(args));
            if (service.rows.empty()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::PermissionDenied);
            }
            if (service.rows.size()!=1U || service.rows.front().size()!=1U)
                throw std::runtime_error{"Malformed service identity"};
            identityId=required(service.rows.front()[0]);
            Params audienceArgs{clientId,audience};
            const auto permitted=co_await execute(
                "SELECT audience FROM openproof.service_identity_audiences WHERE client_id=$1 AND audience=$2 FOR SHARE",
                std::move(audienceArgs));
            if (permitted.rows.size()!=1U) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::PermissionDenied);
            }
            Params scopeArgs{clientId};
            const auto grants=co_await execute(
                "SELECT scope FROM openproof.service_identity_scopes WHERE client_id=$1 ORDER BY scope COLLATE \"C\" LIMIT 257 FOR SHARE",
                std::move(scopeArgs));
            sourceScopes=scopesFrom(grants.rows);
        }
        const bool defaultScopes=requestedScopes.empty();
        auto scopes=defaultScopes?std::move(sourceScopes):std::move(requestedScopes);
        // Default scopes are checked against the resource as well: no
        // implicit scope expansion when the registry has narrowed a grant.
        if (scopes.empty() || !std::ranges::all_of(scopes,[&](const auto& scope){
            return std::ranges::find(allowedResource,scope)!=allowedResource.end()
                && (defaultScopes || std::ranges::find(sourceScopes,scope)!=sourceScopes.end());
        })) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::PermissionDenied);
        }
        Params familyArgs{family,clientId,identityId,provider,assurance,factors,phishing,authenticatedAt,
            sender?std::optional<std::string>{std::to_string(static_cast<int>(sender->kind()))}:std::nullopt,
            sender?std::optional<std::string>{std::string{sender->value()}}:std::nullopt};
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.oauth_token_families "
            "(id,client_id,identity_id,provider,assurance,factors,phishing_resistant,authenticated_at_ms,sender_constraint_kind,sender_constraint_value) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",std::move(familyArgs)));
        for (const auto& scope:scopes) {
            Params args{family,scope};
            static_cast<void>(co_await execute(
                "INSERT INTO openproof.oauth_token_family_scopes(family_id,scope) VALUES($1,$2)",std::move(args)));
        }
        Params audienceArgs{family,audience};
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.oauth_token_family_audiences(family_id,audience) VALUES($1,$2)",std::move(audienceArgs)));
        Params accessArgs{accessDigest,family,timestamp,std::to_string(expires)};
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.oauth_access_tokens(token_digest,family_id,state,issued_at_ms,expires_at_ms) "
            "VALUES(decode($1,'hex'),$2,0,$3,$4)",std::move(accessArgs)));
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return oauth::NativeMachineGrantResult{std::move(scopes),foundation::Duration{expires-observed}};
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native OAuth machine grant is unavailable.");
    }
}

asio::awaitable<foundation::Result<oauth::NativeDevicePollResult>>
CoroutinePostgresCanonicalFinalizer::pollOAuthDeviceAsync(
    std::string clientId,std::optional<std::string> clientDigest,std::string deviceDigest,
    std::string family,std::string accessDigest,std::string refreshDigest,
    std::optional<session::DelegatedSenderConstraint> sender,foundation::Instant now,
    foundation::Duration accessLifetime,foundation::Duration refreshLifetime)
{
    using E=foundation::ErrorCode;
    using State=oauth::NativeDevicePollState;
    const auto validDigest=[](std::string_view digest) {
        return digest.size()==64U && std::ranges::all_of(digest,[](char ch) {
            return (ch>='0' && ch<='9') || (ch>='a' && ch<='f');
        });
    };
    if (clientId.empty() || clientId.size()>256U || !validDigest(deviceDigest)
        || !validDigest(accessDigest) || !validDigest(refreshDigest) || accessDigest==refreshDigest
        || (clientDigest && !validDigest(*clientDigest)) || family.empty() || family.size()>200U
        || accessLifetime<=foundation::Duration::zero() || accessLifetime>std::chrono::hours{1}
        || refreshLifetime<=accessLifetime || refreshLifetime>std::chrono::hours{24*365}
        || now.time_since_epoch().count()<0
        || now.time_since_epoch().count()>foundation::Duration::max().count()-refreshLifetime.count()
        || (sender && (sender->value().empty() || sender->value().size()>256U)))
        co_return foundation::fail(E::InvalidArgument);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params params) {
            return connection.query(std::move(sql),std::move(params),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        const std::string tenant{m_impl->organization.value()};
        Params callerParams{clientId,tenant};
        const auto caller=co_await execute(
            "SELECT c.kind,encode(c.secret_digest,'hex') FROM openproof.oauth_clients c "
            "JOIN openproof.applications a ON a.id=c.application_id "
            "JOIN openproof.organizations o ON o.id=a.organization_id "
            "WHERE c.id=$1 AND a.organization_id=$2 AND o.state=0 "
            "AND c.status=0 AND a.status=0 FOR SHARE OF c,a,o",std::move(callerParams));
        bool authenticated=false;
        if (caller.rows.size()==1U && caller.rows.front().size()==2U) {
            const auto& row=caller.rows.front();
            const auto kind=milliseconds(row[0]);
            if ((kind==1 || kind==2) && !row[1] && !clientDigest) authenticated=true;
            if ((kind==0 || kind==3) && row[1] && clientDigest) {
                auto presented=foundation::fromHex(*clientDigest);
                auto stored=foundation::fromHex(*row[1]);
                authenticated=presented && stored && presented->size()==32U
                    && stored->size()==32U && security::constantTimeEquals(*presented,*stored);
            }
        }
        if (!authenticated) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationRequired);
        }
        const auto observed=now.time_since_epoch().count();
        const auto timestamp=std::to_string(observed);
        Params deviceArgs{deviceDigest,clientId};
        const auto locked=co_await execute(
            "SELECT status,issued_at_ms,expires_at_ms,poll_interval_ms,last_poll_at_ms,"
            "identity_id,provider,assurance,factors,phishing_resistant,authenticated_at_ms,resource "
            "FROM openproof.oauth_device_authorizations "
            "WHERE device_digest=decode($1,'hex') AND client_id=$2 FOR UPDATE",std::move(deviceArgs));
        if (locked.rows.empty()) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationFailed);
        }
        if (locked.rows.size()!=1U || locked.rows.front().size()!=12U)
            throw std::runtime_error{"Malformed device authorization"};
        const auto& row=locked.rows.front();
        const auto state=milliseconds(row[0]),issued=milliseconds(row[1]),expires=milliseconds(row[2]),
            interval=milliseconds(row[3]);
        if (issued>observed || interval<=0 || interval>std::numeric_limits<std::int64_t>::max()-5000)
            throw std::runtime_error{"Invalid device chronology"};
        if (state==3) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationFailed);
        }
        if (expires<=observed || state==2) {
            static_cast<void>(co_await execute("COMMIT",{}));
            co_return oauth::NativeDevicePollResult{expires<=observed?State::Expired:State::Denied,{}};
        }
        if (state!=0 && state!=1) throw std::runtime_error{"Invalid device status"};
        const auto last=row[4]?milliseconds(row[4]):0;
        if (row[4] && (last>observed || observed-last<interval)) {
            Params args{deviceDigest,std::to_string(interval+5000),timestamp};
            static_cast<void>(co_await execute(
                "UPDATE openproof.oauth_device_authorizations SET poll_interval_ms=$2,last_poll_at_ms=GREATEST(last_poll_at_ms,$3::bigint) "
                "WHERE device_digest=decode($1,'hex')",std::move(args)));
            static_cast<void>(co_await execute("COMMIT",{}));
            co_return oauth::NativeDevicePollResult{State::SlowDown,{}};
        }
        if (state==0) {
            Params args{deviceDigest,timestamp};
            static_cast<void>(co_await execute(
                "UPDATE openproof.oauth_device_authorizations SET last_poll_at_ms=$2 "
                "WHERE device_digest=decode($1,'hex') AND status=0",std::move(args)));
            static_cast<void>(co_await execute("COMMIT",{}));
            co_return oauth::NativeDevicePollResult{State::Pending,{}};
        }
        // An approved code is still bound to an active identity in the
        // authenticated client's tenant. No token is minted from stale approval.
        const auto identityId=required(row[5]);
        Params ownerArgs{identityId,tenant};
        const auto owner=co_await execute(
            "SELECT id FROM openproof.identities WHERE id=$1 AND organization_id=$2 AND status=0 FOR SHARE",
            std::move(ownerArgs));
        if (owner.rows.size()!=1U) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationFailed);
        }
        if (milliseconds(row[7])>4 || milliseconds(row[8])>7 || milliseconds(row[10])>observed)
            throw std::runtime_error{"Malformed device authentication context"};
        Params scopeArgs{deviceDigest};
        const auto grants=co_await execute(
            "SELECT scope FROM openproof.oauth_device_authorization_scopes WHERE device_digest=decode($1,'hex') "
            "ORDER BY scope COLLATE \"C\" LIMIT 257 FOR SHARE",std::move(scopeArgs));
        if (grants.rows.empty() || grants.rows.size()>256U)
            throw std::runtime_error{"Invalid device grant scopes"};
        std::vector<std::string> scopes;
        for (const auto& grant:grants.rows) {
            if (grant.size()!=1U || !client::Scope::create(required(grant[0])))
                throw std::runtime_error{"Invalid device scope"};
            scopes.push_back(required(grant[0]));
        }
        Params familyArgs{family,clientId,identityId,required(row[6]),required(row[7]),required(row[8]),
            boolean(row[9])?"true":"false",required(row[10]),
            sender?std::optional<std::string>{std::to_string(static_cast<int>(sender->kind()))}:std::nullopt,
            sender?std::optional<std::string>{std::string{sender->value()}}:std::nullopt};
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.oauth_token_families "
            "(id,client_id,identity_id,provider,assurance,factors,phishing_resistant,authenticated_at_ms,sender_constraint_kind,sender_constraint_value) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",std::move(familyArgs)));
        for (const auto& scope:scopes) {
            Params args{family,scope};
            static_cast<void>(co_await execute(
                "INSERT INTO openproof.oauth_token_family_scopes(family_id,scope) VALUES($1,$2)",std::move(args)));
        }
        if (row[11]) {
            Params args{family,*row[11]};
            static_cast<void>(co_await execute(
                "INSERT INTO openproof.oauth_token_family_audiences(family_id,audience) VALUES($1,$2)",std::move(args)));
        }
        Params accessArgs{accessDigest,family,timestamp,std::to_string((now+accessLifetime).time_since_epoch().count())};
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.oauth_access_tokens(token_digest,family_id,state,issued_at_ms,expires_at_ms) "
            "VALUES(decode($1,'hex'),$2,0,$3,$4)",std::move(accessArgs)));
        Params refreshArgs{refreshDigest,family,timestamp,std::to_string((now+refreshLifetime).time_since_epoch().count())};
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.oauth_refresh_tokens(token_digest,family_id,sequence,state,issued_at_ms,expires_at_ms) "
            "VALUES(decode($1,'hex'),$2,0,0,$3,$4)",std::move(refreshArgs)));
        Params consumeArgs{deviceDigest,clientId,timestamp};
        const auto consumed=co_await execute(
            "UPDATE openproof.oauth_device_authorizations SET status=3,last_poll_at_ms=$3 "
            "WHERE device_digest=decode($1,'hex') AND client_id=$2 AND status=1 RETURNING client_id",
            std::move(consumeArgs));
        if (consumed.rows.size()!=1U || consumed.rows.front().size()!=1U || required(consumed.rows.front()[0])!=clientId)
            throw std::runtime_error{"Device code consumption mismatch"};
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return oauth::NativeDevicePollResult{State::Issued,std::move(scopes)};
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native device polling is unavailable.");
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresCanonicalFinalizer::beginOAuthDeviceAsync(
    std::string clientId,std::optional<std::string> clientDigest,
    std::string deviceDigest,std::string userDigest,std::vector<std::string> scopes,
    std::optional<std::string> resource,foundation::Instant now,
    foundation::Duration lifetime,foundation::Duration interval)
{
    using E=foundation::ErrorCode;
    const auto validDigest=[](std::string_view digest) {
        return digest.size()==64U && std::ranges::all_of(digest,[](char ch) {
            return (ch>='0' && ch<='9') || (ch>='a' && ch<='f');
        });
    };
    if (clientId.empty() || clientId.size()>256U || !validDigest(deviceDigest)
        || !validDigest(userDigest) || deviceDigest==userDigest
        || (clientDigest && !validDigest(*clientDigest))
        || scopes.empty() || scopes.size()>256U
        || (resource && (resource->empty() || resource->size()>2048U))
        || lifetime<=foundation::Duration::zero() || lifetime>std::chrono::hours{1}
        || interval<=foundation::Duration::zero() || interval>=lifetime
        || now.time_since_epoch().count()<0
        || now.time_since_epoch().count()>foundation::Duration::max().count()-lifetime.count())
        co_return foundation::fail(E::InvalidArgument);
    for (const auto& scope:scopes)
        if (!client::Scope::create(scope)) co_return foundation::fail(E::InvalidArgument);
    std::ranges::sort(scopes);
    if (std::adjacent_find(scopes.begin(),scopes.end())!=scopes.end())
        co_return foundation::fail(E::InvalidArgument);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params params) {
            return connection.query(std::move(sql),std::move(params),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        const std::string tenant{m_impl->organization.value()};
        Params callerParams{clientId,tenant};
        const auto caller=co_await execute(
            "SELECT c.kind,encode(c.secret_digest,'hex') FROM openproof.oauth_clients c "
            "JOIN openproof.applications a ON a.id=c.application_id "
            "JOIN openproof.organizations o ON o.id=a.organization_id "
            "WHERE c.id=$1 AND a.organization_id=$2 AND o.state=0 "
            "AND c.status=0 AND a.status=0 FOR SHARE OF c,a,o",std::move(callerParams));
        bool authenticated=false;
        if (caller.rows.size()==1U && caller.rows.front().size()==2U) {
            const auto& row=caller.rows.front();
            const auto kind=milliseconds(row[0]);
            if ((kind==1 || kind==2) && !row[1] && !clientDigest) authenticated=true;
            if ((kind==0 || kind==3) && row[1] && clientDigest) {
                auto presented=foundation::fromHex(*clientDigest);
                auto stored=foundation::fromHex(*row[1]);
                authenticated=presented && stored && presented->size()==32U
                    && stored->size()==32U && security::constantTimeEquals(*presented,*stored);
            }
        }
        if (!authenticated) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationRequired);
        }
        Params clientScopeArgs{clientId};
        const auto permitted=co_await execute(
            "SELECT scope FROM openproof.oauth_client_scopes WHERE client_id=$1 "
            "ORDER BY scope COLLATE \"C\" LIMIT 257 FOR SHARE",std::move(clientScopeArgs));
        if (permitted.rows.size()>256U) throw std::runtime_error{"Oversized client scope set"};
        std::vector<std::string> allowed;
        for (const auto& row:permitted.rows) {
            if (row.size()!=1U) throw std::runtime_error{"Malformed client scope"};
            allowed.push_back(required(row[0]));
        }
        if (!std::ranges::all_of(scopes,[&](const auto& scope){
            return std::ranges::find(allowed,scope)!=allowed.end();
        })) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::PermissionDenied);
        }
        const auto oidcOnly=[](std::string_view scope) {
            return scope=="openid" || scope=="profile" || scope=="email"
                || scope=="phone" || scope=="offline_access" || scope=="account";
        };
        if (!resource && !std::ranges::all_of(scopes,oidcOnly)) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::NotFound);
        }
        if (resource) {
            Params resourceArgs{*resource};
            const auto target=co_await execute(
                "SELECT id FROM openproof.oauth_resources WHERE audience=$1 AND status=0 FOR SHARE",
                std::move(resourceArgs));
            if (target.rows.size()!=1U || target.rows.front().size()!=1U) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::NotFound);
            }
            Params scopeArgs{required(target.rows.front()[0])};
            const auto grants=co_await execute(
                "SELECT scope FROM openproof.oauth_resource_scopes WHERE resource_id=$1 "
                "ORDER BY scope COLLATE \"C\" LIMIT 257 FOR SHARE",std::move(scopeArgs));
            if (grants.rows.size()>256U) throw std::runtime_error{"Oversized resource scope set"};
            std::vector<std::string> resourceScopes;
            for (const auto& row:grants.rows) {
                if (row.size()!=1U) throw std::runtime_error{"Malformed resource scope"};
                resourceScopes.push_back(required(row[0]));
            }
            if (!std::ranges::all_of(scopes,[&](const auto& scope){
                return oidcOnly(scope) || std::ranges::find(resourceScopes,scope)!=resourceScopes.end();
            })) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::NotFound);
            }
        }
        Params args{deviceDigest,userDigest,clientId,resource,std::to_string(now.time_since_epoch().count()),
            std::to_string((now+lifetime).time_since_epoch().count()),std::to_string(interval.count())};
        const auto inserted=co_await execute(
            "INSERT INTO openproof.oauth_device_authorizations "
            "(device_digest,user_code_digest,client_id,resource,status,issued_at_ms,expires_at_ms,poll_interval_ms) "
            "VALUES(decode($1,'hex'),decode($2,'hex'),$3,$4,0,$5,$6,$7) "
            "ON CONFLICT DO NOTHING RETURNING client_id",std::move(args));
        if (inserted.rows.empty()) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::Conflict);
        }
        if (inserted.rows.size()!=1U || inserted.rows.front().size()!=1U || required(inserted.rows.front()[0])!=clientId)
            throw std::runtime_error{"Device authorization insertion mismatch"};
        for (const auto& scope:scopes) {
            Params scopeArgs{deviceDigest,scope};
            static_cast<void>(co_await execute(
                "INSERT INTO openproof.oauth_device_authorization_scopes(device_digest,scope) "
                "VALUES(decode($1,'hex'),$2)",std::move(scopeArgs)));
        }
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native device authorization is unavailable.");
    }
}

asio::awaitable<foundation::Result<oauth::NativeDeviceApproval>>
CoroutinePostgresCanonicalFinalizer::readOAuthDeviceApprovalAsync(std::string userDigest,
    core::IdentityId owner,foundation::Instant now)
{
    using E=foundation::ErrorCode;
    if (userDigest.size()!=64U || owner.empty()) co_return foundation::fail(E::InvalidArgument);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        Params args{std::move(userDigest),std::string{owner.value()},
            std::string{m_impl->organization.value()},std::to_string(now.time_since_epoch().count())};
        const auto rows=co_await lease.connection().query(
            "SELECT c.display_name,d.resource,s.scope FROM openproof.oauth_device_authorizations d "
            "JOIN openproof.oauth_clients c ON c.id=d.client_id "
            "JOIN openproof.applications a ON a.id=c.application_id "
            "JOIN openproof.organizations o ON o.id=a.organization_id "
            "JOIN openproof.identities i ON i.id=$2 AND i.organization_id=a.organization_id "
            "JOIN openproof.oauth_device_authorization_scopes s ON s.device_digest=d.device_digest "
            "WHERE d.user_code_digest=decode($1,'hex') AND a.organization_id=$3 "
            "AND d.status=0 AND d.issued_at_ms<=$4 AND d.expires_at_ms>$4 "
            "AND c.status=0 AND a.status=0 AND o.state=0 AND i.status=0 "
            "ORDER BY s.scope COLLATE \"C\" LIMIT 257",std::move(args),remaining(deadline));
        if (rows.rows.empty()) co_return foundation::fail(E::NotFound);
        if (rows.rows.size()>256U || rows.rows.front().size()!=3U)
            co_return foundation::fail(E::Unavailable);
        const auto& first=rows.rows.front();
        oauth::NativeDeviceApproval result{required(first[0]),first[1],{}};
        for (const auto& row:rows.rows) {
            if (row.size()!=3U || row[0]!=first[0] || row[1]!=first[1]
                || !client::Scope::create(required(row[2])))
                throw std::runtime_error{"Malformed device approval"};
            result.scopes.push_back(required(row[2]));
        }
        co_return result;
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable);
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresCanonicalFinalizer::decideOAuthDeviceAsync(std::string userDigest,
    core::IdentityId owner,session::SessionId sessionId,bool approve,std::string consentId,
    foundation::Instant now)
{
    using E=foundation::ErrorCode;
    if (userDigest.size()!=64U || owner.empty() || sessionId.empty()
        || (approve && (consentId.empty() || consentId.size()>200U)))
        co_return foundation::fail(E::InvalidArgument);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params params) {
            return connection.query(std::move(sql),std::move(params),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        const std::string tenant{m_impl->organization.value()},identityId{owner.value()};
        const auto timestamp=std::to_string(now.time_since_epoch().count());
        // Match client -> device -> identity/session order of native polling.
        Params clientArgs{userDigest,tenant};
        const auto client=co_await execute(
            "SELECT c.id FROM openproof.oauth_device_authorizations d "
            "JOIN openproof.oauth_clients c ON c.id=d.client_id "
            "JOIN openproof.applications a ON a.id=c.application_id "
            "JOIN openproof.organizations o ON o.id=a.organization_id "
            "WHERE d.user_code_digest=decode($1,'hex') AND a.organization_id=$2 "
            "AND c.status=0 AND a.status=0 AND o.state=0 FOR SHARE OF c,a,o",std::move(clientArgs));
        if (client.rows.size()!=1U || client.rows.front().size()!=1U) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::NotFound);
        }
        const auto clientId=required(client.rows.front()[0]);
        Params deviceArgs{userDigest,clientId,timestamp};
        const auto locked=co_await execute(
            "SELECT encode(device_digest,'hex'),resource FROM openproof.oauth_device_authorizations "
            "WHERE user_code_digest=decode($1,'hex') AND client_id=$2 AND status=0 "
            "AND issued_at_ms<=$3 AND expires_at_ms>$3 FOR UPDATE",std::move(deviceArgs));
        if (locked.rows.size()!=1U || locked.rows.front().size()!=2U) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::NotFound);
        }
        const auto digest=required(locked.rows.front()[0]);
        const auto resource=locked.rows.front()[1];
        // Serialize consent supersession and recheck the exact first-party
        // session under transaction locks. Never trust claims from the form.
        Params ownerArgs{identityId,tenant,std::string{sessionId.value()},timestamp};
        const auto actor=co_await execute(
            "SELECT s.provider,s.assurance,s.factors,s.phishing_resistant,s.authenticated_at_ms "
            "FROM openproof.identities i JOIN openproof.sessions s ON s.identity_id=i.id "
            "WHERE i.id=$1 AND i.organization_id=$2 AND i.status=0 AND s.id=$3 AND s.state=0 "
            "AND s.issued_at_ms<=$4 AND s.absolute_expires_at_ms>$4 "
            "AND s.last_seen_at_ms+s.idle_timeout_ms>$4 FOR UPDATE OF i FOR SHARE OF s",std::move(ownerArgs));
        if (actor.rows.size()!=1U || actor.rows.front().size()!=5U) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationFailed);
        }
        if (approve) {
            Params scopeArgs{digest};
            const auto grants=co_await execute(
                "SELECT scope FROM openproof.oauth_device_authorization_scopes "
                "WHERE device_digest=decode($1,'hex') ORDER BY scope COLLATE \"C\" LIMIT 257 FOR SHARE",
                std::move(scopeArgs));
            if (grants.rows.empty() || grants.rows.size()>256U)
                throw std::runtime_error{"Invalid device approval scope set"};
            std::vector<std::string> scopes;
            for (const auto& row:grants.rows) {
                if (row.size()!=1U || !client::Scope::create(required(row[0])))
                    throw std::runtime_error{"Invalid device scope"};
                scopes.push_back(required(row[0]));
            }
            const std::string audience=resource.value_or("urn:openproof:client:"+clientId);
            Params supersede{identityId,clientId,audience,timestamp};
            static_cast<void>(co_await execute(
                "UPDATE openproof.oauth_consents SET revoked_at_ms=$4 "
                "WHERE identity_id=$1 AND client_id=$2 AND audience=$3 AND revoked_at_ms IS NULL "
                "AND (expires_at_ms IS NULL OR expires_at_ms>$4)",std::move(supersede)));
            Params consentArgs{consentId,identityId,clientId,audience,timestamp};
            static_cast<void>(co_await execute(
                "INSERT INTO openproof.oauth_consents(id,identity_id,client_id,audience,granted_at_ms) "
                "VALUES($1,$2,$3,$4,$5)",std::move(consentArgs)));
            for (const auto& scope:scopes) {
                Params args{consentId,scope};
                static_cast<void>(co_await execute(
                    "INSERT INTO openproof.oauth_consent_scopes(consent_id,scope) VALUES($1,$2)",std::move(args)));
            }
            const auto& row=actor.rows.front();
            Params args{digest,identityId,required(row[0]),required(row[1]),required(row[2]),
                boolean(row[3])?"true":"false",required(row[4])};
            const auto updated=co_await execute(
                "UPDATE openproof.oauth_device_authorizations SET status=1,identity_id=$2,provider=$3,"
                "assurance=$4,factors=$5,phishing_resistant=$6,authenticated_at_ms=$7 "
                "WHERE device_digest=decode($1,'hex') AND status=0 RETURNING client_id",std::move(args));
            if (updated.rows.size()!=1U || updated.rows.front().size()!=1U || required(updated.rows.front()[0])!=clientId)
                throw std::runtime_error{"Device approval update mismatch"};
        } else {
            Params args{digest};
            const auto updated=co_await execute(
                "UPDATE openproof.oauth_device_authorizations SET status=2 "
                "WHERE device_digest=decode($1,'hex') AND status=0 RETURNING client_id",std::move(args));
            if (updated.rows.size()!=1U || updated.rows.front().size()!=1U || required(updated.rows.front()[0])!=clientId)
                throw std::runtime_error{"Device denial update mismatch"};
        }
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native device decision is unavailable.");
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresCanonicalFinalizer::pushOAuthAuthorizationAsync(std::string clientId,
    std::optional<std::string> clientDigest,std::string requestDigest,
    std::optional<oauth::AuthorizationRequest> direct,VerifyJar verifyJar,
    foundation::Instant now,foundation::Duration lifetime,bool signedFrontChannel)
{
    using E=foundation::ErrorCode;
    if (clientId.empty() || clientId.size()>256U || requestDigest.size()!=64U
        || (clientDigest && clientDigest->size()!=64U) || (direct.has_value()==static_cast<bool>(verifyJar))
        || (signedFrontChannel && (!verifyJar || direct || clientDigest))
        || lifetime<=foundation::Duration::zero() || lifetime>std::chrono::minutes{10}
        || now.time_since_epoch().count()<0
        || now.time_since_epoch().count()>foundation::Duration::max().count()-lifetime.count())
        co_return foundation::fail(E::InvalidArgument);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params params) {
            return connection.query(std::move(sql),std::move(params),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        const std::string tenant{m_impl->organization.value()};
        Params callerParams{clientId,tenant};
        const auto caller=co_await execute(
            "SELECT c.kind,encode(c.secret_digest,'hex') FROM openproof.oauth_clients c "
            "JOIN openproof.applications a ON a.id=c.application_id "
            "JOIN openproof.organizations o ON o.id=a.organization_id "
            "WHERE c.id=$1 AND a.organization_id=$2 AND o.state=0 "
            "AND c.status=0 AND a.status=0 FOR SHARE OF c,a,o",std::move(callerParams));
        bool authenticated=false;
        std::int64_t clientKind=-1;
        if (caller.rows.size()==1U && caller.rows.front().size()==2U) {
            const auto& row=caller.rows.front();
            const auto kind=milliseconds(row[0]);
            clientKind=kind;
            // A front-channel signed request authenticates through the
            // pinned JAR signature, not a browser-visible client secret.
            if (signedFrontChannel && kind>=0 && kind<=2) authenticated=true;
            if ((kind==1 || kind==2) && !row[1] && !clientDigest) authenticated=true;
            if ((kind==0 || kind==3) && row[1] && clientDigest) {
                auto presented=foundation::fromHex(*clientDigest);
                auto stored=foundation::fromHex(*row[1]);
                authenticated=presented && stored && presented->size()==32U
                    && stored->size()==32U && security::constantTimeEquals(*presented,*stored);
            }
        }
        if (!authenticated) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationRequired);
        }
        std::optional<oauth::NativeJarAuthorization> jar;
        if (verifyJar) {
            Params keyArgs{clientId};
            const auto key=co_await execute(
                "SELECT key_id,public_key_pem FROM openproof.oauth_client_request_signing_keys "
                "WHERE client_id=$1 FOR SHARE",std::move(keyArgs));
            if (key.rows.size()!=1U || key.rows.front().size()!=2U) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::InvalidArgument);
            }
            auto verified=verifyJar(required(key.rows.front()[0]),required(key.rows.front()[1]),now);
            if (!verified) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::InvalidArgument);
            }
            jar.emplace(std::move(verified).value());
            verifyJar={};
        }
        const auto& request=jar?jar->request:*direct;
        if (request.clientId().value()!=clientId || clientKind<0 || clientKind>3
            || !client::RedirectUri::create(std::string{request.redirectUri()},static_cast<client::ClientKind>(clientKind))) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::InvalidArgument);
        }
        Params redirectArgs{clientId};
        const auto redirects=co_await execute(
            "SELECT redirect_uri FROM openproof.oauth_client_redirect_uris WHERE client_id=$1 "
            "ORDER BY redirect_uri COLLATE \"C\" LIMIT 257 FOR SHARE",std::move(redirectArgs));
        if (redirects.rows.size()>256U) throw std::runtime_error{"Oversized redirect registry"};
        if (!std::ranges::any_of(redirects.rows,[&](const auto& row) {
            return row.size()==1U && client::matchesRegisteredRedirect(static_cast<client::ClientKind>(clientKind),
                required(row[0]),request.redirectUri());
        })) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::InvalidArgument);
        }
        Params scopeArgs{clientId};
        const auto grants=co_await execute(
            "SELECT scope FROM openproof.oauth_client_scopes WHERE client_id=$1 LIMIT 257 FOR SHARE",
            std::move(scopeArgs));
        if (grants.rows.size()>256U) throw std::runtime_error{"Oversized client scope registry"};
        const auto hasScope=[](const auto& rows,std::string_view scope) {
            return std::ranges::any_of(rows,[&](const auto& row){return row.size()==1U && required(row[0])==scope;});
        };
        if (!std::ranges::all_of(request.scopes(),[&](const auto& scope){return hasScope(grants.rows,scope.value());})) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::PermissionDenied);
        }
        const auto oidcOnly=[](std::string_view s) {
            return s=="openid" || s=="profile" || s=="email" || s=="phone" || s=="offline_access" || s=="account";
        };
        if (request.resource()) {
            Params resourceArgs{*request.resource()};
            const auto resource=co_await execute(
                "SELECT id FROM openproof.oauth_resources WHERE audience=$1 AND status=0 FOR SHARE",std::move(resourceArgs));
            if (resource.rows.size()!=1U || resource.rows.front().size()!=1U) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::PermissionDenied);
            }
            Params args{required(resource.rows.front()[0])};
            const auto allowed=co_await execute(
                "SELECT scope FROM openproof.oauth_resource_scopes WHERE resource_id=$1 LIMIT 257 FOR SHARE",std::move(args));
            if (allowed.rows.size()>256U) throw std::runtime_error{"Oversized resource scope registry"};
            if (!std::ranges::all_of(request.scopes(),[&](const auto& scope) {
                return oidcOnly(scope.value()) || hasScope(allowed.rows,scope.value());
            })) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::PermissionDenied);
            }
        } else if (!std::ranges::all_of(request.scopes(),[&](const auto& scope){return oidcOnly(scope.value());})) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::PermissionDenied);
        }
        const auto timestamp=std::to_string(now.time_since_epoch().count());
        if (jar) {
            if (jar->jwtId.empty() || jar->jwtId.size()>256U || jar->expiresAt<=now
                || std::ranges::any_of(jar->jwtId,[](unsigned char c){return c<0x20U || c==0x7fU;})
                || jar->issuedAt>now+std::chrono::seconds{60} || jar->issuedAt<now-std::chrono::minutes{10}
                || jar->expiresAt<=jar->issuedAt || jar->expiresAt-jar->issuedAt>std::chrono::minutes{10}) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::InvalidArgument);
            }
            // Bounded opportunistic cleanup; never wait on unrelated
            // clients' replay rows or perform a global purge on the reactor.
            Params purgeArgs{clientId,timestamp};
            static_cast<void>(co_await execute(
                "WITH expired AS (SELECT jwt_id FROM openproof.oauth_jar_replays "
                "WHERE client_id=$1 AND expires_at_ms<=$2 ORDER BY expires_at_ms LIMIT 128 FOR UPDATE SKIP LOCKED) "
                "DELETE FROM openproof.oauth_jar_replays r USING expired e "
                "WHERE r.client_id=$1 AND r.jwt_id=e.jwt_id",std::move(purgeArgs)));
            Params replayArgs{clientId,jar->jwtId,std::to_string(jar->expiresAt.time_since_epoch().count()),timestamp};
            const auto consumed=co_await execute(
                "INSERT INTO openproof.oauth_jar_replays(client_id,jwt_id,expires_at_ms) VALUES($1,$2,$3) "
                "ON CONFLICT(client_id,jwt_id) DO UPDATE SET expires_at_ms=EXCLUDED.expires_at_ms "
                "WHERE openproof.oauth_jar_replays.expires_at_ms<=$4 RETURNING client_id",std::move(replayArgs));
            if (consumed.rows.size()!=1U) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::InvalidArgument);
            }
        }
        Params args{requestDigest,clientId,std::string{request.redirectUri()},std::string{request.codeChallenge().value()},
            request.state(),request.nonce(),request.maximumAuthenticationAge()
                ?std::optional<std::string>{std::to_string(request.maximumAuthenticationAge()->count())}:std::nullopt,
            request.resource(),std::to_string(static_cast<int>(request.responseMode())),timestamp,
            std::to_string((now+lifetime).time_since_epoch().count())};
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.oauth_pushed_authorization_requests "
            "(request_digest,client_id,redirect_uri,code_challenge,state,nonce,maximum_authentication_age_ms,resource,response_mode,issued_at_ms,expires_at_ms) "
            "VALUES(decode($1,'hex'),$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",std::move(args)));
        for (const auto& scope:request.scopes()) {
            Params pushedScopeArgs{requestDigest,std::string{scope.value()}};
            static_cast<void>(co_await execute(
                "INSERT INTO openproof.oauth_pushed_authorization_request_scopes(request_digest,scope) "
                "VALUES(decode($1,'hex'),$2)",std::move(pushedScopeArgs)));
        }
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native pushed authorization is unavailable.");
    }
}

asio::awaitable<foundation::Result<oauth::NativeAuthorizationResult>>
CoroutinePostgresCanonicalFinalizer::completeOAuthAuthorizationAsync(
    std::string clientId,std::optional<std::string> parDigest,std::optional<oauth::AuthorizationRequest> direct,
    core::IdentityId owner,session::SessionId sessionId,oauth::NativeAuthorizationDecision decision,
    std::string consentId,std::string codeDigest,foundation::Instant now,
    foundation::Duration lifetime,SignAuthorizationResponse signResponse)
{
    using E=foundation::ErrorCode;
    using Decision=oauth::NativeAuthorizationDecision;
    const auto validDigest=[](std::string_view value) {
        return value.size()==64U && std::ranges::all_of(value,[](char ch){
            return (ch>='0' && ch<='9') || (ch>='a' && ch<='f');
        });
    };
    if (clientId.empty() || clientId.size()>256U || owner.empty() || sessionId.empty()
        || direct.has_value()==parDigest.has_value() || (parDigest && !validDigest(*parDigest))
        || !validDigest(codeDigest) || (decision==Decision::Approve && (consentId.empty() || consentId.size()>200U))
        || lifetime<=foundation::Duration::zero() || lifetime>std::chrono::minutes{10}
        || now.time_since_epoch().count()<0
        || now.time_since_epoch().count()>foundation::Duration::max().count()-lifetime.count())
        co_return foundation::fail(E::InvalidArgument);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params params) {
            return connection.query(std::move(sql),std::move(params),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        const std::string tenant{m_impl->organization.value()},identityId{owner.value()};
        const auto observed=now.time_since_epoch().count();
        const auto timestamp=std::to_string(observed);
        Params clientArgs{clientId,tenant};
        const auto caller=co_await execute(
            "SELECT c.kind,c.display_name FROM openproof.oauth_clients c "
            "JOIN openproof.applications a ON a.id=c.application_id "
            "JOIN openproof.organizations o ON o.id=a.organization_id "
            "WHERE c.id=$1 AND a.organization_id=$2 AND o.state=0 AND c.status=0 AND a.status=0 "
            "FOR SHARE OF c,a,o",std::move(clientArgs));
        if (caller.rows.size()!=1U || caller.rows.front().size()!=2U) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::InvalidArgument);
        }
        const auto clientKind=milliseconds(caller.rows.front()[0]);
        const auto clientName=required(caller.rows.front()[1]);
        if (parDigest) {
            Params args{*parDigest,clientId,timestamp};
            const auto locked=co_await execute(
                "SELECT redirect_uri,code_challenge,state,nonce,maximum_authentication_age_ms,resource,response_mode "
                "FROM openproof.oauth_pushed_authorization_requests "
                "WHERE request_digest=decode($1,'hex') AND client_id=$2 "
                "AND issued_at_ms<=$3 AND expires_at_ms>$3 FOR UPDATE",std::move(args));
            if (locked.rows.size()!=1U || locked.rows.front().size()!=7U) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::AuthenticationFailed);
            }
            const auto& row=locked.rows.front();
            auto challenge=oauth::PkceChallenge::create(required(row[1]));
            const auto mode=milliseconds(row[6]);
            if (!challenge || mode>1) throw std::runtime_error{"Invalid stored PAR"};
            Params scopeArgs{*parDigest};
            const auto grants=co_await execute(
                "SELECT scope FROM openproof.oauth_pushed_authorization_request_scopes "
                "WHERE request_digest=decode($1,'hex') ORDER BY scope COLLATE \"C\" LIMIT 65 FOR SHARE",std::move(scopeArgs));
            std::vector<client::Scope> scopes;
            for (const auto& grant:grants.rows) {
                if (grant.size()!=1U) throw std::runtime_error{"Malformed PAR scope"};
                auto scope=client::Scope::create(required(grant[0]));
                if (!scope) throw std::runtime_error{"Invalid PAR scope"};
                scopes.push_back(std::move(scope).value());
            }
            auto restored=oauth::AuthorizationRequest::create(client::ClientId{clientId},required(row[0]),
                std::move(scopes),std::move(challenge).value(),row[2],row[3],
                row[4]?std::optional<foundation::Duration>{foundation::Duration{milliseconds(row[4])}}:std::nullopt,
                row[5],static_cast<oauth::AuthorizationResponseMode>(mode));
            if (!restored) throw std::runtime_error{"Invalid stored PAR"};
            direct.emplace(std::move(restored).value());
        }
        const auto& request=*direct;
        if (request.clientId().value()!=clientId || clientKind<0 || clientKind>3
            || !client::RedirectUri::create(std::string{request.redirectUri()},static_cast<client::ClientKind>(clientKind))) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::InvalidArgument);
        }
        Params redirectArgs{clientId};
        const auto redirects=co_await execute(
            "SELECT redirect_uri FROM openproof.oauth_client_redirect_uris WHERE client_id=$1 "
            "ORDER BY redirect_uri COLLATE \"C\" LIMIT 257 FOR SHARE",std::move(redirectArgs));
        if (redirects.rows.size()>256U) throw std::runtime_error{"Oversized redirect registry"};
        if (!std::ranges::any_of(redirects.rows,[&](const auto& row) {
            return row.size()==1U && client::matchesRegisteredRedirect(static_cast<client::ClientKind>(clientKind),
                required(row[0]),request.redirectUri());
        })) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::InvalidArgument);
        }
        Params scopeArgs{clientId};
        const auto grants=co_await execute(
            "SELECT scope FROM openproof.oauth_client_scopes WHERE client_id=$1 LIMIT 257 FOR SHARE",
            std::move(scopeArgs));
        if (grants.rows.size()>256U) throw std::runtime_error{"Oversized client scope registry"};
        const auto hasScope=[](const auto& rows,std::string_view scope) {
            return std::ranges::any_of(rows,[&](const auto& row){return row.size()==1U && required(row[0])==scope;});
        };
        if (!std::ranges::all_of(request.scopes(),[&](const auto& scope){return hasScope(grants.rows,scope.value());})) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::PermissionDenied);
        }
        const auto oidcOnly=[](std::string_view s) {
            return s=="openid" || s=="profile" || s=="email" || s=="phone" || s=="offline_access" || s=="account";
        };
        if (request.resource()) {
            Params resourceArgs{*request.resource()};
            const auto resource=co_await execute(
                "SELECT id FROM openproof.oauth_resources WHERE audience=$1 AND status=0 FOR SHARE",std::move(resourceArgs));
            if (resource.rows.size()!=1U || resource.rows.front().size()!=1U) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::PermissionDenied);
            }
            Params args{required(resource.rows.front()[0])};
            const auto allowed=co_await execute(
                "SELECT scope FROM openproof.oauth_resource_scopes WHERE resource_id=$1 LIMIT 257 FOR SHARE",std::move(args));
            if (allowed.rows.size()>256U) throw std::runtime_error{"Oversized resource scope registry"};
            if (!std::ranges::all_of(request.scopes(),[&](const auto& scope) {
                return oidcOnly(scope.value()) || hasScope(allowed.rows,scope.value());
            })) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::PermissionDenied);
            }
        } else if (!std::ranges::all_of(request.scopes(),[&](const auto& scope){return oidcOnly(scope.value());})) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::PermissionDenied);
        }
        Params actorArgs{identityId,tenant,std::string{sessionId.value()},timestamp};
        const auto actor=co_await execute(
            "SELECT s.provider,s.assurance,s.factors,s.phishing_resistant,s.authenticated_at_ms "
            "FROM openproof.identities i JOIN openproof.sessions s ON s.identity_id=i.id "
            "WHERE i.id=$1 AND i.organization_id=$2 AND i.status=0 AND s.id=$3 AND s.state=0 "
            "AND s.issued_at_ms<=$4 AND s.absolute_expires_at_ms>$4 "
            "AND s.last_seen_at_ms+s.idle_timeout_ms>$4 FOR UPDATE OF i FOR SHARE OF s",std::move(actorArgs));
        if (actor.rows.size()!=1U || actor.rows.front().size()!=5U) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationFailed);
        }
        const auto& context=actor.rows.front();
        const auto authenticatedAt=milliseconds(context[4]);
        if (authenticatedAt>observed || (decision!=Decision::Deny && request.maximumAuthenticationAge()
            && observed-authenticatedAt>=request.maximumAuthenticationAge()->count())) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationRequired);
        }
        const auto audience=request.resource().value_or("urn:openproof:client:"+clientId);
        if (decision==Decision::ExistingConsent) {
            Params args{identityId,clientId,audience,timestamp};
            const auto existing=co_await execute(
                "SELECT id FROM openproof.oauth_consents WHERE identity_id=$1 AND client_id=$2 "
                "AND audience=$3 AND granted_at_ms<=$4 AND revoked_at_ms IS NULL "
                "AND (expires_at_ms IS NULL OR expires_at_ms>$4) ORDER BY granted_at_ms DESC,id DESC LIMIT 1 FOR SHARE",
                std::move(args));
            bool covered=false;
            if (existing.rows.size()==1U && existing.rows.front().size()==1U) {
                Params consentScopeArgs{required(existing.rows.front()[0])};
                const auto scopes=co_await execute(
                    "SELECT scope FROM openproof.oauth_consent_scopes WHERE consent_id=$1 LIMIT 257 FOR SHARE",std::move(consentScopeArgs));
                if (scopes.rows.size()>256U) throw std::runtime_error{"Oversized consent"};
                covered=std::ranges::all_of(request.scopes(),[&](const auto& scope){return hasScope(scopes.rows,scope.value());});
            }
            if (!covered) {
                static_cast<void>(co_await execute("COMMIT",{}));
                co_return oauth::NativeAuthorizationResult{request,clientName,true,std::nullopt};
            }
        }
        oauth::NativeAuthorizationResult result{request,clientName,false,std::nullopt};
        if (request.responseMode()==oauth::AuthorizationResponseMode::Jwt) {
            if (!signResponse) co_return foundation::fail(E::Unavailable);
            auto signedResponse=signResponse(request,decision==Decision::Deny);
            if (!signedResponse) co_return foundation::fail(E::Unavailable);
            result.signedResponse.emplace(std::move(signedResponse).value());
        }
        if (decision==Decision::Approve) {
            Params args{identityId,clientId,audience,timestamp};
            static_cast<void>(co_await execute(
                "UPDATE openproof.oauth_consents SET revoked_at_ms=$4 WHERE identity_id=$1 AND client_id=$2 "
                "AND audience=$3 AND revoked_at_ms IS NULL AND (expires_at_ms IS NULL OR expires_at_ms>$4)",std::move(args)));
            Params insert{consentId,identityId,clientId,audience,timestamp};
            static_cast<void>(co_await execute(
                "INSERT INTO openproof.oauth_consents(id,identity_id,client_id,audience,granted_at_ms) VALUES($1,$2,$3,$4,$5)",std::move(insert)));
            for (const auto& scope:request.scopes()) {
                Params consentScopeArgs{consentId,std::string{scope.value()}};
                static_cast<void>(co_await execute(
                    "INSERT INTO openproof.oauth_consent_scopes(consent_id,scope) VALUES($1,$2)",std::move(consentScopeArgs)));
            }
        }
        if (decision!=Decision::Deny) {
            Params args{codeDigest,clientId,identityId,std::string{request.redirectUri()},
                std::string{request.codeChallenge().value()},request.nonce(),required(context[0]),required(context[1]),
                required(context[2]),boolean(context[3])?"true":"false",required(context[4]),timestamp,
                std::to_string((now+lifetime).time_since_epoch().count()),request.resource()};
            static_cast<void>(co_await execute(
                "INSERT INTO openproof.oauth_authorization_codes "
                "(code_digest,client_id,identity_id,redirect_uri,code_challenge,nonce,provider,assurance,factors,phishing_resistant,authenticated_at_ms,issued_at_ms,expires_at_ms,resource) "
                "VALUES(decode($1,'hex'),$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",std::move(args)));
            for (const auto& scope:request.scopes()) {
                Params codeScopeArgs{codeDigest,std::string{scope.value()}};
                static_cast<void>(co_await execute(
                    "INSERT INTO openproof.oauth_authorization_code_scopes(code_digest,scope) VALUES(decode($1,'hex'),$2)",std::move(codeScopeArgs)));
            }
        }
        if (parDigest) {
            Params args{*parDigest,clientId};
            const auto consumed=co_await execute(
                "DELETE FROM openproof.oauth_pushed_authorization_requests WHERE request_digest=decode($1,'hex') "
                "AND client_id=$2 RETURNING client_id",std::move(args));
            if (consumed.rows.size()!=1U || consumed.rows.front().size()!=1U || required(consumed.rows.front()[0])!=clientId)
                throw std::runtime_error{"PAR consumption mismatch"};
        }
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return std::move(result);
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native authorization completion is unavailable.");
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresCanonicalFinalizer::healthCheckAsync()
{
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto rows=co_await lease.connection().query("SELECT 1",{},remaining(deadline));
        if (rows.rows.size()!=1U || rows.rows.front().size()!=1U
            || rows.rows.front().front()!=std::optional<std::string>{"1"})
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable);
    }
}

asio::awaitable<foundation::Result<std::string>>
CoroutinePostgresCanonicalFinalizer::readApplicationManagementAsync(
    application::ManagementRead operation,core::IdentityId actor,session::SessionId sessionId,
    std::optional<std::string> filter,foundation::Instant now)
{
    using E=foundation::ErrorCode;
    using Read=application::ManagementRead;
    const bool filtered=operation==Read::Clients || operation==Read::JarKey || operation==Read::ServiceIdentity;
    if (actor.empty() || sessionId.empty() || actor.value().size()>200U || sessionId.value().size()>200U
        || filtered!=filter.has_value() || (filter && (filter->empty() || filter->size()>256U))
        || now.time_since_epoch().count()<0)
        co_return foundation::fail(E::InvalidArgument);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params params) {
            return connection.query(std::move(sql),std::move(params),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",{}));
        const std::string tenant{m_impl->organization.value()};
        Params actorArgs{std::string{actor.value()},tenant,std::string{sessionId.value()},
            std::to_string(now.time_since_epoch().count())};
        const auto permitted=co_await execute(
            "SELECT s.assurance FROM openproof.sessions s "
            "JOIN openproof.identities i ON i.id=s.identity_id "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "JOIN openproof.memberships m ON m.identity_id=i.id AND m.organization_id=o.id "
            "WHERE i.id=$1 AND o.id=$2 AND s.id=$3 AND s.state=0 "
            "AND i.status=0 AND o.state=0 AND m.state=1 "
            "AND s.issued_at_ms<=$4 AND s.absolute_expires_at_ms>$4 AND s.last_seen_at_ms+s.idle_timeout_ms>$4 "
            "AND EXISTS(SELECT 1 FROM openproof.membership_roles r WHERE r.identity_id=i.id "
            "AND r.organization_id=o.id AND r.role='owner')",std::move(actorArgs));
        if (permitted.rows.size()!=1U || permitted.rows.front().size()!=1U) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::PermissionDenied);
        }
        const auto assurance=milliseconds(permitted.rows.front()[0]);
        if (assurance<2 || assurance>4) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AssuranceInsufficient);
        }
        std::string query,label;
        Params args;
        switch(operation) {
        case Read::Console:
            static_cast<void>(co_await execute("COMMIT",{}));
            co_return std::string{"{}"};
        case Read::Applications:
            label="applications"; args={tenant};
            query=
                "SELECT jsonb_build_object('id',id,'identifier',identifier,'name',display_name,"
                "'environment',(ARRAY['development','staging','production'])[environment+1],"
                "'status',(ARRAY['active','suspended','revoked'])[status+1])::text "
                "FROM openproof.applications WHERE organization_id=$1 ORDER BY id COLLATE \"C\" LIMIT 257";
            break;
        case Read::Clients: {
            label="clients";
            Params appArgs{*filter,tenant};
            const auto app=co_await execute(
                "SELECT id FROM openproof.applications WHERE id=$1 AND organization_id=$2",std::move(appArgs));
            if (app.rows.size()!=1U) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::NotFound);
            }
            args={*filter,tenant};
            // Deliberately never project secret_digest, not even for the owner.
            query=
                "SELECT CASE WHEN cardinality(redirects)<=256 AND cardinality(scopes)<=256 THEN "
                "jsonb_build_object('id',c.id,'application_id',c.application_id,'name',c.display_name,"
                "'kind',(ARRAY['web','native','browser','service'])[c.kind+1],"
                "'status',(ARRAY['active','suspended','revoked'])[c.status+1],"
                "'redirect_uris',redirects,'scopes',scopes)::text END "
                "FROM openproof.oauth_clients c JOIN openproof.applications a ON a.id=c.application_id "
                "CROSS JOIN LATERAL (SELECT ARRAY(SELECT redirect_uri FROM openproof.oauth_client_redirect_uris "
                "WHERE client_id=c.id ORDER BY redirect_uri COLLATE \"C\" LIMIT 257) AS redirects,"
                "ARRAY(SELECT scope FROM openproof.oauth_client_scopes WHERE client_id=c.id "
                "ORDER BY scope COLLATE \"C\" LIMIT 257) AS scopes) children "
                "WHERE c.application_id=$1 AND a.organization_id=$2 ORDER BY c.id COLLATE \"C\" LIMIT 257";
            break;
        }
        case Read::JarKey:
            args={*filter,tenant};
            query=
                "SELECT CASE WHEN octet_length(k.public_key_pem)<=32768 THEN "
                "jsonb_build_object('client_id',c.id,'key_id',k.key_id,'public_key_pem',k.public_key_pem)::text END "
                "FROM openproof.oauth_client_request_signing_keys k JOIN openproof.oauth_clients c ON c.id=k.client_id "
                "JOIN openproof.applications a ON a.id=c.application_id "
                "WHERE c.id=$1 AND a.organization_id=$2";
            break;
        case Read::Resources:
            // The existing resource registry has no organization column.
            // Preserve its platform-wide visibility for authorized owners.
            label="resources";
            query=
                "SELECT CASE WHEN cardinality(scopes)<=256 THEN "
                "jsonb_build_object('id',r.id,'audience',r.audience,'name',r.display_name,"
                "'status',(ARRAY['active','suspended','revoked'])[r.status+1],'scopes',scopes)::text END "
                "FROM openproof.oauth_resources r CROSS JOIN LATERAL "
                "(SELECT ARRAY(SELECT scope FROM openproof.oauth_resource_scopes WHERE resource_id=r.id "
                "ORDER BY scope COLLATE \"C\" LIMIT 257) AS scopes) children "
                "ORDER BY r.id COLLATE \"C\" LIMIT 257";
            break;
        case Read::ServiceIdentity:
            args={*filter,tenant};
            query=
                "SELECT CASE WHEN cardinality(audiences)<=256 AND cardinality(scopes)<=256 THEN "
                "jsonb_build_object('identity_id',s.identity_id,'client_id',s.client_id,'active',s.active,"
                "'audiences',audiences,'scopes',scopes)::text END "
                "FROM openproof.service_identities s JOIN openproof.oauth_clients c ON c.id=s.client_id "
                "JOIN openproof.applications a ON a.id=c.application_id "
                "JOIN openproof.identities i ON i.id=s.identity_id AND i.organization_id=a.organization_id "
                "CROSS JOIN LATERAL (SELECT ARRAY(SELECT audience FROM openproof.service_identity_audiences "
                "WHERE client_id=s.client_id ORDER BY audience COLLATE \"C\" LIMIT 257) AS audiences,"
                "ARRAY(SELECT scope FROM openproof.service_identity_scopes WHERE client_id=s.client_id "
                "ORDER BY scope COLLATE \"C\" LIMIT 257) AS scopes) children "
                "WHERE s.client_id=$1 AND a.organization_id=$2 AND i.kind=1";
            break;
        default:
            co_return foundation::fail(E::InvalidArgument);
        }
        // Enforce the aggregate byte budget inside PostgreSQL, before
        // libpq allocates the result. A NULL sentinel distinguishes an
        // oversized projection from an authorized empty collection.
        query="WITH projected AS MATERIALIZED (SELECT row_number() OVER () AS ordinal,value FROM ("+
            query+") AS q(value)), bounds AS (SELECT count(*)<=256 AND "
            "count(value)=count(*) AND COALESCE(sum(octet_length(value)),0)<=2096000 "
            "AND COALESCE(max(octet_length(value)),0)<=1048576 AS ok FROM projected) "
            "SELECT value FROM (SELECT ordinal,value FROM projected,bounds WHERE ok "
            "UNION ALL SELECT 0::bigint,NULL::text FROM bounds WHERE NOT ok) bounded ORDER BY ordinal";
        auto rows=co_await execute(std::move(query),std::move(args));
        if (label.empty() && rows.rows.empty()) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::NotFound);
        }
        if (rows.rows.size()>256U || (label.empty() && rows.rows.size()!=1U))
            co_return foundation::fail(E::Unavailable);
        std::string output=label.empty()?std::string{}:"{\""+label+"\":[";
        for (std::size_t index=0;index<rows.rows.size();++index) {
            const auto& row=rows.rows[index];
            if (row.size()!=1U || !row[0] || row[0]->size()>1024U*1024U
                || output.size()+row[0]->size()>2U*1024U*1024U)
                co_return foundation::fail(E::Unavailable);
            if (index!=0U) output.push_back(',');
            output.append(*row[0]);
        }
        if (!label.empty()) output.append("]}");
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return output;
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native application management read is unavailable.");
    }
}

asio::awaitable<foundation::Result<application::Application>>
CoroutinePostgresCanonicalFinalizer::mutateApplicationAsync(
    application::ApplicationMutationCommand command,core::IdentityId actor,
    session::SessionId sessionId,foundation::Instant now)
{
    using E=foundation::ErrorCode;
    using Mutation=application::ApplicationMutation;
    if (actor.empty() || actor.value().size()>200U || sessionId.empty() || sessionId.value().size()>200U
        || command.id.empty() || command.id.value().size()>200U || now.time_since_epoch().count()<0
        || (command.operation!=Mutation::Create && command.operation!=Mutation::Suspend
            && command.operation!=Mutation::Activate && command.operation!=Mutation::Revoke)
        || (command.operation!=Mutation::Create && (!command.identifier.empty() || !command.name.empty())))
        co_return foundation::fail(E::InvalidArgument);
    const auto tenant=std::string{m_impl->organization.value()};
    const auto timestamp=std::to_string(now.time_since_epoch().count());
    std::optional<application::Application> value;
    if (command.operation==Mutation::Create) {
        if (static_cast<unsigned int>(command.environment)>2U) co_return foundation::fail(E::InvalidArgument);
        auto created=application::Application::create(command.id,m_impl->organization,
            std::move(command.identifier),std::move(command.name),command.environment,now);
        if (!created) co_return foundation::fail(created.error());
        value.emplace(std::move(created).value());
    }
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params args) {
            return connection.query(std::move(sql),std::move(args),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        // Serialize against native/legacy owner lifecycle changes. Keep the
        // authorization rows locked until the application change commits.
        static_cast<void>(co_await execute("SELECT pg_advisory_xact_lock(7299730475761673315)",{}));
        Params actorArgs{std::string{actor.value()},tenant,std::string{sessionId.value()},timestamp};
        const auto permitted=co_await execute(
            "SELECT s.assurance FROM openproof.organizations o "
            "JOIN openproof.identities i ON i.organization_id=o.id "
            "JOIN openproof.memberships m ON m.identity_id=i.id AND m.organization_id=o.id "
            "JOIN openproof.membership_roles r ON r.identity_id=i.id AND r.organization_id=o.id "
            "JOIN openproof.sessions s ON s.identity_id=i.id "
            "WHERE i.id=$1 AND o.id=$2 AND s.id=$3 AND s.state=0 "
            "AND i.status=0 AND o.state=0 AND m.state=1 AND r.role='owner' "
            "AND s.issued_at_ms<=$4 AND s.absolute_expires_at_ms>$4 AND s.last_seen_at_ms+s.idle_timeout_ms>$4 "
            "FOR SHARE OF o,i,m,r,s",std::move(actorArgs));
        if (permitted.rows.size()!=1U || permitted.rows.front().size()!=1U) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::PermissionDenied);
        }
        const auto assurance=milliseconds(permitted.rows.front()[0]);
        if (assurance<2 || assurance>4) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AssuranceInsufficient);
        }
        if (value) {
            Params args{std::string{value->id().value()},tenant,std::string{value->identifier()},
                std::string{value->displayName()},std::to_string(static_cast<unsigned int>(value->environment())),timestamp};
            const auto inserted=co_await execute(
                "INSERT INTO openproof.applications(id,organization_id,identifier,display_name,environment,status,created_at_ms,updated_at_ms) "
                "VALUES($1,$2,$3,$4,$5,0,$6,$6) ON CONFLICT DO NOTHING RETURNING id",std::move(args));
            if (inserted.rows.empty()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::AlreadyExists);
            }
            if (inserted.rows.size()!=1U || inserted.rows.front().size()!=1U
                || required(inserted.rows.front()[0])!=value->id().value())
                throw std::runtime_error{"Application insert mismatch"};
        } else {
            Params args{std::string{command.id.value()},tenant};
            const auto locked=co_await execute(
                "SELECT identifier,display_name,environment,status,created_at_ms,updated_at_ms "
                "FROM openproof.applications WHERE id=$1 AND organization_id=$2 FOR UPDATE",std::move(args));
            if (locked.rows.empty()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::NotFound);
            }
            if (locked.rows.size()!=1U || locked.rows.front().size()!=6U)
                throw std::runtime_error{"Malformed application row"};
            const auto& row=locked.rows.front();
            const auto environment=milliseconds(row[2]),status=milliseconds(row[3]);
            if (environment>2 || status>2) throw std::runtime_error{"Invalid application state"};
            auto restored=application::Application::restore(command.id,m_impl->organization,
                required(row[0]),required(row[1]),static_cast<application::Environment>(environment),
                static_cast<application::ApplicationStatus>(status),
                foundation::Instant{foundation::Duration{milliseconds(row[4])}},
                foundation::Instant{foundation::Duration{milliseconds(row[5])}});
            if (!restored) throw std::runtime_error{"Invalid stored application"};
            auto changed=command.operation==Mutation::Suspend?restored->suspend(now)
                :command.operation==Mutation::Activate?restored->activate(now):restored->revoke(now);
            if (!changed) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(changed.error());
            }
            value.emplace(std::move(restored).value());
            Params updateArgs{std::string{value->id().value()},tenant,
                std::to_string(static_cast<unsigned int>(value->status())),timestamp};
            const auto updated=co_await execute(
                "UPDATE openproof.applications SET status=$3,updated_at_ms=$4 "
                "WHERE id=$1 AND organization_id=$2 RETURNING id",std::move(updateArgs));
            if (updated.rows.size()!=1U || updated.rows.front().size()!=1U
                || required(updated.rows.front()[0])!=value->id().value())
                throw std::runtime_error{"Application update mismatch"};
        }
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return std::move(*value);
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native application mutation is unavailable.");
    }
}

asio::awaitable<foundation::Result<client::Client>>
CoroutinePostgresCanonicalFinalizer::mutateOAuthClientAsync(
    client::ManagementMutationCommand command,core::IdentityId actor,
    session::SessionId sessionId,foundation::Instant now)
{
    using E=foundation::ErrorCode;
    using Mutation=client::ManagementMutation;
    if (actor.empty() || actor.value().size()>200U || sessionId.empty() || sessionId.value().size()>200U
        || command.id.empty() || command.id.value().size()>256U || now.time_since_epoch().count()<0
        || static_cast<unsigned int>(command.operation)>static_cast<unsigned int>(Mutation::RotateSecret))
        co_return foundation::fail(E::InvalidArgument);
    const auto tenant=std::string{m_impl->organization.value()};
    const auto timestamp=std::to_string(now.time_since_epoch().count());
    std::optional<client::Client> value;
    if (command.operation==Mutation::Create) {
        if (!command.applicationId || command.applicationId->empty() || command.applicationId->value().size()>256U
            || static_cast<unsigned int>(command.kind)>3U)
            co_return foundation::fail(E::InvalidArgument);
        auto created=client::Client::create(command.id,*command.applicationId,std::move(command.name),
            command.kind,std::move(command.redirects),std::move(command.scopes),command.digest,now);
        if (!created) co_return foundation::fail(created.error());
        value.emplace(std::move(created).value());
    } else if (command.applicationId || !command.name.empty() || !command.redirects.empty() || !command.scopes.empty()
        || command.digest.has_value()!=(command.operation==Mutation::RotateSecret)) {
        co_return foundation::fail(E::InvalidArgument);
    }
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params args) {
            return connection.query(std::move(sql),std::move(args),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        // Serialize against native/legacy owner lifecycle changes. Keep the
        // authorization rows locked until the application change commits.
        static_cast<void>(co_await execute("SELECT pg_advisory_xact_lock(7299730475761673315)",{}));
        Params actorArgs{std::string{actor.value()},tenant,std::string{sessionId.value()},timestamp};
        const auto permitted=co_await execute(
            "SELECT s.assurance FROM openproof.organizations o "
            "JOIN openproof.identities i ON i.organization_id=o.id "
            "JOIN openproof.memberships m ON m.identity_id=i.id AND m.organization_id=o.id "
            "JOIN openproof.membership_roles r ON r.identity_id=i.id AND r.organization_id=o.id "
            "JOIN openproof.sessions s ON s.identity_id=i.id "
            "WHERE i.id=$1 AND o.id=$2 AND s.id=$3 AND s.state=0 "
            "AND i.status=0 AND o.state=0 AND m.state=1 AND r.role='owner' "
            "AND s.issued_at_ms<=$4 AND s.absolute_expires_at_ms>$4 AND s.last_seen_at_ms+s.idle_timeout_ms>$4 "
            "FOR SHARE OF o,i,m,r,s",std::move(actorArgs));
        if (permitted.rows.size()!=1U || permitted.rows.front().size()!=1U) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::PermissionDenied);
        }
        const auto assurance=milliseconds(permitted.rows.front()[0]);
        if (assurance<2 || assurance>4) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AssuranceInsufficient);
        }
        if (value) {
            Params appArgs{std::string{value->applicationId().value()},tenant};
            const auto parent=co_await execute(
                "SELECT status FROM openproof.applications WHERE id=$1 AND organization_id=$2 FOR SHARE",
                std::move(appArgs));
            if (parent.rows.empty()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::NotFound);
            }
            if (parent.rows.size()!=1U || parent.rows.front().size()!=1U)
                throw std::runtime_error{"Malformed client parent"};
            if (milliseconds(parent.rows.front()[0])!=0) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::FailedPrecondition);
            }
            Params args{std::string{value->id().value()},std::string{value->applicationId().value()},
                std::string{value->displayName()},std::to_string(static_cast<unsigned int>(value->kind())),
                value->secretDigest()?std::optional<std::string>{foundation::toHex(value->secretDigest()->bytes())}:std::nullopt,
                timestamp};
            const auto inserted=co_await execute(
                "INSERT INTO openproof.oauth_clients(id,application_id,display_name,kind,status,secret_digest,created_at_ms,updated_at_ms) "
                "VALUES($1,$2,$3,$4,0,decode($5,'hex'),$6,$6) ON CONFLICT DO NOTHING RETURNING id",std::move(args));
            if (inserted.rows.empty()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::AlreadyExists);
            }
            if (inserted.rows.size()!=1U || inserted.rows.front().size()!=1U
                || required(inserted.rows.front()[0])!=value->id().value())
                throw std::runtime_error{"Client insert mismatch"};
            for (const auto& uri:value->redirectUris()) {
                Params uriArgs{std::string{value->id().value()},std::string{uri.value()}};
                static_cast<void>(co_await execute(
                    "INSERT INTO openproof.oauth_client_redirect_uris(client_id,redirect_uri) VALUES($1,$2)",std::move(uriArgs)));
            }
            for (const auto& scope:value->scopes()) {
                Params clientScopeArgs{std::string{value->id().value()},std::string{scope.value()}};
                static_cast<void>(co_await execute(
                    "INSERT INTO openproof.oauth_client_scopes(client_id,scope) VALUES($1,$2)",std::move(clientScopeArgs)));
            }
        } else {
            // Lock parent and client in the same statement as grant admission.
            Params args{std::string{command.id.value()},tenant};
            const auto locked=co_await execute(
                "SELECT c.application_id,c.display_name,c.kind,c.status,encode(c.secret_digest,'hex'),"
                "c.created_at_ms,c.updated_at_ms FROM openproof.oauth_clients c "
                "JOIN openproof.applications a ON a.id=c.application_id "
                "WHERE c.id=$1 AND a.organization_id=$2 FOR UPDATE OF c FOR SHARE OF a",std::move(args));
            if (locked.rows.empty()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::NotFound);
            }
            if (locked.rows.size()!=1U || locked.rows.front().size()!=7U)
                throw std::runtime_error{"Malformed client row"};
            const auto& row=locked.rows.front();
            const auto kind=milliseconds(row[2]),status=milliseconds(row[3]);
            if (kind>3 || status>2) throw std::runtime_error{"Invalid client state"};
            const auto clientKind=static_cast<client::ClientKind>(kind);
            std::optional<client::ClientSecretDigest> digest;
            if (row[4]) {
                auto bytes=foundation::fromHex(*row[4]);
                if (!bytes || bytes->size()!=32U) throw std::runtime_error{"Invalid client digest"};
                std::array<std::byte,32> data{};
                std::ranges::copy(*bytes,data.begin());
                digest.emplace(data);
            }
            Params redirectArgs{std::string{command.id.value()}};
            const auto redirects=co_await execute(
                "SELECT redirect_uri FROM openproof.oauth_client_redirect_uris WHERE client_id=$1 LIMIT 33 FOR SHARE",
                std::move(redirectArgs));
            if (redirects.rows.size()>32U) throw std::runtime_error{"Oversized client redirects"};
            std::vector<client::RedirectUri> uriValues;
            for (const auto& uri:redirects.rows) {
                if (uri.size()!=1U) throw std::runtime_error{"Malformed redirect"};
                auto parsed=client::RedirectUri::create(required(uri[0]),clientKind);
                if (!parsed) throw std::runtime_error{"Invalid stored redirect"};
                uriValues.push_back(std::move(parsed).value());
            }
            Params scopeArgs{std::string{command.id.value()}};
            const auto scopes=co_await execute(
                "SELECT scope FROM openproof.oauth_client_scopes WHERE client_id=$1 LIMIT 65 FOR SHARE",
                std::move(scopeArgs));
            if (scopes.rows.size()>64U) throw std::runtime_error{"Oversized client scopes"};
            std::vector<client::Scope> scopeValues;
            for (const auto& scope:scopes.rows) {
                if (scope.size()!=1U) throw std::runtime_error{"Malformed scope"};
                auto parsed=client::Scope::create(required(scope[0]));
                if (!parsed) throw std::runtime_error{"Invalid stored scope"};
                scopeValues.push_back(std::move(parsed).value());
            }
            auto restored=client::Client::restore(command.id,application::ApplicationId{required(row[0])},
                required(row[1]),clientKind,static_cast<client::ClientStatus>(status),std::move(uriValues),
                std::move(scopeValues),digest,foundation::Instant{foundation::Duration{milliseconds(row[5])}},
                foundation::Instant{foundation::Duration{milliseconds(row[6])}});
            if (!restored) throw std::runtime_error{"Invalid stored client"};
            auto changed=command.operation==Mutation::Suspend?restored->suspend(now)
                :command.operation==Mutation::Activate?restored->activate(now)
                :command.operation==Mutation::Revoke?restored->revoke(now):restored->replaceSecret(*command.digest,now);
            if (!changed) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(changed.error());
            }
            value.emplace(std::move(restored).value());
            Params updateArgs{std::string{value->id().value()},std::string{value->applicationId().value()},
                std::to_string(static_cast<unsigned int>(value->status())),
                value->secretDigest()?std::optional<std::string>{foundation::toHex(value->secretDigest()->bytes())}:std::nullopt,
                timestamp};
            const auto updated=co_await execute(
                "UPDATE openproof.oauth_clients SET status=$3,secret_digest=decode($4,'hex'),updated_at_ms=$5 "
                "WHERE id=$1 AND application_id=$2 RETURNING id",std::move(updateArgs));
            if (updated.rows.size()!=1U || updated.rows.front().size()!=1U
                || required(updated.rows.front()[0])!=value->id().value())
                throw std::runtime_error{"Client update mismatch"};
        }
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return std::move(*value);
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native OAuth client mutation is unavailable.");
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresCanonicalFinalizer::mutateOAuthJarKeyAsync(client::ClientId id,
    std::optional<std::string> keyId,std::optional<std::string> publicKeyPem,
    core::IdentityId actor,session::SessionId sessionId,foundation::Instant now)
{
    using E=foundation::ErrorCode;
    if (actor.empty() || actor.value().size()>200U || sessionId.empty() || sessionId.value().size()>200U
        || id.empty() || id.value().size()>256U || now.time_since_epoch().count()<0
        || keyId.has_value()!=publicKeyPem.has_value())
        co_return foundation::fail(E::InvalidArgument);
    std::optional<oauth::ClientRequestSigningKey> key;
    if (keyId) {
        // Accept exactly one public PEM envelope, not a concatenated
        // certificate/private key or unrelated trailing material.
        std::string_view pem{*publicKeyPem};
        constexpr std::string_view begin="-----BEGIN PUBLIC KEY-----",end="-----END PUBLIC KEY-----";
        const auto whitespace=[](char c){return c==' ' || c=='\t' || c=='\r' || c=='\n';};
        while (!pem.empty() && whitespace(pem.front())) pem.remove_prefix(1U);
        while (!pem.empty() && whitespace(pem.back())) pem.remove_suffix(1U);
        if (pem.size()>16U*1024U || !pem.starts_with(begin) || !pem.ends_with(end)
            || pem.find("-----BEGIN ",begin.size())!=std::string_view::npos
            || pem.find("-----END ")!=pem.size()-end.size()
            || std::ranges::any_of(*keyId,[](unsigned char c){return c<0x20U || c==0x7fU;}))
            co_return foundation::fail(E::InvalidArgument);
        auto valid=security::validateRs256PublicKey(pem);
        if (!valid) co_return foundation::fail(valid.error());
        auto prepared=oauth::ClientRequestSigningKey::create(id,std::move(*keyId),std::string{pem}+"\n",now);
        if (!prepared) co_return foundation::fail(prepared.error());
        key.emplace(std::move(prepared).value());
    }
    const auto tenant=std::string{m_impl->organization.value()};
    const auto timestamp=std::to_string(now.time_since_epoch().count());
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params args) {
            return connection.query(std::move(sql),std::move(args),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        // Serialize against native/legacy owner lifecycle changes. Keep the
        // authorization rows locked until the application change commits.
        static_cast<void>(co_await execute("SELECT pg_advisory_xact_lock(7299730475761673315)",{}));
        Params actorArgs{std::string{actor.value()},tenant,std::string{sessionId.value()},timestamp};
        const auto permitted=co_await execute(
            "SELECT s.assurance FROM openproof.organizations o "
            "JOIN openproof.identities i ON i.organization_id=o.id "
            "JOIN openproof.memberships m ON m.identity_id=i.id AND m.organization_id=o.id "
            "JOIN openproof.membership_roles r ON r.identity_id=i.id AND r.organization_id=o.id "
            "JOIN openproof.sessions s ON s.identity_id=i.id "
            "WHERE i.id=$1 AND o.id=$2 AND s.id=$3 AND s.state=0 "
            "AND i.status=0 AND o.state=0 AND m.state=1 AND r.role='owner' "
            "AND s.issued_at_ms<=$4 AND s.absolute_expires_at_ms>$4 AND s.last_seen_at_ms+s.idle_timeout_ms>$4 "
            "FOR SHARE OF o,i,m,r,s",std::move(actorArgs));
        if (permitted.rows.size()!=1U || permitted.rows.front().size()!=1U) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::PermissionDenied);
        }
        const auto assurance=milliseconds(permitted.rows.front()[0]);
        if (assurance<2 || assurance>4) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AssuranceInsufficient);
        }
        Params clientArgs{std::string{id.value()},tenant};
        const auto parent=co_await execute(
            "SELECT c.id,c.status FROM openproof.oauth_clients c "
            "JOIN openproof.applications a ON a.id=c.application_id "
            "WHERE c.id=$1 AND a.organization_id=$2 FOR UPDATE OF c FOR SHARE OF a",std::move(clientArgs));
        if (parent.rows.empty()) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::NotFound);
        }
        if (parent.rows.size()!=1U || parent.rows.front().size()!=2U)
            throw std::runtime_error{"Malformed JAR client"};
        if (key && milliseconds(parent.rows.front()[1])==2) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::FailedPrecondition);
        }
        if (key) {
            Params args{std::string{id.value()},std::string{key->keyId()},
                std::string{key->publicKeyPem()},timestamp};
            const auto changed=co_await execute(
                "INSERT INTO openproof.oauth_client_request_signing_keys(client_id,key_id,public_key_pem,updated_at_ms) "
                "VALUES($1,$2,$3,$4) ON CONFLICT(client_id) DO UPDATE SET key_id=EXCLUDED.key_id,"
                "public_key_pem=EXCLUDED.public_key_pem,updated_at_ms=EXCLUDED.updated_at_ms "
                "WHERE openproof.oauth_client_request_signing_keys.updated_at_ms<=EXCLUDED.updated_at_ms "
                "RETURNING client_id",std::move(args));
            if (changed.rows.empty()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::Conflict);
            }
            if (changed.rows.size()!=1U || changed.rows.front().size()!=1U
                || required(changed.rows.front()[0])!=id.value())
                throw std::runtime_error{"JAR key update mismatch"};
        } else {
            Params args{std::string{id.value()}};
            static_cast<void>(co_await execute(
                "DELETE FROM openproof.oauth_client_request_signing_keys WHERE client_id=$1",std::move(args)));
        }
        // Replay records intentionally survive rotation and removal.
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native JAR key mutation is unavailable.");
    }
}

asio::awaitable<foundation::Result<resource::ResourceServer>>
CoroutinePostgresCanonicalFinalizer::mutateOAuthResourceAsync(
    resource::ResourceMutationCommand command,core::IdentityId actor,
    session::SessionId sessionId,foundation::Instant now)
{
    using E=foundation::ErrorCode;
    using Op=resource::ResourceMutation;
    if (actor.empty() || actor.value().size()>200U || sessionId.empty() || sessionId.value().size()>200U
        || now.time_since_epoch().count()<0 || command.audience.empty() || command.audience.size()>2048U
        || std::ranges::any_of(command.audience,[](unsigned char c){return c<=0x20U || c==0x7fU;})
        || static_cast<unsigned int>(command.operation)>static_cast<unsigned int>(Op::Revoke))
        co_return foundation::fail(E::InvalidArgument);
    std::optional<resource::ResourceServer> value;
    if (command.operation==Op::Create) {
        if (command.id.empty() || command.id.value().size()>200U
            || std::ranges::any_of(command.name,[](unsigned char c){return c<0x20U || c==0x7fU;}))
            co_return foundation::fail(E::InvalidArgument);
        auto created=resource::ResourceServer::create(command.id,std::move(command.audience),
            std::move(command.name),std::move(command.scopes),now);
        if (!created) co_return foundation::fail(created.error());
        value.emplace(std::move(created).value());
    } else if (!command.id.empty() || !command.name.empty() || !command.scopes.empty()) {
        co_return foundation::fail(E::InvalidArgument);
    }
    const auto tenant=std::string{m_impl->organization.value()};
    const auto timestamp=std::to_string(now.time_since_epoch().count());
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params args) {
            return connection.query(std::move(sql),std::move(args),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        // Serialize against native/legacy owner lifecycle changes. Keep the
        // authorization rows locked until the application change commits.
        static_cast<void>(co_await execute("SELECT pg_advisory_xact_lock(7299730475761673315)",{}));
        Params actorArgs{std::string{actor.value()},tenant,std::string{sessionId.value()},timestamp};
        const auto permitted=co_await execute(
            "SELECT s.assurance FROM openproof.organizations o "
            "JOIN openproof.identities i ON i.organization_id=o.id "
            "JOIN openproof.memberships m ON m.identity_id=i.id AND m.organization_id=o.id "
            "JOIN openproof.membership_roles r ON r.identity_id=i.id AND r.organization_id=o.id "
            "JOIN openproof.sessions s ON s.identity_id=i.id "
            "WHERE i.id=$1 AND o.id=$2 AND s.id=$3 AND s.state=0 "
            "AND i.status=0 AND o.state=0 AND m.state=1 AND r.role='owner' "
            "AND s.issued_at_ms<=$4 AND s.absolute_expires_at_ms>$4 AND s.last_seen_at_ms+s.idle_timeout_ms>$4 "
            "FOR SHARE OF o,i,m,r,s",std::move(actorArgs));
        if (permitted.rows.size()!=1U || permitted.rows.front().size()!=1U) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::PermissionDenied);
        }
        const auto assurance=milliseconds(permitted.rows.front()[0]);
        if (assurance<2 || assurance>4) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AssuranceInsufficient);
        }
        // Resources are platform-wide in the current schema; the actor is
        // still authorized against the configured tenant. Grant issuance
        // takes a SHARE lock on these same resource rows.
        if (value) {
            Params args{std::string{value->id().value()},std::string{value->audience()},
                std::string{value->displayName()},timestamp};
            const auto inserted=co_await execute(
                "INSERT INTO openproof.oauth_resources(id,audience,display_name,status,created_at_ms,updated_at_ms) "
                "VALUES($1,$2,$3,0,$4,$4) ON CONFLICT DO NOTHING RETURNING id",std::move(args));
            if (inserted.rows.empty()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::AlreadyExists);
            }
            if (inserted.rows.size()!=1U || inserted.rows.front().size()!=1U
                || required(inserted.rows.front()[0])!=value->id().value())
                throw std::runtime_error{"Resource insert mismatch"};
            for (const auto& scope:value->scopes()) {
                Params resourceScopeArgs{std::string{value->id().value()},scope};
                static_cast<void>(co_await execute(
                    "INSERT INTO openproof.oauth_resource_scopes(resource_id,scope) VALUES($1,$2)",std::move(resourceScopeArgs)));
            }
        } else {
            Params args{command.audience};
            const auto locked=co_await execute(
                "SELECT id,display_name,status,created_at_ms,updated_at_ms "
                "FROM openproof.oauth_resources WHERE audience=$1 FOR UPDATE",std::move(args));
            if (locked.rows.empty()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::NotFound);
            }
            if (locked.rows.size()!=1U || locked.rows.front().size()!=5U)
                throw std::runtime_error{"Malformed resource row"};
            const auto& row=locked.rows.front();
            const auto status=milliseconds(row[2]);
            if (status>2) throw std::runtime_error{"Invalid resource status"};
            Params scopeArgs{required(row[0])};
            const auto grants=co_await execute(
                "SELECT scope FROM openproof.oauth_resource_scopes WHERE resource_id=$1 "
                "ORDER BY scope COLLATE \"C\" LIMIT 257 FOR SHARE",std::move(scopeArgs));
            if (grants.rows.empty() || grants.rows.size()>256U)
                throw std::runtime_error{"Invalid resource scopes"};
            std::vector<std::string> scopes;
            for (const auto& grant:grants.rows) {
                if (grant.size()!=1U) throw std::runtime_error{"Malformed resource scope"};
                scopes.push_back(required(grant[0]));
            }
            const auto updatedAt=foundation::Instant{foundation::Duration{milliseconds(row[4])}};
            auto restored=resource::ResourceServer::restore(resource::ResourceId{required(row[0])},
                command.audience,required(row[1]),std::move(scopes),static_cast<resource::ResourceStatus>(status),
                foundation::Instant{foundation::Duration{milliseconds(row[3])}},updatedAt);
            if (!restored) throw std::runtime_error{"Invalid stored resource"};
            if (now<updatedAt) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::Conflict);
            }
            const auto target=command.operation==Op::Suspend?resource::ResourceStatus::Suspended:
                command.operation==Op::Activate?resource::ResourceStatus::Active:resource::ResourceStatus::Revoked;
            auto changed=restored->setStatus(target,now);
            if (!changed) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(changed.error());
            }
            value.emplace(std::move(restored).value());
            Params updateArgs{std::string{value->id().value()},command.audience,
                std::to_string(static_cast<unsigned int>(value->status())),timestamp};
            // A lifecycle change never deletes or replaces scope grants.
            const auto updated=co_await execute(
                "UPDATE openproof.oauth_resources SET status=$3,updated_at_ms=$4 "
                "WHERE id=$1 AND audience=$2 RETURNING id",std::move(updateArgs));
            if (updated.rows.size()!=1U || updated.rows.front().size()!=1U
                || required(updated.rows.front()[0])!=value->id().value())
                throw std::runtime_error{"Resource update mismatch"};
        }
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return std::move(*value);
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native resource mutation is unavailable.");
    }
}

asio::awaitable<foundation::Result<resource::ServiceIdentity>>
CoroutinePostgresCanonicalFinalizer::mutateServiceIdentityAsync(
    resource::ServiceMutationCommand command,core::IdentityId actor,
    session::SessionId sessionId,foundation::Instant now)
{
    using E=foundation::ErrorCode;
    using Op=resource::ServiceMutation;
    if (actor.empty() || actor.value().size()>200U || sessionId.empty() || sessionId.value().size()>200U
        || command.clientId.empty() || command.clientId.value().size()>256U
        || now.time_since_epoch().count()<0 || static_cast<unsigned int>(command.operation)>2U)
        co_return foundation::fail(E::InvalidArgument);
    std::optional<resource::ServiceIdentity> value;
    if (command.operation==Op::Provision) {
        if (command.identityId.empty() || command.identityId.value().size()>200U ||
            std::ranges::any_of(command.audiences,[](const auto& audience) {
                return std::ranges::any_of(audience,[](unsigned char c){return c<=0x20U || c==0x7fU;});
            })) co_return foundation::fail(E::InvalidArgument);
        auto created=resource::ServiceIdentity::create(command.identityId,command.clientId,
            std::move(command.audiences),std::move(command.scopes),now);
        if (!created) co_return foundation::fail(created.error());
        value.emplace(std::move(created).value());
    } else if (!command.identityId.empty() || !command.audiences.empty() || !command.scopes.empty()) {
        co_return foundation::fail(E::InvalidArgument);
    }
    const auto tenant=std::string{m_impl->organization.value()};
    const auto timestamp=std::to_string(now.time_since_epoch().count());
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params args) {
            return connection.query(std::move(sql),std::move(args),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        // Serialize against native/legacy owner lifecycle changes. Keep the
        // authorization rows locked until the application change commits.
        static_cast<void>(co_await execute("SELECT pg_advisory_xact_lock(7299730475761673315)",{}));
        Params actorArgs{std::string{actor.value()},tenant,std::string{sessionId.value()},timestamp};
        const auto permitted=co_await execute(
            "SELECT s.assurance FROM openproof.organizations o "
            "JOIN openproof.identities i ON i.organization_id=o.id "
            "JOIN openproof.memberships m ON m.identity_id=i.id AND m.organization_id=o.id "
            "JOIN openproof.membership_roles r ON r.identity_id=i.id AND r.organization_id=o.id "
            "JOIN openproof.sessions s ON s.identity_id=i.id "
            "WHERE i.id=$1 AND o.id=$2 AND s.id=$3 AND s.state=0 "
            "AND i.status=0 AND o.state=0 AND m.state=1 AND r.role='owner' "
            "AND s.issued_at_ms<=$4 AND s.absolute_expires_at_ms>$4 AND s.last_seen_at_ms+s.idle_timeout_ms>$4 "
            "FOR SHARE OF o,i,m,r,s",std::move(actorArgs));
        if (permitted.rows.size()!=1U || permitted.rows.front().size()!=1U) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::PermissionDenied);
        }
        const auto assurance=milliseconds(permitted.rows.front()[0]);
        if (assurance<2 || assurance>4) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AssuranceInsufficient);
        }
        const std::string clientId{command.clientId.value()};
        // Exclusive client lock serializes provisioning/activation with
        // machine grant admission, which takes a SHARE lock on this row.
        Params clientArgs{clientId,tenant};
        const auto parent=co_await execute(
            "SELECT c.kind,c.status,a.status,c.secret_digest IS NOT NULL FROM openproof.oauth_clients c "
            "JOIN openproof.applications a ON a.id=c.application_id "
            "WHERE c.id=$1 AND a.organization_id=$2 FOR UPDATE OF c FOR SHARE OF a",std::move(clientArgs));
        if (parent.rows.empty()) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::NotFound);
        }
        if (parent.rows.size()!=1U || parent.rows.front().size()!=4U)
            throw std::runtime_error{"Malformed service client"};
        const auto& clientRow=parent.rows.front();
        if (milliseconds(clientRow[0])!=3 || !boolean(clientRow[3])
            || (command.operation!=Op::Deactivate &&
                (milliseconds(clientRow[1])!=0 || milliseconds(clientRow[2])!=0))) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::FailedPrecondition);
        }
        Params serviceArgs{clientId};
        const auto existing=co_await execute(
            "SELECT s.identity_id,s.active,s.created_at_ms,s.updated_at_ms,i.organization_id,i.kind,i.status "
            "FROM openproof.service_identities s JOIN openproof.identities i ON i.id=s.identity_id "
            "WHERE s.client_id=$1 FOR UPDATE OF s FOR SHARE OF i",std::move(serviceArgs));
        if (value && !existing.rows.empty()) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AlreadyExists);
        }
        if (!value) {
            if (existing.rows.empty()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::NotFound);
            }
            if (existing.rows.size()!=1U || existing.rows.front().size()!=7U)
                throw std::runtime_error{"Malformed service identity"};
            const auto& row=existing.rows.front();
            if (required(row[4])!=tenant || milliseconds(row[5])!=1 ||
                (command.operation==Op::Activate && milliseconds(row[6])!=0)) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::FailedPrecondition);
            }
            Params audienceArgs{clientId};
            const auto audiences=co_await execute(
                "SELECT audience FROM openproof.service_identity_audiences WHERE client_id=$1 "
                "ORDER BY audience COLLATE \"C\" LIMIT 65 FOR SHARE",std::move(audienceArgs));
            Params scopeArgs{clientId};
            const auto grants=co_await execute(
                "SELECT scope FROM openproof.service_identity_scopes WHERE client_id=$1 "
                "ORDER BY scope COLLATE \"C\" LIMIT 257 FOR SHARE",std::move(scopeArgs));
            if (audiences.rows.empty() || audiences.rows.size()>64U || grants.rows.empty() || grants.rows.size()>256U)
                throw std::runtime_error{"Invalid service grant size"};
            std::vector<std::string> audienceValues,scopeValues;
            for (const auto& item:audiences.rows) {
                if (item.size()!=1U) throw std::runtime_error{"Malformed audience"};
                audienceValues.push_back(required(item[0]));
            }
            for (const auto& item:grants.rows) {
                if (item.size()!=1U) throw std::runtime_error{"Malformed scope"};
                scopeValues.push_back(required(item[0]));
            }
            const auto updatedAt=foundation::Instant{foundation::Duration{milliseconds(row[3])}};
            if (now<updatedAt) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::Conflict);
            }
            auto restored=resource::ServiceIdentity::restore(core::IdentityId{required(row[0])},
                command.clientId,std::move(audienceValues),std::move(scopeValues),boolean(row[1]),
                foundation::Instant{foundation::Duration{milliseconds(row[2])}},updatedAt);
            if (!restored) throw std::runtime_error{"Invalid stored service identity"};
            auto changed=command.operation==Op::Activate?restored->activate(now):restored->deactivate(now);
            if (!changed) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(changed.error());
            }
            value.emplace(std::move(restored).value());
        }
        if (command.operation!=Op::Deactivate) {
            // Validate every audience against current registry and scope set
            // under row locks. No widening, even on reactivation.
            for (const auto& audience:value->audiences()) {
                Params resourceArgs{audience};
                const auto target=co_await execute(
                    "SELECT id FROM openproof.oauth_resources WHERE audience=$1 AND status=0 FOR SHARE",
                    std::move(resourceArgs));
                if (target.rows.size()!=1U || target.rows.front().size()!=1U) {
                    co_await rollback(connection,deadline);
                    co_return foundation::fail(E::PermissionDenied);
                }
                Params grantArgs{required(target.rows.front()[0])};
                const auto grants=co_await execute(
                    "SELECT scope FROM openproof.oauth_resource_scopes WHERE resource_id=$1 LIMIT 257 FOR SHARE",
                    std::move(grantArgs));
                if (grants.rows.size()>256U) throw std::runtime_error{"Oversized resource scopes"};
                if (!std::ranges::all_of(value->scopes(),[&](const auto& scope) {
                    return std::ranges::any_of(grants.rows,[&](const auto& row) {
                        return row.size()==1U && required(row[0])==scope;
                    });
                })) {
                    co_await rollback(connection,deadline);
                    co_return foundation::fail(E::PermissionDenied);
                }
            }
        }
        if (command.operation==Op::Provision) {
            const std::string identityId{value->identity().value()};
            Params identityArgs{identityId,tenant,timestamp};
            const auto inserted=co_await execute(
                "INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) "
                "VALUES($1,$2,1,0,$3) ON CONFLICT DO NOTHING RETURNING id",std::move(identityArgs));
            if (inserted.rows.empty()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::AlreadyExists);
            }
            if (inserted.rows.size()!=1U || inserted.rows.front().size()!=1U || required(inserted.rows.front()[0])!=identityId)
                throw std::runtime_error{"Service identity insert mismatch"};
            Params mappingArgs{clientId,identityId,timestamp};
            static_cast<void>(co_await execute(
                "INSERT INTO openproof.service_identities(client_id,identity_id,active,created_at_ms,updated_at_ms) "
                "VALUES($1,$2,true,$3,$3)",std::move(mappingArgs)));
            for (const auto& audience:value->audiences()) {
                Params args{clientId,audience};
                static_cast<void>(co_await execute(
                    "INSERT INTO openproof.service_identity_audiences(client_id,audience) VALUES($1,$2)",std::move(args)));
            }
            for (const auto& scope:value->scopes()) {
                Params args{clientId,scope};
                static_cast<void>(co_await execute(
                    "INSERT INTO openproof.service_identity_scopes(client_id,scope) VALUES($1,$2)",std::move(args)));
            }
        } else {
            Params args{clientId,std::string{value->identity().value()},value->active()?"true":"false",timestamp};
            const auto updated=co_await execute(
                "UPDATE openproof.service_identities SET active=$3,updated_at_ms=$4 "
                "WHERE client_id=$1 AND identity_id=$2 RETURNING client_id",std::move(args));
            if (updated.rows.size()!=1U || updated.rows.front().size()!=1U || required(updated.rows.front()[0])!=clientId)
                throw std::runtime_error{"Service state update mismatch"};
        }
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return std::move(*value);
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native service identity mutation is unavailable.");
    }
}

asio::awaitable<foundation::Result<std::vector<provider::passkey::CredentialSummary>>>
CoroutinePostgresCanonicalFinalizer::readPasskeyAccountAsync(core::IdentityId actor,
    session::SessionId sessionId,foundation::Instant now,
    std::optional<provider::passkey::RegistrationCeremony> ceremony)
{
    using E=foundation::ErrorCode;
    using Summary=provider::passkey::CredentialSummary;
    if (actor.empty() || actor.value().size()>200U || sessionId.empty() || sessionId.value().size()>200U
        || now.time_since_epoch().count()<0 || (ceremony &&
        (ceremony->identity!=actor || ceremony->id.empty() || ceremony->id.value().size()>256U
            || ceremony->expiresAt<=now || ceremony->expiresAt-now>std::chrono::minutes{10})))
        co_return foundation::fail(E::InvalidArgument);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params args) {
            return connection.query(std::move(sql),std::move(args),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        const std::string identityId{actor.value()},tenant{m_impl->organization.value()};
        const auto timestamp=std::to_string(now.time_since_epoch().count());
        if (ceremony) {
            Params args{identityId};
            static_cast<void>(co_await execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 684271993))",std::move(args)));
        }
        Params sessionArgs{identityId,tenant,std::string{sessionId.value()},timestamp};
        const auto permitted=co_await execute(
            "SELECT s.id FROM openproof.sessions s JOIN openproof.identities i ON i.id=s.identity_id "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "WHERE i.id=$1 AND o.id=$2 AND s.id=$3 AND s.state=0 "
            "AND i.status=0 AND i.kind=0 AND o.state=0 "
            "AND s.issued_at_ms<=$4 AND s.absolute_expires_at_ms>$4 AND s.last_seen_at_ms+s.idle_timeout_ms>$4 "
            "FOR SHARE OF i,o,s",std::move(sessionArgs));
        if (permitted.rows.size()!=1U || permitted.rows.front().size()!=1U) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationFailed);
        }
        Params credentialArgs{identityId};
        const auto rows=co_await execute(
            "SELECT credential_id,sign_count,created_at_ms,last_used_at_ms "
            "FROM openproof.passkey_credentials WHERE identity_id=$1 "
            "ORDER BY created_at_ms,credential_id LIMIT 257",std::move(credentialArgs));
        if (rows.rows.size()>256U) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::Unavailable);
        }
        std::vector<Summary> result;
        result.reserve(rows.rows.size());
        for (const auto& row:rows.rows) {
            if (row.size()!=4U) throw std::runtime_error{"Malformed passkey metadata"};
            auto credentialId=required(row[0]);
            const auto count=milliseconds(row[1]);
            if (credentialId.empty() || credentialId.size()>4096U || count>4294967295LL)
                throw std::runtime_error{"Invalid passkey metadata"};
            result.push_back(Summary{std::move(credentialId),static_cast<std::uint32_t>(count),
                foundation::Instant{foundation::Duration{milliseconds(row[2])}},
                foundation::Instant{foundation::Duration{milliseconds(row[3])}}});
        }
        if (ceremony) {
            // Reclaim a bounded batch of expired records for this identity.
            // Do not invalidate other concurrently active ceremonies.
            Params purgeArgs{identityId,timestamp};
            static_cast<void>(co_await execute(
                "WITH expired AS (SELECT id FROM openproof.passkey_registration_ceremonies "
                "WHERE identity_id=$1 AND expires_at_ms<=$2 ORDER BY expires_at_ms LIMIT 128 FOR UPDATE SKIP LOCKED) "
                "DELETE FROM openproof.passkey_registration_ceremonies c USING expired e WHERE c.id=e.id",
                std::move(purgeArgs)));
            Params countArgs{identityId,timestamp};
            const auto active=co_await execute(
                "SELECT id FROM openproof.passkey_registration_ceremonies "
                "WHERE identity_id=$1 AND expires_at_ms>$2 AND consumed_at_ms IS NULL LIMIT 33",
                std::move(countArgs));
            if (active.rows.size()>=32U) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::RateLimited);
            }
            Params args{std::string{ceremony->id.value()},identityId,
                std::to_string(ceremony->expiresAt.time_since_epoch().count())};
            const auto inserted=co_await execute(
                "INSERT INTO openproof.passkey_registration_ceremonies(id,identity_id,expires_at_ms) "
                "VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING id",std::move(args));
            if (inserted.rows.size()!=1U || inserted.rows.front().size()!=1U
                || required(inserted.rows.front()[0])!=ceremony->id.value()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::Conflict);
            }
        }
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return result;
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native passkey account operation is unavailable.");
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresCanonicalFinalizer::mutatePasskeyAccountAsync(core::IdentityId actor,
    session::SessionId sessionId,foundation::Instant now,std::string credentialId,
    std::optional<idp::ChallengeId> ceremony,std::optional<provider::passkey::PasskeyCredential> verified)
{
    using E=foundation::ErrorCode;
    const auto encoded=[](std::string_view value,std::size_t limit){
        return !value.empty() && value.size()<=limit && std::ranges::all_of(value,[](char c){
            return (c>='A' && c<='Z') || (c>='a' && c<='z') || (c>='0' && c<='9') || c=='-' || c=='_';
        });
    };
    if (actor.empty() || actor.value().size()>200U || sessionId.empty() || sessionId.value().size()>200U
        || now.time_since_epoch().count()<0 || !encoded(credentialId,4096U)
        || ceremony.has_value()!=verified.has_value()
        || (verified && (verified->identity!=actor || verified->credentialId!=credentialId
            || !encoded(ceremony->value(),256U) || !encoded(verified->publicKeyX,43U)
            || !encoded(verified->publicKeyY,43U) || verified->publicKeyX.size()!=43U
            || verified->publicKeyY.size()!=43U || verified->createdAt!=now || verified->lastUsedAt!=now)))
        co_return foundation::fail(E::InvalidArgument);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params args){
            return connection.query(std::move(sql),std::move(args),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        const std::string identityId{actor.value()},tenant{m_impl->organization.value()};
        const auto timestamp=std::to_string(now.time_since_epoch().count());
        Params lockArgs{identityId};
        static_cast<void>(co_await execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 684271993))",std::move(lockArgs)));
        Params actorArgs{identityId,tenant,std::string{sessionId.value()},timestamp};
        const auto permitted=co_await execute(
            "SELECT s.id FROM openproof.sessions s JOIN openproof.identities i ON i.id=s.identity_id "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "WHERE i.id=$1 AND o.id=$2 AND s.id=$3 AND s.state=0 "
            "AND i.status=0 AND i.kind=0 AND o.state=0 "
            "AND s.issued_at_ms<=$4 AND s.absolute_expires_at_ms>$4 AND s.last_seen_at_ms+s.idle_timeout_ms>$4 "
            "FOR UPDATE OF i FOR SHARE OF o,s",std::move(actorArgs));
        if (permitted.rows.size()!=1U || permitted.rows.front().size()!=1U) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationFailed);
        }
        Params ownerArgs{identityId};
        const auto link=co_await execute(
            "SELECT identity_id FROM openproof.external_identities "
            "WHERE provider='passkey' AND external_subject=$1 FOR UPDATE",std::move(ownerArgs));
        if (link.rows.size()>1U || (!link.rows.empty() && link.rows.front().size()!=1U))
            throw std::runtime_error{"Malformed passkey link"};
        if (!link.rows.empty() && required(link.rows.front()[0])!=identityId) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::PermissionDenied);
        }
        Params countArgs{identityId,credentialId};
        const auto counts=co_await execute(
            "SELECT count(*),count(*) FILTER (WHERE credential_id=$2) "
            "FROM openproof.passkey_credentials WHERE identity_id=$1",std::move(countArgs));
        if (counts.rows.size()!=1U || counts.rows.front().size()!=2U)
            throw std::runtime_error{"Malformed passkey count"};
        const auto total=milliseconds(counts.rows.front()[0]),matching=milliseconds(counts.rows.front()[1]);
        if (verified) {
            if (total>=256 || matching!=0) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(matching?E::AlreadyExists:E::RateLimited);
            }
            Params ceremonyArgs{std::string{ceremony->value()},identityId,timestamp};
            const auto consumed=co_await execute(
                "UPDATE openproof.passkey_registration_ceremonies SET consumed_at_ms=$3 "
                "WHERE id=$1 AND identity_id=$2 AND consumed_at_ms IS NULL AND expires_at_ms>$3 RETURNING id",
                std::move(ceremonyArgs));
            if (consumed.rows.size()!=1U || consumed.rows.front().size()!=1U
                || required(consumed.rows.front()[0])!=ceremony->value()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::AuthenticationFailed);
            }
            Params credentialArgs{credentialId,identityId,verified->publicKeyX,verified->publicKeyY,
                std::to_string(verified->signCount),timestamp};
            const auto added=co_await execute(
                "INSERT INTO openproof.passkey_credentials"
                "(credential_id,identity_id,public_key_x,public_key_y,sign_count,created_at_ms,last_used_at_ms) "
                "VALUES($1,$2,$3,$4,$5,$6,$6) ON CONFLICT DO NOTHING RETURNING credential_id",std::move(credentialArgs));
            if (added.rows.empty()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::AlreadyExists);
            }
            if (added.rows.size()!=1U || added.rows.front().size()!=1U || required(added.rows.front()[0])!=credentialId)
                throw std::runtime_error{"Passkey insert mismatch"};
            Params linkArgs{identityId,timestamp};
            const auto attached=co_await execute(
                "INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) "
                "VALUES('passkey',$1,$1,$2) ON CONFLICT(provider,external_subject) DO UPDATE SET "
                "identity_id=EXCLUDED.identity_id WHERE openproof.external_identities.identity_id=EXCLUDED.identity_id "
                "RETURNING identity_id",std::move(linkArgs));
            if (attached.rows.size()!=1U || attached.rows.front().size()!=1U
                || required(attached.rows.front()[0])!=identityId) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::Conflict);
            }
        } else {
            if (matching!=1) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::NotFound);
            }
            if (total<=1 && !link.rows.empty()) {
                co_await rollback(connection,deadline);
                co_return foundation::fail(E::FailedPrecondition);
            }
            Params args{identityId,credentialId};
            const auto deleted=co_await execute(
                "DELETE FROM openproof.passkey_credentials WHERE identity_id=$1 AND credential_id=$2 RETURNING credential_id",
                std::move(args));
            if (deleted.rows.size()!=1U || deleted.rows.front().size()!=1U || required(deleted.rows.front()[0])!=credentialId)
                throw std::runtime_error{"Passkey removal mismatch"};
        }
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native passkey mutation is unavailable.");
    }
}

asio::awaitable<foundation::Result<core::IdentityId>>
CoroutinePostgresCanonicalFinalizer::verifyPasskeyAssertionAsync(const provider::passkey::PasskeyConfig& config,
    idp::ChallengeId challenge,provider::passkey::AssertionResponse assertion,foundation::Instant now)
{
    using E=foundation::ErrorCode;
    if (challenge.empty() || challenge.value().size()>256U || assertion.credentialId.empty()
        || assertion.credentialId.size()>4096U || now.time_since_epoch().count()<0)
        co_return foundation::fail(E::AuthenticationFailed);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params args){
            return connection.query(std::move(sql),std::move(args),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        const std::string tenant{m_impl->organization.value()};
        Params lookupArgs{assertion.credentialId,tenant};
        const auto owner=co_await execute(
            "SELECT p.identity_id FROM openproof.passkey_credentials p "
            "JOIN openproof.identities i ON i.id=p.identity_id WHERE p.credential_id=$1 AND i.organization_id=$2",
            std::move(lookupArgs));
        if (owner.rows.size()!=1U || owner.rows.front().size()!=1U)
            co_return foundation::fail(E::AuthenticationFailed);
        const auto identityId=required(owner.rows.front()[0]);
        Params lockArgs{identityId};
        static_cast<void>(co_await execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 684271993))",std::move(lockArgs)));
        Params actorArgs{identityId,tenant};
        const auto actor=co_await execute(
            "SELECT i.id FROM openproof.identities i JOIN openproof.organizations o ON o.id=i.organization_id "
            "WHERE i.id=$1 AND o.id=$2 AND i.status=0 AND i.kind=0 AND o.state=0 FOR SHARE OF i,o",
            std::move(actorArgs));
        if (actor.rows.size()!=1U) co_return foundation::fail(E::AuthenticationFailed);
        Params linkArgs{identityId};
        const auto link=co_await execute(
            "SELECT identity_id FROM openproof.external_identities WHERE provider='passkey' "
            "AND external_subject=$1 AND identity_id=$1 FOR SHARE",std::move(linkArgs));
        if (link.rows.size()!=1U) co_return foundation::fail(E::AuthenticationFailed);
        Params credentialArgs{assertion.credentialId,identityId};
        const auto locked=co_await execute(
            "SELECT public_key_x,public_key_y,sign_count,created_at_ms,last_used_at_ms "
            "FROM openproof.passkey_credentials WHERE credential_id=$1 AND identity_id=$2 FOR UPDATE",
            std::move(credentialArgs));
        if (locked.rows.size()!=1U || locked.rows.front().size()!=5U)
            co_return foundation::fail(E::AuthenticationFailed);
        const auto& row=locked.rows.front();
        const auto counter=milliseconds(row[2]);
        if (counter>4294967295LL) co_return foundation::fail(E::AuthenticationFailed);
        provider::passkey::PasskeyCredential credential{assertion.credentialId,core::IdentityId{identityId},
            required(row[0]),required(row[1]),static_cast<std::uint32_t>(counter),
            foundation::Instant{foundation::Duration{milliseconds(row[3])}},
            foundation::Instant{foundation::Duration{milliseconds(row[4])}}};
        auto verified=provider::passkey::verifyAssertionProof(config,challenge,assertion,credential);
        if (!verified) {
            co_await rollback(connection,deadline);
            co_return foundation::fail(E::AuthenticationFailed);
        }
        Params updateArgs{credential.credentialId,identityId,std::to_string(credential.signCount),
            std::to_string(verified.value()),std::to_string(now.time_since_epoch().count())};
        const auto advanced=co_await execute(
            "UPDATE openproof.passkey_credentials SET sign_count=$4,last_used_at_ms=GREATEST(last_used_at_ms,$5) "
            "WHERE credential_id=$1 AND identity_id=$2 AND sign_count=$3 RETURNING credential_id",
            std::move(updateArgs));
        if (advanced.rows.size()!=1U || advanced.rows.front().size()!=1U
            || required(advanced.rows.front()[0])!=credential.credentialId)
            co_return foundation::fail(E::AuthenticationFailed);
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return core::IdentityId{identityId};
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native passkey verification is unavailable.");
    }
}

namespace {
std::string scimProjection(bool users,enterprise::scim::ReadSelector selector)
{
    namespace scim=enterprise::scim;
        std::string projection=users?
            "SELECT u.user_name AS sort_name,u.identity_id AS id,u.updated_at_ms AS updated,"
            "jsonb_strip_nulls(jsonb_build_object('schemas',jsonb_build_array('urn:ietf:params:scim:schemas:core:2.0:User'),"
            "'id',u.identity_id,'externalId',u.external_id,'userName',u.user_name,'active',i.status=0,"
            "'displayName',p.display_name,'emails',CASE WHEN p.email IS NOT NULL THEN "
            "jsonb_build_array(jsonb_build_object('value',p.email,'primary',true)) END,"
            "'meta',jsonb_build_object('resourceType','User','created',"
            "to_char(to_timestamp(u.created_at_ms/1000.0) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),"
            "'lastModified',to_char(to_timestamp(u.updated_at_ms/1000.0) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),"
            "'location','/scim/v2/Users/'||u.identity_id,'version','W/\"'||u.updated_at_ms::text||'\"')))::text AS value "
            "FROM openproof.scim_users u JOIN openproof.identities i ON i.id=u.identity_id AND i.organization_id=u.organization_id "
            "LEFT JOIN openproof.identity_profiles p ON p.identity_id=i.id WHERE u.organization_id=$1 AND i.kind=0"
            :
            "SELECT g.display_name AS sort_name,g.id,g.updated_at_ms AS updated,"
            "CASE WHEN children.total<=10000 THEN jsonb_strip_nulls(jsonb_build_object("
            "'schemas',jsonb_build_array('urn:ietf:params:scim:schemas:core:2.0:Group'),"
            "'id',g.id,'externalId',g.external_id,'displayName',g.display_name,'members',children.members,"
            "'meta',jsonb_build_object('resourceType','Group','created',"
            "to_char(to_timestamp(g.created_at_ms/1000.0) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),"
            "'lastModified',to_char(to_timestamp(g.updated_at_ms/1000.0) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),"
            "'location','/scim/v2/Groups/'||g.id,'version','W/\"'||g.updated_at_ms::text||'\"')))::text END AS value "
            "FROM openproof.scim_groups g CROSS JOIN LATERAL (SELECT count(*) AS total,"
            "COALESCE(jsonb_agg(jsonb_build_object('value',m.identity_id,'$ref','/scim/v2/Users/'||m.identity_id) "
            "ORDER BY m.identity_id COLLATE \"C\"),'[]'::jsonb) AS members FROM "
            "(SELECT identity_id FROM openproof.scim_group_members WHERE organization_id=g.organization_id "
            "AND group_id=g.id ORDER BY identity_id COLLATE \"C\" LIMIT 10001) m) children WHERE g.organization_id=$1";
        if (selector!=scim::ReadSelector::All) {
            if (selector==scim::ReadSelector::Id)
                projection+=users?" AND u.identity_id=$2":" AND g.id=$2";
            else projection+=users?" AND u.user_name=$2":" AND g.display_name=$2";
        }
        projection+=" ORDER BY sort_name,id LIMIT 10001";
        return "WITH projected AS MATERIALIZED ("+projection+"), "
            "bounds AS (SELECT count(*)<=10000 AND count(value)=count(*) AND "
            "COALESCE(sum(octet_length(value)),0)<=8380000 AS ok FROM projected) "
            "SELECT value,updated::text FROM (SELECT sort_name,id,value,updated FROM projected,bounds WHERE ok "
            "UNION ALL SELECT NULL::text,NULL::text,NULL::text,NULL::bigint FROM bounds WHERE NOT ok) bounded "
            "ORDER BY sort_name,id";

}
}

asio::awaitable<foundation::Result<enterprise::scim::ReadResult>>
CoroutinePostgresCanonicalFinalizer::readScimAsync(enterprise::scim::ReadRequest request)
{
    namespace scim=enterprise::scim;
    using E=foundation::ErrorCode;
    if ((request.kind!=scim::ReadKind::Users && request.kind!=scim::ReadKind::Groups)
        || (request.selector!=scim::ReadSelector::All && request.selector!=scim::ReadSelector::Id
            && request.selector!=scim::ReadSelector::Name)
        || (request.selector==scim::ReadSelector::All)==request.value.has_value()
        || (request.value && (request.value->empty() || request.value->size()>512U ||
            std::ranges::any_of(*request.value,[](unsigned char c){return c<0x20U || c==0x7fU;}))))
        co_return foundation::fail(E::InvalidArgument);
    const bool users=request.kind==scim::ReadKind::Users;
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params args) {
            return connection.query(std::move(sql),std::move(args),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",{}));
        const std::string tenant{m_impl->organization.value()};
        Params tenantArgs{tenant};
        const auto permitted=co_await execute(
            "SELECT id FROM openproof.organizations WHERE id=$1 AND state=0",std::move(tenantArgs));
        if (permitted.rows.size()!=1U) co_return foundation::fail(E::PermissionDenied);
        // Bound SQL materialization before libpq transfers it. Do not silently
        // truncate directory lists or individual group membership.
        Params args{tenant};
        if (request.value) args.push_back(*request.value);
        const auto sql=scimProjection(users,request.selector);
        const auto rows=co_await execute(sql,std::move(args));
        if (request.selector==scim::ReadSelector::Id && rows.rows.empty())
            co_return foundation::fail(E::NotFound);
        if (rows.rows.size()>10000U || (request.selector!=scim::ReadSelector::All && rows.rows.size()>1U))
            co_return foundation::fail(E::Unavailable);
        scim::ReadResult result;
        std::size_t bytes=0;
        for (const auto& row:rows.rows) {
            if (row.size()!=2U || !row[0] || !row[1] || row[0]->size()>8380000U
                || bytes>8380000U-row[0]->size()) co_return foundation::fail(E::Unavailable);
            bytes+=row[0]->size();
            result.rows.push_back(scim::ReadRow{*row[0],foundation::Instant{foundation::Duration{milliseconds(row[1])}}});
        }
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return result;
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native SCIM read is unavailable.");
    }
}

asio::awaitable<foundation::Result<enterprise::scim::ReadResult>>
CoroutinePostgresCanonicalFinalizer::mutateScimAsync(enterprise::scim::MutationRequest request,foundation::Instant now)
{
    namespace scim=enterprise::scim;
    using E=foundation::ErrorCode;
    using Op=scim::MutationKind;
    const bool users=request.kind==scim::ReadKind::Users;
    const bool create=request.operation==Op::Create,remove=request.operation==Op::Remove,
        patch=request.operation==Op::Patch;
    const auto valid=[](std::string_view v,std::size_t max) {
        return !v.empty() && v.size()<=max && std::ranges::none_of(v,[](unsigned char c){return c<32U || c==127U;});
    };
    const auto optional=[&](const std::optional<std::string>& v,std::size_t max){return !v || valid(*v,max);};
    if ((!users && request.kind!=scim::ReadKind::Groups) ||
        static_cast<unsigned>(request.operation)>static_cast<unsigned>(Op::Remove)
        || !valid(request.id,256U) || now.time_since_epoch().count()<0
        || (!remove && !patch && !request.name) || !optional(request.name,users?128U:512U)
        || !optional(request.externalId,1024U) || !optional(request.displayName,256U)
        || !optional(request.email,320U) || request.memberChanges.size()>128U
        || (users && !request.memberChanges.empty()) || (!users && (request.active || request.email || request.displayName)))
        co_return foundation::fail(E::InvalidArgument);
    std::size_t totalMembers=0;
    for (const auto& change:request.memberChanges) {
        if (static_cast<unsigned>(change.action)>2U || change.members.size()>10000U
            || totalMembers>10000U-change.members.size()) co_return foundation::fail(E::InvalidArgument);
        totalMembers+=change.members.size();
        if (std::ranges::any_of(change.members,[&](const auto& member){return !valid(member.value(),256U);}))
            co_return foundation::fail(E::InvalidArgument);
    }
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params args){return connection.query(std::move(sql),std::move(args),remaining(deadline));};
        const std::string tenant{m_impl->organization.value()},id=request.id;
        std::int64_t timestamp=now.time_since_epoch().count();
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        static_cast<void>(co_await execute("SELECT pg_advisory_xact_lock(7299730475761673315)",{}));
        Params tenantArgs{tenant};
        const auto org=co_await execute("SELECT id FROM openproof.organizations WHERE id=$1 AND state=0 FOR SHARE",std::move(tenantArgs));
        if (org.rows.size()!=1U) co_return foundation::fail(E::PermissionDenied);
        if (users && !create) {
            Params lockArgs{id};
            static_cast<void>(co_await execute("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 684271993))",std::move(lockArgs)));
        }
        Params targetArgs{tenant,id};
        const auto current=co_await execute(users?
            "SELECT u.updated_at_ms,u.user_name,i.status,m.state,"
            "EXISTS(SELECT 1 FROM openproof.membership_roles r WHERE r.organization_id=u.organization_id AND r.identity_id=u.identity_id AND r.role='owner') "
            "FROM openproof.scim_users u JOIN openproof.identities i ON i.id=u.identity_id AND i.organization_id=u.organization_id "
            "JOIN openproof.memberships m ON m.organization_id=u.organization_id AND m.identity_id=u.identity_id "
            "WHERE u.organization_id=$1 AND u.identity_id=$2 AND i.kind=0 FOR UPDATE OF u,i,m":
            "SELECT updated_at_ms,display_name FROM openproof.scim_groups WHERE organization_id=$1 AND id=$2 FOR UPDATE",std::move(targetArgs));
        if (create && !current.rows.empty()) co_return foundation::fail(E::AlreadyExists);
        if (!create && current.rows.empty()) co_return foundation::fail(E::NotFound);
        if (!create) {
            if (current.rows.size()!=1U || current.rows.front().size()!=(users?5U:2U))
                throw std::runtime_error{"Malformed SCIM target"};
            const auto previous=milliseconds(current.rows.front()[0]);
            if (request.expectedVersion && request.expectedVersion->time_since_epoch().count()!=previous)
                co_return foundation::fail(E::FailedPrecondition);
            if (previous==std::numeric_limits<std::int64_t>::max()) co_return foundation::fail(E::Unavailable);
            timestamp=std::max(timestamp,previous+1);
        }
        const auto stamp=std::to_string(timestamp);
        if (request.name && !remove) {
            Params nameArgs{tenant,*request.name,id};
            const auto duplicate=co_await execute(users?
                "SELECT identity_id FROM openproof.scim_users WHERE organization_id=$1 AND user_name=$2 AND identity_id<>$3":
                "SELECT id FROM openproof.scim_groups WHERE organization_id=$1 AND display_name=$2 AND id<>$3",std::move(nameArgs));
            if (!duplicate.rows.empty()) co_return foundation::fail(E::AlreadyExists);
        }
        if (users) {
            if (create) {
                const bool active=request.active.value_or(true);
                Params identityArgs{id,tenant,active?"0":"1",stamp};
                const auto inserted=co_await execute(
                    "INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) "
                    "VALUES($1,$2,0,$3,$4) ON CONFLICT DO NOTHING RETURNING id",std::move(identityArgs));
                if (inserted.rows.empty()) co_return foundation::fail(E::AlreadyExists);
                Params memberArgs{tenant,id,active?"1":"2",stamp};
                static_cast<void>(co_await execute("INSERT INTO openproof.memberships(organization_id,identity_id,state,invited_at_ms) VALUES($1,$2,$3,$4)",std::move(memberArgs)));
                Params profileArgs{id,request.displayName,request.name,request.email,stamp};
                static_cast<void>(co_await execute(
                    "INSERT INTO openproof.identity_profiles(identity_id,display_name,preferred_username,email,email_verified,created_at_ms,updated_at_ms) "
                    "VALUES($1,$2,$3,$4,false,$5,$5)",std::move(profileArgs)));
                Params recordArgs{id,tenant,*request.name,request.externalId,stamp};
                const auto record=co_await execute(
                    "INSERT INTO openproof.scim_users(identity_id,organization_id,user_name,external_id,created_at_ms,updated_at_ms) "
                    "VALUES($1,$2,$3,$4,$5,$5) ON CONFLICT DO NOTHING RETURNING identity_id",std::move(recordArgs));
                if (record.rows.empty()) co_return foundation::fail(E::AlreadyExists);
            } else {
                const auto& row=current.rows.front();
                const auto status=milliseconds(row[2]),membership=milliseconds(row[3]);
                const bool owner=boolean(row[4]);
                // SCIM may not reactivate locked, terminal or removed identities.
                if (status>=4 || membership>3 || (!remove && (status==3 || membership==3))
                    || (request.active.value_or(false) && (status==2 || membership==0)))
                    co_return foundation::fail(E::FailedPrecondition);
                const bool disable=remove || (request.active && !*request.active);
                if (disable && owner && status==0 && membership==1) {
                    Params survivorArgs{tenant,id};
                    const auto survivor=co_await execute(
                        "SELECT m.identity_id FROM openproof.memberships m JOIN openproof.identities i ON i.id=m.identity_id AND i.organization_id=m.organization_id "
                        "JOIN openproof.membership_roles r ON r.organization_id=m.organization_id AND r.identity_id=m.identity_id AND r.role='owner' "
                        "WHERE m.organization_id=$1 AND m.identity_id<>$2 AND m.state=1 AND i.status=0 ORDER BY m.identity_id LIMIT 1 FOR UPDATE OF m,i,r",
                        std::move(survivorArgs));
                    if (survivor.rows.empty()) co_return foundation::fail(E::FailedPrecondition);
                }
                if (remove || request.active) {
                    // Never downgrade a security lock to a reversible suspension.
                    const auto nextStatus=remove?3:(*request.active?0:(status==2?2:1));
                    const auto nextMember=remove?3:(*request.active?1:(membership==0?0:2));
                    Params stateArgs{tenant,id,std::to_string(nextStatus)};
                    static_cast<void>(co_await execute("UPDATE openproof.identities SET status=$3 WHERE organization_id=$1 AND id=$2",std::move(stateArgs)));
                    Params membershipArgs{tenant,id,std::to_string(nextMember)};
                    static_cast<void>(co_await execute("UPDATE openproof.memberships SET state=$3 WHERE organization_id=$1 AND identity_id=$2",std::move(membershipArgs)));
                }
                if (disable) {
                    Params sessionArgs{id,stamp};
                    static_cast<void>(co_await execute("UPDATE openproof.sessions SET state=1,revoked_at_ms=$2 WHERE identity_id=$1 AND state=0",std::move(sessionArgs)));
                    Params familyArgs{id,stamp};
                    static_cast<void>(co_await execute("UPDATE openproof.oauth_token_families SET revoked_at_ms=$2 WHERE identity_id=$1 AND revoked_at_ms IS NULL",std::move(familyArgs)));
                }
                if (remove) {
                    Params roleArgs{tenant,id};
                    static_cast<void>(co_await execute("DELETE FROM openproof.membership_roles WHERE organization_id=$1 AND identity_id=$2",std::move(roleArgs)));
                    Params groupArgs{tenant,id,stamp};
                    static_cast<void>(co_await execute(
                        "UPDATE openproof.scim_groups g SET updated_at_ms=GREATEST(g.updated_at_ms+1,$3::bigint) "
                        "WHERE g.organization_id=$1 AND EXISTS(SELECT 1 FROM openproof.scim_group_members m WHERE m.organization_id=$1 AND m.group_id=g.id AND m.identity_id=$2)",
                        std::move(groupArgs)));
                    Params deleteArgs{tenant,id};
                    static_cast<void>(co_await execute("DELETE FROM openproof.scim_users WHERE organization_id=$1 AND identity_id=$2",std::move(deleteArgs)));
                } else {
                    const std::string name=request.name.value_or(required(row[1]));
                    if (!valid(name,128U)) co_return foundation::fail(E::InvalidArgument);
                    Params profileArgs{id,request.displayName,name,request.email,stamp,patch?"true":"false"};
                    static_cast<void>(co_await execute(
                        "INSERT INTO openproof.identity_profiles(identity_id,display_name,preferred_username,email,email_verified,created_at_ms,updated_at_ms) "
                        "VALUES($1,$2,$3,$4,false,$5,$5) ON CONFLICT(identity_id) DO UPDATE SET "
                        "display_name=CASE WHEN $6::boolean AND EXCLUDED.display_name IS NULL THEN openproof.identity_profiles.display_name ELSE EXCLUDED.display_name END,"
                        "preferred_username=EXCLUDED.preferred_username,email=COALESCE(EXCLUDED.email,openproof.identity_profiles.email),"
                        "email_verified=CASE WHEN EXCLUDED.email IS NULL THEN openproof.identity_profiles.email_verified ELSE false END,"
                        "updated_at_ms=GREATEST(openproof.identity_profiles.updated_at_ms,EXCLUDED.updated_at_ms)",std::move(profileArgs)));
                    Params metadataArgs{tenant,id,name,request.externalId,stamp,patch?"true":"false"};
                    static_cast<void>(co_await execute(
                        "UPDATE openproof.scim_users SET user_name=$3,external_id=CASE WHEN $6::boolean AND $4::text IS NULL THEN external_id ELSE $4::text END,updated_at_ms=$5 "
                        "WHERE organization_id=$1 AND identity_id=$2",std::move(metadataArgs)));
                }
            }
        } else if (remove) {
            Params deleteArgs{tenant,id};
            static_cast<void>(co_await execute("DELETE FROM openproof.scim_groups WHERE organization_id=$1 AND id=$2",std::move(deleteArgs)));
        } else {
            if (create) {
                Params createArgs{id,tenant,*request.name,request.externalId,stamp};
                const auto added=co_await execute(
                    "INSERT INTO openproof.scim_groups(id,organization_id,display_name,external_id,created_at_ms,updated_at_ms) "
                    "VALUES($1,$2,$3,$4,$5,$5) ON CONFLICT DO NOTHING RETURNING id",std::move(createArgs));
                if (added.rows.empty()) co_return foundation::fail(E::AlreadyExists);
            } else {
                Params metadataArgs{tenant,id,request.name,request.externalId,stamp,patch?"true":"false"};
                static_cast<void>(co_await execute(
                    "UPDATE openproof.scim_groups SET display_name=COALESCE($3,display_name),"
                    "external_id=CASE WHEN $6::boolean AND $4::text IS NULL THEN external_id ELSE $4::text END,updated_at_ms=$5 "
                    "WHERE organization_id=$1 AND id=$2",std::move(metadataArgs)));
            }
            for (const auto& change:request.memberChanges) {
                std::vector<std::string> members;
                for (const auto& member:change.members) members.emplace_back(member.value());
                std::ranges::sort(members);
                if (std::ranges::adjacent_find(members)!=members.end()) co_return foundation::fail(E::InvalidArgument);
                std::string encoded="[";
                for (const auto& member:members) {
                    if (encoded.size()>1U) encoded+=",";
                    encoded+="\""+foundation::escapeJsonString(member)+"\"";
                }
                encoded+="]";
                if (change.action!=scim::MemberAction::Remove) {
                    Params validationArgs{tenant,encoded};
                    const auto validMembers=co_await execute(
                        "SELECT count(*) FROM jsonb_array_elements_text($2::jsonb) v(id) "
                        "JOIN openproof.scim_users u ON u.organization_id=$1 AND u.identity_id=v.id",std::move(validationArgs));
                    if (validMembers.rows.size()!=1U || milliseconds(validMembers.rows.front()[0])!=static_cast<std::int64_t>(members.size()))
                        co_return foundation::fail(E::NotFound);
                }
                if (change.action==scim::MemberAction::Replace) {
                    Params clearArgs{tenant,id};
                    static_cast<void>(co_await execute("DELETE FROM openproof.scim_group_members WHERE organization_id=$1 AND group_id=$2",std::move(clearArgs)));
                }
                Params memberArgs{tenant,id,encoded};
                if (change.action==scim::MemberAction::Remove)
                    static_cast<void>(co_await execute(
                        "DELETE FROM openproof.scim_group_members WHERE organization_id=$1 AND group_id=$2 "
                        "AND identity_id IN(SELECT jsonb_array_elements_text($3::jsonb))",std::move(memberArgs)));
                else
                    static_cast<void>(co_await execute(
                        "INSERT INTO openproof.scim_group_members(organization_id,group_id,identity_id) "
                        "SELECT $1,$2,v.id FROM jsonb_array_elements_text($3::jsonb) v(id) ON CONFLICT DO NOTHING",std::move(memberArgs)));
            }
        }
        scim::ReadResult result;
        if (!remove) {
            Params resultArgs{tenant,id};
            const auto projected=co_await execute(scimProjection(users,scim::ReadSelector::Id),std::move(resultArgs));
            if (projected.rows.size()!=1U || projected.rows.front().size()!=2U || !projected.rows.front()[0])
                co_return foundation::fail(E::Unavailable);
            result.rows.push_back(scim::ReadRow{required(projected.rows.front()[0]),
                foundation::Instant{foundation::Duration{milliseconds(projected.rows.front()[1])}}});
        }
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return result;
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native SCIM mutation is unavailable.");
    }
}

asio::awaitable<foundation::Result<std::vector<evidence::Evidence>>>
CoroutinePostgresCanonicalFinalizer::evidenceAccountAsync(core::IdentityId actor,session::SessionId sessionId,
    foundation::Instant now,evidence::verification::AccountCommand command)
{
    using E=foundation::ErrorCode;
    using Op=evidence::verification::AccountOperation;
    const auto op=command.operation;
    if (actor.empty() || actor.value().size()>200U || sessionId.empty() || sessionId.value().size()>200U ||
        now.time_since_epoch().count()<0 || static_cast<unsigned>(op)>3U ||
        (op!=Op::List && (command.provider.empty() || command.provider.value().size()>200U)) ||
        ((op==Op::Issue || op==Op::Consume) && (command.digest.value().size()!=64U ||
        !std::ranges::all_of(command.digest.value(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');}))) ||
        (op==Op::Issue && (command.expiresAt<=now || command.expiresAt-now>std::chrono::minutes{5})) ||
        (op==Op::Persist && (command.records.empty() || command.records.size()>16U)) ||
        (op!=Op::Persist && !command.records.empty()))
        co_return foundation::fail(E::InvalidArgument);
    for (const auto& record:command.records)
        if (record.identity()!=actor || record.provider()!=command.provider ||
            record.status()!=evidence::EvidenceStatus::Verified || !record.activeAt(now) || record.verifiedAt()>now)
            co_return foundation::fail(E::PermissionDenied);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params args){
            return connection.query(std::move(sql),std::move(args),remaining(deadline));
        };
        static_cast<void>(co_await execute(op==Op::List?"BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY":
            "BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        const std::string identityId{actor.value()},tenant{m_impl->organization.value()};
        const auto timestamp=std::to_string(now.time_since_epoch().count());
        if (op!=Op::List) {
            Params lockArgs{identityId};
            static_cast<void>(co_await execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 684271993))",std::move(lockArgs)));
        }
        Params actorArgs{identityId,tenant,std::string{sessionId.value()},timestamp};
        std::string check="SELECT s.id FROM openproof.sessions s JOIN openproof.identities i ON i.id=s.identity_id "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "WHERE i.id=$1 AND o.id=$2 AND s.id=$3 AND s.state=0 AND i.status=0 AND o.state=0 "
            "AND s.issued_at_ms<=$4 AND s.absolute_expires_at_ms>$4 AND s.last_seen_at_ms+s.idle_timeout_ms>$4";
        if (op!=Op::List) check+=" FOR SHARE OF i,o,s";
        const auto permitted=co_await execute(std::move(check),std::move(actorArgs));
        if (permitted.rows.size()!=1U) co_return foundation::fail(E::AuthenticationFailed);
        std::vector<evidence::Evidence> result;
        if (op==Op::List) {
            Params args{identityId};
            const auto rows=co_await execute(
                "SELECT id,provider,kind,claim,value,confidence,status,verified_at_ms,expires_at_ms "
                "FROM openproof.evidence WHERE identity_id=$1 ORDER BY verified_at_ms,id LIMIT 257",std::move(args));
            if (rows.rows.size()>256U) co_return foundation::fail(E::Unavailable);
            for (const auto& row:rows.rows) {
                if (row.size()!=9U) throw std::runtime_error{"Malformed evidence row"};
                const auto confidence=milliseconds(row[5]),status=milliseconds(row[6]);
                if (confidence>100 || status>1) throw std::runtime_error{"Malformed evidence state"};
                std::optional<foundation::Instant> expiry;
                if (row[8]) expiry.emplace(foundation::Duration{milliseconds(row[8])});
                auto restored=evidence::Evidence::restore(evidence::EvidenceId{required(row[0])},actor,
                    idp::ProviderId{required(row[1])},required(row[2]),required(row[3]),required(row[4]),
                    static_cast<unsigned>(confidence),static_cast<evidence::EvidenceStatus>(status),
                    foundation::Instant{foundation::Duration{milliseconds(row[7])}},expiry);
                if (!restored) throw std::runtime_error{"Invalid stored evidence"};
                result.push_back(std::move(restored).value());
            }
        } else if (op==Op::Issue) {
            Params purgeArgs{identityId,timestamp};
            static_cast<void>(co_await execute(
                "WITH expired AS (SELECT digest FROM openproof.evidence_verification_challenges "
                "WHERE identity_id=$1 AND expires_at_ms<=$2 ORDER BY expires_at_ms LIMIT 128 FOR UPDATE SKIP LOCKED) "
                "DELETE FROM openproof.evidence_verification_challenges c USING expired e WHERE c.digest=e.digest",
                std::move(purgeArgs)));
            Params countArgs{identityId,timestamp};
            const auto active=co_await execute(
                "SELECT digest FROM openproof.evidence_verification_challenges WHERE identity_id=$1 "
                "AND expires_at_ms>$2 AND consumed_at_ms IS NULL LIMIT 33",std::move(countArgs));
            if (active.rows.size()>=32U) co_return foundation::fail(E::RateLimited);
            Params args{std::string{command.digest.value()},identityId,std::string{command.provider.value()},
                timestamp,std::to_string(command.expiresAt.time_since_epoch().count())};
            const auto inserted=co_await execute(
                "INSERT INTO openproof.evidence_verification_challenges(digest,identity_id,provider,issued_at_ms,expires_at_ms) "
                "VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING digest",std::move(args));
            if (inserted.rows.size()!=1U) co_return foundation::fail(E::Conflict);
        } else if (op==Op::Consume) {
            Params args{std::string{command.digest.value()},identityId,std::string{command.provider.value()},timestamp};
            const auto consumed=co_await execute(
                "UPDATE openproof.evidence_verification_challenges SET consumed_at_ms=$4 "
                "WHERE digest=$1 AND identity_id=$2 AND provider=$3 AND consumed_at_ms IS NULL "
                "AND issued_at_ms<=$4 AND expires_at_ms>$4 RETURNING digest",std::move(args));
            if (consumed.rows.size()!=1U) co_return foundation::fail(E::AuthenticationFailed);
        } else {
            Params countArgs{identityId};
            const auto count=co_await execute("SELECT id FROM openproof.evidence WHERE identity_id=$1 LIMIT 257",std::move(countArgs));
            if (count.rows.size()+command.records.size()>256U) co_return foundation::fail(E::RateLimited);
            for (const auto& record:command.records) {
                Params args{std::string{record.id().value()},identityId,std::string{record.provider().value()},
                    std::string{record.kind()},std::string{record.claim()},std::string{record.value()},
                    std::to_string(record.confidence()),std::to_string(record.verifiedAt().time_since_epoch().count()),
                    record.expiresAt()?std::optional<std::string>{std::to_string(record.expiresAt()->time_since_epoch().count())}:std::nullopt};
                const auto inserted=co_await execute(
                    "INSERT INTO openproof.evidence(id,identity_id,provider,kind,claim,value,confidence,status,verified_at_ms,expires_at_ms) "
                    "VALUES($1,$2,$3,$4,$5,$6,$7,0,$8,$9) ON CONFLICT DO NOTHING RETURNING id",std::move(args));
                if (inserted.rows.size()!=1U) co_return foundation::fail(E::Conflict);
            }
            result=std::move(command.records);
        }
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return result;
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native evidence account operation is unavailable.");
    }
}

} // namespace openproof::storage::postgres

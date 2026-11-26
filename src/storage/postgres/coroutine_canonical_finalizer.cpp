#include "async_pool.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>

#include <algorithm>
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
import openproof.organization;
import openproof.policy;
import openproof.session;

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

} // namespace openproof::storage::postgres

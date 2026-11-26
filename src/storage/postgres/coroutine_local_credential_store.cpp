#include "async_pool.hpp"
#include <charconv>
#include <chrono>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>
#include "coroutine_local_credential_store.hpp"
#include "bounded_password_executor.hpp"

namespace openproof::storage::postgres {
namespace asio = boost::asio;
namespace core = identity::core;
namespace idp = identity::provider;
namespace {
using Clock = std::chrono::steady_clock;
using Params = std::vector<std::optional<std::string>>;

bool bounded(std::string_view value, std::size_t limit)
{
    return !value.empty() && value.size() <= limit
        && value.find('\0') == std::string_view::npos;
}
bool decimal(std::string_view value)
{
    std::uint64_t parsed{};
    const auto [end, error] = std::from_chars(value.data(), value.data()+value.size(), parsed);
    return error == std::errc{} && end == value.data()+value.size()
        && parsed <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
}
bool valid(const LocalCredentialSnapshot& value)
{
    if (!bounded(value.owner.value(), 200U) || !bounded(value.passwordHash, 4096U)
        || !decimal(value.passwordChangedAt)) return false;
    if (!value.encryptedTotpHex)
        return !value.keyVersion && !value.lastAcceptedStep && !value.totpEnrolledAt;
    if (!bounded(*value.encryptedTotpHex, 4096U)
        || value.encryptedTotpHex->size() % 2U != 0U
        || !value.keyVersion || !decimal(*value.keyVersion) || *value.keyVersion == "0"
        || !value.totpEnrolledAt || !decimal(*value.totpEnrolledAt)
        || (value.lastAcceptedStep && !decimal(*value.lastAcceptedStep))) return false;
    for (char c : *value.encryptedTotpHex)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}
foundation::Duration remaining(Clock::time_point deadline)
{
    const auto left = std::chrono::duration_cast<foundation::Duration>(deadline - Clock::now());
    if (left <= foundation::Duration::zero()) throw std::runtime_error{"Credential SQL deadline"};
    return left;
}
foundation::Status confirmed(const async_detail::QueryRows& result, std::string_view owner)
{
    if (result.rows.empty())
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    if (result.rows.size() != 1U || result.rows.front().size() != 1U
        || !result.rows.front().front() || *result.rows.front().front() != owner)
        return foundation::fail(foundation::ErrorCode::Unavailable);
    return foundation::ok();
}
constexpr std::string_view kUnavailable = "Native credential storage is unavailable.";
}

class CoroutineLocalCredentialStore::Impl final {
public:
    Impl(asio::any_io_executor executor, foundation::SecretString dsn,
        core::OrganizationId organization, idp::ProviderId providerValue, std::size_t capacity,
        foundation::Duration acquireTimeout, foundation::Duration connectTimeout,
        foundation::Duration timeout)
        : pool(std::move(executor), std::string{dsn.expose()}, capacity, acquireTimeout,
               connectTimeout), tenant(std::move(organization)), provider(std::move(providerValue)),
          queryTimeout(timeout)
    {
        if (!bounded(tenant.value(), 200U) || !bounded(provider.value(), 200U)
            || queryTimeout <= foundation::Duration::zero())
            throw std::invalid_argument{"Invalid native credential store configuration"};
    }
    async_detail::AsyncConnectionPool pool;
    core::OrganizationId tenant;
    idp::ProviderId provider;
    foundation::Duration queryTimeout;
};

CoroutineLocalCredentialStore::CoroutineLocalCredentialStore(asio::any_io_executor executor,
    foundation::SecretString connectionString, core::OrganizationId tenant,
    idp::ProviderId provider, std::size_t capacity, foundation::Duration acquireTimeout,
    foundation::Duration connectTimeout, foundation::Duration queryTimeout)
    : m_impl(std::make_unique<Impl>(std::move(executor), std::move(connectionString),
        std::move(tenant), std::move(provider), capacity, acquireTimeout, connectTimeout, queryTimeout))
{}
CoroutineLocalCredentialStore::~CoroutineLocalCredentialStore() = default;

asio::awaitable<foundation::Result<std::optional<LocalCredentialSnapshot>>>
CoroutineLocalCredentialStore::readAsync(idp::ExternalSubject subject)
{
    if (!bounded(subject.value(), 1000U))
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const auto deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        Params params{std::string{m_impl->provider.value()}, std::string{subject.value()},
                      std::string{m_impl->tenant.value()}};
        const auto result = co_await lease.connection().query(
            "SELECT i.id,p.password_hash,CASE WHEN octet_length(t.encrypted_seed)>2048 "
            "THEN '!' ELSE encode(t.encrypted_seed,'hex') END,t.key_version::text,"
            "t.last_accepted_step::text,p.changed_at_ms::text,t.enrolled_at_ms::text "
            "FROM openproof.external_identities e "
            "JOIN openproof.identities i ON i.id=e.identity_id "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "JOIN openproof.password_credentials p ON p.identity_id=i.id "
            "LEFT JOIN openproof.totp_credentials t ON t.identity_id=i.id "
            "WHERE e.provider=$1 AND e.external_subject=$2 AND i.organization_id=$3 "
            "AND i.status=0 AND o.state=0 LIMIT 2", std::move(params), remaining(deadline));
        if (result.rows.empty()) co_return std::optional<LocalCredentialSnapshot>{};
        if (result.rows.size() != 1U || result.rows.front().size() != 7U)
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        const auto& row = result.rows.front();
        if (!row[0] || !row[1] || !row[5])
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        LocalCredentialSnapshot snapshot{core::IdentityId{*row[0]}, *row[1], row[2],
            row[3], row[4], *row[5], row[6]};
        if (!valid(snapshot)) co_return foundation::fail(foundation::ErrorCode::Unavailable);
        co_return std::optional<LocalCredentialSnapshot>{std::move(snapshot)};
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable, std::string{kUnavailable});
    }
}

asio::awaitable<foundation::Result<std::pair<core::IdentityId, std::optional<bool>>>>
CoroutineLocalCredentialStore::readPasswordUpgradeStatusAsync(
    core::IdentityId owner, const credentials::BoundedPasswordExecutor& policy)
{
    using Output = std::pair<core::IdentityId, std::optional<bool>>;
    if (!bounded(owner.value(), 200U))
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const auto deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        const bool inspectHash = policy.prefersArgon2id();
        Params params{std::string{owner.value()}, std::string{m_impl->tenant.value()},
            std::string{m_impl->provider.value()}, inspectHash ? "true" : "false"};
        // Resolve the link and password under a single tenant/owner snapshot.
        // No TOTP data, recovery codes or password plaintext is queried.
        // Do not even retrieve the encoded hash if Argon2id is not selected.
        const auto result = co_await lease.connection().query(
            "SELECT i.id,EXISTS(SELECT 1 FROM openproof.external_identities e "
            "WHERE e.identity_id=i.id AND e.provider=$3),"
            "CASE WHEN $4::boolean AND octet_length(p.password_hash)<=4096 "
            "THEN p.password_hash END "
            "FROM openproof.identities i JOIN openproof.organizations o ON o.id=i.organization_id "
            "LEFT JOIN openproof.password_credentials p ON p.identity_id=i.id "
            "AND EXISTS(SELECT 1 FROM openproof.external_identities e "
            "WHERE e.identity_id=i.id AND e.provider=$3) "
            "WHERE i.id=$1 AND i.organization_id=$2 AND i.status=0 AND o.state=0 LIMIT 2",
            std::move(params), remaining(deadline));
        if (result.rows.empty())
            co_return foundation::fail(foundation::ErrorCode::NotFound);
        if (result.rows.size()!=1U || result.rows.front().size()!=3U)
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        const auto& row = result.rows.front();
        if (!row[0] || *row[0]!=owner.value() || !row[1]
            || (*row[1]!="t" && *row[1]!="f"))
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        if (*row[1]=="f") co_return Output{std::move(owner), std::nullopt};
        if (!inspectHash) co_return Output{std::move(owner), false};
        if (!row[2] || !bounded(*row[2], 4096U))
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        auto hash = credentials::PasswordHash::parse(*row[2]);
        if (!hash) co_return foundation::fail(foundation::ErrorCode::Unavailable);
        auto needed = policy.upgradeNeeded(hash.value());
        if (!needed) co_return foundation::fail(needed.error());
        co_return Output{std::move(owner), needed.value()};
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable, std::string{kUnavailable});
    }
}

asio::awaitable<foundation::Result<std::pair<core::IdentityId, bool>>>
CoroutineLocalCredentialStore::confirmPasswordUpgradeAsync(core::IdentityId owner,
    foundation::SecretString password, credentials::BoundedPasswordExecutor& policy)
{
    using Output = std::pair<core::IdentityId, bool>;
    if (!bounded(owner.value(), 200U) || password.empty() || password.expose().size()>1024U)
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    if (!policy.prefersArgon2id())
        co_return foundation::fail(foundation::ErrorCode::FailedPrecondition);
    try {
        std::string subject;
        std::string encoded;
        std::string changedAt;
        {
            const auto deadline = Clock::now() + m_impl->queryTimeout;
            auto lease = co_await m_impl->pool.acquire(deadline);
            Params params{std::string{owner.value()}, std::string{m_impl->tenant.value()},
                          std::string{m_impl->provider.value()}};
            const auto rows = co_await lease.connection().query(
                "SELECT e.external_subject,CASE WHEN octet_length(p.password_hash)<=4096 "
                "THEN p.password_hash END,p.changed_at_ms::text FROM openproof.identities i "
                "JOIN openproof.organizations o ON o.id=i.organization_id "
                "JOIN openproof.external_identities e ON e.identity_id=i.id AND e.provider=$3 "
                "JOIN openproof.password_credentials p ON p.identity_id=i.id "
                "WHERE i.id=$1 AND i.organization_id=$2 AND i.status=0 AND o.state=0 LIMIT 2",
                std::move(params), remaining(deadline));
            if (rows.rows.empty())
                co_return foundation::fail(foundation::ErrorCode::FailedPrecondition);
            if (rows.rows.size()!=1U || rows.rows.front().size()!=3U)
                co_return foundation::fail(foundation::ErrorCode::Unavailable);
            const auto& row = rows.rows.front();
            if (!row[0] || !bounded(*row[0],1000U) || !row[1] || !bounded(*row[1],4096U)
                || !row[2] || !decimal(*row[2]))
                co_return foundation::fail(foundation::ErrorCode::Unavailable);
            subject=*row[0]; encoded=*row[1]; changedAt=*row[2];
        }
        // The lease was destroyed before dispatching any memory-hard KDF.
        auto hash = credentials::PasswordHash::parse(encoded);
        if (!hash) co_return foundation::fail(foundation::ErrorCode::Unavailable);
        auto replacement = co_await policy.confirmUpgradeAsync(std::move(password),
                                                               std::move(hash).value());
        if (!replacement) co_return foundation::fail(replacement.error());
        const auto deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        Params params{std::string{owner.value()}, encoded, changedAt,
            std::string{m_impl->provider.value()}, subject, std::string{m_impl->tenant.value()}};
        // Even an already-current hash requires a fresh generation check.
        // No TOTP state or changed_at_ms mutation is part of a rehash.
        constexpr std::string_view predicate =
            " WHERE p.identity_id=$1 AND p.password_hash=$2 AND p.changed_at_ms=$3::bigint "
            "AND EXISTS(SELECT 1 FROM openproof.identities i "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "JOIN openproof.external_identities e ON e.identity_id=i.id "
            "WHERE i.id=p.identity_id AND e.provider=$4 AND e.external_subject=$5 "
            "AND i.organization_id=$6 AND i.status=0 AND o.state=0)";
        std::string sql;
        const bool upgraded = replacement->has_value();
        if (upgraded) {
            if (!bounded(replacement->value().encoded(),4096U))
                co_return foundation::fail(foundation::ErrorCode::Unavailable);
            params.emplace_back(std::string{replacement->value().encoded()});
            sql = "UPDATE openproof.password_credentials p SET password_hash=$7";
            sql += predicate;
            sql += " RETURNING p.identity_id";
        } else {
            sql = "SELECT p.identity_id FROM openproof.password_credentials p";
            sql += predicate;
        }
        const auto rows = co_await lease.connection().query(sql, std::move(params), remaining(deadline));
        if (rows.rows.empty())
            co_return foundation::fail(foundation::ErrorCode::FailedPrecondition);
        auto status = confirmed(rows,owner.value());
        if (!status) co_return foundation::fail(status.error());
        co_return Output{std::move(owner),upgraded};
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,std::string{kUnavailable});
    }
}

asio::awaitable<foundation::Status> CoroutineLocalCredentialStore::confirmPasswordOnlyAsync(
    idp::ExternalSubject subject, LocalCredentialSnapshot snapshot)
{
    if (!bounded(subject.value(), 1000U) || !valid(snapshot) || snapshot.encryptedTotpHex)
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    try {
        const auto deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        Params params{std::string{snapshot.owner.value()}, snapshot.passwordHash,
            snapshot.passwordChangedAt, std::string{m_impl->provider.value()},
            std::string{subject.value()}, std::string{m_impl->tenant.value()}};
        const auto result = co_await lease.connection().query(
            "SELECT i.id FROM openproof.identities i "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "JOIN openproof.external_identities e ON e.identity_id=i.id "
            "JOIN openproof.password_credentials p ON p.identity_id=i.id "
            "WHERE i.id=$1 AND p.password_hash=$2 AND p.changed_at_ms=$3::bigint "
            "AND e.provider=$4 AND e.external_subject=$5 AND i.organization_id=$6 "
            "AND i.status=0 AND o.state=0 AND NOT EXISTS "
            "(SELECT 1 FROM openproof.totp_credentials t WHERE t.identity_id=i.id)",
            std::move(params), remaining(deadline));
        co_return confirmed(result, snapshot.owner.value());
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable, std::string{kUnavailable});
    }
}

asio::awaitable<foundation::Status> CoroutineLocalCredentialStore::consumeTotpAsync(
    idp::ExternalSubject subject, LocalCredentialSnapshot snapshot, std::uint64_t step)
{
    if (!bounded(subject.value(), 1000U) || !valid(snapshot) || !snapshot.encryptedTotpHex
        || step > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    try {
        const auto deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        Params params{std::string{snapshot.owner.value()}, snapshot.passwordHash,
            snapshot.passwordChangedAt, std::string{m_impl->provider.value()},
            std::string{subject.value()}, std::string{m_impl->tenant.value()},
            snapshot.encryptedTotpHex, snapshot.keyVersion, snapshot.totpEnrolledAt,
            std::to_string(step)};
        const auto result = co_await lease.connection().query(
            "UPDATE openproof.totp_credentials t SET last_accepted_step=$10::bigint "
            "WHERE t.identity_id=$1 AND t.encrypted_seed=decode($7,'hex') "
            "AND t.key_version=$8::integer AND t.enrolled_at_ms=$9::bigint "
            "AND (t.last_accepted_step IS NULL OR t.last_accepted_step<$10::bigint) "
            "AND EXISTS (SELECT 1 FROM openproof.identities i "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "JOIN openproof.external_identities e ON e.identity_id=i.id "
            "JOIN openproof.password_credentials p ON p.identity_id=i.id "
            "WHERE i.id=t.identity_id AND p.password_hash=$2 AND p.changed_at_ms=$3::bigint "
            "AND e.provider=$4 AND e.external_subject=$5 AND i.organization_id=$6 "
            "AND i.status=0 AND o.state=0) RETURNING t.identity_id",
            std::move(params), remaining(deadline));
        co_return confirmed(result, snapshot.owner.value());
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable, std::string{kUnavailable});
    }
}

asio::awaitable<foundation::Status> CoroutineLocalCredentialStore::consumeRecoveryAsync(
    idp::ExternalSubject subject, LocalCredentialSnapshot snapshot,
    credentials::RecoveryCodeDigest digest)
{
    if (!bounded(subject.value(), 1000U) || !valid(snapshot) || !snapshot.encryptedTotpHex)
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    try {
        const auto deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        auto& conn = lease.connection();
        static_cast<void>(co_await conn.query("BEGIN", {}, remaining(deadline)));
        // Same transaction advisory lock as native and legacy code rotation.
        // Acquire before DELETE so a rotation cannot leave an obsolete batch
        // usable after it commits. Recheck all proof inputs in a fresh snapshot.
        Params lockParams{std::string{snapshot.owner.value()}};
        static_cast<void>(co_await conn.query(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            std::move(lockParams), remaining(deadline)));
        Params params{std::string{snapshot.owner.value()}, snapshot.passwordHash,
            snapshot.passwordChangedAt, std::string{m_impl->provider.value()},
            std::string{subject.value()}, std::string{m_impl->tenant.value()},
            snapshot.encryptedTotpHex, snapshot.keyVersion, snapshot.totpEnrolledAt,
            foundation::toHex(digest)};
        const auto result = co_await conn.query(
            "DELETE FROM openproof.recovery_codes r WHERE r.identity_id=$1 "
            "AND r.code_digest=decode($10,'hex') "
            "AND EXISTS (SELECT 1 FROM openproof.identities i "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "JOIN openproof.external_identities e ON e.identity_id=i.id "
            "JOIN openproof.password_credentials p ON p.identity_id=i.id "
            "JOIN openproof.totp_credentials t ON t.identity_id=i.id "
            "WHERE i.id=r.identity_id AND p.password_hash=$2 AND p.changed_at_ms=$3::bigint "
            "AND e.provider=$4 AND e.external_subject=$5 AND i.organization_id=$6 "
            "AND i.status=0 AND o.state=0 AND t.encrypted_seed=decode($7,'hex') "
            "AND t.key_version=$8::integer AND t.enrolled_at_ms=$9::bigint) "
            "RETURNING r.identity_id", std::move(params), remaining(deadline));
        auto status = confirmed(result, snapshot.owner.value());
        if (!status) {
            static_cast<void>(co_await conn.query("ROLLBACK", {}, remaining(deadline)));
            co_return status;
        }
        static_cast<void>(co_await conn.query("COMMIT", {}, remaining(deadline)));
        co_return foundation::ok();
    } catch (const std::exception&) {
        // A non-idle/ambiguous lease is discarded by the pool; no retry.
        co_return foundation::fail(foundation::ErrorCode::Unavailable, std::string{kUnavailable});
    }
}

asio::awaitable<foundation::Result<bool>> CoroutineLocalCredentialStore::rehashAsync(
    idp::ExternalSubject subject, LocalCredentialSnapshot snapshot,
    credentials::PasswordHash replacement)
{
    if (!bounded(subject.value(), 1000U) || !valid(snapshot)
        || !bounded(replacement.encoded(), 4096U))
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const auto deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        Params params{std::string{snapshot.owner.value()}, snapshot.passwordHash,
            snapshot.passwordChangedAt, std::string{m_impl->provider.value()},
            std::string{subject.value()}, std::string{m_impl->tenant.value()},
            std::string{replacement.encoded()}};
        const auto result = co_await lease.connection().query(
            "UPDATE openproof.password_credentials p SET password_hash=$7 "
            "WHERE p.identity_id=$1 AND p.password_hash=$2 AND p.changed_at_ms=$3::bigint "
            "AND EXISTS (SELECT 1 FROM openproof.identities i "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "JOIN openproof.external_identities e ON e.identity_id=i.id "
            "WHERE i.id=p.identity_id AND e.provider=$4 AND e.external_subject=$5 "
            "AND i.organization_id=$6 AND i.status=0 AND o.state=0) RETURNING p.identity_id",
            std::move(params), remaining(deadline));
        if (result.rows.empty()) co_return false;
        auto status = confirmed(result, snapshot.owner.value());
        if (!status) co_return foundation::fail(status.error());
        co_return true;
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable, std::string{kUnavailable});
    }
}

}

#include "async_pool.hpp"
#include "async_recovery_code.hpp"

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <charconv>
#include <cstdint>
#include <cstddef>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "coroutine_recovery_code_repository.hpp"

import openproof.foundation;

namespace openproof::storage::postgres {
namespace asio = boost::asio;
namespace {
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;

// The queue, physical connection/reset, DELETE/INSERT and COMMIT must
// consume one shared operation budget; a saturated pool does not reset it.
[[nodiscard]] std::chrono::milliseconds remaining(Deadline deadline)
{
    const auto budget = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - Clock::now());
    if (budget <= std::chrono::milliseconds::zero()) {
        throw std::runtime_error{"Recovery-code SQL deadline exceeded"};
    }
    return budget;
}
} // namespace

class CoroutinePostgresRecoveryCodeRepository::Impl final {
public:
    Impl(asio::any_io_executor executor, std::string dsn,
         std::size_t maximumConnections,
         foundation::Duration acquireTimeout,
         foundation::Duration connectTimeout,
         foundation::Duration timeout,identity::core::OrganizationId tenantValue,
         identity::provider::ProviderId providerValue)
        : pool(std::move(executor), std::move(dsn), maximumConnections,
               acquireTimeout, connectTimeout), queryTimeout(timeout),tenant(std::move(tenantValue)),provider(std::move(providerValue)) {}

    async_detail::AsyncConnectionPool pool;
    async_detail::AsyncRecoveryCodeSql sql;
    foundation::Duration queryTimeout;
    identity::core::OrganizationId tenant;
    identity::provider::ProviderId provider;
};

CoroutinePostgresRecoveryCodeRepository::CoroutinePostgresRecoveryCodeRepository(
    asio::any_io_executor executor, foundation::SecretString dsn,
    std::size_t maxConnections, foundation::Duration acquireTimeout,
    foundation::Duration connectTimeout, foundation::Duration queryTimeout,
    identity::core::OrganizationId tenant,identity::provider::ProviderId localProvider)
{
    if (queryTimeout <= foundation::Duration::zero() || tenant.empty() || localProvider.empty()) {
        throw std::invalid_argument{"Invalid recovery-code SQL timeout"};
    }
    m_impl = std::make_unique<Impl>(
        std::move(executor), std::string{dsn.expose()},
        maxConnections, acquireTimeout, connectTimeout, queryTimeout,std::move(tenant),std::move(localProvider));
}

CoroutinePostgresRecoveryCodeRepository::~CoroutinePostgresRecoveryCodeRepository()
    = default;

asio::awaitable<foundation::Status>
CoroutinePostgresRecoveryCodeRepository::replaceAsync(
    identity::core::IdentityId identity,
    std::vector<credentials::RecoveryCodeDigest> digests)
{
    if (identity.empty() || !digests.empty()) {
        co_return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "Invalid recovery-code set.");
    }
    std::vector<std::string> digestsHex;
    digestsHex.reserve(digests.size());
    for (const auto& digest : digests) {
        digestsHex.emplace_back(foundation::toHex(digest));
    }
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        co_await m_impl->sql.replace(
            lease.connection(), std::string{identity.value()},
            std::move(digestsHex), remaining(deadline));
        co_return foundation::ok();
    } catch (const std::invalid_argument&) {
        co_return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "Invalid recovery-code set.");
    } catch (const std::exception&) {
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "Recovery-code persistence is unavailable.");
    }
}

asio::awaitable<foundation::Result<credentials::RecoveryIssuanceFence>>
CoroutinePostgresRecoveryCodeRepository::captureIssuanceAsync(identity::core::IdentityId identity)
{
    if (identity.empty() || identity.value().size()>200U)
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const Deadline deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        std::vector<std::optional<std::string>> params{std::string{identity.value()},
            std::string{m_impl->tenant.value()},std::string{m_impl->provider.value()}};
        const auto rows=co_await lease.connection().query(
            "SELECT e.external_subject,p.changed_at_ms::text,t.enrolled_at_ms::text "
            "FROM openproof.identities i JOIN openproof.organizations o ON o.id=i.organization_id "
            "JOIN openproof.external_identities e ON e.identity_id=i.id "
            "JOIN openproof.password_credentials p ON p.identity_id=i.id "
            "JOIN openproof.totp_credentials t ON t.identity_id=i.id "
            "WHERE i.id=$1 AND i.organization_id=$2 AND e.provider=$3 "
            "AND i.kind=0 AND i.status=0 AND o.state=0 LIMIT 2",std::move(params),remaining(deadline));
        if (rows.rows.empty()) co_return foundation::fail(foundation::ErrorCode::FailedPrecondition);
        if (rows.rows.size()!=1U || rows.rows.front().size()!=3U)
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        const auto& row=rows.rows.front();
        const auto validGeneration=[](const std::optional<std::string>& value) {
            if (!value) return false;
            std::int64_t number{};
            const auto result=std::from_chars(value->data(),value->data()+value->size(),number);
            return result.ec==std::errc{} && result.ptr==value->data()+value->size() && number>=0;
        };
        if (!row[0] || row[0]->empty() || row[0]->size()>1000U
            || !validGeneration(row[1]) || !validGeneration(row[2]))
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        co_return credentials::RecoveryIssuanceFence{*row[0],*row[1],*row[2]};
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,"Recovery eligibility unavailable.");
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresRecoveryCodeRepository::replaceFencedAsync(identity::core::IdentityId identity,
    std::vector<credentials::RecoveryCodeDigest> digests,credentials::RecoveryIssuanceFence fence)
{
    if (identity.empty() || digests.empty() || digests.size()>async_detail::AsyncRecoveryCodeSql::kMaximumRecoveryCodes)
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    std::vector<std::string> hex;
    hex.reserve(digests.size());
    for (const auto& digest:digests) hex.emplace_back(foundation::toHex(digest));
    try {
        const Deadline deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        async_detail::AsyncRecoveryCodeSql::IssuanceScope scope{std::string{m_impl->tenant.value()},
            std::string{m_impl->provider.value()},std::move(fence.subject),
            std::move(fence.credentialGeneration),std::move(fence.factorGeneration)};
        if (!(co_await m_impl->sql.replaceFenced(lease.connection(),std::string{identity.value()},
            std::move(hex),std::move(scope),remaining(deadline))))
            co_return foundation::fail(foundation::ErrorCode::FailedPrecondition);
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,"Recovery-code persistence unavailable.");
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresRecoveryCodeRepository::consumeAsync(
    identity::core::IdentityId identity, credentials::RecoveryCodeDigest digest)
{
    if (identity.empty()) {
        co_return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "Invalid recovery-code identity.");
    }
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        const bool found = co_await m_impl->sql.consume(
            lease.connection(), std::string{identity.value()},
            foundation::toHex(digest), remaining(deadline));
        if (!found) {
            co_return foundation::fail(
                foundation::ErrorCode::AuthenticationFailed,
                "Recovery code is unknown or already used.");
        }
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "Recovery-code redemption is unavailable.");
    }
}

asio::awaitable<foundation::Result<std::size_t>>
CoroutinePostgresRecoveryCodeRepository::remainingAsync(
    identity::core::IdentityId identity)
{
    if (identity.empty()) {
        co_return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "Invalid recovery-code identity.");
    }
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        co_return co_await m_impl->sql.remaining(
            lease.connection(), std::string{identity.value()},
            remaining(deadline));
    } catch (const std::exception&) {
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "Recovery-code enumeration is unavailable.");
    }
}

asio::awaitable<foundation::Result<bool>>
CoroutinePostgresRecoveryCodeRepository::eligibleAsync(
    identity::core::IdentityId identity,
    identity::provider::ProviderId configuredLocalProvider)
{
    if (identity.empty() || configuredLocalProvider.empty()) {
        co_return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "Recovery-code eligibility requires a local provider and identity.");
    }
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        co_return co_await m_impl->sql.eligible(
            lease.connection(), std::string{identity.value()},
            std::string{configuredLocalProvider.value()}, remaining(deadline));
    } catch (const std::exception&) {
        // SQL failures must not be mistaken for ineligible users (412), nor
        // may database diagnostic strings leak through public HTTP responses.
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "Recovery-code eligibility cannot be verified.");
    }
}

} // namespace openproof::storage::postgres

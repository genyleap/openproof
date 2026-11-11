#include "async_pool.hpp"
#include "async_recovery_code.hpp"

#include <boost/asio/awaitable.hpp>

#include <chrono>
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
         foundation::Duration timeout)
        : pool(std::move(executor), std::move(dsn), maximumConnections,
               acquireTimeout, connectTimeout), queryTimeout(timeout) {}

    async_detail::AsyncConnectionPool pool;
    async_detail::AsyncRecoveryCodeSql sql;
    foundation::Duration queryTimeout;
};

CoroutinePostgresRecoveryCodeRepository::CoroutinePostgresRecoveryCodeRepository(
    asio::any_io_executor executor, foundation::SecretString dsn,
    std::size_t maxConnections, foundation::Duration acquireTimeout,
    foundation::Duration connectTimeout, foundation::Duration queryTimeout)
{
    if (queryTimeout <= foundation::Duration::zero()) {
        throw std::invalid_argument{"Invalid recovery-code SQL timeout"};
    }
    m_impl = std::make_unique<Impl>(
        std::move(executor), std::string{dsn.expose()},
        maxConnections, acquireTimeout, connectTimeout, queryTimeout);
}

CoroutinePostgresRecoveryCodeRepository::~CoroutinePostgresRecoveryCodeRepository()
    = default;

asio::awaitable<foundation::Status>
CoroutinePostgresRecoveryCodeRepository::replaceAsync(
    identity::core::IdentityId identity,
    std::vector<credentials::RecoveryCodeDigest> digests)
{
    if (identity.empty()
        || digests.size() > async_detail::AsyncRecoveryCodeSql::kMaximumRecoveryCodes) {
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

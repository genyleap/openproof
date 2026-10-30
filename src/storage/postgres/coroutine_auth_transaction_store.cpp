#include "async_pool.hpp"
#include "async_auth_transaction.hpp"

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include "coroutine_auth_transaction_store.hpp"

import openproof.foundation;
import openproof.identity.provider;
import openproof.security;

namespace openproof::storage::postgres {
namespace asio = boost::asio;
namespace idp = identity::provider;

namespace {
using Snapshot = async_detail::AsyncAuthenticationTransactionSql::Record;

[[nodiscard]] Snapshot capture(const idp::AuthenticationTransaction& transaction)
{
    return {
        std::string{transaction.id().value()},
        std::string{transaction.provider().value()},
        static_cast<unsigned int>(transaction.interactionModel()),
        foundation::toHex(transaction.nonceDigest()),
        foundation::toHex(transaction.binding()),
        std::string{transaction.correlation().value()},
        static_cast<unsigned int>(transaction.state()),
        transaction.createdAt().time_since_epoch().count(),
        transaction.expiresAt().time_since_epoch().count(),
        transaction.metadata()
    };
}

[[nodiscard]] foundation::Result<idp::AuthenticationTransaction>
restore(Snapshot row)
{
    auto nonceBytes = foundation::fromHex(row.nonceDigestHex);
    auto bindingBytes = foundation::fromHex(row.bindingDigestHex);
    if (!nonceBytes || !bindingBytes || nonceBytes->size() != 32U
        || bindingBytes->size() != 32U || row.state > 3U
        || row.interaction > 4U) {
        return foundation::fail(foundation::ErrorCode::Unavailable,
                                "Authentication transaction row is invalid.");
    }
    security::Sha256Digest nonceDigest{};
    security::Sha256Digest bindingDigest{};
    std::copy(nonceBytes->begin(), nonceBytes->end(), nonceDigest.begin());
    std::copy(bindingBytes->begin(), bindingBytes->end(), bindingDigest.begin());
    return idp::AuthenticationTransaction::restore(
        idp::TransactionId{std::move(row.id)},
        idp::ProviderId{std::move(row.provider)},
        static_cast<idp::InteractionModel>(row.interaction),
        nonceDigest, bindingDigest,
        foundation::CorrelationId{std::move(row.correlationId)},
        static_cast<idp::TransactionState>(row.state),
        foundation::Instant{foundation::Duration{row.createdMs}},
        foundation::Instant{foundation::Duration{row.expiresMs}},
        std::move(row.metadata));
}
}

class CoroutinePostgresAuthenticationTransactionStore::Impl final {
public:
    Impl(asio::any_io_executor executor, std::string dsn,
         std::size_t capacity, foundation::Duration acquireTimeout,
         foundation::Duration connectTimeout, foundation::Duration queryTimeoutValue)
        : pool(std::move(executor), std::move(dsn), capacity,
               acquireTimeout, connectTimeout),
          queryTimeout(queryTimeoutValue)
    {}
    async_detail::AsyncConnectionPool pool;
    async_detail::AsyncAuthenticationTransactionSql sql;
    foundation::Duration queryTimeout;
};

CoroutinePostgresAuthenticationTransactionStore::
CoroutinePostgresAuthenticationTransactionStore(
    asio::any_io_executor executor, foundation::SecretString dsn,
    std::size_t maxConnections, foundation::Duration acquireTimeout,
    foundation::Duration connectTimeout, foundation::Duration queryTimeout)
{
    if (queryTimeout <= foundation::Duration::zero())
        throw std::invalid_argument{"Invalid authentication transaction SQL deadline"};
    m_impl = std::make_unique<Impl>(
        std::move(executor), std::string{dsn.expose()}, maxConnections,
        acquireTimeout, connectTimeout, queryTimeout);
}

CoroutinePostgresAuthenticationTransactionStore::
~CoroutinePostgresAuthenticationTransactionStore() = default;

asio::awaitable<foundation::Status>
CoroutinePostgresAuthenticationTransactionStore::beginAsync(
    idp::AuthenticationTransaction transaction)
{
    const auto captured = capture(transaction);
    try {
        auto lease = co_await m_impl->pool.acquire();
        const bool inserted = co_await m_impl->sql.begin(
            lease.connection(), captured, m_impl->queryTimeout);
        if (!inserted) {
            co_return foundation::fail(
                foundation::ErrorCode::AlreadyExists,
                "This authentication request could not be started.");
        }
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Authentication transaction persistence is unavailable.");
    }
}

asio::awaitable<foundation::Result<idp::AuthenticationTransaction>>
CoroutinePostgresAuthenticationTransactionStore::consumeAsync(
    idp::TransactionId id, foundation::SecretString nonce,
    idp::BindingDigest binding, foundation::Instant now)
{
    // Raw nonce credentials are never supplied to SQL. Their SHA-256 digest is
    // compared by PostgreSQL's single atomic UPDATE against persisted digests.
    auto nonceDigest = security::sha256(nonce.expose());
    if (!nonceDigest) co_return foundation::fail(nonceDigest.error());
    const std::string nonceHex = foundation::toHex(nonceDigest.value());
    nonce = foundation::SecretString{};
    try {
        auto lease = co_await m_impl->pool.acquire();
        auto consumed = co_await m_impl->sql.consume(
            lease.connection(), std::string{id.value()},
            nonceHex, foundation::toHex(binding),
            now.time_since_epoch().count(), m_impl->queryTimeout);
        if (!consumed) {
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                "The authentication transaction is unknown or already consumed.");
        }
        auto restored = restore(std::move(*consumed));
        if (!restored) co_return foundation::fail(restored.error());
        if (restored->state() == idp::TransactionState::Expired) {
            co_return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                       "This authentication request has expired.");
        }
        if (restored->state() != idp::TransactionState::Consumed) {
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                       "Transaction verification failed.");
        }
        co_return restored;
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Authentication transaction redemption is unavailable.");
    }
}

foundation::Status
CoroutinePostgresAuthenticationTransactionStore::begin(idp::AuthenticationTransaction)
{
    return foundation::fail(foundation::ErrorCode::Unavailable,
        "Native PostgreSQL transaction store requires coroutine authentication.");
}

foundation::Result<idp::AuthenticationTransaction>
CoroutinePostgresAuthenticationTransactionStore::consume(
    const idp::TransactionId&, const foundation::SecretString&,
    const idp::BindingDigest&, foundation::Instant)
{
    return foundation::fail(foundation::ErrorCode::Unavailable,
        "Native PostgreSQL transaction store requires coroutine authentication.");
}

foundation::Result<std::optional<idp::AuthenticationTransaction>>
CoroutinePostgresAuthenticationTransactionStore::find(
    const idp::TransactionId&) const
{
    return foundation::fail(foundation::ErrorCode::Unavailable,
        "Native PostgreSQL transaction store does not support synchronous lookups.");
}

std::size_t CoroutinePostgresAuthenticationTransactionStore::purgeExpired(
    foundation::Instant)
{
    throw std::logic_error{"Native PostgreSQL transaction store has no synchronous purge"};
}

std::size_t CoroutinePostgresAuthenticationTransactionStore::size() const
{
    throw std::logic_error{"Native PostgreSQL transaction store has no synchronous count"};
}
} // namespace openproof::storage::postgres

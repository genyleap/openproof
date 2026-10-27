module;

#include "async_pool.hpp"
#include "async_session.hpp"

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

module openproof.storage.postgres;

import openproof.foundation;
import openproof.session;

namespace openproof::storage::postgres {
namespace asio = boost::asio;

class CoroutinePostgresSessionRepository::Impl final {
public:
    Impl(asio::any_io_executor executor, std::string connectionString,
         std::size_t capacity, foundation::Duration acquireTimeout,
         foundation::Duration connectTimeout, foundation::Duration queryTimeout)
        : pool(std::move(executor), std::move(connectionString),
               capacity, acquireTimeout, connectTimeout),
          queryTimeout(queryTimeout) {}
    async_detail::AsyncConnectionPool pool;
    async_detail::AsyncSessionSql sql;
    foundation::Duration queryTimeout{};
};

CoroutinePostgresSessionRepository::CoroutinePostgresSessionRepository(
    asio::any_io_executor executor, foundation::SecretString connectionString,
    std::size_t maxConnections, foundation::Duration acquireTimeout,
    foundation::Duration connectTimeout, foundation::Duration queryTimeout)
{
    if (queryTimeout <= foundation::Duration::zero()) {
        throw std::invalid_argument{"Invalid async session query deadline"};
    }
    // The pool retains the owned libpq parameters; neither this operation
    // nor any failure path logs database credentials or tenant content.
    m_impl = std::make_unique<Impl>(
        std::move(executor), std::string{connectionString.expose()},
        maxConnections, acquireTimeout, connectTimeout, queryTimeout);
}

CoroutinePostgresSessionRepository::~CoroutinePostgresSessionRepository() = default;

asio::awaitable<foundation::Result<session::Session>>
CoroutinePostgresSessionRepository::use(
    session::TokenDigest token, foundation::Instant now)
{
    try {
        auto lease = co_await m_impl->pool.acquire();
        auto fields = co_await m_impl->sql.useToken(
            lease.connection(), foundation::toHex(token.bytes()),
            now.time_since_epoch().count(), m_impl->queryTimeout);
        if (!fields) {
            co_return foundation::fail(
                foundation::ErrorCode::AuthenticationFailed,
                "The session token is unknown, revoked or expired.");
        }
        co_return PostgresSessionDomainAdapter::restore(*fields);
    } catch (const std::exception&) {
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "The session database is unavailable.");
    }
}

asio::awaitable<foundation::Result<std::optional<session::Session>>>
CoroutinePostgresSessionRepository::find(session::SessionId id)
{
    try {
        auto lease = co_await m_impl->pool.acquire();
        auto fields = co_await m_impl->sql.find(
            lease.connection(), std::string{id.value()}, m_impl->queryTimeout);
        if (!fields) co_return std::optional<session::Session>{};
        auto restored = PostgresSessionDomainAdapter::restore(*fields);
        if (!restored) co_return foundation::fail(restored.error());
        co_return std::optional<session::Session>{std::move(restored).value()};
    } catch (const std::exception&) {
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "The session database is unavailable.");
    }
}
} // namespace openproof::storage::postgres

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
#include <vector>

module openproof.storage.postgres;

import openproof.foundation;
import openproof.identity.core;
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

asio::awaitable<foundation::Status>
CoroutinePostgresSessionRepository::add(session::Session value)
{
    if (value.state() != session::SessionState::Active) {
        co_return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "Only an active session can be issued.");
    }
    try {
        async_detail::AsyncSessionSql::NewSession record{
            std::string{value.id().value()},
            std::string{value.identity().value()},
            std::string{value.provider().value()},
            foundation::toHex(value.tokenDigest().bytes()),
            static_cast<unsigned int>(value.assurance()),
            static_cast<unsigned int>(value.strength().factors()),
            value.strength().isPhishingResistant(),
            value.authenticatedAt().time_since_epoch().count(),
            value.issuedAt().time_since_epoch().count(),
            value.lastSeenAt().time_since_epoch().count(),
            value.absoluteExpiresAt().time_since_epoch().count(),
            value.idleTimeout().count(),
            value.userAgent(), value.remoteAddress()
        };
        auto lease = co_await m_impl->pool.acquire();
        co_await m_impl->sql.add(
            lease.connection(), std::move(record), m_impl->queryTimeout);
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "The session could not be persisted.");
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresSessionRepository::rotate(
    session::SessionId id, session::TokenDigest expected,
    session::TokenDigest replacement, foundation::Instant now)
{
    try {
        auto lease = co_await m_impl->pool.acquire();
        const bool changed = co_await m_impl->sql.rotateToken(
            lease.connection(), std::string{id.value()},
            foundation::toHex(expected.bytes()),
            foundation::toHex(replacement.bytes()),
            now.time_since_epoch().count(), m_impl->queryTimeout);
        if (!changed) {
            co_return foundation::fail(
                foundation::ErrorCode::AuthenticationFailed,
                "The session rotation was refused.");
        }
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "The session could not be rotated.");
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresSessionRepository::revoke(
    session::SessionId id, foundation::Instant now)
{
    try {
        auto lease = co_await m_impl->pool.acquire();
        const auto status = co_await m_impl->sql.revoke(
            lease.connection(), std::string{id.value()},
            now.time_since_epoch().count(), m_impl->queryTimeout);
        switch (status) {
        case async_detail::AsyncSessionSql::RevokeStatus::Revoked:
        case async_detail::AsyncSessionSql::RevokeStatus::AlreadyRevoked:
            co_return foundation::ok();
        case async_detail::AsyncSessionSql::RevokeStatus::NotFound:
            co_return foundation::fail(
                foundation::ErrorCode::NotFound,
                "That session was not found.");
        case async_detail::AsyncSessionSql::RevokeStatus::Expired:
            co_return foundation::fail(
                foundation::ErrorCode::FailedPrecondition,
                "An expired session cannot be revoked.");
        }
        co_return foundation::fail(
            foundation::ErrorCode::Internal, "Unknown session state.");
    } catch (const std::exception&) {
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "The session could not be revoked.");
    }
}

asio::awaitable<foundation::Result<std::size_t>>
CoroutinePostgresSessionRepository::revokeAll(
    identity::core::IdentityId identity, foundation::Instant now)
{
    try {
        auto lease = co_await m_impl->pool.acquire();
        co_return co_await m_impl->sql.revokeAll(
            lease.connection(), std::string{identity.value()},
            now.time_since_epoch().count(), m_impl->queryTimeout);
    } catch (const std::exception&) {
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "The sessions could not be revoked.");
    }
}

asio::awaitable<foundation::Result<std::vector<session::Session>>>
CoroutinePostgresSessionRepository::list(identity::core::IdentityId identity)
{
    try {
        auto lease = co_await m_impl->pool.acquire();
        auto rows = co_await m_impl->sql.list(
            lease.connection(), std::string{identity.value()},
            m_impl->queryTimeout);
        std::vector<session::Session> result;
        result.reserve(rows.size());
        for (const auto& fields : rows) {
            auto restored = PostgresSessionDomainAdapter::restore(fields);
            if (!restored) co_return foundation::fail(restored.error());
            result.emplace_back(std::move(restored).value());
        }
        co_return result;
    } catch (const std::exception&) {
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "The sessions could not be listed.");
    }
}

asio::awaitable<foundation::Result<std::size_t>>
CoroutinePostgresSessionRepository::purgeExpired(foundation::Instant now)
{
    try {
        auto lease = co_await m_impl->pool.acquire();
        co_return co_await m_impl->sql.purgeExpired(
            lease.connection(), now.time_since_epoch().count(),
            m_impl->queryTimeout);
    } catch (const std::exception&) {
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "The expired sessions could not be purged.");
    }
}

asio::awaitable<foundation::Result<std::size_t>>
CoroutinePostgresSessionRepository::size()
{
    try {
        auto lease = co_await m_impl->pool.acquire();
        co_return co_await m_impl->sql.size(
            lease.connection(), m_impl->queryTimeout);
    } catch (const std::exception&) {
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "The session count is unavailable.");
    }
}
} // namespace openproof::storage::postgres

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

// Import modules only after all transitive textual standard/Asio headers.
#include "coroutine_session_repository.hpp"

import openproof.foundation;
import openproof.identity.core;
import openproof.session;

namespace openproof::storage::postgres {
namespace asio = boost::asio;

namespace {
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;

// An operation must consume the same budget for pool admission, connection
// (including DISCARD ALL) and SQL. An expired budget may not start new I/O.
[[nodiscard]] std::chrono::milliseconds remaining(Deadline deadline)
{
    const auto budget = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - Clock::now());
    if (budget <= std::chrono::milliseconds::zero()) {
        throw std::runtime_error{"Native session operation deadline exceeded"};
    }
    return budget;
}

[[nodiscard]] async_detail::AsyncSessionSql::NewSession
captureSessionRecord(const session::Session& value)
{
    return {
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
}

// The identity lock precedes the password/link lock, matching reset.
// The second READ COMMITTED statement sees changes committed while
// waiting for the owner lock. Locks survive through session persistence.
asio::awaitable<bool> lockPasswordGeneration(
    async_detail::AsyncConnection& connection,const async_detail::AsyncSessionSql::NewSession& row,
    const CoroutinePostgresSessionRepository::PasswordFence& fence,Deadline deadline)
{
    if (fence.subject.empty() || fence.subject.value().size()>1000U
        || fence.subject.value().find('\0')!=std::string_view::npos
        || fence.generation.time_since_epoch().count()<0)
        co_return false;
    using Params=std::vector<std::optional<std::string>>;
    Params owner{row.identityId};
    const auto active=co_await connection.query(
        "SELECT i.id FROM openproof.identities i JOIN openproof.organizations o ON o.id=i.organization_id "
        "WHERE i.id=$1 AND i.kind=0 AND i.status=0 AND o.state=0 FOR UPDATE OF i FOR SHARE OF o",
        std::move(owner),remaining(deadline));
    const auto exact=[&](const auto& result) {
        return result.rows.size()==1U && result.rows.front().size()==1U
            && result.rows.front().front()==row.identityId;
    };
    if (!exact(active)) co_return false;
    Params credential{row.identityId,row.provider,std::string{fence.subject.value()},
        std::to_string(fence.generation.time_since_epoch().count())};
    const auto generation=co_await connection.query(
        "SELECT p.identity_id FROM openproof.password_credentials p "
        "JOIN openproof.external_identities e ON e.identity_id=p.identity_id "
        "WHERE p.identity_id=$1 AND e.provider=$2 AND e.external_subject=$3 "
        "AND p.changed_at_ms=$4 FOR SHARE OF p,e",std::move(credential),remaining(deadline));
    co_return exact(generation);
}

asio::awaitable<foundation::Status> insertCapturedSession(
    async_detail::AsyncConnectionPool& pool,
    async_detail::AsyncSessionSql& sql,
    foundation::Duration timeout,
    std::optional<async_detail::AsyncSessionSql::NewSession> row,
    std::optional<CoroutinePostgresSessionRepository::PasswordFence> fence=std::nullopt)
{
    if (!row) {
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                   "Only active sessions can be added.");
    }
    try {
        const Deadline deadline = Clock::now() + timeout;
        auto lease = co_await pool.acquire(deadline);
        auto& connection=lease.connection();
        if (fence) {
            static_cast<void>(co_await connection.query("BEGIN ISOLATION LEVEL READ COMMITTED",{},remaining(deadline)));
            if (!(co_await lockPasswordGeneration(connection,*row,*fence,deadline))) {
                static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
                co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
            }
        }
        co_await sql.add(connection, std::move(*row), remaining(deadline));
        if (fence) static_cast<void>(co_await connection.query("COMMIT",{},remaining(deadline)));
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
                                   "Session persistence unavailable.");
    }
}
} // namespace

class CoroutinePostgresSessionRepository::Impl final {
public:
    Impl(asio::any_io_executor executor, std::string connectionString,
         std::size_t capacity, foundation::Duration acquireTimeout,
         foundation::Duration connectTimeout, foundation::Duration queryTimeoutValue)
        : pool(std::move(executor), std::move(connectionString),
               capacity, acquireTimeout, connectTimeout),
          queryTimeout(queryTimeoutValue) {}
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
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        auto fields = co_await m_impl->sql.useToken(
            lease.connection(), foundation::toHex(token.bytes()),
            now.time_since_epoch().count(), remaining(deadline));
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
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        auto fields = co_await m_impl->sql.find(
            lease.connection(), std::string{id.value()}, remaining(deadline));
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
    std::optional<async_detail::AsyncSessionSql::NewSession> row;
    if (value.state() == session::SessionState::Active) {
        row.emplace(captureSessionRecord(value));
    }
    return insertCapturedSession(
        m_impl->pool, m_impl->sql, m_impl->queryTimeout, std::move(row));
}

asio::awaitable<foundation::Status>
CoroutinePostgresSessionRepository::addFenced(session::Session value,PasswordFence fence)
{
    std::optional<async_detail::AsyncSessionSql::NewSession> row;
    if (value.state()==session::SessionState::Active) row.emplace(captureSessionRecord(value));
    return insertCapturedSession(m_impl->pool,m_impl->sql,m_impl->queryTimeout,
        std::move(row),std::move(fence));
}

asio::awaitable<foundation::Status>
CoroutinePostgresSessionRepository::replace(
    session::Session value, session::SessionId previousId,
    session::TokenDigest previousDigest, foundation::Instant now,std::optional<PasswordFence> fence)
{
    if (value.state() != session::SessionState::Active
        || value.id() == previousId) {
        co_return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "The replacement session must be new and active.");
    }
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto row = captureSessionRecord(value);
        auto lease = co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        if (fence) {
            static_cast<void>(co_await connection.query("BEGIN ISOLATION LEVEL READ COMMITTED",{},remaining(deadline)));
            if (!(co_await lockPasswordGeneration(connection,row,*fence,deadline))) {
                static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
                co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
            }
        }
        const bool replaced = co_await m_impl->sql.replace(
            connection, std::move(row), std::string{previousId.value()},
            foundation::toHex(previousDigest.bytes()),
            now.time_since_epoch().count(), remaining(deadline));
        if (!replaced) {
            if (fence) static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(
                foundation::ErrorCode::FailedPrecondition,
                "The previous session is no longer active.");
        }
        if (fence) static_cast<void>(co_await connection.query("COMMIT",{},remaining(deadline)));
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "The session could not be replaced.");
    }
}

asio::awaitable<foundation::Status>
CoroutinePostgresSessionRepository::rotate(
    session::SessionId id, session::TokenDigest expected,
    session::TokenDigest replacement, foundation::Instant now)
{
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        const bool changed = co_await m_impl->sql.rotateToken(
            lease.connection(), std::string{id.value()},
            foundation::toHex(expected.bytes()),
            foundation::toHex(replacement.bytes()),
            now.time_since_epoch().count(), remaining(deadline));
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
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        const auto status = co_await m_impl->sql.revoke(
            lease.connection(), std::string{id.value()},
            now.time_since_epoch().count(), remaining(deadline));
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

asio::awaitable<foundation::Status>
CoroutinePostgresSessionRepository::revokeOwned(
    identity::core::IdentityId identity, session::SessionId id,
    foundation::Instant now)
{
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        const auto status = co_await m_impl->sql.revokeOwned(
            lease.connection(), std::string{identity.value()},
            std::string{id.value()}, now.time_since_epoch().count(),
            remaining(deadline));
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
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        co_return co_await m_impl->sql.revokeAll(
            lease.connection(), std::string{identity.value()},
            now.time_since_epoch().count(), remaining(deadline));
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
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        auto rows = co_await m_impl->sql.list(
            lease.connection(), std::string{identity.value()},
            remaining(deadline));
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

asio::awaitable<foundation::Result<std::vector<session::Session>>>
CoroutinePostgresSessionRepository::listActive(
    identity::core::IdentityId identity, foundation::Instant now)
{
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        auto rows = co_await m_impl->sql.listActive(
            lease.connection(), std::string{identity.value()},
            now.time_since_epoch().count(), remaining(deadline));
        std::vector<session::Session> result;
        result.reserve(rows.size());
        for (const auto& fields : rows) {
            auto restored = PostgresSessionDomainAdapter::restore(fields);
            if (!restored) co_return foundation::fail(restored.error());
            // Fail closed if SQL changes its scope or active-state predicate.
            if (restored->identity() != identity
                || restored->state() != session::SessionState::Active
                || restored->isExpiredAt(now)) {
                co_return foundation::fail(
                    foundation::ErrorCode::Unavailable,
                    "An invalid active session row was returned.");
            }
            result.emplace_back(std::move(restored).value());
        }
        co_return result;
    } catch (const std::exception&) {
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "The active sessions could not be listed.");
    }
}

asio::awaitable<foundation::Result<std::size_t>>
CoroutinePostgresSessionRepository::purgeExpired(foundation::Instant now)
{
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        co_return co_await m_impl->sql.purgeExpired(
            lease.connection(), now.time_since_epoch().count(),
            remaining(deadline));
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
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        co_return co_await m_impl->sql.size(
            lease.connection(), remaining(deadline));
    } catch (const std::exception&) {
        co_return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "The session count is unavailable.");
    }
}
} // namespace openproof::storage::postgres

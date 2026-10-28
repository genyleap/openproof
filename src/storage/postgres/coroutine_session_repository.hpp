#pragma once

// C++26 application adapter, not part of the exported OpenProof protocol
// module. Keep Boost.Asio declarations in ordinary header translation units
// to avoid GCC 16 C++ Modules ODR duplication of Asio thread-context TLS.
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <optional>
#include <vector>

import openproof.foundation;
import openproof.identity.core;
import openproof.session;

namespace openproof::storage::postgres {

/**
 * Validate and restore the actual Session domain object from libpq-owned
 * columns; malformed rows cannot escape as authenticated sessions.
 */
class PostgresSessionDomainAdapter final {
public:
    [[nodiscard]] static foundation::Result<session::Session> restore(
        const std::vector<std::optional<std::string>>& fields);
};

/**
 * Async PostgreSQL session repository, independent of the legacy blocking
 * SessionRepository SPI. The owner must outlive all in-flight awaitables.
 * The handler-to-service coroutine migration is still pending.
 */
class CoroutinePostgresSessionRepository final {
public:
    CoroutinePostgresSessionRepository(
        boost::asio::any_io_executor executor,
        foundation::SecretString connectionString,
        std::size_t maxConnections,
        foundation::Duration acquireTimeout,
        foundation::Duration connectTimeout,
        foundation::Duration queryTimeout);
    CoroutinePostgresSessionRepository(const CoroutinePostgresSessionRepository&) = delete;
    CoroutinePostgresSessionRepository& operator=(const CoroutinePostgresSessionRepository&) = delete;
    ~CoroutinePostgresSessionRepository();

    [[nodiscard]] boost::asio::awaitable<foundation::Result<session::Session>>
    use(session::TokenDigest token, foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<
        foundation::Result<std::optional<session::Session>>>
    find(session::SessionId id);

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    add(session::Session value);

    // One-statement, cancellation-safe replacement of a previously verified
    // active session; stale/unknown cookies must use add() instead.
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    replace(session::Session value, session::SessionId previousId,
            session::TokenDigest previousDigest, foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    rotate(session::SessionId id, session::TokenDigest expected,
           session::TokenDigest replacement, foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    revoke(session::SessionId id, foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::size_t>>
    revokeAll(identity::core::IdentityId identity, foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<
        foundation::Result<std::vector<session::Session>>>
    list(identity::core::IdentityId identity);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::size_t>>
    purgeExpired(foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::size_t>>
    size();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace openproof::storage::postgres

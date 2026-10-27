#pragma once
#include "async_connection.hpp"
#include <boost/asio/awaitable.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace openproof::storage::postgres::async_detail {

// Native async implementation of the session token SQL critical section.
// The caller owns an exclusive AsyncConnectionPool::Lease throughout each call;
// there is no sync compatibility wait, borrowed PGresult, or thread offload.
// Domain-level Session::restore and AuthenticationService wiring remain
// separate pending migrations. Only approved fixed table identifiers exist.
class AsyncSessionSql final {
public:
    enum class Table { Production, TemporaryTest };
    explicit AsyncSessionSql(Table table = Table::Production) noexcept : m_table(table) {}

    using SessionFields = std::vector<std::optional<std::string>>;

    // Atomic update+return; nullopt means unknown, revoked or expired.
    [[nodiscard]] boost::asio::awaitable<std::optional<SessionFields>> useToken(
        AsyncConnection& connection, std::string digestHex,
        std::int64_t nowMilliseconds, std::chrono::milliseconds deadline);

    // Changes a token digest only if the expected previous digest still owns
    // an active unexpired session. False is the generic denied/replayed result.
    [[nodiscard]] boost::asio::awaitable<bool> rotateToken(
        AsyncConnection& connection, std::string sessionId,
        std::string oldDigestHex, std::string newDigestHex,
        std::int64_t nowMilliseconds, std::chrono::milliseconds deadline);

    enum class RevokeStatus { Revoked, AlreadyRevoked, NotFound, Expired };

    // Idempotent revocation, retaining the legacy distinction between an
    // unknown session, an already-revoked session and an expired session.
    [[nodiscard]] boost::asio::awaitable<RevokeStatus> revoke(
        AsyncConnection& connection, std::string sessionId,
        std::int64_t nowMilliseconds, std::chrono::milliseconds deadline);

    // Atomically revoke all still-active sessions for an identity. No caller
    // can observe a partially revoked batch; result is the affected count.
    [[nodiscard]] boost::asio::awaitable<std::size_t> revokeAll(
        AsyncConnection& connection, std::string identityId,
        std::int64_t nowMilliseconds, std::chrono::milliseconds deadline);

    // A direct lookup must not renew last-seen or mark an expired row active.
    [[nodiscard]] boost::asio::awaitable<std::optional<SessionFields>> find(
        AsyncConnection& connection, std::string sessionId,
        std::chrono::milliseconds deadline);

private:
    Table m_table;
};
} // namespace openproof::storage::postgres::async_detail

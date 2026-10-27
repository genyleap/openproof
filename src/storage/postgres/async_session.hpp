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

    // Strict, owned row representation at the storage-to-domain boundary.
    // A future coroutine repository converts this into session::Session only
    // after shape, enum values, timestamps and digest have been validated.
    struct SessionSnapshot final {
        std::string id;
        std::string identityId;
        std::string provider;
        std::string tokenDigestHex;
        unsigned int assurance{};
        unsigned int factors{};
        bool phishingResistant{};
        unsigned int state{};
        std::int64_t authenticatedAtMs{};
        std::int64_t issuedAtMs{};
        std::int64_t lastSeenAtMs{};
        std::int64_t absoluteExpiresAtMs{};
        std::int64_t idleTimeoutMs{};
        std::optional<std::int64_t> revokedAtMs;
        std::optional<std::string> userAgent;
        std::optional<std::string> remoteAddress;
    };
    [[nodiscard]] static SessionSnapshot decodeRow(const SessionFields& fields);

    struct NewSession final {
        std::string id;
        std::string identityId;
        std::string provider;
        std::string tokenDigestHex;
        unsigned int assurance{};
        unsigned int factors{};
        bool phishingResistant{};
        std::int64_t authenticatedAtMs{};
        std::int64_t issuedAtMs{};
        std::int64_t lastSeenAtMs{};
        std::int64_t absoluteExpiresAtMs{};
        std::int64_t idleTimeoutMs{};
        std::optional<std::string> userAgent;
        std::optional<std::string> remoteAddress;
    };

    // Persist a new active session with the same 16-column contract as the
    // existing sync repository, without storing the raw bearer secret.
    [[nodiscard]] boost::asio::awaitable<void> add(
        AsyncConnection& connection, NewSession session,
        std::chrono::milliseconds deadline);

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

    // Returns all available rows, ordered by descending last-seen. The
    // transport's explicit result bound rejects oversized sets; pagination
    // must be added to the public session listing API prior to deployment.
    [[nodiscard]] boost::asio::awaitable<std::vector<SessionFields>> list(
        AsyncConnection& connection, std::string identityId,
        std::chrono::milliseconds deadline);

    [[nodiscard]] boost::asio::awaitable<std::size_t> purgeExpired(
        AsyncConnection& connection, std::int64_t nowMilliseconds,
        std::chrono::milliseconds deadline);

    [[nodiscard]] boost::asio::awaitable<std::size_t> size(
        AsyncConnection& connection, std::chrono::milliseconds deadline);

private:
    Table m_table;
};
} // namespace openproof::storage::postgres::async_detail

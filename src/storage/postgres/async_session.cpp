#include "async_session.hpp"

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace openproof::storage::postgres::async_detail {
namespace asio = boost::asio;
namespace {

constexpr std::string_view kSessionFields =
    "id, identity_id, provider, assurance, factors, phishing_resistant, state, "
    "encode(token_digest, 'hex'), authenticated_at_ms, issued_at_ms, "
    "last_seen_at_ms, absolute_expires_at_ms, idle_timeout_ms, revoked_at_ms, "
    "user_agent, remote_address";

[[nodiscard]] bool validDigest(std::string_view digest) noexcept
{
    return digest.size() == 64U &&
        std::ranges::all_of(digest, [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                || (c >= 'A' && c <= 'F');
        });
}

[[nodiscard]] bool validId(std::string_view id) noexcept
{
    return !id.empty() && id.size() <= 200U
        && id.find('\0') == std::string_view::npos;
}

[[nodiscard]] std::string tableName(AsyncSessionSql::Table table)
{
    // No user input may ever enter this SQL identifier.
    return table == AsyncSessionSql::Table::Production
        ? "openproof.sessions" : "pg_temp.sessions";
}

[[nodiscard]] std::optional<AsyncSessionSql::SessionFields> singleSession(QueryRows rows)
{
    if (rows.rows.empty()) return std::nullopt;
    if (rows.rows.size() != 1U || rows.rows.front().size() != 16U) {
        throw std::runtime_error{"PostgreSQL session query returned invalid shape"};
    }
    return std::move(rows.rows.front());
}

} // namespace

asio::awaitable<std::optional<AsyncSessionSql::SessionFields>>
AsyncSessionSql::useToken(AsyncConnection& connection, std::string digestHex,
                          std::int64_t nowMilliseconds,
                          std::chrono::milliseconds deadline)
{
    if (!validDigest(digestHex) || nowMilliseconds < 0) {
        throw std::invalid_argument{"Invalid async session token lookup arguments"};
    }
    // Exactly the current synchronous production SQL semantics: one atomic
    // UPDATE protects both the single-use clock check and last-seen update.
    const std::string sql =
        "UPDATE " + tableName(m_table) + " SET "
        "state=CASE WHEN $2::bigint>=absolute_expires_at_ms OR "
        "$2::bigint>=last_seen_at_ms+idle_timeout_ms THEN 2 ELSE state END, "
        "last_seen_at_ms=CASE WHEN $2::bigint<absolute_expires_at_ms AND "
        "$2::bigint<last_seen_at_ms+idle_timeout_ms THEN $2::bigint ELSE last_seen_at_ms END "
        "WHERE token_digest=decode($1,'hex') AND state=0 RETURNING "
        + std::string{kSessionFields};
    auto rows = co_await connection.query(
        sql, {std::move(digestHex), std::to_string(nowMilliseconds)}, deadline);
    auto session = singleSession(std::move(rows));
    if (session.has_value()
        && session->at(6U) != std::optional<std::string>{"0"}) {
        // Expired sessions can be updated to state=2 by this query, but their
        // identifiers and assurance MUST never escape to the caller.
        co_return std::nullopt;
    }
    co_return session;
}

asio::awaitable<bool> AsyncSessionSql::rotateToken(
    AsyncConnection& connection, std::string sessionId,
    std::string oldDigestHex, std::string newDigestHex,
    std::int64_t nowMilliseconds, std::chrono::milliseconds deadline)
{
    if (!validId(sessionId) || !validDigest(oldDigestHex)
        || !validDigest(newDigestHex) || nowMilliseconds < 0) {
        throw std::invalid_argument{"Invalid async session token rotation arguments"};
    }
    const std::string sql =
        "UPDATE " + tableName(m_table) +
        " SET token_digest=decode($3,'hex'),last_seen_at_ms=$4 "
        "WHERE id=$1 AND token_digest=decode($2,'hex') AND state=0 "
        "AND $4::bigint<absolute_expires_at_ms AND $4::bigint<last_seen_at_ms+idle_timeout_ms "
        "RETURNING id";
    auto rows = co_await connection.query(
        sql, {std::move(sessionId), std::move(oldDigestHex),
              std::move(newDigestHex), std::to_string(nowMilliseconds)}, deadline);
    if (rows.rows.size() > 1U
        || (!rows.rows.empty() && rows.rows.front().size() != 1U)) {
        throw std::runtime_error{"PostgreSQL token rotation returned invalid shape"};
    }
    co_return rows.rows.size() == 1U;
}

asio::awaitable<AsyncSessionSql::RevokeStatus> AsyncSessionSql::revoke(
    AsyncConnection& connection, std::string sessionId,
    std::int64_t nowMilliseconds, std::chrono::milliseconds deadline)
{
    if (!validId(sessionId) || nowMilliseconds < 0) {
        throw std::invalid_argument{"Invalid async session revocation arguments"};
    }
    if (deadline <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument{"Invalid async session revocation deadline"};
    }
    const auto expiresAt = std::chrono::steady_clock::now() + deadline;
    const std::string update =
        "UPDATE " + tableName(m_table) +
        " SET state=1,revoked_at_ms=$2 WHERE id=$1 AND state=0 RETURNING id";
    const std::string now = std::to_string(nowMilliseconds);
    auto rows = co_await connection.query(update, {sessionId, now}, deadline);
    if (rows.rows.size() > 1U
        || (!rows.rows.empty() && rows.rows.front().size() != 1U)) {
        throw std::runtime_error{"PostgreSQL revocation returned invalid shape"};
    }
    if (rows.rows.size() == 1U) co_return RevokeStatus::Revoked;

    // Serialize a retry through this lease. Already-revoked is successful,
    // but missing or expired must never mint an authenticated session.
    const std::string sql =
        "SELECT state FROM " + tableName(m_table) + " WHERE id=$1";
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        expiresAt - std::chrono::steady_clock::now());
    if (remaining <= std::chrono::milliseconds::zero()) {
        throw std::runtime_error{"Async session revocation deadline exceeded"};
    }
    auto state = co_await connection.query(sql, {std::move(sessionId)}, remaining);
    if (state.rows.empty()) co_return RevokeStatus::NotFound;
    if (state.rows.size() != 1U || state.rows.front().size() != 1U
        || !state.rows.front().front().has_value()) {
        throw std::runtime_error{"PostgreSQL session state returned invalid shape"};
    }
    if (state.rows.front().front() == "1") {
        co_return RevokeStatus::AlreadyRevoked;
    }
    if (state.rows.front().front() == "2") {
        co_return RevokeStatus::Expired;
    }
    throw std::runtime_error{"PostgreSQL session state changed unexpectedly"};
}

asio::awaitable<std::size_t> AsyncSessionSql::revokeAll(
    AsyncConnection& connection, std::string identityId,
    std::int64_t nowMilliseconds, std::chrono::milliseconds deadline)
{
    if (!validId(identityId) || nowMilliseconds < 0) {
        throw std::invalid_argument{"Invalid async session identity revocation arguments"};
    }
    // Statement-level atomicity matches the original repository contract.
    // RETURNING avoids a synchronous PQcmdTuples() result on this adapter.
    const std::string sql =
        "UPDATE " + tableName(m_table)
        + " SET state=1,revoked_at_ms=$2 WHERE identity_id=$1 AND state=0 "
          "RETURNING id";
    auto rows = co_await connection.query(
        sql, {std::move(identityId), std::to_string(nowMilliseconds)}, deadline);
    for (const auto& row : rows.rows) {
        if (row.size() != 1U || !row.front().has_value()) {
            throw std::runtime_error{"PostgreSQL bulk revocation returned invalid shape"};
        }
    }
    co_return rows.rows.size();
}

asio::awaitable<std::optional<AsyncSessionSql::SessionFields>>
AsyncSessionSql::find(AsyncConnection& connection, std::string sessionId,
                      std::chrono::milliseconds deadline)
{
    if (!validId(sessionId)) {
        throw std::invalid_argument{"Invalid async session identifier"};
    }
    const std::string sql =
        "SELECT " + std::string{kSessionFields} + " FROM "
        + tableName(m_table) + " WHERE id=$1";
    auto rows = co_await connection.query(
        sql, {std::move(sessionId)}, deadline);
    co_return singleSession(std::move(rows));
}
} // namespace openproof::storage::postgres::async_detail

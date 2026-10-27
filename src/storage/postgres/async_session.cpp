#include "async_session.hpp"

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
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

template <typename Integer>
[[nodiscard]] Integer parseRequiredNumber(
    const std::optional<std::string>& field)
{
    if (!field) throw std::runtime_error{"PostgreSQL session field is NULL"};
    Integer value{};
    const auto [end, ec] = std::from_chars(
        field->data(), field->data() + field->size(), value);
    if (ec != std::errc{} || end != field->data() + field->size()) {
        throw std::runtime_error{"PostgreSQL session number is invalid"};
    }
    return value;
}

[[nodiscard]] const std::string& requiredText(
    const std::optional<std::string>& field)
{
    if (!field) throw std::runtime_error{"PostgreSQL session field is NULL"};
    return *field;
}

[[nodiscard]] std::size_t parseScalarCount(const QueryRows& rows)
{
    if (rows.rows.size() != 1U || rows.rows[0].size() != 1U
        || !rows.rows[0][0].has_value()) {
        throw std::runtime_error{"PostgreSQL session count returned invalid shape"};
    }
    const std::string& count = *rows.rows[0][0];
    std::size_t total{};
    const auto [end, ec] = std::from_chars(
        count.data(), count.data() + count.size(), total);
    if (ec != std::errc{} || end != count.data() + count.size()) {
        throw std::runtime_error{"PostgreSQL session count was invalid"};
    }
    return total;
}

asio::awaitable<void> executeInsert(
    AsyncConnection& connection, std::string sql,
    std::vector<std::optional<std::string>> params,
    std::chrono::milliseconds deadline)
{
    static_cast<void>(co_await connection.query(
        std::move(sql), std::move(params), deadline));
}

} // namespace

AsyncSessionSql::SessionSnapshot AsyncSessionSql::decodeRow(
    const SessionFields& fields)
{
    if (fields.size() != 16U) {
        throw std::runtime_error{"PostgreSQL session row has invalid shape"};
    }
    SessionSnapshot result;
    result.id = requiredText(fields[0]);
    result.identityId = requiredText(fields[1]);
    result.provider = requiredText(fields[2]);
    result.assurance = parseRequiredNumber<unsigned int>(fields[3]);
    result.factors = parseRequiredNumber<unsigned int>(fields[4]);
    const std::string& resistant = requiredText(fields[5]);
    if (resistant != "t" && resistant != "f") {
        throw std::runtime_error{"PostgreSQL session boolean is invalid"};
    }
    result.phishingResistant = resistant == "t";
    result.state = parseRequiredNumber<unsigned int>(fields[6]);
    result.tokenDigestHex = requiredText(fields[7]);
    result.authenticatedAtMs = parseRequiredNumber<std::int64_t>(fields[8]);
    result.issuedAtMs = parseRequiredNumber<std::int64_t>(fields[9]);
    result.lastSeenAtMs = parseRequiredNumber<std::int64_t>(fields[10]);
    result.absoluteExpiresAtMs = parseRequiredNumber<std::int64_t>(fields[11]);
    result.idleTimeoutMs = parseRequiredNumber<std::int64_t>(fields[12]);
    if (fields[13]) {
        result.revokedAtMs = parseRequiredNumber<std::int64_t>(fields[13]);
    }
    result.userAgent = fields[14];
    result.remoteAddress = fields[15];

    if (!validId(result.id) || !validId(result.identityId)
        || !validId(result.provider) || !validDigest(result.tokenDigestHex)
        || result.assurance > 4U || result.factors > 7U || result.state > 2U
        || result.authenticatedAtMs > result.issuedAtMs
        || result.issuedAtMs > result.lastSeenAtMs
        || result.lastSeenAtMs >= result.absoluteExpiresAtMs
        || result.idleTimeoutMs <= 0
        || (result.state == 1U) != result.revokedAtMs.has_value()) {
        throw std::runtime_error{"PostgreSQL session data violates invariants"};
    }
    return result;
}

asio::awaitable<void> AsyncSessionSql::add(
    AsyncConnection& connection, NewSession session,
    std::chrono::milliseconds deadline)
{
    if (!validId(session.id) || !validId(session.identityId)
        || !validId(session.provider) || !validDigest(session.tokenDigestHex)
        || session.assurance > 4U || session.factors > 7U
        || session.authenticatedAtMs > session.issuedAtMs
        || session.issuedAtMs > session.lastSeenAtMs
        || session.lastSeenAtMs >= session.absoluteExpiresAtMs
        || session.idleTimeoutMs <= 0) {
        throw std::invalid_argument{"Invalid async session insert arguments"};
    }
    const std::string sql =
        "INSERT INTO " + tableName(m_table) +
        " (id,identity_id,provider,assurance,factors,phishing_resistant,"
        "state,token_digest,authenticated_at_ms,issued_at_ms,last_seen_at_ms,"
        "absolute_expires_at_ms,idle_timeout_ms,revoked_at_ms,user_agent,remote_address) "
        "VALUES($1,$2,$3,$4,$5,$6,0,decode($7,'hex'),$8,$9,$10,$11,$12,NULL,$13,$14)";
    // Preserve SQL NULL distinct from an empty string in the transport.
    // The original repository maps empty metadata strings to SQL NULL.
    if (session.userAgent && session.userAgent->empty()) session.userAgent.reset();
    if (session.remoteAddress && session.remoteAddress->empty()) session.remoteAddress.reset();
    return executeInsert(connection, sql, {
        std::move(session.id), std::move(session.identityId),
        std::move(session.provider), std::to_string(session.assurance),
        std::to_string(session.factors),
        session.phishingResistant ? "true" : "false",
        std::move(session.tokenDigestHex),
        std::to_string(session.authenticatedAtMs),
        std::to_string(session.issuedAtMs),
        std::to_string(session.lastSeenAtMs),
        std::to_string(session.absoluteExpiresAtMs),
        std::to_string(session.idleTimeoutMs),
        std::move(session.userAgent), std::move(session.remoteAddress)
    }, deadline);
}

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
    // Return one count row rather than one row per revoked session: the
    // latter could breach the bounded AsyncConnection result-copy limit
    // *after* PostgreSQL had already committed the UPDATE.
    // The data modification and its count remain one atomic statement.
    const std::string sql =
        "WITH changed AS (UPDATE " + tableName(m_table)
        + " SET state=1,revoked_at_ms=$2 WHERE identity_id=$1 AND state=0 "
          "RETURNING 1) SELECT count(*)::text FROM changed";
    auto rows = co_await connection.query(
        sql, {std::move(identityId), std::to_string(nowMilliseconds)}, deadline);
    co_return parseScalarCount(rows);
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
asio::awaitable<std::vector<AsyncSessionSql::SessionFields>>
AsyncSessionSql::list(AsyncConnection& connection, std::string identityId,
                       std::chrono::milliseconds deadline)
{
    if (!validId(identityId)) {
        throw std::invalid_argument{"Invalid async session list identity"};
    }
    const std::string sql =
        "SELECT " + std::string{kSessionFields} + " FROM "
        + tableName(m_table)
        + " WHERE identity_id=$1 ORDER BY last_seen_at_ms DESC";
    auto rows = co_await connection.query(sql, {std::move(identityId)}, deadline);
    for (const auto& row : rows.rows) {
        if (row.size() != 16U) {
            throw std::runtime_error{"PostgreSQL session list returned invalid shape"};
        }
    }
    co_return std::move(rows.rows);
}

asio::awaitable<std::size_t> AsyncSessionSql::purgeExpired(
    AsyncConnection& connection, std::int64_t nowMilliseconds,
    std::chrono::milliseconds deadline)
{
    if (nowMilliseconds < 0) {
        throw std::invalid_argument{"Invalid async session purge timestamp"};
    }
    const std::string sql =
        "WITH removed AS (DELETE FROM " + tableName(m_table)
        + " WHERE $1::bigint>=absolute_expires_at_ms "
          "OR $1::bigint>=last_seen_at_ms+idle_timeout_ms RETURNING 1) "
          "SELECT count(*)::text FROM removed";
    auto rows = co_await connection.query(
        sql, {std::to_string(nowMilliseconds)}, deadline);
    co_return parseScalarCount(rows);
}

asio::awaitable<std::size_t> AsyncSessionSql::size(
    AsyncConnection& connection, std::chrono::milliseconds deadline)
{
    const std::string sql =
        "SELECT count(*)::text FROM " + tableName(m_table);
    auto rows = co_await connection.query(sql, {}, deadline);
    co_return parseScalarCount(rows);
}

} // namespace openproof::storage::postgres::async_detail

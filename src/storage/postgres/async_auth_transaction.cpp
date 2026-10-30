#include "async_auth_transaction.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace openproof::storage::postgres::async_detail {
namespace {
using Clock = std::chrono::steady_clock;

[[nodiscard]] bool validDigest(std::string_view digest)
{
    return digest.size() == 64U
        && std::all_of(digest.begin(), digest.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                || (c >= 'A' && c <= 'F');
        });
}

[[nodiscard]] bool validText(std::string_view text)
{
    return !text.empty() && text.size() <= 200U
        && text.find('\0') == std::string_view::npos;
}

[[nodiscard]] std::chrono::milliseconds remaining(Clock::time_point deadline)
{
    if (Clock::now() >= deadline)
        throw std::runtime_error{"Authentication transaction SQL deadline exceeded"};
    const auto value = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - Clock::now());
    if (value <= std::chrono::milliseconds::zero())
        throw std::runtime_error{"Authentication transaction SQL deadline exceeded"};
    return value;
}

[[nodiscard]] const std::string& required(
    const std::optional<std::string>& value)
{
    if (!value) throw std::runtime_error{"Invalid PostgreSQL authentication row"};
    return *value;
}

template<typename Number>
[[nodiscard]] Number number(const std::optional<std::string>& field)
{
    const auto& text = required(field);
    Number result{};
    const auto [pos, error] =
        std::from_chars(text.data(), text.data() + text.size(), result);
    if (error != std::errc{} || pos != text.data() + text.size())
        throw std::runtime_error{"Invalid PostgreSQL authentication number"};
    return result;
}

[[nodiscard]] bool one(const QueryRows& rows)
{
    if (rows.rows.size() > 1U || (!rows.rows.empty()
        && (rows.rows[0].size() != 1U || !rows.rows[0][0])))
        throw std::runtime_error{"Invalid PostgreSQL insert result"};
    return !rows.rows.empty();
}

[[nodiscard]] AsyncAuthenticationTransactionSql::Record parse(
    const std::vector<std::optional<std::string>>& row)
{
    if (row.size() != 9U)
        throw std::runtime_error{"Invalid PostgreSQL authentication shape"};
    AsyncAuthenticationTransactionSql::Record record;
    record.id = required(row[0]);
    record.provider = required(row[1]);
    record.interaction = number<unsigned int>(row[2]);
    record.nonceDigestHex = required(row[3]);
    record.bindingDigestHex = required(row[4]);
    record.correlationId = required(row[5]);
    record.state = number<unsigned int>(row[6]);
    record.createdMs = number<std::int64_t>(row[7]);
    record.expiresMs = number<std::int64_t>(row[8]);
    if (!validText(record.id) || !validText(record.provider)
        || !validText(record.correlationId)
        || !validDigest(record.nonceDigestHex)
        || !validDigest(record.bindingDigestHex)
        || record.interaction > 4U || record.state > 3U
        || record.expiresMs <= record.createdMs)
        throw std::runtime_error{"PostgreSQL authentication invariant violated"};
    return record;
}
}

boost::asio::awaitable<bool> AsyncAuthenticationTransactionSql::begin(
    AsyncConnection& connection, Record row, std::chrono::milliseconds timeout)
{
    if (!validText(row.id) || !validText(row.provider)
        || !validText(row.correlationId)
        || !validDigest(row.nonceDigestHex)
        || !validDigest(row.bindingDigestHex)
        || row.interaction > 4U || row.state != 0U
        || row.expiresMs <= row.createdMs || row.metadata.size() > 64U)
        throw std::invalid_argument{"Invalid authentication transaction arguments"};

    // Invalid input must not open an SQL transaction on a pooled lease.
    for (const auto& [key, value] : row.metadata) {
        if (key.empty() || key.size() > 200U
            || key.find('\0') != std::string::npos || value.size() > 8192U
            || value.find('\0') != std::string::npos)
            throw std::invalid_argument{"Invalid authentication metadata"};
    }

    const auto deadline = Clock::now() + timeout;
    const std::string transactions = m_table == Table::Production
        ? "openproof.authentication_transactions" : "pg_temp.auth_transactions";
    const std::string metadata = m_table == Table::Production
        ? "openproof.authentication_transaction_metadata"
        : "pg_temp.auth_transaction_metadata";

    static_cast<void>(co_await connection.query("BEGIN", {}, remaining(deadline)));
    const auto inserted = co_await connection.query(
        "INSERT INTO " + transactions +
        " (id,provider,interaction,nonce_digest,binding_digest,correlation_id,"
        "state,created_at_ms,expires_at_ms) "
        "VALUES($1,$2,$3,decode($4,'hex'),decode($5,'hex'),$6,$7,$8,$9) "
        "ON CONFLICT (id) DO NOTHING RETURNING id",
        {row.id, row.provider, std::to_string(row.interaction),
         row.nonceDigestHex, row.bindingDigestHex, row.correlationId,
         std::to_string(row.state), std::to_string(row.createdMs),
         std::to_string(row.expiresMs)},
        remaining(deadline));
    if (!one(inserted)) {
        static_cast<void>(co_await connection.query(
            "ROLLBACK", {}, remaining(deadline)));
        co_return false;
    }
    for (const auto& [key, value] : row.metadata) {
        static_cast<void>(co_await connection.query(
            "INSERT INTO " + metadata +
            " (transaction_id,key,value) VALUES($1,$2,$3)",
            {row.id, key, value}, remaining(deadline)));
    }
    static_cast<void>(co_await connection.query(
        "COMMIT", {}, remaining(deadline)));
    co_return true;
}

boost::asio::awaitable<std::optional<AsyncAuthenticationTransactionSql::Record>>
AsyncAuthenticationTransactionSql::consume(
    AsyncConnection& connection, std::string id,
    std::string nonceDigestHex, std::string bindingDigestHex,
    std::int64_t nowMs, std::chrono::milliseconds timeout)
{
    if (!validText(id) || !validDigest(nonceDigestHex)
        || !validDigest(bindingDigestHex))
        throw std::invalid_argument{"Invalid authentication redemption parameters"};

    const auto deadline = Clock::now() + timeout;
    const std::string transactions = m_table == Table::Production
        ? "openproof.authentication_transactions" : "pg_temp.auth_transactions";
    const std::string metadata = m_table == Table::Production
        ? "openproof.authentication_transaction_metadata"
        : "pg_temp.auth_transaction_metadata";

    static_cast<void>(co_await connection.query("BEGIN", {}, remaining(deadline)));
    const auto updated = co_await connection.query(
        "UPDATE " + transactions + " SET state=CASE "
        "WHEN expires_at_ms <= $4::bigint THEN 3 "
        "WHEN nonce_digest<>decode($2,'hex') OR binding_digest<>decode($3,'hex') "
        "THEN 2 ELSE 1 END "
        "WHERE id=$1 AND state=0 RETURNING "
        "id,provider,interaction,encode(nonce_digest,'hex'),"
        "encode(binding_digest,'hex'),correlation_id,state,created_at_ms,expires_at_ms",
        {id, std::move(nonceDigestHex), std::move(bindingDigestHex),
         std::to_string(nowMs)}, remaining(deadline));
    if (updated.rows.empty()) {
        static_cast<void>(co_await connection.query(
            "ROLLBACK", {}, remaining(deadline)));
        co_return std::nullopt;
    }
    if (updated.rows.size() != 1U)
        throw std::runtime_error{"PostgreSQL transaction redemption was not unique"};
    auto result = parse(updated.rows.front());
    if (result.id != id)
        throw std::runtime_error{"PostgreSQL transaction identity changed"};
    const auto values = co_await connection.query(
        "SELECT key,value FROM " + metadata +
        " WHERE transaction_id=$1 ORDER BY key",
        {id}, remaining(deadline));
    if (values.rows.size() > 64U)
        throw std::runtime_error{"PostgreSQL transaction metadata exceeds limit"};
    for (const auto& item : values.rows) {
        if (item.size() != 2U
            || !result.metadata.emplace(required(item[0]), required(item[1])).second)
            throw std::runtime_error{"Invalid PostgreSQL transaction metadata"};
    }
    // The burn must commit even for an invalid nonce or expired challenge.
    static_cast<void>(co_await connection.query(
        "COMMIT", {}, remaining(deadline)));
    co_return result;
}

} // namespace openproof::storage::postgres::async_detail

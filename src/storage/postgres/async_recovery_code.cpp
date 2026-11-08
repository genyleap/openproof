#include "async_recovery_code.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace openproof::storage::postgres::async_detail {
namespace {
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;

[[nodiscard]] std::string tableName(AsyncRecoveryCodeSql::Table table)
{
    return table == AsyncRecoveryCodeSql::Table::Production
        ? "openproof.recovery_codes" : "pg_temp.recovery_codes";
}

[[nodiscard]] bool validIdentity(std::string_view id) noexcept
{
    return !id.empty() && id.size() <= 200U
        && std::all_of(id.begin(), id.end(), [](char value) {
            const auto byte = static_cast<unsigned char>(value);
            return byte >= 0x20U && byte < 0x7fU;
        });
}

[[nodiscard]] bool validDigest(std::string_view text) noexcept
{
    return text.size() == 64U && std::all_of(
        text.begin(), text.end(), [](char c) {
            return (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
                || (c >= '0' && c <= '9');
        });
}

[[nodiscard]] std::string canonicalDigest(std::string digest)
{
    if (!validDigest(digest)) {
        throw std::invalid_argument{"Invalid recovery code digest"};
    }
    for (char& symbol : digest) {
        if (symbol >= 'A' && symbol <= 'F') {
            symbol = static_cast<char>(symbol - 'A' + 'a');
        }
    }
    return digest;
}

[[nodiscard]] std::chrono::milliseconds remainingBudget(Deadline deadline)
{
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - Clock::now());
    if (duration <= std::chrono::milliseconds::zero()) {
        throw std::runtime_error{"Recovery-code SQL deadline exceeded"};
    }
    return duration;
}

[[nodiscard]] std::size_t countRows(const QueryRows& rows)
{
    if (rows.rows.size() != 1U || rows.rows.front().size() != 1U
        || !rows.rows.front().front()) {
        throw std::runtime_error{"Recovery-code count had an invalid shape"};
    }
    const std::string& value = *rows.rows.front().front();
    std::size_t number{};
    const auto [end, error] = std::from_chars(
        value.data(), value.data() + value.size(), number);
    if (error != std::errc{} || end != value.data() + value.size()
        || number > AsyncRecoveryCodeSql::kMaximumRecoveryCodes) {
        throw std::runtime_error{"Recovery-code count exceeds safe bounds"};
    }
    return number;
}

} // namespace

boost::asio::awaitable<void> AsyncRecoveryCodeSql::replace(
    AsyncConnection& conn, std::string identityId,
    std::vector<std::string> digestsHex, std::chrono::milliseconds timeout)
{
    if (!validIdentity(identityId)
        || digestsHex.size() > kMaximumRecoveryCodes
        || timeout <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument{"Invalid recovery code replacement"};
    }
    for (auto& digest : digestsHex) digest = canonicalDigest(std::move(digest));
    std::sort(digestsHex.begin(), digestsHex.end());
    if (std::adjacent_find(digestsHex.begin(), digestsHex.end())
            != digestsHex.end()) {
        throw std::invalid_argument{"Recovery-code digests are not unique"};
    }
    const Deadline deadline = Clock::now() + timeout;
    const std::string table = tableName(m_table);
    static_cast<void>(co_await conn.query(
        "BEGIN", {}, remainingBudget(deadline)));
    // Two concurrent rotations of the same identity must serialize BEFORE
    // either DELETE. Otherwise READ COMMITTED can let both transactions
    // insert disjoint code sets after deleting the same prior snapshot,
    // accidentally leaving both rotated batches valid. Advisory xact locks
    // are transaction-scoped and need no vendor-specific schema migration.
    // A timeout/cancellation closes the libpq session and releases the lock.
    static_cast<void>(co_await conn.query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        {identityId}, remainingBudget(deadline)));
    static_cast<void>(co_await conn.query(
        "DELETE FROM " + table + " WHERE identity_id=$1",
        {identityId}, remainingBudget(deadline)));

    if (!digestsHex.empty()) {
        // INSERT all validated digests with a single parameterized statement.
        // Every SQL placeholder is generated from a bounded integer index;
        // the caller's identity/digests are never interpolated into SQL.
        std::string sql = "INSERT INTO " + table
            + " (identity_id,code_digest,issued_at_ms) VALUES ";
        std::vector<std::optional<std::string>> parameters;
        parameters.reserve(digestsHex.size() + 1U);
        parameters.emplace_back(std::move(identityId));
        for (const auto& digest : digestsHex) {
            if (parameters.size() != 1U) sql.push_back(',');
            const std::size_t index = parameters.size() + 1U;
            sql += "($1,decode($" + std::to_string(index)
                + ",'hex'),(extract(epoch FROM clock_timestamp())*1000)::bigint)";
            parameters.emplace_back(digest);
        }
        static_cast<void>(co_await conn.query(
            std::move(sql), std::move(parameters), remainingBudget(deadline)));
    }
    static_cast<void>(co_await conn.query(
        "COMMIT", {}, remainingBudget(deadline)));
    co_return;
}

boost::asio::awaitable<bool> AsyncRecoveryCodeSql::consume(
    AsyncConnection& conn, std::string identityId, std::string digestHex,
    std::chrono::milliseconds timeout)
{
    if (!validIdentity(identityId)
        || timeout <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument{"Invalid recovery-code consumption"};
    }
    digestHex = canonicalDigest(std::move(digestHex));
    auto rows = co_await conn.query(
        "DELETE FROM " + tableName(m_table)
        + " WHERE identity_id=$1 AND code_digest=decode($2,'hex') "
          "RETURNING identity_id",
        {std::move(identityId), std::move(digestHex)}, timeout);
    if (rows.rows.size() > 1U
        || (!rows.rows.empty()
            && (rows.rows.front().size() != 1U
                || !rows.rows.front().front()))) {
        throw std::runtime_error{"Recovery-code redemption returned invalid rows"};
    }
    co_return !rows.rows.empty();
}

boost::asio::awaitable<std::size_t> AsyncRecoveryCodeSql::remaining(
    AsyncConnection& conn, std::string identityId,
    std::chrono::milliseconds timeout)
{
    if (!validIdentity(identityId)
        || timeout <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument{"Invalid recovery-code count"};
    }
    auto rows = co_await conn.query(
        "SELECT count(*)::text FROM " + tableName(m_table)
        + " WHERE identity_id=$1",
        {std::move(identityId)}, timeout);
    co_return countRows(rows);
}

} // namespace openproof::storage::postgres::async_detail

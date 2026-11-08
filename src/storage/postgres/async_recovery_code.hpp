#pragma once

#include "async_connection.hpp"

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <string>
#include <vector>

namespace openproof::storage::postgres::async_detail {

// Native, nonblocking SQL critical sections for single-use recovery codes.
// No raw recovery code, human identity or pepper is stored by this adapter.
// Every digest is a validated SHA-256 hex string and every SQL value is a
// libpq parameter. The only table names are compile-time approved constants.
//
// Each replace owns one exclusively leased AsyncConnection across
// BEGIN/DELETE/batched INSERT/COMMIT. If it throws, that connection is not
// reusable while in a transaction; the pool must dispose of it.
class AsyncRecoveryCodeSql final {
public:
    enum class Table { Production, TemporaryTest };
    explicit AsyncRecoveryCodeSql(Table table = Table::Production) noexcept
        : m_table(table) {}

    static constexpr std::size_t kMaximumRecoveryCodes = 64U;

    [[nodiscard]] boost::asio::awaitable<void> replace(
        AsyncConnection& conn, std::string identityId,
        std::vector<std::string> digestsHex,
        std::chrono::milliseconds timeout);

    // Atomic DELETE ... RETURNING, false for missing, used or foreign codes.
    // A replay can never succeed, even with concurrent clients.
    [[nodiscard]] boost::asio::awaitable<bool> consume(
        AsyncConnection& conn, std::string identityId, std::string digestHex,
        std::chrono::milliseconds timeout);

    [[nodiscard]] boost::asio::awaitable<std::size_t> remaining(
        AsyncConnection& conn, std::string identityId,
        std::chrono::milliseconds timeout);

private:
    Table m_table;
};
} // namespace openproof::storage::postgres::async_detail

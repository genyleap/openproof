#pragma once
#include "async_connection.hpp"
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace openproof::storage::postgres::async_detail {

// A tightly scoped, nonblocking SQL adapter for single-use identity proofs.
// Only fixed identifiers may be selected; no caller-supplied SQL table names.
// The temporary variant is for disposable per-connection PostgreSQL tests.
class AsyncAuthenticationTransactionSql final {
public:
    enum class Table { Production, TemporaryTest };
    explicit AsyncAuthenticationTransactionSql(Table table = Table::Production)
        : m_table(table) {}

    struct Record final {
        std::string id;
        std::string provider;
        unsigned int interaction{};
        std::string nonceDigestHex;
        std::string bindingDigestHex;
        std::string correlationId;
        unsigned int state{};
        std::int64_t createdMs{};
        std::int64_t expiresMs{};
        std::map<std::string, std::string, std::less<>> metadata;
    };

    // One exclusive libpq connection spans BEGIN, insertion, metadata and
    // COMMIT. A failure leaves the connection in a non-reusable transaction
    // state; the pool must discard it instead of leaking partial records.
    [[nodiscard]] boost::asio::awaitable<bool> begin(
        AsyncConnection& conn, Record row, std::chrono::milliseconds timeout);

    // An atomic UPDATE (WHERE state=0) burns incorrect and expired proofs.
    // The returned snapshot includes immutable metadata under one PG
    // transaction. Missing / replayed identifiers return nullopt.
    [[nodiscard]] boost::asio::awaitable<std::optional<Record>> consume(
        AsyncConnection& conn, std::string id,
        std::string nonceDigestHex, std::string bindingDigestHex,
        std::int64_t nowMs, std::chrono::milliseconds timeout);

private:
    Table m_table;
};

} // namespace openproof::storage::postgres::async_detail

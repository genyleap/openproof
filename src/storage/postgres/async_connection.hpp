#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Internal storage adapter, not a public OpenProof protocol or API.
// Its libpq session is single-owner and must be used from one Asio execution
// strand at a time. No operation is allowed to overlap another operation.
struct pg_conn;

namespace openproof::storage::postgres::async_detail {

struct QueryRows final {
    // SQL NULL is semantically distinct from an empty string.
    std::vector<std::vector<std::optional<std::string>>> rows;
};

class AsyncConnection final {
public:
    AsyncConnection(const AsyncConnection&) = delete;
    AsyncConnection& operator=(const AsyncConnection&) = delete;
    AsyncConnection(AsyncConnection&&) = delete;
    AsyncConnection& operator=(AsyncConnection&&) = delete;
    ~AsyncConnection();

    // PQconnectStart/PQconnectPoll use nonblocking socket polling. libpq's
    // hostname resolution may still be synchronous on some platforms; fully
    // async DNS must be verified separately before the release gate passes.
    // Connection string remains owned by the coroutine until it completes.
    static boost::asio::awaitable<std::unique_ptr<AsyncConnection>> connect(
        std::string connectionString, std::chrono::milliseconds timeout);

    // Implements the nonblocking libpq send/flush/consume/result protocol.
    // Throws sanitized errors; a timeout or cancellation invalidates the
    // connection rather than returning a PGconn with unknown transaction state.
    boost::asio::awaitable<QueryRows> query(
        std::string sql, std::vector<std::optional<std::string>> params,
        std::chrono::milliseconds timeout);

    [[nodiscard]] bool healthy() const noexcept;

    // Pool admission must require an idle transaction boundary, not merely
    // CONNECTION_OK. No caller may share the same lease concurrently.
    [[nodiscard]] bool reusable() const noexcept;

private:
    AsyncConnection(boost::asio::any_io_executor executor, pg_conn* handle);
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace openproof::storage::postgres::async_detail

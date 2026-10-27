#pragma once

#include "async_connection.hpp"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>

namespace openproof::storage::postgres::async_detail {

// Internal, bounded coroutine pool. A channel token represents exactly one
// exclusive connection slot, even when its physical PGconn must be replaced.
// No condition_variable or blocking pool wait is permitted on the reactor.
// Must outlive in-progress acquire() calls; leases can outlive the pool owner.
class AsyncConnectionPool final {
    struct State;
public:
    class Lease final {
    public:
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&&) noexcept = default;
        Lease& operator=(Lease&&) = delete;
        ~Lease() noexcept;

        [[nodiscard]] AsyncConnection& connection() const noexcept;
    private:
        friend class AsyncConnectionPool;
        Lease(std::shared_ptr<State> state, std::unique_ptr<AsyncConnection> conn);
        std::shared_ptr<State> m_state;
        std::unique_ptr<AsyncConnection> m_connection;
    };

    AsyncConnectionPool(boost::asio::any_io_executor executor,
                        std::string connectionString, std::size_t maximumConnections,
                        std::chrono::milliseconds acquireTimeout,
                        std::chrono::milliseconds connectTimeout);
    AsyncConnectionPool(const AsyncConnectionPool&) = delete;
    AsyncConnectionPool& operator=(const AsyncConnectionPool&) = delete;
    ~AsyncConnectionPool() = default;

    [[nodiscard]] boost::asio::awaitable<Lease> acquire();
    [[nodiscard]] std::size_t capacity() const noexcept;

private:
    std::shared_ptr<State> m_state;
};

} // namespace openproof::storage::postgres::async_detail

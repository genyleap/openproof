#pragma once

#include "async_connection.hpp"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <string>

namespace openproof::storage::postgres::async_detail {

// Unlike a raw function-pointer deleter, this POD is default-constructible.
// Asio's channel cancellation/close messages may need an empty permit token.
// A nonempty token must always carry an explicit recovery callback.
struct PoolPermitDeleter final {
    void (*recover)(void*) noexcept = nullptr;
    void operator()(void* raw) const noexcept
    {
        if (!raw) return;
        if (!recover) std::terminate();
        recover(raw);
    }
};

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
        // A received slot remains an RAII permit until its Lease returns it.
        // If a cancelled async channel receive drops the slot before a Lease
        // is constructed, the slot's deleter safely restores pool capacity.
        Lease(std::shared_ptr<State> state,
              std::unique_ptr<void, PoolPermitDeleter> permit,
              std::unique_ptr<AsyncConnection> conn);
        std::shared_ptr<State> m_state;
        std::unique_ptr<void, PoolPermitDeleter> m_permit;
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

    // Operation-wide monotonic deadline: cap queue admission, connection
    // establishment and session reset against the SAME caller budget.
    // Existing callers retain acquire() compatibility behavior.
    [[nodiscard]] boost::asio::awaitable<Lease> acquire(
        std::chrono::steady_clock::time_point deadline);

    // Fresh database round-trip: a recycled connection's verified reset
    // already proves server responsiveness. Newly opened connections run SELECT 1.
    [[nodiscard]] boost::asio::awaitable<bool> probeReadiness(
        std::chrono::steady_clock::time_point deadline);

    [[nodiscard]] std::size_t capacity() const noexcept;

private:
    [[nodiscard]] boost::asio::awaitable<Lease> acquireImpl(
        std::optional<std::chrono::steady_clock::time_point> deadline,
        bool* resetConfirmed = nullptr);
    std::shared_ptr<State> m_state;
};

} // namespace openproof::storage::postgres::async_detail

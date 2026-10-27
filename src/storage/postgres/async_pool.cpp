#include "async_pool.hpp"

#include <boost/asio/cancel_after.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <boost/system/error_code.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace openproof::storage::postgres::async_detail {
namespace asio = boost::asio;

struct AsyncConnectionPool::State final {
    using SlotChannel = asio::experimental::concurrent_channel<
        void(boost::system::error_code, std::unique_ptr<AsyncConnection>)>;

    State(asio::any_io_executor executor, std::string connectionStringValue,
          std::size_t capacity, std::chrono::milliseconds acquireTimeoutValue,
          std::chrono::milliseconds connectTimeoutValue)
        : slots(std::move(executor), capacity),
          connectionString(std::move(connectionStringValue)),
          maximumConnections(capacity),
          acquireTimeout(acquireTimeoutValue),
          connectTimeout(connectTimeoutValue)
    {
        // A null slot is an exclusive permit to create the physical connection.
        // Replacing a poisoned connection consumes the same permit.
        for (std::size_t index = 0U; index < capacity; ++index) {
            if (!slots.try_send(boost::system::error_code{},
                                std::unique_ptr<AsyncConnection>{})) {
                throw std::runtime_error{"Unable to initialize async PostgreSQL pool"};
            }
        }
    }

    ~State() noexcept
    {
        // Reconnect credentials are held for this pool's lifetime. Scrub
        // the owned buffer at disposal, without claiming to erase libpq or
        // allocator copies that may still exist elsewhere in the process.
        volatile char* bytes = connectionString.data();
        for (std::size_t i = 0U; i < connectionString.size(); ++i) {
            bytes[i] = '\0';
        }
    }

    SlotChannel slots;
    // Required for lazy reconnection; never expose, emit to logs or serialize.
    // Before public repository adoption, replace this string with the
    // foundation's secret-storage abstraction and avoid excess copies.
    std::string connectionString;
    std::size_t maximumConnections;
    std::chrono::milliseconds acquireTimeout;
    std::chrono::milliseconds connectTimeout;
};

AsyncConnectionPool::Lease::Lease(
    std::shared_ptr<State> state, std::unique_ptr<AsyncConnection> conn)
    : m_state(std::move(state)), m_connection(std::move(conn)) {}

AsyncConnectionPool::Lease::~Lease() noexcept
{
    if (!m_state) return;
    // Every acquired permit must return even if connect/query throws. Poisoned
    // or aborted transactions become null slots, never an inherited PGconn.
    if (m_connection && !m_connection->reusable()) m_connection.reset();
    const bool returned = m_state->slots.try_send(
        boost::system::error_code{}, std::move(m_connection));
    // If channel lifetime/slot accounting breaks, fail closed rather than
    // accidentally sharing the same physical connection with another lease.
    if (!returned) std::terminate();
}

AsyncConnection& AsyncConnectionPool::Lease::connection() const noexcept
{
    return *m_connection;
}

AsyncConnectionPool::AsyncConnectionPool(
    asio::any_io_executor executor, std::string connectionString,
    std::size_t maximumConnections, std::chrono::milliseconds acquireTimeout,
    std::chrono::milliseconds connectTimeout)
{
    if (connectionString.empty() || connectionString.contains('\0')
        || maximumConnections == 0U || maximumConnections > 64U
        || acquireTimeout <= std::chrono::milliseconds::zero()
        || connectTimeout <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument{"Invalid async PostgreSQL pool configuration"};
    }
    m_state = std::make_shared<State>(
        std::move(executor), std::move(connectionString), maximumConnections,
        acquireTimeout, connectTimeout);
}

asio::awaitable<AsyncConnectionPool::Lease> AsyncConnectionPool::acquire()
{
    auto state = m_state;
    boost::system::error_code error;
    std::unique_ptr<AsyncConnection> connection = co_await state->slots.async_receive(
        asio::cancel_after(state->acquireTimeout,
            asio::redirect_error(asio::use_awaitable, error)));
    if (error) {
        throw std::runtime_error{"Async PostgreSQL pool acquisition timed out or cancelled"};
    }

    Lease lease{state, std::move(connection)};
    if (!lease.m_connection) {
        // A failed or cancelled connection attempt is also slot-safe:
        // the local lease reissues a null permit from its noexcept destructor.
        lease.m_connection = co_await AsyncConnection::connect(
            state->connectionString, state->connectTimeout);
    }
    co_return std::move(lease);
}

std::size_t AsyncConnectionPool::capacity() const noexcept
{
    return m_state->maximumConnections;
}

} // namespace openproof::storage::postgres::async_detail

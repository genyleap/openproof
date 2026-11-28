#include "async_pool.hpp"

#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/cancellation_state.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <boost/system/error_code.hpp>

#include <algorithm>
#include <chrono>
#include <optional>
#include <cstddef>
#include <memory>
#include <list>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

namespace openproof::storage::postgres::async_detail {
namespace asio = boost::asio;

struct AsyncConnectionPool::State final : std::enable_shared_from_this<State> {
    // The connection travels inside an exclusive slot, rather than being the
    // channel payload itself. A cancellation which drops a delivered payload
    // before co_await resumes must NOT permanently consume pool capacity.
    struct Slot final {
        std::weak_ptr<State> owner;
        std::unique_ptr<AsyncConnection> connection;
    };
    using SlotToken = std::unique_ptr<void, PoolPermitDeleter>;
    using SlotChannel = asio::experimental::concurrent_channel<
        void(boost::system::error_code, SlotToken)>;

    // This deleter is also installed on a slot while it is in the channel.
    // Normal channel destruction occurs after the last State strong reference
    // is gone, so weak_ptr::lock fails and frees the slot. If a cancelled
    // receiver discards an already delivered token, it is put back once.
    static void recoverSlot(void* raw) noexcept
    {
        if (!raw) return;
        auto* slot = static_cast<Slot*>(raw);
        auto state = slot->owner.lock();
        if (!state) {
            delete slot;
            return;
        }
        SlotToken recovered{raw, PoolPermitDeleter{&State::recoverSlot}};
        if (!state->slots.try_send(boost::system::error_code{},
                                    std::move(recovered))) {
            // A full channel here violates exclusive slot accounting.
            // Do not recurse through this token's recovery deleter.
            delete static_cast<Slot*>(recovered.release());
            std::terminate();
        }
        state->notifyWaiter();
    }

    // A dirty connection and its permit travel together until reset succeeds.
    // Member destruction closes a dirty PGconn before recovering its permit,
    // even when co_spawn fails or executor shutdown destroys a queued frame.
    struct SanitizingSlot final {
        std::shared_ptr<State> state;
        SlotToken permit;
        std::unique_ptr<AsyncConnection> connection;
    };

    static asio::awaitable<void> sanitize(SanitizingSlot pending)
    {
        try {
            const auto reset = co_await pending.connection->query(
                "DISCARD ALL", {}, pending.state->connectTimeout);
            if (reset.commandTag == "DISCARD ALL" && reset.rows.empty()
                && pending.connection->reusable()) {
                auto* slot = static_cast<Slot*>(pending.permit.get());
                slot->connection = std::move(pending.connection);
            }
        } catch (...) {
            // Reset failure or cancellation is never a reusable session.
        }
        pending.connection.reset();
        // Publish only a proven clean connection or an empty reconnect slot.
        // Keep State alive through permit recovery and waiter notification.
        pending.permit.reset();
    }

    // The wait queue carries notifications only, never exclusive permits.
    // Each timer is accessed on its own serialized executor. A release
    // selects one waiter; cancellation hands an unused notification onward.
    struct Waiter final {
        explicit Waiter(asio::any_io_executor executorValue)
            : executor(std::move(executorValue)), timer(executor) {}
        const asio::any_io_executor executor;
        asio::steady_timer timer;
        bool notified = false; // accessed only on the timer's strand
    };

    void notifyWaiter() noexcept
    {
        std::shared_ptr<Waiter> selected;
        {
            std::lock_guard guard{waitersMutex};
            if (waiters.empty()) return;
            selected = std::move(waiters.front());
            waiters.pop_front();
        }
        // Posting, not dispatching, also protects registration followed by
        // the second try_receive and async_wait initiation from lost wakeups.
        // Read immutable executor metadata, not the concurrently used timer.
        auto executor = selected->executor;
        asio::post(executor, [selected = std::move(selected)] {
            selected->notified = true;
            selected->timer.cancel();
        });
    }

    struct Registration final {
        State& state;
        std::shared_ptr<Waiter> waiter;

        Registration(State& owner, std::shared_ptr<Waiter> value)
            : state(owner), waiter(std::move(value))
        {
            std::lock_guard guard{state.waitersMutex};
            state.waiters.push_back(waiter);
        }
        ~Registration() noexcept
        {
            bool selected = false;
            {
                std::lock_guard guard{state.waitersMutex};
                const auto it = std::find(state.waiters.begin(), state.waiters.end(), waiter);
                selected = it == state.waiters.end();
                if (!selected) state.waiters.erase(it);
            }
            // Pass a still-available permit onward, including when this
            // waiter consumed a different permit just before selection.
            // Never circulate wakeups while the channel is exhausted.
            if (selected && state.slots.ready()) state.notifyWaiter();
        }
        Registration(const Registration&) = delete;
        Registration& operator=(const Registration&) = delete;
    };

    SlotToken tryTake()
    {
        SlotToken permit;
        boost::system::error_code channelError;
        const bool received = slots.try_receive(
            [&](boost::system::error_code error, SlotToken value) {
                channelError = error;
                permit = std::move(value);
            });
        if (received && (channelError || !permit))
            throw std::runtime_error{"Async PostgreSQL pool returned an invalid permit"};
        return permit;
    }

    static asio::awaitable<SlotToken> waitForPermit(
        std::shared_ptr<State> state, std::chrono::steady_clock::time_point deadline)
    {
        auto executor = co_await asio::this_coro::executor;
        for (;;) {
            if (std::chrono::steady_clock::now() >= deadline)
                throw std::runtime_error{"Async PostgreSQL pool acquisition timed out"};
            auto waiter = std::make_shared<Waiter>(executor);
            waiter->timer.expires_at(deadline);
            Registration registration{*state, waiter};
            // Register BEFORE checking availability a second time. A return
            // before registration is observed here; a later return posts a
            // wakeup on this same strand, after async_wait is initiated.
            auto permit = state->tryTake();
            if (permit) {
                if (std::chrono::steady_clock::now() >= deadline)
                    throw std::runtime_error{"Async PostgreSQL pool acquisition timed out"};
                co_return std::move(permit);
            }
            boost::system::error_code error;
            co_await waiter->timer.async_wait(
                asio::redirect_error(asio::use_awaitable, error));
            if (!error || std::chrono::steady_clock::now() >= deadline)
                throw std::runtime_error{"Async PostgreSQL pool acquisition timed out"};
            const auto cancellation = co_await asio::this_coro::cancellation_state;
            if (error != asio::error::operation_aborted || !waiter->notified
                || cancellation.cancelled() != asio::cancellation_type::none)
                throw std::runtime_error{"Async PostgreSQL pool acquisition cancelled"};
            // The notification does not own a permit. Try the channel
            // before deregistration; the guard forwards spare capacity.
            permit = state->tryTake();
            if (permit) {
                if (std::chrono::steady_clock::now() >= deadline)
                    throw std::runtime_error{"Async PostgreSQL pool acquisition timed out"};
                co_return std::move(permit);
            }
        }
    }

    State(asio::any_io_executor executor, std::string connectionStringValue,
          std::size_t capacity, std::chrono::milliseconds acquireTimeoutValue,
          std::chrono::milliseconds connectTimeoutValue)
        : slots(std::move(executor), capacity),
          connectionString(std::move(connectionStringValue)),
          maximumConnections(capacity),
          acquireTimeout(acquireTimeoutValue),
          connectTimeout(connectTimeoutValue) {}

    void initialize()
    {
        // A null physical connection is an exclusive permit for a lazy
        // nonblocking connect. initialize() runs only after shared ownership
        // exists, allowing every slot to carry a recovery-safe weak owner.
        for (std::size_t index = 0U; index < maximumConnections; ++index) {
            SlotToken slot{static_cast<void*>(new Slot{weak_from_this(), {}}),
                           PoolPermitDeleter{&State::recoverSlot}};
            if (!slots.try_send(boost::system::error_code{}, std::move(slot))) {
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
    std::mutex waitersMutex;
    std::list<std::shared_ptr<Waiter>> waiters;
    // Required for lazy reconnection; never expose, emit to logs or serialize.
    // Before public repository adoption, replace this string with the
    // foundation's secret-storage abstraction and avoid excess copies.
    std::string connectionString;
    std::size_t maximumConnections;
    std::chrono::milliseconds acquireTimeout;
    std::chrono::milliseconds connectTimeout;
};

AsyncConnectionPool::Lease::Lease(
    std::shared_ptr<State> state, State::SlotToken permit,
    std::unique_ptr<AsyncConnection> conn)
    : m_state(std::move(state)), m_permit(std::move(permit)),
      m_connection(std::move(conn)) {}

AsyncConnectionPool::Lease::~Lease() noexcept
{
    if (!m_state) return;
    // A reusable PGconn is still dirty: transaction-idle is not evidence
    // of tenant isolation. Never publish it until the async reset finishes.
    if (!m_connection || !m_connection->reusable()) {
        m_connection.reset();
        m_permit.reset();
        return;
    }
    State::SanitizingSlot pending{m_state, std::move(m_permit),
        std::move(m_connection)};
    try {
        // One bounded operation per exclusive slot, not an unbounded queue.
        // Use the pool's executor rather than the completed request's strand.
        auto executor = asio::make_strand(m_state->slots.get_executor());
        asio::co_spawn(executor, State::sanitize(std::move(pending)), asio::detached);
    } catch (...) {
        // The RAII pending slot drops the dirty connection before recovering
        // capacity if scheduling fails. No exception leaves the destructor.
    }
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
    m_state->initialize();
}

asio::awaitable<AsyncConnectionPool::Lease> AsyncConnectionPool::acquire()
{
    // Forward the lazy awaitable directly: no additional coroutine frame,
    // suspension or cancellation boundary for an otherwise empty wrapper.
    return acquireImpl(std::nullopt);
}

asio::awaitable<AsyncConnectionPool::Lease> AsyncConnectionPool::acquire(
    std::chrono::steady_clock::time_point deadline)
{
    return acquireImpl(deadline);
}

asio::awaitable<AsyncConnectionPool::Lease> AsyncConnectionPool::acquireImpl(
    std::optional<std::chrono::steady_clock::time_point> deadline)
{
    auto state = m_state;
    // A caller-level deadline must never be restarted between different
    // stages of acquiring a reusable connection. Reject an expired deadline
    // before touching the channel or initiating any network operation.
    const auto bounded = [deadline](std::chrono::milliseconds configured) {
        if (!deadline) return configured;
        const auto now = std::chrono::steady_clock::now();
        if (now >= *deadline) {
            throw std::runtime_error{"Async PostgreSQL operation deadline expired"};
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(*deadline - now);
        // Millisecond-based libpq connection APIs cannot enforce a smaller
        // positive remainder. Fail closed instead of extending an absolute
        // deadline by rounding a sub-millisecond budget up to 1 ms.
        if (remaining <= std::chrono::milliseconds::zero()) {
            throw std::runtime_error{"Async PostgreSQL operation deadline expired"};
        }
        return std::min(configured, remaining);
    };

    const auto admissionTimeout = bounded(state->acquireTimeout);
    const auto startedAt = std::chrono::steady_clock::now();
    const auto availableClockRange =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::time_point::max() - startedAt);
    const auto admissionDeadline = admissionTimeout >= availableClockRange
        ? std::chrono::steady_clock::time_point::max()
        : startedAt + admissionTimeout;

    // Preserve the cancellation-safe synchronous channel handoff. Only
    // contended acquisitions register a separate notification timer. The
    // fast path allocates no waiter, strand or periodic polling timer.
    if (std::chrono::steady_clock::now() >= admissionDeadline)
        throw std::runtime_error{"Async PostgreSQL pool acquisition timed out"};
    auto permit = state->tryTake();
    if (!permit) {
        auto executor = co_await asio::this_coro::executor;
        permit = co_await asio::co_spawn(asio::make_strand(executor),
            State::waitForPermit(state, admissionDeadline), asio::use_awaitable);
    }
    if (!permit || std::chrono::steady_clock::now() >= admissionDeadline)
        throw std::runtime_error{"Async PostgreSQL pool acquisition timed out"};
    auto* slot = static_cast<State::Slot*>(permit.get());
    auto connection = std::move(slot->connection);
    Lease lease{state, std::move(permit), std::move(connection)};
    if (!lease.m_connection) {
        // A failed or cancelled connection attempt is also slot-safe:
        // the local lease reissues a null permit from its noexcept destructor.
        lease.m_connection = co_await AsyncConnection::connect(
            state->connectionString, bounded(state->connectTimeout));
    }
    // Recycled slots contain only a completed reset, never an in-flight
    // sanitizer. A dirty slot cannot be received until its permit returns.
    // Avoid handing a connection to the caller after its total budget has
    // expired. The lease destructor returns the permit (or drops a poisoned
    // PGconn), so a timeout cannot leak pool capacity.
    static_cast<void>(bounded(state->connectTimeout));
    co_return std::move(lease);
}

std::size_t AsyncConnectionPool::capacity() const noexcept
{
    return m_state->maximumConnections;
}

} // namespace openproof::storage::postgres::async_detail

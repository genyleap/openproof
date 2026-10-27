#include "async_connection.hpp"

#include <boost/asio.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>

#include <libpq-fe.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

namespace openproof::storage::postgres::async_detail {
namespace {
namespace asio = boost::asio;
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;
// Bound the application-owned copy of a SQL result. The underlying libpq
// PGresult is still buffered; streaming large responses is a separate gate.
constexpr std::size_t kMaximumCopiedResultBytes = 8U * 1024U * 1024U;
constexpr std::size_t kMaximumResultCells = 250'000U;

struct PgDeleter final {
    void operator()(PGconn* connection) const noexcept
    {
        if (connection != nullptr) PQfinish(connection);
    }
};
using PgPointer = std::unique_ptr<PGconn, PgDeleter>;

struct ResultDeleter final {
    void operator()(PGresult* result) const noexcept
    {
        if (result != nullptr) PQclear(result);
    }
};
using ResultPointer = std::unique_ptr<PGresult, ResultDeleter>;

[[nodiscard]] Deadline makeDeadline(std::chrono::milliseconds timeout)
{
    if (timeout <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument{"PostgreSQL deadline must be positive"};
    }
    return Clock::now() + timeout;
}

asio::awaitable<void> waitForSocket(
    asio::any_io_executor executor, PGconn* connection,
    asio::posix::stream_descriptor::wait_type direction, Deadline deadline)
{
    // PQsocket belongs to libpq; register a *duplicate* with Asio so the
    // descriptor destructor cannot accidentally close libpq's original FD.
    if (Clock::now() >= deadline) {
        throw std::runtime_error{"PostgreSQL operation timed out"};
    }
    const int originalFd = PQsocket(connection);
    if (originalFd < 0) {
        throw std::runtime_error{"PostgreSQL socket is unavailable"};
    }
    const int fd = ::dup(originalFd);
    if (fd < 0) {
        throw std::runtime_error{"Unable to duplicate PostgreSQL socket"};
    }
    asio::posix::stream_descriptor descriptor{executor, fd};
    boost::system::error_code error;
    // Cancellation and timeout are scoped to this one readiness wait.
    // A single absolute deadline is shared across all flush/read cycles.
    const auto remaining = deadline - Clock::now();
    co_await descriptor.async_wait(direction,
        asio::cancel_after(remaining,
            asio::redirect_error(asio::use_awaitable, error)));
    if (Clock::now() >= deadline) {
        throw std::runtime_error{"PostgreSQL operation timed out"};
    }
    if (error) {
        throw std::runtime_error{"PostgreSQL readiness wait failed or was cancelled"};
    }
}
} // namespace

struct AsyncConnection::Impl final {
    asio::any_io_executor executor;
    PgPointer connection;
    std::atomic<bool> busy{false};

    Impl(asio::any_io_executor executorValue, PGconn* handle)
        : executor(std::move(executorValue)), connection(handle) {}
};

AsyncConnection::AsyncConnection(asio::any_io_executor executor, pg_conn* handle)
    : m_impl(std::make_unique<Impl>(std::move(executor), handle)) {}

AsyncConnection::~AsyncConnection() = default;

bool AsyncConnection::healthy() const noexcept
{
    return m_impl->connection != nullptr
        && PQstatus(m_impl->connection.get()) == CONNECTION_OK;
}

bool AsyncConnection::reusable() const noexcept
{
    return !m_impl->busy.load(std::memory_order_acquire)
        && healthy()
        && PQtransactionStatus(m_impl->connection.get()) == PQTRANS_IDLE;
}

asio::awaitable<std::unique_ptr<AsyncConnection>> AsyncConnection::connect(
    std::string connectionString, std::chrono::milliseconds timeout)
{
    const Deadline deadline = makeDeadline(timeout);
    auto executor = co_await asio::this_coro::executor;
    PGconn* rawConnection = PQconnectStart(connectionString.c_str());
    // Libpq retains its own configuration; erase the caller-owned credential
    // buffer before the first suspension point. This does not erase copies
    // held by libc, libpq or the allocator.
    volatile char* secret = connectionString.data();
    for (std::size_t index = 0; index < connectionString.size(); ++index) {
        secret[index] = '\0';
    }
    connectionString.clear();
    PgPointer connection{rawConnection};
    if (!connection) {
        throw std::runtime_error{"Unable to create PostgreSQL connection"};
    }

    try {
        for (;;) {
            // One absolute deadline includes all polling, including ACTIVE.
            // Without this check an unexpected libpq ACTIVE loop spins forever.
            if (Clock::now() >= deadline) {
                throw std::runtime_error{"PostgreSQL connection timed out"};
            }
            // libpq owns and may replace its socket during connect polling.
            const PostgresPollingStatusType step = PQconnectPoll(connection.get());
            if (step == PGRES_POLLING_OK) break;
            if (step == PGRES_POLLING_FAILED) {
                throw std::runtime_error{"PostgreSQL connection failed"};
            }
            if (step == PGRES_POLLING_READING || step == PGRES_POLLING_WRITING) {
                co_await waitForSocket(
                    executor, connection.get(),
                    step == PGRES_POLLING_READING
                        ? asio::posix::stream_descriptor::wait_read
                        : asio::posix::stream_descriptor::wait_write,
                    deadline);
            }
            // ACTIVE can be repeated; yield to other ready operations
            // instead of monopolizing one CPU thread.
            if (step == PGRES_POLLING_ACTIVE) {
                co_await asio::post(executor, asio::use_awaitable);
            }
        }
        if (PQsetnonblocking(connection.get(), 1) != 0) {
            throw std::runtime_error{"Unable to enable nonblocking PostgreSQL"};
        }
    } catch (...) {
        // Never hand a partially connected PGconn to the repository pool.
        throw;
    }
    co_return std::unique_ptr<AsyncConnection>{
        new AsyncConnection{executor, connection.release()}};
}

asio::awaitable<QueryRows> AsyncConnection::query(
    std::string sql, std::vector<std::optional<std::string>> params,
    std::chrono::milliseconds timeout)
{
    const Deadline deadline = makeDeadline(timeout);
    if (m_impl->busy.exchange(true, std::memory_order_acq_rel)) {
        throw std::runtime_error{"PostgreSQL connection is already busy"};
    }
    struct BusyReset final {
        std::atomic<bool>& value;
        ~BusyReset() { value.store(false, std::memory_order_release); }
    } busyReset{m_impl->busy};
    if (!healthy()) {
        throw std::runtime_error{"PostgreSQL connection is unavailable"};
    }
    // libpq's text-parameter protocol uses NUL-terminated strings when
    // lengths are omitted. Refuse embedded NUL bytes rather than silently
    // submitting truncated identity, credential or tenant values.
    for (const auto& parameter : params) {
        if (parameter.has_value() && parameter->find('\0') != std::string::npos) {
            throw std::invalid_argument{"PostgreSQL text parameter contains NUL"};
        }
    }

    if (sql.find('\0') != std::string::npos) {
        throw std::invalid_argument{"PostgreSQL SQL text contains NUL"};
    }
    if (params.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::invalid_argument{"PostgreSQL parameter count exceeds libpq bounds"};
    }
    PGconn* connection = m_impl->connection.get();
    try {
        std::vector<const char*> values;
        values.reserve(params.size());
        for (const auto& parameter : params) {
            values.push_back(parameter.has_value() ? parameter->c_str() : nullptr);
        }
        if (PQsendQueryParams(connection, sql.c_str(),
                static_cast<int>(values.size()), nullptr,
                values.empty() ? nullptr : values.data(),
                nullptr, nullptr, 0) == 0) {
            throw std::runtime_error{"PostgreSQL query could not be submitted"};
        }
        // Enable libpq's row-at-a-time protocol immediately after send.
        // Without this, libpq buffers an entire PGresult before our own
        // result-copy limit can reject oversized queries.
        if (PQsetSingleRowMode(connection) != 1) {
            throw std::runtime_error{"PostgreSQL single-row mode unavailable"};
        }

        for (;;) {
            const int flushStatus = PQflush(connection);
            if (flushStatus == 0) break;
            if (flushStatus < 0) {
                throw std::runtime_error{"PostgreSQL query flush failed"};
            }
            co_await waitForSocket(m_impl->executor, connection,
                asio::posix::stream_descriptor::wait_write, deadline);
        }

        QueryRows output;
        std::size_t copiedBytes = 0U;
        std::size_t copiedCells = 0U;
        bool finished = false;
        for (;;) {
            if (Clock::now() >= deadline) {
                throw std::runtime_error{"PostgreSQL operation timed out"};
            }
            if (PQconsumeInput(connection) == 0) {
                throw std::runtime_error{"PostgreSQL query read failed"};
            }
            if (PQisBusy(connection) != 0) {
                co_await waitForSocket(m_impl->executor, connection,
                    asio::posix::stream_descriptor::wait_read, deadline);
                continue;
            }
            ResultPointer result{PQgetResult(connection)};
            if (!result) {
                if (!finished) {
                    throw std::runtime_error{"PostgreSQL returned no complete result"};
                }
                break;
            }
            const ExecStatusType status = PQresultStatus(result.get());
            if (status == PGRES_COMMAND_OK || status == PGRES_TUPLES_OK) {
                if (finished || PQntuples(result.get()) != 0) {
                    throw std::runtime_error{"Unexpected PostgreSQL result completion"};
                }
                finished = true;
                continue;
            }
            if (status != PGRES_SINGLE_TUPLE || finished) {
                // An error after partial rows discards both the rows and the
                // connection; nothing escapes before the terminal result.
                throw std::runtime_error{"PostgreSQL query returned an error"};
            }
            const int rowCount = PQntuples(result.get());
            const int fieldCount = PQnfields(result.get());
            if (rowCount < 0 || fieldCount < 0
                || static_cast<std::uint64_t>(rowCount)
                    * static_cast<std::uint64_t>(fieldCount)
                    > kMaximumResultCells - copiedCells) {
                throw std::runtime_error{"PostgreSQL result cell limit exceeded"};
            }
            for (int row = 0; row < rowCount; ++row) {
                if (Clock::now() >= deadline) {
                    throw std::runtime_error{"PostgreSQL operation timed out"};
                }
                std::vector<std::optional<std::string>> fields;
                fields.reserve(static_cast<std::size_t>(fieldCount));
                for (int column = 0; column < fieldCount; ++column) {
                    ++copiedCells;
                    if (PQgetisnull(result.get(), row, column)) {
                        fields.emplace_back(std::nullopt);
                    } else {
                        const int length = PQgetlength(result.get(), row, column);
                        if (length < 0
                            || static_cast<std::size_t>(length)
                                > kMaximumCopiedResultBytes - copiedBytes) {
                            throw std::runtime_error{"PostgreSQL result size limit exceeded"};
                        }
                        copiedBytes += static_cast<std::size_t>(length);
                        fields.emplace_back(std::string{
                            PQgetvalue(result.get(), row, column),
                            static_cast<std::size_t>(length)});
                    }
                }
                output.rows.push_back(std::move(fields));
            }
        }
        co_return output;
    } catch (...) {
        // A lost or cancelled query may still be executing on the server.
        // Discard the connection instead of risking transaction/session reuse.
        m_impl->connection.reset();
        throw;
    }
}

} // namespace openproof::storage::postgres::async_detail

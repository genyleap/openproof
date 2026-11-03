#include "async_connection.hpp"

#include <boost/asio.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>

#include <libpq-fe.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <string_view>
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

// libpq's parsed options may contain the complete database password.
// Erase every owned copy before PQconninfoFree; malloc/libpq/OpenSSL
// internal buffers are not covered by this best-effort scrubbing.
struct ConnInfoDeleter final {
    void operator()(PQconninfoOption* options) const noexcept
    {
        if (!options) return;
        for (auto* option = options; option->keyword != nullptr; ++option) {
            if (option->val == nullptr) continue;
            volatile char* value = option->val;
            const auto size = std::strlen(option->val);
            for (std::size_t i = 0; i < size; ++i) value[i] = '\0';
        }
        PQconninfoFree(options);
    }
};
using ConnInfoPointer = std::unique_ptr<PQconninfoOption, ConnInfoDeleter>;

struct SecretBufferScrub final {
    std::string& value;
    ~SecretBufferScrub() noexcept
    {
        volatile char* bytes = value.data();
        for (std::size_t i = 0; i < value.size(); ++i) bytes[i] = '\0';
    }
};

struct SecretVectorScrub final {
    std::vector<std::string>& values;
    ~SecretVectorScrub() noexcept
    {
        for (auto& value : values) {
            volatile char* bytes = value.data();
            for (std::size_t i = 0; i < value.size(); ++i) bytes[i] = '\0';
        }
    }
};

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
    // The original conninfo may contain credentials. Preserve it across
    // asynchronous DNS resolution, then wipe on success, timeout or cancel.
    SecretBufferScrub scrubConnectionString{connectionString};
    auto executor = co_await asio::this_coro::executor;

    // PQconnectStart can resolve DNS synchronously before the PGconn exists.
    // Handle every hostname in keyword/URI multi-host connection lists on
    // Asio first, preserving per-host port and TLS hostname associations.
    // Numeric addresses, Unix sockets and explicitly pinned hostaddr lists
    // do not need a separate hostname resolver.
    char* parseError = nullptr;
    ConnInfoPointer options{PQconninfoParse(connectionString.c_str(), &parseError)};
    if (parseError) {
        volatile char* bytes = parseError;
        const auto length = std::strlen(parseError);
        for (std::size_t i = 0; i < length; ++i) bytes[i] = '\0';
        PQfreemem(parseError);
    }
    auto optionValue = [&](std::string_view key) -> std::string_view {
        if (!options) return {};
        for (const auto* option = options.get(); option->keyword; ++option) {
            if (key == option->keyword && option->val) return option->val;
        }
        return {};
    };
    // libpq can inherit connection location from PGHOST/PGHOSTADDR/PGPORT
    // when conninfo leaves these fields unspecified. Copy environment
    // values before suspension instead of holding process-env pointers.
    const auto effective = [&](std::string_view key, const char* envKey) {
        const std::string_view explicitValue = optionValue(key);
        if (!explicitValue.empty()) return std::string{explicitValue};
        const char* inherited = std::getenv(envKey);
        return inherited == nullptr ? std::string{} : std::string{inherited};
    };
    // PQconninfoParse does not expand host/port values from service files.
    // Letting PQconnectStart process a service implicitly could therefore
    // restart synchronous DNS on the coroutine reactor. Reject the service
    // indirection until the resolved host/port/TLS options can be obtained
    // without allowing libpq to connect or resolve names on this executor.
    const char* inheritedService = std::getenv("PGSERVICE");
    if (!optionValue("service").empty()
        || (inheritedService != nullptr && inheritedService[0] != '\0')) {
        throw std::runtime_error{
            "PostgreSQL service files are unsupported by the native connector"};
    }
    const std::string hostStorage = effective("host", "PGHOST");
    const std::string hostaddrStorage = effective("hostaddr", "PGHOSTADDR");
    const std::string portStorage = effective("port", "PGPORT");
    const std::string_view host{hostStorage};
    const std::string_view hostaddr{hostaddrStorage};
    const auto csv = [](std::string_view value) {
        std::vector<std::string_view> parts;
        do {
            const auto comma = value.find(',');
            parts.push_back(value.substr(0, comma));
            if (comma == std::string_view::npos) break;
            value.remove_prefix(comma + 1U);
        } while (true);
        return parts;
    };
    const auto hosts = csv(host);
    const auto ports = csv(portStorage);
    const auto pinnedAddresses = csv(hostaddr);
    const auto numeric = [](std::string_view value) {
        boost::system::error_code error;
        static_cast<void>(asio::ip::make_address(std::string{value}, error));
        return !error;
    };
    bool resolveWithAsio = false;
    for (std::size_t i = 0; i < hosts.size(); ++i) {
        const auto name = hosts[i];
        const auto address = hostaddr.empty() ? std::string_view{}
            : i < pinnedAddresses.size() ? pinnedAddresses[i] : std::string_view{};
        if (address.empty() && !name.empty() && !name.starts_with("/")
            && !numeric(name)) {
            resolveWithAsio = true;
            break;
        }
    }

    PGconn* rawConnection = nullptr;
    if (resolveWithAsio) {
        if ((ports.size() != 1U && ports.size() != hosts.size())
            || (!hostaddr.empty() && pinnedAddresses.size() != hosts.size())) {
            throw std::runtime_error{"Invalid PostgreSQL host/port configuration"};
        }
        asio::ip::tcp::resolver resolver{executor};
        std::string resolvedHosts;
        std::string resolvedAddresses;
        std::string resolvedPorts;
        std::size_t addressCount = 0U;
        const auto append = [&](std::string_view name, std::string_view address,
                                std::string_view port) {
            if (addressCount == 64U) {
                throw std::runtime_error{"PostgreSQL DNS address limit exceeded"};
            }
            if (addressCount++ > 0U) {
                resolvedHosts.push_back(',');
                resolvedAddresses.push_back(',');
                resolvedPorts.push_back(',');
            }
            resolvedHosts.append(name);
            resolvedAddresses.append(address);
            resolvedPorts.append(port);
        };
        for (std::size_t i = 0; i < hosts.size(); ++i) {
            const std::string_view name = hosts[i];
            const std::string_view port =
                ports.size() == 1U ? ports.front() : ports[i];
            const std::string_view pinned = hostaddr.empty()
                ? std::string_view{} : pinnedAddresses[i];
            if (!pinned.empty()) {
                append(name, pinned, port);
                continue;
            }
            if (name.empty() || name.starts_with("/")) {
                // An empty hostaddr element retains libpq's Unix socket
                // semantics for this slot in a mixed multi-host list.
                append(name, "", port);
                continue;
            }
            if (numeric(name)) {
                append(name, name, port);
                continue;
            }
            if (Clock::now() >= deadline) {
                throw std::runtime_error{"PostgreSQL DNS resolution timed out"};
            }
            boost::system::error_code error;
            const std::string service =
                port.empty() ? "5432" : std::string{port};
            auto endpoints = co_await resolver.async_resolve(
                std::string{name}, service,
                asio::cancel_after(deadline - Clock::now(),
                    asio::redirect_error(asio::use_awaitable, error)));
            if (Clock::now() >= deadline) {
                throw std::runtime_error{"PostgreSQL DNS resolution timed out"};
            }
            if (error == asio::error::operation_aborted
                || error == asio::error::timed_out) {
                // Cancellation is an operation-wide boundary. It must
                // never turn into another HA network attempt.
                throw std::runtime_error{"PostgreSQL DNS resolution cancelled"};
            }
            if (error || endpoints.empty()) {
                // A genuinely unresolvable HA hostname must not prevent
                // trying later hosts, but a cancelled operation must stop.
                // Never fall back to synchronous libpq DNS resolution.
                continue;
            }
            for (const auto& endpoint : endpoints) {
                append(name, endpoint.endpoint().address().to_string(), port);
            }
        }
        if (addressCount == 0U) {
            throw std::runtime_error{"PostgreSQL DNS resolved no usable hosts"};
        }
        // Passing parsed parameters instead of appending to a DSN supports
        // both keyword/value and postgres:// URI connection strings.
        std::vector<std::string> ownedKeys;
        std::vector<std::string> ownedValues;
        SecretVectorScrub scrubValues{ownedValues};
        for (const auto* option = options.get(); option->keyword; ++option) {
            if (option->val == nullptr || option->val[0] == '\0') continue;
            const std::string_view key{option->keyword};
            if (key == "host" || key == "hostaddr" || key == "port") continue;
            ownedKeys.emplace_back(option->keyword);
            ownedValues.emplace_back(option->val);
        }
        ownedKeys.emplace_back("host");
        ownedValues.emplace_back(std::move(resolvedHosts));
        if (!portStorage.empty()) {
            ownedKeys.emplace_back("port");
            ownedValues.emplace_back(ports.size() > 1U ? std::move(resolvedPorts)
                                                       : portStorage);
        }
        ownedKeys.emplace_back("hostaddr");
        ownedValues.emplace_back(std::move(resolvedAddresses));
        std::vector<const char*> keys;
        std::vector<const char*> values;
        for (std::size_t i = 0; i < ownedKeys.size(); ++i) {
            keys.push_back(ownedKeys[i].c_str());
            values.push_back(ownedValues[i].c_str());
        }
        keys.push_back(nullptr);
        values.push_back(nullptr);
        rawConnection = PQconnectStartParams(keys.data(), values.data(), 0);
        // scrubValues runs on both normal completion and exceptions.
    } else {
        rawConnection = PQconnectStart(connectionString.c_str());
    }
    PgPointer connection{rawConnection};
    // libpq has copied all necessary options. Drop and wipe the parsed
    // credential copies and caller-owned DSN *before* any socket polling.
    options.reset();
    {
        volatile char* bytes = connectionString.data();
        for (std::size_t i = 0; i < connectionString.size(); ++i) {
            bytes[i] = '\0';
        }
        connectionString.clear();
    }
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

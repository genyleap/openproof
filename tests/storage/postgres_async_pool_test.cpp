#include <gtest/gtest.h>

#include <boost/asio.hpp>

#include "async_pool.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <thread>
#include <vector>

namespace {
namespace asio = boost::asio;
namespace pg = openproof::storage::postgres::async_detail;
using namespace std::chrono_literals;

[[nodiscard]] const char* disposableDatabase()
{
    return std::getenv("OPENPROOF_TEST_POSTGRES");
}

void requireDisposableDatabase()
{
    if (std::getenv("GITHUB_ACTIONS")) {
        FAIL() << "CI requires OPENPROOF_TEST_POSTGRES for pool regressions";
    }
}

asio::awaitable<void> failedConnectRestoresPermit(bool& repeatedFailure)
{
    // An unknown libpq setting fails before touching any socket or database.
    pg::AsyncConnectionPool pool{co_await asio::this_coro::executor,
        "openproof_nonexistent_libpq_parameter=bad", 1U, 100ms, 100ms};
    unsigned int failures = 0U;
    for (unsigned int attempt = 0U; attempt < 2U; ++attempt) {
        try {
            auto lease = co_await pool.acquire();
            static_cast<void>(lease);
        } catch (const std::runtime_error&) {
            ++failures;
        }
    }
    repeatedFailure = failures == 2U;
}

asio::awaitable<void> boundedAcquireAndReuse(
    std::string connectionString, bool& timedOut, bool& reused)
{
    pg::AsyncConnectionPool pool{co_await asio::this_coro::executor,
        std::move(connectionString), 1U, 30ms, 2s};
    EXPECT_EQ(pool.capacity(), 1U);
    {
        auto first = co_await pool.acquire();
        EXPECT_TRUE(first.connection().reusable());
        try {
            // With its only lease held, a concurrent acquire must suspend
            // instead of blocking a reactor worker in condition_variable.
            auto second = co_await pool.acquire();
            static_cast<void>(second);
        } catch (const std::runtime_error&) {
            timedOut = true;
        }
        EXPECT_TRUE(first.connection().reusable());
    }
    auto next = co_await pool.acquire();
    auto rows = co_await next.connection().query("SELECT 7::text", {}, 2s);
    reused = next.connection().reusable()
        && rows.rows.size() == 1U && rows.rows[0].size() == 1U
        && rows.rows[0][0] == "7";
}

asio::awaitable<void> directAcquirePreservesLazyAdmissionAndDeadline(
    std::string connectionString)
{
    using Clock = std::chrono::steady_clock;
    pg::AsyncConnectionPool pool{co_await asio::this_coro::executor,
        std::move(connectionString), 1U, 100ms, 2s};
    {
        // Construct and discard an unstarted awaitable. It must not take
        // the only slot or initiate any connection establishment.
        auto abandoned = pool.acquire();
        EXPECT_TRUE(abandoned.valid());
        auto first = co_await pool.acquire(Clock::now() + 2s);
        EXPECT_TRUE(first.connection().reusable());
    }
    auto expired = pool.acquire(Clock::now() - 1ms);
    bool denied = false;
    try {
        auto lease = co_await std::move(expired);
        static_cast<void>(lease);
    } catch (const std::runtime_error&) {
        denied = true;
    }
    EXPECT_TRUE(denied);
    auto next = co_await pool.acquire(Clock::now() + 2s);
    const auto result = co_await next.connection().query("SELECT 31::text", {}, 2s);
    EXPECT_EQ(result.rows.size(), 1U);
    if (result.rows.size() == 1U && result.rows.front().size() == 1U) {
        EXPECT_EQ(result.rows.front().front(), "31");
    } else {
        ADD_FAILURE() << "Unexpected PostgreSQL result shape";
    }
    EXPECT_TRUE(next.connection().reusable());
}

asio::awaitable<void> recycledLeaseClearsSessionState(
    std::string connectionString, bool& cleared)
{
    pg::AsyncConnectionPool pool{co_await asio::this_coro::executor,
        std::move(connectionString), 1U, 1s, 2s};
    constexpr auto marker = "openproof_previous_tenant_marker";
    std::optional<std::string> backend;
    {
        auto first = co_await pool.acquire();
        static_cast<void>(co_await first.connection().query(
            "SET application_name = 'openproof_previous_tenant_marker'", {}, 2s));
        static_cast<void>(co_await first.connection().query(
            "CREATE TEMP TABLE openproof_previous_tenant_temp (value integer)", {}, 2s));
        static_cast<void>(co_await first.connection().query(
            "PREPARE openproof_previous_tenant_plan AS SELECT 1", {}, 2s));
        static_cast<void>(co_await first.connection().query(
            "SELECT pg_advisory_lock(1827364513)", {}, 2s));
        const auto before = co_await first.connection().query(
            "SELECT pg_backend_pid()::text,current_setting('application_name'),"
            "to_regclass('pg_temp.openproof_previous_tenant_temp') IS NOT NULL,"
            "EXISTS (SELECT 1 FROM pg_prepared_statements WHERE name='openproof_previous_tenant_plan'),"
            "EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid())", {}, 2s);
        if (before.rows.size()!=1U || before.rows[0].size()!=5U) {
            ADD_FAILURE() << "Unexpected session state probe shape";
            co_return;
        }
        backend=before.rows[0][0];
        EXPECT_TRUE(backend.has_value());
        EXPECT_EQ(before.rows[0][1],marker);
        EXPECT_EQ(before.rows[0][2],"t");
        EXPECT_EQ(before.rows[0][3],"t");
        EXPECT_EQ(before.rows[0][4],"t");
    }
    auto next = co_await pool.acquire();
    const auto after = co_await next.connection().query(
        "SELECT pg_backend_pid()::text,current_setting('application_name'),"
        "to_regclass('pg_temp.openproof_previous_tenant_temp') IS NULL,"
        "NOT EXISTS (SELECT 1 FROM pg_prepared_statements WHERE name='openproof_previous_tenant_plan'),"
        "NOT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid())", {}, 2s);
    cleared = after.rows.size() == 1U && after.rows[0].size() == 5U
        && backend.has_value() && after.rows[0][0] == backend
        && after.rows[0][1] != marker && after.rows[0][2] == "t"
        && after.rows[0][3] == "t" && after.rows[0][4] == "t"
        && next.connection().reusable();
    const auto reset=co_await next.connection().query("DISCARD ALL",{},2s);
    EXPECT_EQ(reset.commandTag,"DISCARD ALL");
    EXPECT_TRUE(reset.rows.empty());
    EXPECT_TRUE(next.connection().reusable());
    // Ordinary parameterless SQL must still use extended protocol, which
    // rejects multiple statements before executing any of them.
    bool rejected=false;
    try {
        static_cast<void>(co_await next.connection().query("SELECT 1; SELECT 2",{},2s));
    } catch (const std::runtime_error& error) {
        rejected=std::string{error.what()}=="PostgreSQL query returned an error";
    }
    EXPECT_TRUE(rejected);
    EXPECT_FALSE(next.connection().reusable());
}

asio::awaitable<void> uncommittedLeaseIsReplaced(
    std::string connectionString, bool& freshLease)
{
    pg::AsyncConnectionPool pool{co_await asio::this_coro::executor,
        std::move(connectionString), 1U, 1s, 2s};
    {
        auto lease = co_await pool.acquire();
        static_cast<void>(co_await lease.connection().query("BEGIN", {}, 2s));
        EXPECT_FALSE(lease.connection().reusable());
    }
    auto replacement = co_await pool.acquire();
    const auto result = co_await replacement.connection().query(
        "SELECT 23::text", {}, 2s);
    freshLease = replacement.connection().reusable()
        && result.rows.size() == 1U && result.rows[0].size() == 1U
        && result.rows[0][0] == "23";
}

asio::awaitable<void> poisonedLeaseIsReplaced(
    std::string connectionString, bool& deniedPoison, bool& freshLease)
{
    pg::AsyncConnectionPool pool{co_await asio::this_coro::executor,
        std::move(connectionString), 1U, 1s, 2s};
    {
        auto lease = co_await pool.acquire();
        static_cast<void>(co_await lease.connection().query("BEGIN", {}, 2s));
        try {
            static_cast<void>(co_await lease.connection().query(
                "SELECT 1 / 0", {}, 2s));
        } catch (const std::runtime_error&) {
            deniedPoison = !lease.connection().reusable();
        }
    }
    // The returned permit must not contain the aborted PGconn.
    auto replacement = co_await pool.acquire();
    const auto result = co_await replacement.connection().query(
        "SELECT 17::text", {}, 2s);
    freshLease = replacement.connection().reusable()
        && result.rows.size() == 1U && result.rows[0].size() == 1U
        && result.rows[0][0] == "17";
}
asio::awaitable<void> contendForExclusiveSlot(pg::AsyncConnectionPool& pool,
    std::atomic<unsigned int>& active, std::atomic<unsigned int>& completed)
{
    for (unsigned int iteration=0; iteration<5U; ++iteration) {
        auto lease = co_await pool.acquire();
        const auto previous = active.fetch_add(1U);
        EXPECT_EQ(previous, 0U);
        struct Exit final {
            std::atomic<unsigned int>& count;
            ~Exit() { count.fetch_sub(1U); }
        } exit{active};
        const auto rows = co_await lease.connection().query("SELECT 11::text", {}, 2s);
        EXPECT_EQ(rows.rows.size(), 1U);
        if (rows.rows.size()==1U && rows.rows.front().size()==1U) {
            EXPECT_EQ(rows.rows.front().front(), "11");
        }
        completed.fetch_add(1U);
    }
}

asio::awaitable<void> holdAndCancelWaiter(pg::AsyncConnectionPool& pool,
    asio::cancellation_signal& signal)
{
    auto lease = co_await pool.acquire();
    // Let both waiters attempt admission while this slot remains held.
    asio::steady_timer hold{co_await asio::this_coro::executor};
    hold.expires_after(20ms);
    co_await hold.async_wait(asio::use_awaitable);
    signal.emit(asio::cancellation_type::terminal);
    hold.expires_after(20ms);
    co_await hold.async_wait(asio::use_awaitable);
}

asio::awaitable<void> waitAfterHolderStarts(pg::AsyncConnectionPool& pool)
{
    asio::steady_timer delay{co_await asio::this_coro::executor};
    delay.expires_after(10ms);
    co_await delay.async_wait(asio::use_awaitable);
    auto lease=co_await pool.acquire();
    EXPECT_TRUE(lease.connection().reusable());
}
} // namespace

TEST(PostgresAsyncPoolTest, EventDrivenContentionPreservesExclusiveSlots)
{
    const char* connectionString=disposableDatabase();
    if (!connectionString || !*connectionString) {
        requireDisposableDatabase();
        GTEST_SKIP()<<"No disposable PostgreSQL integration database configured";
    }
    asio::io_context io;
    pg::AsyncConnectionPool pool{io.get_executor(),connectionString,1U,2s,2s};
    std::atomic<unsigned int> active{0U},completed{0U};
    std::vector<std::future<void>> futures;
    for (unsigned int i=0;i<8U;++i) {
        futures.emplace_back(asio::co_spawn(io,contendForExclusiveSlot(pool,active,completed),
            asio::use_future));
    }
    std::thread other([&io]{io.run();});
    io.run();
    other.join();
    for (auto& future : futures) {
        EXPECT_NO_THROW(future.get());
    }
    EXPECT_EQ(active.load(),0U);
    EXPECT_EQ(completed.load(),40U);
}

TEST(PostgresAsyncPoolTest, EventDrivenCancelledWaiterDoesNotStrandFollowingWaiter)
{
    const char* connectionString=disposableDatabase();
    if (!connectionString || !*connectionString) {
        requireDisposableDatabase();
        GTEST_SKIP()<<"No disposable PostgreSQL integration database configured";
    }
    asio::io_context io;
    pg::AsyncConnectionPool pool{io.get_executor(),connectionString,1U,1s,2s};
    asio::cancellation_signal signal;
    auto holder=asio::co_spawn(io,holdAndCancelWaiter(pool,signal),asio::use_future);
    auto cancelled=asio::co_spawn(io,waitAfterHolderStarts(pool),
        asio::bind_cancellation_slot(signal.slot(),asio::use_future));
    auto next=asio::co_spawn(io,waitAfterHolderStarts(pool),asio::use_future);
    io.run();
    EXPECT_NO_THROW(holder.get());
    EXPECT_ANY_THROW(cancelled.get());
    EXPECT_NO_THROW(next.get());
    io.restart();
    auto final=asio::co_spawn(io,waitAfterHolderStarts(pool),asio::use_future);
    io.run();
    EXPECT_NO_THROW(final.get());
}

TEST(PostgresAsyncPoolTest, InvalidCapacityAndDeadlinesFailClosed)
{
    asio::io_context io;
    EXPECT_THROW((pg::AsyncConnectionPool{io.get_executor(), "irrelevant",
        0U, 1s, 1s}), std::invalid_argument);
    EXPECT_THROW((pg::AsyncConnectionPool{io.get_executor(), "irrelevant",
        65U, 1s, 1s}), std::invalid_argument);
    EXPECT_THROW((pg::AsyncConnectionPool{io.get_executor(), "irrelevant",
        1U, 0ms, 1s}), std::invalid_argument);
    EXPECT_THROW((pg::AsyncConnectionPool{io.get_executor(), "irrelevant",
        1U, 1s, 0ms}), std::invalid_argument);
}

TEST(PostgresAsyncPoolTest, FailedConnectReturnsPermitWithoutBlocking)
{
    asio::io_context io;
    bool repeatedFailure = false;
    auto done = asio::co_spawn(io,
        failedConnectRestoresPermit(repeatedFailure), asio::use_future);
    io.run();
    ASSERT_NO_THROW(done.get());
    EXPECT_TRUE(repeatedFailure);
}

TEST(PostgresAsyncPoolTest, TimedAcquireReturnsPermitForSubsequentLease)
{
    const char* connectionString = disposableDatabase();
    if (!connectionString || !*connectionString) {
        requireDisposableDatabase();
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context io;
    bool timedOut = false;
    bool reused = false;
    auto done = asio::co_spawn(io, boundedAcquireAndReuse(
        connectionString, timedOut, reused), asio::use_future);
    io.run();
    ASSERT_NO_THROW(done.get());
    EXPECT_TRUE(timedOut);
    EXPECT_TRUE(reused);
}

TEST(PostgresAsyncPoolTest, DirectAcquirePreservesLazyAdmissionAndDeadline)
{
    const char* connectionString = disposableDatabase();
    if (!connectionString || !*connectionString) {
        requireDisposableDatabase();
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context io;
    auto done = asio::co_spawn(io,
        directAcquirePreservesLazyAdmissionAndDeadline(connectionString), asio::use_future);
    io.run();
    ASSERT_NO_THROW(done.get());
}

TEST(PostgresAsyncPoolTest, RecycledConnectionClearsPriorTenantSessionState)
{
    const char* connectionString = disposableDatabase();
    if (!connectionString || !*connectionString) {
        requireDisposableDatabase();
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context io;
    bool cleared = false;
    auto done = asio::co_spawn(io, recycledLeaseClearsSessionState(
        connectionString, cleared), asio::use_future);
    io.run();
    ASSERT_NO_THROW(done.get());
    EXPECT_TRUE(cleared);
}

TEST(PostgresAsyncPoolTest, OpenTransactionCannotLeakIntoNextLease)
{
    const char* connectionString = disposableDatabase();
    if (!connectionString || !*connectionString) {
        requireDisposableDatabase();
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context io;
    bool freshLease = false;
    auto done = asio::co_spawn(io, uncommittedLeaseIsReplaced(
        connectionString, freshLease), asio::use_future);
    io.run();
    ASSERT_NO_THROW(done.get());
    EXPECT_TRUE(freshLease);
}

TEST(PostgresAsyncPoolTest, AbortedTransactionReopensPhysicalConnection)
{
    const char* connectionString = disposableDatabase();
    if (!connectionString || !*connectionString) {
        requireDisposableDatabase();
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context io;
    bool deniedPoison = false;
    bool freshLease = false;
    auto done = asio::co_spawn(io, poisonedLeaseIsReplaced(
        connectionString, deniedPoison, freshLease), asio::use_future);
    io.run();
    ASSERT_NO_THROW(done.get());
    EXPECT_TRUE(deniedPoison);
    EXPECT_TRUE(freshLease);
}

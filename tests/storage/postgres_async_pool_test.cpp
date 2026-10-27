#include <gtest/gtest.h>

#include <boost/asio.hpp>

#include "async_pool.hpp"

#include <chrono>
#include <cstdlib>
#include <exception>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

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

asio::awaitable<void> recycledLeaseClearsSessionState(
    std::string connectionString, bool& cleared)
{
    pg::AsyncConnectionPool pool{co_await asio::this_coro::executor,
        std::move(connectionString), 1U, 1s, 2s};
    constexpr auto marker = "openproof_previous_tenant_marker";
    {
        auto first = co_await pool.acquire();
        static_cast<void>(co_await first.connection().query(
            "SET application_name = 'openproof_previous_tenant_marker'", {}, 2s));
        const auto before = co_await first.connection().query(
            "SELECT current_setting('application_name')", {}, 2s);
        EXPECT_EQ(before.rows[0][0], marker);
    }
    auto next = co_await pool.acquire();
    const auto after = co_await next.connection().query(
        "SELECT current_setting('application_name')", {}, 2s);
    cleared = after.rows.size() == 1U && after.rows[0].size() == 1U
        && after.rows[0][0] != marker && next.connection().reusable();
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
} // namespace

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

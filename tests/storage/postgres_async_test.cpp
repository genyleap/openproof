#include <gtest/gtest.h>

#include <boost/asio.hpp>

#include "async_connection.hpp"

#include <chrono>
#include <cstdlib>
#include <exception>
#include <future>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace {
namespace asio = boost::asio;
namespace pg = openproof::storage::postgres::async_detail;
using namespace std::chrono_literals;

asio::awaitable<void> queryWithParameter(
    std::string connectionString, std::optional<pg::QueryRows>& rows)
{
    auto connection = co_await pg::AsyncConnection::connect(
        std::move(connectionString), 2s);
    auto reply = co_await connection->query(
        "SELECT $1::text", {"native-async-pg"}, 2s);
    rows.emplace(std::move(reply));
}

asio::awaitable<void> queryWithNull(
    std::string connectionString, std::optional<pg::QueryRows>& rows)
{
    auto connection = co_await pg::AsyncConnection::connect(
        std::move(connectionString), 2s);
    auto response = co_await connection->query(
        "SELECT $1::text, $2::text", {std::nullopt, std::string{}}, 2s);
    rows.emplace(std::move(response));
}

asio::awaitable<void> queryWithDeadline(
    std::string connectionString, bool& failedAsExpected, bool& safelyDiscarded)
{
    auto connection = co_await pg::AsyncConnection::connect(
        std::move(connectionString), 2s);
    try {
        static_cast<void>(co_await connection->query(
            "SELECT pg_sleep(0.3)", {}, 15ms));
    } catch (const std::runtime_error&) {
        failedAsExpected = true;
    }
    safelyDiscarded = !connection->healthy();
}
asio::awaitable<void> slowQuery(
    std::string connectionString, bool& slowCompleted)
{
    auto connection = co_await pg::AsyncConnection::connect(
        std::move(connectionString), 2s);
    static_cast<void>(co_await connection->query(
        "SELECT pg_sleep(0.5)", {}, 2s));
    slowCompleted = true;
}

asio::awaitable<void> independentQuery(
    std::string connectionString, const bool& slowCompleted,
    bool& fastFinishedFirst)
{
    auto connection = co_await pg::AsyncConnection::connect(
        std::move(connectionString), 2s);
    const auto result = co_await connection->query(
        "SELECT 1", {}, 2s);
    fastFinishedFirst = !slowCompleted && result.rows.size() == 1U;
}

asio::awaitable<void> queryWithSqlError(
    std::string connectionString, bool& redacted, bool& discarded)
{
    auto connection = co_await pg::AsyncConnection::connect(
        std::move(connectionString), 2s);
    try {
        static_cast<void>(co_await connection->query(
            "SELECT FROM malformed_syntax", {}, 2s));
    } catch (const std::runtime_error& error) {
        // Neither statement content nor database server diagnostics should
        // appear in the exception observed by an application boundary.
        redacted = std::string{error.what()} ==
            "PostgreSQL query returned an error";
    }
    discarded = !connection->healthy();
}
} // namespace

TEST(PostgresNativeCoroutineTest, ParameterizedQueryHasRealAsyncLibpqTransport)
{
    const char* connectionString = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!connectionString || !*connectionString) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI requires OPENPROOF_TEST_POSTGRES for native libpq tests";
        }
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context context;
    std::optional<pg::QueryRows> rows;
    auto result = asio::co_spawn(context,
        queryWithParameter(connectionString, rows), asio::use_future);
    context.run();
    ASSERT_NO_THROW(result.get());
    ASSERT_TRUE(rows.has_value());
    ASSERT_EQ(rows->rows.size(), 1U);
    ASSERT_EQ(rows->rows.front().size(), 1U);
    EXPECT_EQ(rows->rows.front().front(), "native-async-pg");
}

TEST(PostgresNativeCoroutineTest, SqlNullIsDistinctFromEmptyText)
{
    const char* connectionString = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!connectionString || !*connectionString) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI requires OPENPROOF_TEST_POSTGRES for native libpq tests";
        }
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context context;
    std::optional<pg::QueryRows> rows;
    auto result = asio::co_spawn(context,
        queryWithNull(connectionString, rows), asio::use_future);
    context.run();
    ASSERT_NO_THROW(result.get());
    ASSERT_TRUE(rows.has_value());
    ASSERT_EQ(rows->rows.size(), 1U);
    ASSERT_EQ(rows->rows.front().size(), 2U);
    EXPECT_FALSE(rows->rows.front()[0].has_value());
    ASSERT_TRUE(rows->rows.front()[1].has_value());
    EXPECT_EQ(rows->rows.front()[1].value(), "");
}

TEST(PostgresNativeCoroutineTest, DeadlineInvalidatesBusyConnection)
{
    const char* connectionString = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!connectionString || !*connectionString) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI requires OPENPROOF_TEST_POSTGRES for native libpq tests";
        }
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context context;
    bool failedAsExpected = false;
    bool safelyDiscarded = false;
    auto result = asio::co_spawn(context,
        queryWithDeadline(connectionString, failedAsExpected, safelyDiscarded),
        asio::use_future);
    context.run();
    ASSERT_NO_THROW(result.get());
    EXPECT_TRUE(failedAsExpected);
    EXPECT_TRUE(safelyDiscarded);
}

TEST(PostgresNativeCoroutineTest, SlowQueryDoesNotBlockIndependentSocket)
{
    const char* connectionString = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!connectionString || !*connectionString) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI requires OPENPROOF_TEST_POSTGRES for native libpq tests";
        }
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context context;
    bool slowCompleted = false;
    bool fastFinishedFirst = false;
    auto slow = asio::co_spawn(context,
        slowQuery(connectionString, slowCompleted), asio::use_future);
    auto fast = asio::co_spawn(context,
        independentQuery(connectionString, slowCompleted, fastFinishedFirst),
        asio::use_future);
    context.run();
    ASSERT_NO_THROW(fast.get());
    ASSERT_NO_THROW(slow.get());
    EXPECT_TRUE(slowCompleted);
    EXPECT_TRUE(fastFinishedFirst)
        << "A waiting PostgreSQL operation starved unrelated Asio work";
}

TEST(PostgresNativeCoroutineTest, SqlErrorsAreRedactedAndConnectionDiscarded)
{
    const char* connectionString = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!connectionString || !*connectionString) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI requires OPENPROOF_TEST_POSTGRES for native libpq tests";
        }
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context context;
    bool redacted = false;
    bool discarded = false;
    auto result = asio::co_spawn(context,
        queryWithSqlError(connectionString, redacted, discarded),
        asio::use_future);
    context.run();
    ASSERT_NO_THROW(result.get());
    EXPECT_TRUE(redacted);
    EXPECT_TRUE(discarded);
}

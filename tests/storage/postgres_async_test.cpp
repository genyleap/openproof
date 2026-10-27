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
#include <string_view>
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
asio::awaitable<void> transactionBoundary(
    std::string connectionString, bool& initialIdle,
    bool& blockedDuringTransaction, bool& returnedIdle)
{
    auto connection = co_await pg::AsyncConnection::connect(
        std::move(connectionString), 2s);
    initialIdle = connection->reusable();
    static_cast<void>(co_await connection->query("BEGIN", {}, 2s));
    blockedDuringTransaction = !connection->reusable();
    static_cast<void>(co_await connection->query("ROLLBACK", {}, 2s));
    returnedIdle = connection->reusable();
}

asio::awaitable<void> transactionErrorInvalidatesConnection(
    std::string connectionString, bool& errorCaught, bool& rejectedLease)
{
    auto connection = co_await pg::AsyncConnection::connect(
        std::move(connectionString), 2s);
    static_cast<void>(co_await connection->query("BEGIN", {}, 2s));
    try {
        static_cast<void>(co_await connection->query(
            "SELECT 1 / 0", {}, 2s));
    } catch (const std::runtime_error&) {
        errorCaught = true;
    }
    // A failed SQL statement inside a transaction must NEVER leave an
    // aborted PGconn available to another session or tenant.
    rejectedLease = !connection->healthy() && !connection->reusable();
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

asio::awaitable<void> queryWithEmbeddedNul(
    std::string connectionString, bool& rejected, bool& remainsReusable)
{
    auto connection = co_await pg::AsyncConnection::connect(
        std::move(connectionString), 2s);
    try {
        static_cast<void>(co_await connection->query(
            "SELECT $1::text", {std::string{"abc\0def", 7}}, 2s));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    remainsReusable = connection->reusable();
}

asio::awaitable<void> queryWithSqlNul(
    std::string connectionString, bool& rejected, bool& remainsReusable)
{
    auto connection = co_await pg::AsyncConnection::connect(
        std::move(connectionString), 2s);
    std::string statement{"SELECT 1"};
    statement.push_back('\0');
    statement.append(" SELECT 2");
    try {
        static_cast<void>(co_await connection->query(
            std::move(statement), {}, 2s));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    remainsReusable = connection->reusable();
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
asio::awaitable<void> streamingRowsPreserveResult(
    std::string connectionString, std::optional<pg::QueryRows>& rows)
{
    auto connection = co_await pg::AsyncConnection::connect(
        std::move(connectionString), 3s);
    auto result = co_await connection->query(
        "SELECT n::text FROM generate_series(1, 4) AS n", {}, 3s);
    rows.emplace(std::move(result));
}

asio::awaitable<void> partialStreamingFailureIsDiscarded(
    std::string connectionString, bool& errorCaught, bool& invalidated)
{
    auto connection = co_await pg::AsyncConnection::connect(
        std::move(connectionString), 3s);
    try {
        static_cast<void>(co_await connection->query(
            "SELECT 10 / (4 - n) FROM generate_series(1, 4) AS n", {}, 3s));
    } catch (const std::runtime_error&) {
        errorCaught = true;
    }
    invalidated = !connection->healthy() && !connection->reusable();
}

asio::awaitable<void> oversizedResultIsRejected(
    std::string connectionString, bool& bounded, bool& invalidated)
{
    auto connection = co_await pg::AsyncConnection::connect(
        std::move(connectionString), 3s);
    try {
        static_cast<void>(co_await connection->query(
            "SELECT repeat('x', 8388609)", {}, 8s));
    } catch (const std::runtime_error& error) {
        bounded = std::string_view{error.what()} ==
            "PostgreSQL result size limit exceeded";
    }
    invalidated = !connection->healthy() && !connection->reusable();
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

TEST(PostgresNativeCoroutineTest, TransactionIsNotReusableUntilRollback)
{
    const char* connectionString = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!connectionString || !*connectionString) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI requires OPENPROOF_TEST_POSTGRES for native libpq tests";
        }
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context context;
    bool initialIdle = false;
    bool blockedDuringTransaction = false;
    bool returnedIdle = false;
    auto result = asio::co_spawn(context,
        transactionBoundary(connectionString, initialIdle,
            blockedDuringTransaction, returnedIdle), asio::use_future);
    context.run();
    ASSERT_NO_THROW(result.get());
    EXPECT_TRUE(initialIdle);
    EXPECT_TRUE(blockedDuringTransaction)
        << "A leased transaction must never be returned to another tenant";
    EXPECT_TRUE(returnedIdle);
}

TEST(PostgresNativeCoroutineTest, FailedStatementCannotReturnAbortedLease)
{
    const char* connectionString = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!connectionString || !*connectionString) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI requires OPENPROOF_TEST_POSTGRES for native libpq tests";
        }
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context context;
    bool errorCaught = false;
    bool rejectedLease = false;
    auto result = asio::co_spawn(context,
        transactionErrorInvalidatesConnection(
            connectionString, errorCaught, rejectedLease), asio::use_future);
    context.run();
    ASSERT_NO_THROW(result.get());
    EXPECT_TRUE(errorCaught);
    EXPECT_TRUE(rejectedLease)
        << "Aborted PostgreSQL transactions must never leak into another lease";
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

TEST(PostgresNativeCoroutineTest, EmbeddedNulTextParameterIsRejected)
{
    const char* connectionString = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!connectionString || !*connectionString) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI requires OPENPROOF_TEST_POSTGRES for native libpq tests";
        }
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context context;
    bool rejected = false;
    bool remainsReusable = false;
    auto result = asio::co_spawn(context,
        queryWithEmbeddedNul(connectionString, rejected, remainsReusable),
        asio::use_future);
    context.run();
    ASSERT_NO_THROW(result.get());
    EXPECT_TRUE(rejected);
    EXPECT_TRUE(remainsReusable);
}

TEST(PostgresNativeCoroutineTest, EmbeddedNulSqlIsRejectedWithoutPoisoningConnection)
{
    const char* connectionString = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!connectionString || !*connectionString) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI requires OPENPROOF_TEST_POSTGRES for native libpq tests";
        }
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context context;
    bool rejected = false;
    bool remainsReusable = false;
    auto result = asio::co_spawn(context,
        queryWithSqlNul(connectionString, rejected, remainsReusable),
        asio::use_future);
    context.run();
    ASSERT_NO_THROW(result.get());
    EXPECT_TRUE(rejected);
    EXPECT_TRUE(remainsReusable);
}

TEST(PostgresNativeCoroutineTest, SingleRowModeAccumulatesMultipleRows)
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
    auto future = asio::co_spawn(context,
        streamingRowsPreserveResult(connectionString, rows), asio::use_future);
    context.run();
    ASSERT_NO_THROW(future.get());
    ASSERT_TRUE(rows.has_value());
    ASSERT_EQ(rows->rows.size(), 4U);
    for (std::size_t i = 0; i < 4U; ++i) {
        ASSERT_EQ(rows->rows[i].size(), 1U);
        EXPECT_EQ(rows->rows[i][0], std::to_string(i + 1U));
    }
}

TEST(PostgresNativeCoroutineTest, LateStreamingErrorInvalidatesConnection)
{
    const char* connectionString = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!connectionString || !*connectionString) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI requires OPENPROOF_TEST_POSTGRES for native libpq tests";
        }
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context context;
    bool errorCaught = false;
    bool invalidated = false;
    auto future = asio::co_spawn(context,
        partialStreamingFailureIsDiscarded(connectionString, errorCaught, invalidated),
        asio::use_future);
    context.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(errorCaught);
    EXPECT_TRUE(invalidated);
}

TEST(PostgresNativeCoroutineTest, OversizedResultIsRejectedAndConnectionDiscarded)
{
    const char* connectionString = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!connectionString || !*connectionString) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI requires OPENPROOF_TEST_POSTGRES for native libpq tests";
        }
        GTEST_SKIP() << "No disposable PostgreSQL integration database configured";
    }
    asio::io_context context;
    bool bounded = false;
    bool invalidated = false;
    auto result = asio::co_spawn(context,
        oversizedResultIsRejected(connectionString, bounded, invalidated),
        asio::use_future);
    context.run();
    ASSERT_NO_THROW(result.get());
    EXPECT_TRUE(bounded);
    EXPECT_TRUE(invalidated) << "Oversized results must never enter a new lease";
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

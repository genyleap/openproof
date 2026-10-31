#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include "async_auth_transaction.hpp"
#include "async_connection.hpp"

#include <chrono>
#include <cstdlib>
#include <future>
#include <optional>
#include <string>
#include <utility>

namespace {
namespace asio = boost::asio;
namespace pg = openproof::storage::postgres::async_detail;
using namespace std::chrono_literals;

constexpr auto kNonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr auto kWrongNonce = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
constexpr auto kBinding = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
constexpr auto kWrongBinding = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

[[nodiscard]] pg::AsyncAuthenticationTransactionSql::Record record(
    std::string id, std::int64_t expires = 2000)
{
    return {std::move(id), "generic-provider", 1U, kNonce, kBinding,
            "correlation", 0U, 1000, expires,
            {{"challenge_id", "bound-proof"}, {"purpose", "login"}}};
}

asio::awaitable<void> setup(pg::AsyncConnection& conn)
{
    static_cast<void>(co_await conn.query(
        "CREATE TEMP TABLE auth_transactions ("
        "id text PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 200),"
        "provider text NOT NULL, interaction smallint NOT NULL,"
        "nonce_digest bytea NOT NULL CHECK(octet_length(nonce_digest)=32),"
        "binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),"
        "correlation_id text NOT NULL,state smallint NOT NULL,"
        "created_at_ms bigint NOT NULL,expires_at_ms bigint NOT NULL)",
        {}, 3s));
    static_cast<void>(co_await conn.query(
        "CREATE TEMP TABLE auth_transaction_metadata ("
        "transaction_id text NOT NULL REFERENCES auth_transactions(id),"
        "key text NOT NULL,value text NOT NULL,"
        "PRIMARY KEY(transaction_id,key))",
        {}, 3s));
}

asio::awaitable<void> verifySqlLifecycle(
    std::string dsn, bool& success, bool& burned, bool& expired,
    bool& rejectedDuplicate, bool& reusable)
{
    auto conn = co_await pg::AsyncConnection::connect(std::move(dsn), 3s);
    co_await setup(*conn);
    pg::AsyncAuthenticationTransactionSql sql{
        pg::AsyncAuthenticationTransactionSql::Table::TemporaryTest};

    auto accepted = co_await sql.begin(*conn, record("good"), 3s);
    auto duplicate = co_await sql.begin(*conn, record("good"), 3s);
    auto first = co_await sql.consume(*conn, "good", kNonce, kBinding, 1500, 3s);
    auto replay = co_await sql.consume(*conn, "good", kNonce, kBinding, 1501, 3s);
    success = accepted && first && first->state == 1U
        && first->metadata.at("challenge_id") == "bound-proof"
        && !replay;
    rejectedDuplicate = !duplicate;

    static_cast<void>(co_await sql.begin(*conn, record("invalid"), 3s));
    auto mismatch = co_await sql.consume(
        *conn, "invalid", kWrongNonce, kWrongBinding, 1500, 3s);
    auto correctAfterMismatch = co_await sql.consume(
        *conn, "invalid", kNonce, kBinding, 1600, 3s);
    burned = mismatch && mismatch->state == 2U
        && mismatch->metadata.empty() && !correctAfterMismatch;

    static_cast<void>(co_await sql.begin(*conn, record("deadline"), 3s));
    auto exactlyExpired = co_await sql.consume(
        *conn, "deadline", kNonce, kBinding, 2000, 3s);
    auto afterExpiry = co_await sql.consume(
        *conn, "deadline", kNonce, kBinding, 2001, 3s);
    expired = exactlyExpired && exactlyExpired->state == 3U
        && exactlyExpired->metadata.empty() && !afterExpiry;

    // All operations, including invalid burns, must end their SQL
    // transaction before this connection can be reused.
    reusable = conn->reusable();
}

TEST(AsyncAuthenticationTransactionSqlTest, AtomicRedemptionAndMetadataOnDisposablePgTables)
{
    const char* dsn = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (dsn == nullptr || *dsn == '\0')
        GTEST_SKIP() << "No disposable PostgreSQL URI configured";
    bool success = false, burned = false, expired = false;
    bool rejectedDuplicate = false, reusable = false;
    asio::io_context io;
    auto future = asio::co_spawn(
        io, verifySqlLifecycle(dsn, success, burned, expired,
                               rejectedDuplicate, reusable), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(success);
    EXPECT_TRUE(burned);
    EXPECT_TRUE(expired);
    EXPECT_TRUE(rejectedDuplicate);
    EXPECT_TRUE(reusable);
}

asio::awaitable<void> invalidMetadataNeverOpensTransaction(
    std::string dsn, bool& rejected, bool& reusable)
{
    auto conn = co_await pg::AsyncConnection::connect(std::move(dsn), 3s);
    co_await setup(*conn);
    pg::AsyncAuthenticationTransactionSql sql{
        pg::AsyncAuthenticationTransactionSql::Table::TemporaryTest};
    auto invalid = record("metadata");
    invalid.metadata.emplace(std::string(201, 'k'), "not allowed");
    try {
        static_cast<void>(co_await sql.begin(*conn, std::move(invalid), 3s));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    reusable = conn->reusable();
}

TEST(AsyncAuthenticationTransactionSqlTest, InvalidMetadataIsRejectedBeforePgBegin)
{
    const char* dsn = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (dsn == nullptr || *dsn == '\0')
        GTEST_SKIP() << "No disposable PostgreSQL URI configured";
    bool rejected = false, reusable = false;
    asio::io_context io;
    auto future = asio::co_spawn(
        io, invalidMetadataNeverOpensTransaction(dsn, rejected, reusable),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(rejected);
    EXPECT_TRUE(reusable);
}
} // namespace

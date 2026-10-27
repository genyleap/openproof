#include <gtest/gtest.h>

#include <boost/asio.hpp>

#include "async_connection.hpp"
#include "async_session.hpp"

#include <chrono>
#include <cstdlib>
#include <future>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace {
namespace asio = boost::asio;
namespace pg = openproof::storage::postgres::async_detail;
using namespace std::chrono_literals;
constexpr auto kDigestA =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr auto kDigestB =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

asio::awaitable<void> createDisposableSessionTable(pg::AsyncConnection& conn)
{
    // A session-local PG temp table reproduces the production session column
    // contract, without creating or dropping ANY production schema objects.
    static_cast<void>(co_await conn.query(
        "CREATE TEMP TABLE sessions ("
        "id text PRIMARY KEY, identity_id text NOT NULL, provider text NOT NULL, "
        "assurance smallint NOT NULL, factors smallint NOT NULL, "
        "phishing_resistant boolean NOT NULL, state smallint NOT NULL, "
        "token_digest bytea NOT NULL UNIQUE, authenticated_at_ms bigint NOT NULL, "
        "issued_at_ms bigint NOT NULL, last_seen_at_ms bigint NOT NULL, "
        "absolute_expires_at_ms bigint NOT NULL, idle_timeout_ms bigint NOT NULL, "
        "revoked_at_ms bigint NULL, user_agent text NULL, remote_address text NULL)",
        {}, 3s));
    static_cast<void>(co_await conn.query(
        "INSERT INTO pg_temp.sessions VALUES "
        "('test-session-1','test-identity','test-provider',1,3,true,0,"
        "decode($1,'hex'),1000,1000,1000,10000,1000,NULL,NULL,NULL)",
        {kDigestA}, 3s));
}

asio::awaitable<void> atomicSessionLifecycle(
    std::string connectionString, bool& lookup, bool& rotated,
    bool& replayDenied, bool& expired, bool& unchanged)
{
    auto conn = co_await pg::AsyncConnection::connect(std::move(connectionString), 3s);
    co_await createDisposableSessionTable(*conn);
    pg::AsyncSessionSql sql{pg::AsyncSessionSql::Table::TemporaryTest};
    auto first = co_await sql.useToken(*conn, kDigestA, 1500, 3s);
    lookup = first.has_value() && first->size() == 16U
        && (*first)[0] == "test-session-1" && (*first)[10] == "1500"
        && (*first)[6] == "0";
    rotated = co_await sql.rotateToken(
        *conn, "test-session-1", kDigestA, kDigestB, 1600, 3s);
    auto old = co_await sql.useToken(*conn, kDigestA, 1700, 3s);
    auto repeat = co_await sql.rotateToken(
        *conn, "test-session-1", kDigestA, kDigestB, 1700, 3s);
    replayDenied = !old.has_value() && !repeat;
    // Idle deadline is inclusive; once expired, no previous or new digest
    // can reactivate the session or leak an authorized identity.
    auto timedOut = co_await sql.useToken(*conn, kDigestB, 2600, 3s);
    auto again = co_await sql.useToken(*conn, kDigestB, 2601, 3s);
    expired = !timedOut.has_value() && !again.has_value();
    auto final = co_await sql.find(*conn, "test-session-1", 3s);
    unchanged = final.has_value() && (*final)[6] == "2"
        && (*final)[10] == "1600";
}

asio::awaitable<void> boundaryAndInvalidDigest(
    std::string connectionString, bool& exactDeadlineDenied,
    bool& invalidRejected, bool& untouched)
{
    auto conn = co_await pg::AsyncConnection::connect(std::move(connectionString), 3s);
    co_await createDisposableSessionTable(*conn);
    pg::AsyncSessionSql sql{pg::AsyncSessionSql::Table::TemporaryTest};
    exactDeadlineDenied = !(co_await sql.rotateToken(
        *conn, "test-session-1", kDigestA, kDigestB, 2000, 3s));
    try {
        static_cast<void>(co_await sql.useToken(*conn, "1234", 1200, 3s));
    } catch (const std::invalid_argument&) {
        invalidRejected = true;
    }
    auto current = co_await sql.find(*conn, "test-session-1", 3s);
    untouched = current.has_value() && (*current)[6] == "0"
        && (*current)[10] == "1000" && conn->reusable();
}
asio::awaitable<void> revokeAndBulkRevoke(
    std::string connectionString, bool& revoked, bool& idempotent,
    bool& absentDenied, bool& bulkIsolated)
{
    auto conn = co_await pg::AsyncConnection::connect(std::move(connectionString), 3s);
    co_await createDisposableSessionTable(*conn);
    pg::AsyncSessionSql sql{pg::AsyncSessionSql::Table::TemporaryTest};
    const auto initial = co_await sql.revoke(*conn, "test-session-1", 1700, 3s);
    revoked = initial == pg::AsyncSessionSql::RevokeStatus::Revoked;
    const auto again = co_await sql.revoke(*conn, "test-session-1", 1800, 3s);
    idempotent = again == pg::AsyncSessionSql::RevokeStatus::AlreadyRevoked;
    auto token = co_await sql.useToken(*conn, kDigestA, 1900, 3s);
    const auto snapshot = co_await sql.find(*conn, "test-session-1", 3s);
    const auto unknown = co_await sql.revoke(*conn, "missing-session", 1800, 3s);
    absentDenied = !token.has_value() && snapshot.has_value()
        && (*snapshot)[6] == "1" && (*snapshot)[13] == "1700"
        && unknown == pg::AsyncSessionSql::RevokeStatus::NotFound;

    // Only one still-active session from test-identity may be affected.
    static_cast<void>(co_await conn->query(
        "INSERT INTO pg_temp.sessions "
        "SELECT 'test-session-2',identity_id,provider,assurance,factors,"
        "phishing_resistant,0,decode($1,'hex'),authenticated_at_ms,"
        "issued_at_ms,last_seen_at_ms,absolute_expires_at_ms,idle_timeout_ms,"
        "NULL,user_agent,remote_address "
        "FROM pg_temp.sessions WHERE id='test-session-1'",
        {kDigestB}, 3s));
    static_cast<void>(co_await conn->query(
        "INSERT INTO pg_temp.sessions "
        "SELECT 'other-session','another-identity',provider,assurance,factors,"
        "phishing_resistant,0,decode($1,'hex'),authenticated_at_ms,"
        "issued_at_ms,last_seen_at_ms,absolute_expires_at_ms,idle_timeout_ms,"
        "NULL,user_agent,remote_address "
        "FROM pg_temp.sessions WHERE id='test-session-1'",
        {"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}, 3s));
    const auto affected = co_await sql.revokeAll(
        *conn, "test-identity", 1900, 3s);
    const auto untouched = co_await sql.find(*conn, "other-session", 3s);
    const auto revokedSecond = co_await sql.find(*conn, "test-session-2", 3s);
    bulkIsolated = affected == 1U && untouched.has_value()
        && (*untouched)[6] == "0" && revokedSecond.has_value()
        && (*revokedSecond)[6] == "1";
}

} // namespace

TEST(PostgresAsyncSessionSqlTest, AtomicUseRotationReplayAndIdleExpiry)
{
    const char* uri = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!uri || !*uri) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI must provide an isolated PostgreSQL test database";
        }
        GTEST_SKIP() << "No disposable PostgreSQL URI configured";
    }
    asio::io_context io;
    bool lookup = false, rotated = false, replayDenied = false;
    bool expired = false, unchanged = false;
    auto future = asio::co_spawn(io,
        atomicSessionLifecycle(uri, lookup, rotated, replayDenied, expired, unchanged),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(lookup);
    EXPECT_TRUE(rotated);
    EXPECT_TRUE(replayDenied);
    EXPECT_TRUE(expired);
    EXPECT_TRUE(unchanged);
}

TEST(PostgresAsyncSessionSqlTest, InclusiveBoundaryAndBadDigestFailClosed)
{
    const char* uri = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!uri || !*uri) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI must provide an isolated PostgreSQL test database";
        }
        GTEST_SKIP() << "No disposable PostgreSQL URI configured";
    }
    asio::io_context io;
    bool exactDeadlineDenied = false, invalidRejected = false, untouched = false;
    auto future = asio::co_spawn(io,
        boundaryAndInvalidDigest(uri, exactDeadlineDenied, invalidRejected, untouched),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(exactDeadlineDenied);
    EXPECT_TRUE(invalidRejected);
    EXPECT_TRUE(untouched);
}

TEST(PostgresAsyncSessionSqlTest, RevocationIsIdempotentAndIdentityScoped)
{
    const char* uri = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!uri || !*uri) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI must provide an isolated PostgreSQL test database";
        }
        GTEST_SKIP() << "No disposable PostgreSQL URI configured";
    }
    asio::io_context io;
    bool revoked = false, idempotent = false;
    bool absentDenied = false, bulkIsolated = false;
    auto future = asio::co_spawn(io,
        revokeAndBulkRevoke(uri, revoked, idempotent, absentDenied, bulkIsolated),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(revoked);
    EXPECT_TRUE(idempotent);
    EXPECT_TRUE(absentDenied);
    EXPECT_TRUE(bulkIsolated);
}

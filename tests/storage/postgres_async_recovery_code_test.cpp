#include <gtest/gtest.h>

#include <boost/asio.hpp>

#include "async_connection.hpp"
#include "async_recovery_code.hpp"

#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <future>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
namespace asio = boost::asio;
namespace pg = openproof::storage::postgres::async_detail;
using namespace std::chrono_literals;

[[nodiscard]] std::string digest(char nibble)
{
    return std::string(63U, '0') + nibble;
}

[[nodiscard]] std::vector<std::string> manyDigests(std::size_t count)
{
    constexpr char hex[] = "0123456789abcdef";
    std::vector<std::string> output;
    output.reserve(count);
    for (std::size_t index = 0U; index < count; ++index) {
        std::string value(62U, '0');
        value.push_back(hex[index / 16U]);
        value.push_back(hex[index % 16U]);
        output.push_back(std::move(value));
    }
    return output;
}

asio::awaitable<void> createDisposableCodesTable(pg::AsyncConnection& conn)
{
    // A PG TEMP table in an exclusively owned disposable connection.
    // No production openproof table or schema is read or mutated.
    static_cast<void>(co_await conn.query(
        "CREATE TEMP TABLE recovery_codes ("
        "identity_id text NOT NULL, "
        "code_digest bytea NOT NULL CHECK(octet_length(code_digest)=32), "
        "issued_at_ms bigint NOT NULL, "
        "PRIMARY KEY(identity_id,code_digest))", {}, 3s));
}

asio::awaitable<void> lifecycle(
    std::string dsn, bool& replaceGood, bool& consumed,
    bool& replayDenied, bool& tenantDenied, bool& emptied, bool& reusable)
{
    auto conn = co_await pg::AsyncConnection::connect(std::move(dsn), 3s);
    co_await createDisposableCodesTable(*conn);
    pg::AsyncRecoveryCodeSql sql{pg::AsyncRecoveryCodeSql::Table::TemporaryTest};
    co_await sql.replace(*conn, "identity-A", {digest('a'), digest('b')}, 3s);
    replaceGood = (co_await sql.remaining(*conn, "identity-A", 3s)) == 2U;
    const bool first = co_await sql.consume(*conn, "identity-A", digest('a'), 3s);
    consumed = first
        && (co_await sql.remaining(*conn, "identity-A", 3s)) == 1U;
    const bool replay = co_await sql.consume(*conn, "identity-A", digest('a'), 3s);
    replayDenied = !replay;
    tenantDenied = !(co_await sql.consume(
        *conn, "identity-B", digest('b'), 3s));
    emptied = (co_await sql.remaining(*conn, "identity-A", 3s)) == 1U;
    co_await sql.replace(*conn, "identity-A", {}, 3s);
    emptied = emptied && (co_await sql.remaining(*conn, "identity-A", 3s)) == 0U;
    reusable = conn->reusable();
}

asio::awaitable<void> boundaries(
    std::string dsn, bool& exactLimit, bool& overflowRejected,
    bool& duplicatesRejected, bool& badDigestRejected, bool& reusable)
{
    auto conn = co_await pg::AsyncConnection::connect(std::move(dsn), 3s);
    co_await createDisposableCodesTable(*conn);
    pg::AsyncRecoveryCodeSql sql{pg::AsyncRecoveryCodeSql::Table::TemporaryTest};
    co_await sql.replace(*conn, "identity-A", manyDigests(64U), 3s);
    exactLimit = (co_await sql.remaining(*conn, "identity-A", 3s)) == 64U;
    try {
        co_await sql.replace(*conn, "identity-A", manyDigests(65U), 3s);
    } catch (const std::invalid_argument&) {
        overflowRejected = true;
    }
    try {
        co_await sql.replace(*conn, "identity-A",
            {std::string(63U, 'a') + 'f', std::string(63U, 'a') + 'F'}, 3s);
    } catch (const std::invalid_argument&) {
        duplicatesRejected = true;
    }
    try {
        co_await sql.replace(*conn, "identity-A",
            {std::string(64U, 'x')}, 3s);
    } catch (const std::invalid_argument&) {
        badDigestRejected = true;
    }
    // All malformed requests must be denied before opening a transaction or
    // deleting the 64 existing codes.
    exactLimit = exactLimit
        && (co_await sql.remaining(*conn, "identity-A", 3s)) == 64U;
    reusable = conn->reusable();
}

asio::awaitable<void> failedInsertPoisonsLease(
    std::string dsn, bool& poisonedBeforeRollback)
{
    auto conn = co_await pg::AsyncConnection::connect(std::move(dsn), 3s);
    co_await createDisposableCodesTable(*conn);
    pg::AsyncRecoveryCodeSql sql{pg::AsyncRecoveryCodeSql::Table::TemporaryTest};
    co_await sql.replace(*conn, "identity-A", {digest('a')}, 3s);
    // Reject the next digest only at the DB constraint layer, after the
    // transaction has already deleted the previous code.
    // Only constant test fixture digest bytes are assembled into this DDL.
    static_cast<void>(co_await conn->query(
        "ALTER TABLE pg_temp.recovery_codes ADD CONSTRAINT test_reject_b "
        "CHECK (code_digest<>decode('" + digest('b') + "','hex'))",
        {}, 3s));
    try {
        co_await sql.replace(*conn, "identity-A", {digest('b')}, 3s);
    } catch (const std::runtime_error&) {
        poisonedBeforeRollback = !conn->reusable();
    }
    // The async query adapter force-closes a connection on any SQL error.
    // PostgreSQL rolls back the open transaction when the session closes.
    // The pool must never reuse this lease or return partially changed data.
}

asio::awaitable<void> eligibilityLifecycle(
    std::string dsn, bool& allowed, bool& wrongProvider,
    bool& wrongIdentity, bool& totpDisabled, bool& suspended)
{
    auto conn = co_await pg::AsyncConnection::connect(std::move(dsn), 3s);
    // Only these four disposable PG TEMP tables exist on this connection;
    // never create or modify canonical OpenProof identity/credential rows.
    for (const auto& sql : {
        "CREATE TEMP TABLE identities (id text PRIMARY KEY,status smallint NOT NULL)",
        "CREATE TEMP TABLE external_identities (identity_id text NOT NULL,provider text NOT NULL)",
        "CREATE TEMP TABLE password_credentials (identity_id text PRIMARY KEY)",
        "CREATE TEMP TABLE totp_credentials (identity_id text PRIMARY KEY)",
        "INSERT INTO pg_temp.identities VALUES ('identity-A',0)",
        "INSERT INTO pg_temp.external_identities VALUES ('identity-A','local')",
        "INSERT INTO pg_temp.password_credentials VALUES ('identity-A')",
        "INSERT INTO pg_temp.totp_credentials VALUES ('identity-A')"
    }) {
        static_cast<void>(co_await conn->query(sql, {}, 3s));
    }
    pg::AsyncRecoveryCodeSql sql{pg::AsyncRecoveryCodeSql::Table::TemporaryTest};
    allowed = co_await sql.eligible(*conn, "identity-A", "local", 3s);
    wrongProvider = !(co_await sql.eligible(*conn, "identity-A", "github", 3s));
    wrongIdentity = !(co_await sql.eligible(*conn, "identity-B", "local", 3s));
    static_cast<void>(co_await conn->query(
        "DELETE FROM pg_temp.totp_credentials WHERE identity_id='identity-A'",
        {}, 3s));
    totpDisabled = !(co_await sql.eligible(*conn, "identity-A", "local", 3s));
    static_cast<void>(co_await conn->query(
        "INSERT INTO pg_temp.totp_credentials VALUES ('identity-A')", {}, 3s));
    static_cast<void>(co_await conn->query(
        "UPDATE pg_temp.identities SET status=1 WHERE id='identity-A'",
        {}, 3s));
    suspended = !(co_await sql.eligible(*conn, "identity-A", "local", 3s));
}

} // namespace

TEST(AsyncRecoveryCodeSqlTest, MaximumSetIsDeclaredOnce)
{
    EXPECT_EQ(pg::AsyncRecoveryCodeSql::kMaximumRecoveryCodes, 64U);
}

TEST(AsyncRecoveryCodeSqlTest, AtomicReplacementAndOneTimeUseOnDisposablePg)
{
    const char* dsn = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!dsn || !*dsn)
        GTEST_SKIP() << "No disposable PostgreSQL URI configured";
    asio::io_context io;
    bool replaceGood = false, consumed = false, replayDenied = false;
    bool tenantDenied = false, emptied = false, reusable = false;
    auto done = asio::co_spawn(io,
        lifecycle(dsn, replaceGood, consumed, replayDenied,
                  tenantDenied, emptied, reusable), asio::use_future);
    io.run();
    ASSERT_NO_THROW(done.get());
    EXPECT_TRUE(replaceGood);
    EXPECT_TRUE(consumed);
    EXPECT_TRUE(replayDenied);
    EXPECT_TRUE(tenantDenied);
    EXPECT_TRUE(emptied);
    EXPECT_TRUE(reusable);
}

TEST(AsyncRecoveryCodeSqlTest, SixtyFourCodeBoundAndDuplicatesFailBeforeBegin)
{
    const char* dsn = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!dsn || !*dsn)
        GTEST_SKIP() << "No disposable PostgreSQL URI configured";
    asio::io_context io;
    bool exactLimit = false, overflowRejected = false;
    bool duplicatesRejected = false, badDigestRejected = false, reusable = false;
    auto done = asio::co_spawn(io,
        boundaries(dsn, exactLimit, overflowRejected,
                   duplicatesRejected, badDigestRejected, reusable),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(done.get());
    EXPECT_TRUE(exactLimit);
    EXPECT_TRUE(overflowRejected);
    EXPECT_TRUE(duplicatesRejected);
    EXPECT_TRUE(badDigestRejected);
    EXPECT_TRUE(reusable);
}

TEST(AsyncRecoveryCodeSqlTest, FailedInsertPoisonsLeaseInsteadOfCommitting)
{
    const char* dsn = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!dsn || !*dsn)
        GTEST_SKIP() << "No disposable PostgreSQL URI configured";
    asio::io_context io;
    bool poisoned = false;
    auto done = asio::co_spawn(
        io, failedInsertPoisonsLease(dsn, poisoned), asio::use_future);
    io.run();
    ASSERT_NO_THROW(done.get());
    EXPECT_TRUE(poisoned);
}


TEST(AsyncRecoveryCodeSqlTest, NativeEligibilityRequiresLocalConnectionTotpAndActiveIdentity)
{
    const char* dsn = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!dsn || !*dsn)
        GTEST_SKIP() << "No disposable PostgreSQL URI configured";
    asio::io_context io;
    bool allowed = false, wrongProvider = false, wrongIdentity = false;
    bool totpDisabled = false, suspended = false;
    auto done = asio::co_spawn(io,
        eligibilityLifecycle(dsn, allowed, wrongProvider, wrongIdentity,
                             totpDisabled, suspended), asio::use_future);
    io.run();
    ASSERT_NO_THROW(done.get());
    EXPECT_TRUE(allowed);
    EXPECT_TRUE(wrongProvider);
    EXPECT_TRUE(wrongIdentity);
    EXPECT_TRUE(totpDisabled);
    EXPECT_TRUE(suspended);
}

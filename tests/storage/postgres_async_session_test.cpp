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

asio::awaitable<void> bulkRevocationReturnsScalarCount(
    std::string connectionString, bool& exactCount, bool& noCrossIdentity)
{
    auto conn = co_await pg::AsyncConnection::connect(std::move(connectionString), 3s);
    co_await createDisposableSessionTable(*conn);
    pg::AsyncSessionSql sql{pg::AsyncSessionSql::Table::TemporaryTest};
    static_cast<void>(co_await conn->query(
        "INSERT INTO pg_temp.sessions "
        "SELECT 'mass-' || n::text, 'mass-identity', provider, assurance,"
        "factors,phishing_resistant,0,decode(md5(n::text) || md5(n::text),'hex'),"
        "authenticated_at_ms,issued_at_ms,last_seen_at_ms,"
        "absolute_expires_at_ms,idle_timeout_ms,NULL,NULL,NULL "
        "FROM pg_temp.sessions CROSS JOIN generate_series(1, 2048) AS n "
        "WHERE id='test-session-1'",
        {}, 3s));
    const auto changed = co_await sql.revokeAll(*conn, "mass-identity", 1700, 5s);
    const auto repeated = co_await sql.revokeAll(*conn, "mass-identity", 1701, 5s);
    auto verified = co_await conn->query(
        "SELECT count(*)::text FROM pg_temp.sessions "
        "WHERE identity_id='mass-identity' AND state=1",
        {}, 3s);
    exactCount = changed == 2048U && repeated == 0U
        && verified.rows.size() == 1U
        && verified.rows[0].size() == 1U
        && verified.rows[0][0] == "2048";
    auto separate = co_await sql.find(*conn, "test-session-1", 3s);
    noCrossIdentity = separate.has_value() && (*separate)[6] == "0";
}

asio::awaitable<void> sessionCreationListingAndPurge(
    std::string connectionString, bool& created,
    bool& sorted, bool& purged, bool& rejectedBadInput)
{
    auto conn = co_await pg::AsyncConnection::connect(std::move(connectionString), 3s);
    co_await createDisposableSessionTable(*conn);
    pg::AsyncSessionSql sql{pg::AsyncSessionSql::Table::TemporaryTest};
    pg::AsyncSessionSql::NewSession fresh{
        "new-session-2", "test-identity", "test-provider", kDigestB,
        1U, 3U, true, 1100, 1200, 1500, 9000, 5000,
        std::nullopt, std::nullopt
    };
    co_await sql.add(*conn, std::move(fresh), 3s);
    auto count = co_await sql.size(*conn, 3s);
    auto list = co_await sql.list(*conn, "test-identity", 3s);
    auto found = co_await sql.find(*conn, "new-session-2", 3s);
    created = count == 2U && found.has_value()
        && (*found)[13] == std::nullopt && (*found)[14] == std::nullopt;
    sorted = list.size() == 2U && list[0].size() == 16U
        && list[0][0] == "new-session-2"
        && list[1].size() == 16U && list[1][0] == "test-session-1";
    auto removed = co_await sql.purgeExpired(*conn, 2000, 3s);
    auto countAfter = co_await sql.size(*conn, 3s);
    auto stillThere = co_await sql.find(*conn, "new-session-2", 3s);
    auto expiredGone = co_await sql.find(*conn, "test-session-1", 3s);
    purged = removed == 1U && countAfter == 1U
        && stillThere.has_value() && !expiredGone.has_value();
    pg::AsyncSessionSql::NewSession invalid{
        "bad-session", "test-identity", "test-provider", "bad",
        1U, 3U, true, 1100, 1200, 1500, 9000, 5000,
        std::nullopt, std::nullopt
    };
    try {
        co_await sql.add(*conn, std::move(invalid), 3s);
    } catch (const std::invalid_argument&) {
        rejectedBadInput = true;
    }
    const auto final = co_await sql.size(*conn, 3s);
    rejectedBadInput = rejectedBadInput && final == 1U && conn->reusable();
}

asio::awaitable<void> atomicReplacement(
    std::string connectionString, bool& staleRejected, bool& replaced,
    bool& replayRejected, bool& unchangedOther)
{
    auto conn = co_await pg::AsyncConnection::connect(std::move(connectionString), 3s);
    co_await createDisposableSessionTable(*conn);
    pg::AsyncSessionSql sql{pg::AsyncSessionSql::Table::TemporaryTest};
    auto replacement = [](std::string id, std::string digest) {
        return pg::AsyncSessionSql::NewSession{
            std::move(id), "test-identity", "test-provider", std::move(digest),
            1U, 3U, true, 1100, 1100, 1100, 10000, 1000,
            std::nullopt, std::nullopt
        };
    };

    const bool refused = co_await sql.replace(
        *conn, replacement("should-not-exist", kDigestB),
        "test-session-1", kDigestB, 1300, 3s);
    const auto original = co_await sql.find(*conn, "test-session-1", 3s);
    const auto countBefore = co_await sql.size(*conn, 3s);
    staleRejected = !refused && countBefore == 1U
        && original.has_value() && (*original)[6] == "0";

    const bool issued = co_await sql.replace(
        *conn, replacement("replacement-session", kDigestB),
        "test-session-1", kDigestA, 1400, 3s);
    const auto old = co_await sql.find(*conn, "test-session-1", 3s);
    const auto fresh = co_await sql.find(*conn, "replacement-session", 3s);
    replaced = issued && old.has_value() && fresh.has_value()
        && (*old)[6] == "1" && (*old)[13] == "1400"
        && (*fresh)[6] == "0" && (*fresh)[7] == kDigestB;

    const bool repeated = co_await sql.replace(
        *conn, replacement("replay-session", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        "test-session-1", kDigestA, 1500, 3s);
    const auto countAfter = co_await sql.size(*conn, 3s);
    replayRejected = !repeated && countAfter == 2U
        && !(co_await sql.find(*conn, "replay-session", 3s)).has_value();

    // A failed replacement must never touch an independent active session.
    unchangedOther = (co_await sql.useToken(*conn, kDigestB, 1500, 3s)).has_value()
        && !(co_await sql.useToken(*conn, kDigestA, 1500, 3s)).has_value();
}

asio::awaitable<void> replacementInsertFailureRollsBack(
    std::string connectionString, bool& rolledBack)
{
    auto conn = co_await pg::AsyncConnection::connect(std::move(connectionString), 3s);
    co_await createDisposableSessionTable(*conn);
    pg::AsyncSessionSql sql{pg::AsyncSessionSql::Table::TemporaryTest};
    pg::AsyncSessionSql::NewSession duplicate{
        "test-session-1", "test-identity", "test-provider", kDigestB,
        1U, 3U, true, 1100, 1100, 1100, 10000, 1000,
        std::nullopt, std::nullopt
    };
    bool denied = false;
    try {
        static_cast<void>(co_await sql.replace(
            *conn, std::move(duplicate), "test-session-1", kDigestA, 1300, 3s));
    } catch (const std::runtime_error&) {
        denied = true;
    }
    // AsyncConnection deliberately discards PGconn after any SQL error;
    // never issue a verification query through the poisoned lease. The SQL
    // statement's atomicity is a PostgreSQL guarantee; cross-connection
    // rollback verification belongs in the disposable real-schema suite.
    rolledBack = denied && !conn->healthy() && !conn->reusable();
}

} // namespace

TEST(PostgresAsyncSessionSqlTest, AtomicReplacementRejectsStaleAndReplay)
{
    const char* uri = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!uri || !*uri) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI must provide an isolated PostgreSQL test database";
        }
        GTEST_SKIP() << "No disposable PostgreSQL URI configured";
    }
    asio::io_context io;
    bool stale = false, replaced = false, replay = false, isolated = false;
    auto done = asio::co_spawn(io,
        atomicReplacement(uri, stale, replaced, replay, isolated), asio::use_future);
    io.run();
    ASSERT_NO_THROW(done.get());
    EXPECT_TRUE(stale);
    EXPECT_TRUE(replaced);
    EXPECT_TRUE(replay);
    EXPECT_TRUE(isolated);
}

TEST(PostgresAsyncSessionSqlTest, ReplacementInsertFailureRollsBackRevocation)
{
    const char* uri = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!uri || !*uri) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI must provide an isolated PostgreSQL test database";
        }
        GTEST_SKIP() << "No disposable PostgreSQL URI configured";
    }
    asio::io_context io;
    bool rolledBack = false;
    auto done = asio::co_spawn(
        io, replacementInsertFailureRollsBack(uri, rolledBack), asio::use_future);
    io.run();
    ASSERT_NO_THROW(done.get());
    EXPECT_TRUE(rolledBack);
}

TEST(PostgresAsyncSessionSqlTest, StrictlyDecodesRowsBeforeDomainRestore)
{
    pg::AsyncSessionSql::SessionFields fields{
        "sample-id", "sample-identity", "sample-provider", "1", "3", "t",
        "0", std::string{kDigestA}, "1000", "1000", "1500", "10000",
        "3000", std::nullopt, "sample-agent", std::nullopt
    };
    const auto snapshot = pg::AsyncSessionSql::decodeRow(fields);
    EXPECT_EQ(snapshot.id, "sample-id");
    EXPECT_EQ(snapshot.identityId, "sample-identity");
    EXPECT_EQ(snapshot.factors, 3U);
    EXPECT_TRUE(snapshot.phishingResistant);
    EXPECT_EQ(snapshot.lastSeenAtMs, 1500);
    EXPECT_FALSE(snapshot.revokedAtMs.has_value());
    ASSERT_TRUE(snapshot.userAgent.has_value());
    EXPECT_EQ(*snapshot.userAgent, "sample-agent");

    fields[6] = "1";
    EXPECT_THROW(static_cast<void>(pg::AsyncSessionSql::decodeRow(fields)), std::runtime_error);
    fields[13] = "1600";
    const auto revoked = pg::AsyncSessionSql::decodeRow(fields);
    EXPECT_EQ(revoked.state, 1U);
    ASSERT_TRUE(revoked.revokedAtMs.has_value());
    EXPECT_EQ(*revoked.revokedAtMs, 1600);
    fields[5] = "unexpected";
    EXPECT_THROW(static_cast<void>(pg::AsyncSessionSql::decodeRow(fields)), std::runtime_error);
    fields[5] = "t";
    fields[7] = "not-a-digest";
    EXPECT_THROW(static_cast<void>(pg::AsyncSessionSql::decodeRow(fields)), std::runtime_error);
    fields[7] = std::string{kDigestA};
    fields[12] = "-1";
    EXPECT_THROW(static_cast<void>(pg::AsyncSessionSql::decodeRow(fields)), std::runtime_error);
    fields.pop_back();
    EXPECT_THROW(static_cast<void>(pg::AsyncSessionSql::decodeRow(fields)), std::runtime_error);
}

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

TEST(PostgresAsyncSessionSqlTest, BulkRevocationReturnsBoundedCountForThousands)
{
    const char* uri = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!uri || !*uri) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI must provide an isolated PostgreSQL test database";
        }
        GTEST_SKIP() << "No disposable PostgreSQL URI configured";
    }
    asio::io_context io;
    bool exactCount = false, noCrossIdentity = false;
    auto future = asio::co_spawn(io,
        bulkRevocationReturnsScalarCount(uri, exactCount, noCrossIdentity),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(exactCount);
    EXPECT_TRUE(noCrossIdentity);
}

TEST(PostgresAsyncSessionSqlTest, CreateListAndPurgePreserveSessionBoundaries)
{
    const char* uri = std::getenv("OPENPROOF_TEST_POSTGRES");
    if (!uri || !*uri) {
        if (std::getenv("GITHUB_ACTIONS")) {
            FAIL() << "CI must provide an isolated PostgreSQL test database";
        }
        GTEST_SKIP() << "No disposable PostgreSQL URI configured";
    }
    asio::io_context io;
    bool created = false, sorted = false, purged = false, rejectedBadInput = false;
    auto future = asio::co_spawn(io,
        sessionCreationListingAndPurge(
            uri, created, sorted, purged, rejectedBadInput),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(created);
    EXPECT_TRUE(sorted);
    EXPECT_TRUE(purged);
    EXPECT_TRUE(rejectedBadInput);
}

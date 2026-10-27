#include <gtest/gtest.h>
#include <boost/asio.hpp>

#include <chrono>
#include <future>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "coroutine_session_repository.hpp"

import openproof.foundation;
import openproof.identity.core;
import openproof.session;
import openproof.security;
import openproof.storage.postgres;

namespace {
namespace pg = openproof::storage::postgres;
namespace sess = openproof::session;
using Fields = std::vector<std::optional<std::string>>;

[[nodiscard]] Fields activeRow()
{
    return {
        "session-domain-1", "identity-1", "provider-1",
        "1", "3", "t", "0",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "1000", "1200", "1500", "10000", "3000",
        std::nullopt, "Test client", std::nullopt
    };
}

TEST(PostgresCoroutineDomainTest, ValidRowRestoresStronglyTypedSession)
{
    const auto restored = pg::PostgresSessionDomainAdapter::restore(activeRow());
    ASSERT_TRUE(restored);
    EXPECT_EQ(restored->id().value(), "session-domain-1");
    EXPECT_EQ(restored->identity().value(), "identity-1");
    EXPECT_EQ(restored->provider().value(), "provider-1");
    EXPECT_EQ(restored->state(), sess::SessionState::Active);
    EXPECT_EQ(restored->lastSeenAt().time_since_epoch().count(), 1500);
    EXPECT_EQ(restored->idleTimeout().count(), 3000);
    ASSERT_TRUE(restored->userAgent().has_value());
    EXPECT_EQ(*restored->userAgent(), "Test client");
    EXPECT_FALSE(restored->remoteAddress().has_value());
    EXPECT_FALSE(restored->revokedAt().has_value());
}

TEST(PostgresCoroutineDomainTest, RevokedSessionRestoresWithoutAuthBypass)
{
    auto row = activeRow();
    row[6] = "1";
    row[13] = "1700";
    auto restored = pg::PostgresSessionDomainAdapter::restore(row);
    ASSERT_TRUE(restored);
    EXPECT_EQ(restored->state(), sess::SessionState::Revoked);
    const auto digest = restored->tokenDigest();
    const auto used = restored->use(
        digest, openproof::foundation::Instant{std::chrono::milliseconds{1800}});
    EXPECT_FALSE(used);
}

TEST(PostgresCoroutineDomainTest, CorruptedRowsAreDeniedWithoutException)
{
    const auto original = activeRow();
    const auto checkInvalid = [](Fields row) {
        const auto result = pg::PostgresSessionDomainAdapter::restore(row);
        EXPECT_FALSE(result);
        if (!result) {
            EXPECT_EQ(result.error().code(),
                          openproof::foundation::ErrorCode::Internal);
        }
    };
    auto empty = original;
    empty.pop_back();
    checkInvalid(empty);
    auto badBoolean = original;
    badBoolean[5] = "true";
    checkInvalid(badBoolean);
    auto missingDigest = original;
    missingDigest[7] = "nonhex-digest";
    checkInvalid(missingDigest);
    auto illegalState = original;
    illegalState[6] = "3";
    checkInvalid(illegalState);
    auto missingRequired = original;
    missingRequired[0] = std::nullopt;
    checkInvalid(missingRequired);
    auto invalidLifetime = original;
    invalidLifetime[11] = "1499";
    checkInvalid(invalidLifetime);
    auto orphanRevocation = original;
    orphanRevocation[13] = "1900";
    checkInvalid(orphanRevocation);
    auto overlongAgent = original;
    overlongAgent[14] = std::string(1025, 'x');
    checkInvalid(overlongAgent);
}

boost::asio::awaitable<void> verifyCoroutineRepositoryFailureIsolation(
    pg::CoroutinePostgresSessionRepository& repository,
    bool& findDenied, bool& useDenied,
    bool& writeDenied, bool& collectionDenied)
{
    // A deliberately invalid libpq keyword avoids reaching any live DB.
    // The repository must discard a failed physical connect and return a
    // sanitized error rather than leaking credentials or throwing at HTTP.
    auto first = co_await repository.find(sess::SessionId{"missing"});
    findDenied = !first &&
        first.error().code() == openproof::foundation::ErrorCode::Unavailable;
    auto next = co_await repository.use(
        sess::TokenDigest{openproof::security::Sha256Digest{}},
        openproof::foundation::Instant{std::chrono::milliseconds{1800}});
    useDenied = !next &&
        next.error().code() == openproof::foundation::ErrorCode::Unavailable;
    auto source = pg::PostgresSessionDomainAdapter::restore(activeRow());
    if (source) {
        auto stored = co_await repository.add(std::move(source).value());
        writeDenied = !stored && stored.error().code()
            == openproof::foundation::ErrorCode::Unavailable;
    }
    const auto listing = co_await repository.list(
        openproof::identity::core::IdentityId{"identity-1"});
    const auto counted = co_await repository.size();
    collectionDenied = !listing && !counted &&
        listing.error().code() == openproof::foundation::ErrorCode::Unavailable
        && counted.error().code() == openproof::foundation::ErrorCode::Unavailable;
}

TEST(PostgresCoroutineDomainTest, NativeRepositoryUsesAsyncPoolAndFailsClosed)
{
    boost::asio::io_context io;
    pg::CoroutinePostgresSessionRepository repository{
        io.get_executor(),
        openproof::foundation::SecretString{
            "openproof_invalid_connection_keyword=invalid"},
        1U, std::chrono::milliseconds{100},
        std::chrono::milliseconds{100},
        std::chrono::milliseconds{100}};
    bool findDenied = false, useDenied = false;
    bool writeDenied = false, collectionDenied = false;
    auto future = boost::asio::co_spawn(io,
        verifyCoroutineRepositoryFailureIsolation(
            repository, findDenied, useDenied,
            writeDenied, collectionDenied), boost::asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(findDenied);
    EXPECT_TRUE(useDenied);
    EXPECT_TRUE(writeDenied);
    EXPECT_TRUE(collectionDenied);
}
} // namespace

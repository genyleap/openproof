#include <gtest/gtest.h>

#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <future>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "coroutine_recovery_codes.hpp"

import openproof.credentials;
import openproof.foundation;
import openproof.identity.core;
import openproof.security;

namespace {
namespace asio = boost::asio;
namespace cred = openproof::credentials;
namespace fnd = openproof::foundation;
namespace ids = openproof::identity::core;
namespace sec = openproof::security;

class FakeRecoveryRepository final : public cred::CoroutineRecoveryCodeRepository {
public:
    bool unavailable{false};
    unsigned int replacementCalls{0U};
    unsigned int consumedCalls{0U};
    std::vector<cred::RecoveryCodeDigest> stored;

    [[nodiscard]] asio::awaitable<fnd::Status> replaceAsync(
        ids::IdentityId identity, std::vector<cred::RecoveryCodeDigest> digests) override
    {
        ++replacementCalls;
        if (identity.empty() || unavailable) {
            co_return fnd::fail(fnd::ErrorCode::Unavailable);
        }
        stored = std::move(digests);
        co_return fnd::ok();
    }

    [[nodiscard]] asio::awaitable<fnd::Status> consumeAsync(
        ids::IdentityId identity, cred::RecoveryCodeDigest digest) override
    {
        ++consumedCalls;
        if (identity.empty() || unavailable)
            co_return fnd::fail(fnd::ErrorCode::Unavailable);
        const auto found = std::find(stored.begin(), stored.end(), digest);
        if (found == stored.end())
            co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        stored.erase(found);
        co_return fnd::ok();
    }

    [[nodiscard]] asio::awaitable<fnd::Result<std::size_t>>
    remainingAsync(ids::IdentityId identity) override
    {
        if (identity.empty() || unavailable)
            co_return fnd::fail(fnd::ErrorCode::Unavailable);
        co_return stored.size();
    }
};

template <typename T>
T await(asio::awaitable<T> work)
{
    asio::io_context io;
    auto future = asio::co_spawn(io, std::move(work), asio::use_future);
    io.run();
    return future.get();
}

[[nodiscard]] auto createService(FakeRecoveryRepository& repository)
{
    return cred::CoroutineRecoveryCodeService::create(
        repository, fnd::SecretString{std::string(32U, 'P')});
}

TEST(CoroutineRecoveryCodesTest, IssuanceCommitsHashedDigestsBeforeReturningSecrets)
{
    FakeRecoveryRepository repository;
    auto service = createService(repository);
    ASSERT_TRUE(service.has_value());
    auto result = await(service->issue(ids::IdentityId{"user-A"}, 10U));
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 10U);
    ASSERT_EQ(repository.stored.size(), 10U);
    EXPECT_EQ(repository.replacementCalls, 1U);
    for (std::size_t i = 0U; i < result->size(); ++i) {
        const auto& secret = (*result)[i];
        EXPECT_FALSE(secret.empty());
        EXPECT_GT(secret.size(), 20U);
        const auto hash = sec::hmacSha256(
            fnd::SecretString{std::string(32U, 'P')}, secret.expose());
        ASSERT_TRUE(hash.has_value());
        EXPECT_EQ(repository.stored[i], hash.value());
    }
}

TEST(CoroutineRecoveryCodesTest, PersistFailureNeverReturnsPlaintextCodes)
{
    FakeRecoveryRepository repository;
    repository.unavailable = true;
    auto service = createService(repository);
    ASSERT_TRUE(service);
    auto result = await(service->issue(ids::IdentityId{"user-A"}, 10U));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(repository.stored.empty());
    EXPECT_EQ(repository.replacementCalls, 1U);
}

TEST(CoroutineRecoveryCodesTest, OneTimeConsumptionPreventsReplay)
{
    FakeRecoveryRepository repository;
    auto service = createService(repository);
    ASSERT_TRUE(service);
    auto issued = await(service->issue(ids::IdentityId{"user-A"}, 2U));
    ASSERT_TRUE(issued);
    std::string code{(*issued)[0].expose()};

    auto first = await(service->consume(
        ids::IdentityId{"user-A"}, fnd::SecretString{code}));
    EXPECT_TRUE(first);
    EXPECT_EQ(repository.stored.size(), 1U);
    auto replay = await(service->consume(
        ids::IdentityId{"user-A"}, fnd::SecretString{code}));
    EXPECT_FALSE(replay);
    EXPECT_EQ(repository.consumedCalls, 2U);
}

TEST(CoroutineRecoveryCodesTest, RevokeInvalidatesEverything)
{
    FakeRecoveryRepository repository;
    auto service = createService(repository);
    ASSERT_TRUE(service);
    ASSERT_TRUE(await(service->issue(ids::IdentityId{"user-A"}, 4U)));
    EXPECT_TRUE(await(service->revoke(ids::IdentityId{"user-A"})));
    EXPECT_TRUE(repository.stored.empty());
    auto remaining = await(service->remaining(ids::IdentityId{"user-A"}));
    ASSERT_TRUE(remaining);
    EXPECT_EQ(remaining.value(), 0U);
}

TEST(CoroutineRecoveryCodesTest, InvalidInputNeverReachesPersistence)
{
    FakeRecoveryRepository repository;
    auto weakPepper = cred::CoroutineRecoveryCodeService::create(
        repository, fnd::SecretString{"weak"});
    EXPECT_FALSE(weakPepper);
    auto service = createService(repository);
    ASSERT_TRUE(service);
    EXPECT_FALSE(await(service->issue(ids::IdentityId{"user-A"}, 0U)));
    EXPECT_FALSE(await(service->issue(ids::IdentityId{"user-A"}, 33U)));
    EXPECT_FALSE(await(service->issue(ids::IdentityId{""}, 1U)));
    EXPECT_FALSE(await(service->consume(
        ids::IdentityId{"user-A"}, fnd::SecretString{})));
    EXPECT_FALSE(await(service->revoke(ids::IdentityId{""})));
    EXPECT_FALSE(await(service->remaining(ids::IdentityId{""})));
    EXPECT_EQ(repository.replacementCalls, 0U);
    EXPECT_EQ(repository.consumedCalls, 0U);
}

} // namespace

#include <chrono>
#include <concepts>
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>

import openproof.credentials;
import openproof.foundation;
import openproof.identity.core;

namespace {

namespace cred = openproof::credentials;
namespace fnd = openproof::foundation;
namespace core = openproof::identity::core;

[[nodiscard]] fnd::SecretString pepper()
{
    return fnd::SecretString{std::string(32U, 'p')};
}

TEST(PasswordPolicyTest, RejectsUnsafeAndResourceUnboundedParameters)
{
    EXPECT_FALSE(cred::PasswordPolicy::create(3U, 8U, 1U, 16U, 32U,
                                               64U * 1024U * 1024U));
    EXPECT_FALSE(cred::PasswordPolicy::create(32768U, 8U, 1U, 8U, 32U,
                                               64U * 1024U * 1024U));
    EXPECT_FALSE(cred::PasswordPolicy::create(32768U, 8U, 1U, 16U, 32U,
                                               1024U));
}

TEST(PasswordHasherTest, HashesWithRandomSaltAndVerifiesInConstantTimeBoundary)
{
    auto hasher = cred::PasswordHasher::create(
        pepper(), cred::PasswordPolicy::recommended());
    ASSERT_TRUE(hasher);
    const fnd::SecretString password{"correct horse battery staple"};

    auto first = hasher->hash(password);
    auto second = hasher->hash(password);
    ASSERT_TRUE(first);
    ASSERT_TRUE(second);
    EXPECT_NE(first->encoded(), second->encoded());

    auto correct = hasher->verify(password, first.value());
    auto incorrect = hasher->verify(fnd::SecretString{"wrong password"}, first.value());
    ASSERT_TRUE(correct);
    ASSERT_TRUE(incorrect);
    EXPECT_TRUE(correct.value());
    EXPECT_FALSE(incorrect.value());
}

TEST(PasswordHasherTest, RejectsShortPasswordsAndWeakPeppers)
{
    EXPECT_FALSE(cred::PasswordHasher::create(
        fnd::SecretString{"too-short"}, cred::PasswordPolicy::recommended()));
    auto hasher = cred::PasswordHasher::create(
        pepper(), cred::PasswordPolicy::recommended());
    ASSERT_TRUE(hasher);
    EXPECT_FALSE(hasher->hash(fnd::SecretString{"short"}));
}

TEST(TotpTest, MatchesRfc6238Sha1VectorAtFiftyNineSeconds)
{
    auto secret = cred::TotpSecret::create(
        fnd::SecretString{"12345678901234567890"});
    auto policy = cred::TotpPolicy::create(std::chrono::seconds{30}, 8U, 0U, 0U);
    ASSERT_TRUE(secret);
    ASSERT_TRUE(policy);
    const fnd::Instant at{std::chrono::milliseconds{59000}};

    auto code = cred::totpAt(secret.value(), policy.value(), at);
    ASSERT_TRUE(code);
    EXPECT_EQ(code.value(), "94287082");
}

TEST(TotpTest, AcceptsConfiguredClockSkewThenRejectsReplay)
{
    auto secret = cred::TotpSecret::create(
        fnd::SecretString{"12345678901234567890"});
    ASSERT_TRUE(secret);
    const auto policy = cred::TotpPolicy::recommended();
    const fnd::Instant issuedAt{std::chrono::seconds{60}};
    auto code = cred::totpAt(secret.value(), policy, issuedAt);
    ASSERT_TRUE(code);

    auto accepted = cred::verifyTotp(secret.value(), policy, code.value(),
                                     issuedAt + std::chrono::seconds{30}, std::nullopt);
    ASSERT_TRUE(accepted);
    auto replay = cred::verifyTotp(secret.value(), policy, code.value(), issuedAt,
                                   accepted.value());
    ASSERT_FALSE(replay);
    EXPECT_EQ(replay.error().code(), fnd::ErrorCode::AuthenticationFailed);
}

TEST(TotpTest, RejectsMalformedCodesUniformly)
{
    auto secret = cred::TotpSecret::create(
        fnd::SecretString{"12345678901234567890"});
    ASSERT_TRUE(secret);
    auto result = cred::verifyTotp(secret.value(), cred::TotpPolicy::recommended(),
                                   "12x456", fnd::Instant{}, std::nullopt);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), fnd::ErrorCode::AuthenticationFailed);
}

TEST(RecoveryCodeTest, IssuanceReplacesOldSetAndCodesAreSingleUse)
{
    cred::InMemoryRecoveryCodeRepository repository;
    auto service = cred::RecoveryCodeService::create(repository, pepper());
    ASSERT_TRUE(service);
    const core::IdentityId identity{"identity-1"};

    auto first = service->issue(identity, 3U);
    ASSERT_TRUE(first);
    ASSERT_EQ(first->codes().size(), 3U);
    const std::string superseded{first->codes().front().expose()};

    auto second = service->issue(identity, 2U);
    ASSERT_TRUE(second);
    EXPECT_FALSE(service->consume(identity, fnd::SecretString{superseded}));
    EXPECT_TRUE(service->consume(identity, second->codes().front()));
    EXPECT_FALSE(service->consume(identity, second->codes().front()));
    auto remaining = repository.remaining(identity);
    ASSERT_TRUE(remaining);
    EXPECT_EQ(remaining.value(), 1U);
}

TEST(RecoveryCodeTest, ConcurrentConsumptionHasExactlyOneWinner)
{
    cred::InMemoryRecoveryCodeRepository repository;
    auto service = cred::RecoveryCodeService::create(repository, pepper());
    ASSERT_TRUE(service);
    const core::IdentityId identity{"identity-1"};
    auto batch = service->issue(identity, 1U);
    ASSERT_TRUE(batch);
    const std::string code{batch->codes().front().expose()};

    bool first = false;
    bool second = false;
    std::thread left{[&] {
        first = service->consume(identity, fnd::SecretString{code}).has_value();
    }};
    std::thread right{[&] {
        second = service->consume(identity, fnd::SecretString{code}).has_value();
    }};
    left.join();
    right.join();
    EXPECT_NE(first, second);
}

static_assert(!std::copy_constructible<cred::PasswordHasher>);
static_assert(!std::copy_constructible<cred::TotpSecret>);
static_assert(!std::copy_constructible<cred::RecoveryCodeBatch>);

}

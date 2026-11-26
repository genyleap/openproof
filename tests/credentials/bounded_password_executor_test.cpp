#include <gtest/gtest.h>
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <future>
#include <optional>
#include <string>
#include <utility>
#include "bounded_password_executor.hpp"

import openproof.credentials;
import openproof.foundation;

namespace {
namespace asio = boost::asio;
namespace cred = openproof::credentials;
namespace fnd = openproof::foundation;

TEST(BoundedPasswordExecutorTest, VerifiesRealHashesAndNeverAuthenticatesDummy)
{
    const auto policy = cred::PasswordPolicy::create(1024U, 8U, 1U, 16U, 32U, 2U * 1024U * 1024U);
    ASSERT_TRUE(policy);
    auto maker = cred::PasswordHasher::create(fnd::SecretString{std::string(32U, 'p')}, policy.value());
    auto worker = cred::PasswordHasher::create(fnd::SecretString{std::string(32U, 'p')}, policy.value());
    ASSERT_TRUE(maker && worker);
    auto hash = maker->hash(fnd::SecretString{"fixture-password"});
    ASSERT_TRUE(hash);
    auto executor = cred::BoundedPasswordExecutor::create(std::move(worker).value(), 1U);
    ASSERT_TRUE(executor);
    asio::io_context io;
    auto run = [&]<typename T>(asio::awaitable<T> pending) {
        io.restart();
        auto complete = asio::co_spawn(io, std::move(pending), asio::use_future);
        io.run();
        return complete.get();
    };
    auto correct = run(executor.value()->verifyAsync(fnd::SecretString{"fixture-password"}, hash.value()));
    ASSERT_TRUE(correct);
    EXPECT_TRUE(correct.value());
    auto wrong = run(executor.value()->verifyAsync(fnd::SecretString{"incorrect-password"}, hash.value()));
    ASSERT_TRUE(wrong);
    EXPECT_FALSE(wrong.value());
    auto missing = run(executor.value()->verifyAsync(fnd::SecretString{std::string(32U, 'x')}, std::nullopt));
    ASSERT_TRUE(missing);
    EXPECT_FALSE(missing.value());
    auto unchanged = run(executor.value()->rehashAsync(fnd::SecretString{"fixture-password"}, hash.value()));
    ASSERT_TRUE(unchanged);
    EXPECT_FALSE(unchanged->has_value());
}

TEST(BoundedPasswordExecutorTest, PolicyUpgradeRequiresVerifiedOriginalPassword)
{
    const auto oldPolicy = cred::PasswordPolicy::create(1024U, 8U, 1U, 16U, 32U, 2U * 1024U * 1024U);
    const auto newPolicy = cred::PasswordPolicy::create(2048U, 8U, 1U, 16U, 32U, 4U * 1024U * 1024U);
    ASSERT_TRUE(oldPolicy && newPolicy);
    auto oldHasher = cred::PasswordHasher::create(fnd::SecretString{std::string(32U, 'p')}, oldPolicy.value());
    auto newHasher = cred::PasswordHasher::create(fnd::SecretString{std::string(32U, 'p')}, newPolicy.value());
    ASSERT_TRUE(oldHasher && newHasher);
    auto hash = oldHasher->hash(fnd::SecretString{"fixture-password"});
    ASSERT_TRUE(hash);
    auto executor = cred::BoundedPasswordExecutor::create(std::move(newHasher).value(), 1U);
    ASSERT_TRUE(executor);
    asio::io_context io;
    auto run = [&]<typename T>(asio::awaitable<T> pending) {
        io.restart();
        auto complete = asio::co_spawn(io, std::move(pending), asio::use_future);
        io.run();
        return complete.get();
    };
    auto denied = run(executor.value()->rehashAsync(fnd::SecretString{"incorrect-password"}, hash.value()));
    ASSERT_FALSE(denied);
    EXPECT_EQ(denied.error().code(), fnd::ErrorCode::AuthenticationFailed);
    auto upgraded = run(executor.value()->rehashAsync(fnd::SecretString{"fixture-password"}, hash.value()));
    ASSERT_TRUE(upgraded && upgraded->has_value());
    EXPECT_NE(upgraded->value().encoded(), hash->encoded());
    auto accepted = run(executor.value()->verifyAsync(fnd::SecretString{"fixture-password"}, upgraded->value()));
    ASSERT_TRUE(accepted);
    EXPECT_TRUE(accepted.value());
}

TEST(BoundedPasswordExecutorTest, RejectsUnboundedWorkerConfiguration)
{
    auto hasher = cred::PasswordHasher::create(fnd::SecretString{std::string(32U, 'p')},
                                              cred::PasswordPolicy::recommended());
    ASSERT_TRUE(hasher);
    auto invalid = cred::BoundedPasswordExecutor::create(std::move(hasher).value(), 3U);
    ASSERT_FALSE(invalid);
    EXPECT_EQ(invalid.error().code(), fnd::ErrorCode::InvalidArgument);
}
}

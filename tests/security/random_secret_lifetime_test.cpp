#include <gtest/gtest.h>

#include <cstddef>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

import openproof.foundation;
import openproof.security;

namespace {
namespace foundation = openproof::foundation;
namespace security = openproof::security;

TEST(SecurityRngLifetimeTest, FreshTokensAreUrlSafeAndHaveExpectedEntropyLength)
{
    std::set<std::string> seen;
    for (std::size_t index = 0; index < 16U; ++index) {
        auto token = security::randomTokenBase64Url(32U);
        ASSERT_TRUE(token.has_value());
        EXPECT_EQ(token->size(), 43U);
        EXPECT_TRUE(seen.insert(token.value()).second);
        for (char ch : token.value()) {
            EXPECT_TRUE((ch >= 'a' && ch <= 'z')
                || (ch >= 'A' && ch <= 'Z')
                || (ch >= '0' && ch <= '9')
                || ch == '-' || ch == '_');
        }
    }
}

TEST(SecurityRngLifetimeTest, EmptyTokenRequestCannotAccessInvalidEntropyBuffer)
{
    auto token = security::randomTokenBase64Url(0U);
    ASSERT_TRUE(token.has_value());
    EXPECT_TRUE(token->empty());
    auto raw = security::randomBytes(0U);
    ASSERT_TRUE(raw.has_value());
    EXPECT_TRUE(raw->empty());
}

TEST(SecurityRngLifetimeTest, RejectsImpossibleEntropyWithoutAllocating)
{
    auto raw = security::randomBytes(
        std::numeric_limits<std::size_t>::max());
    ASSERT_FALSE(raw.has_value());
    EXPECT_EQ(raw.error().code(), foundation::ErrorCode::InvalidArgument);
}

TEST(SecurityRngLifetimeTest, ScopedRawEntropyCanBeWipedThroughSecretWrapper)
{
    auto raw = security::randomBytes(32U);
    ASSERT_TRUE(raw.has_value());
    foundation::Secret<std::vector<std::byte>> entropy{
        std::move(raw).value()};
    EXPECT_EQ(entropy.expose().size(), 32U);
    // The same RAII wrapper owns the transient material in the production
    // Base64URL converter. Its destructor invokes foundation::secureWipe.
}
} // namespace

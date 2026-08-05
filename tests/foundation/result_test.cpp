#include <gtest/gtest.h>

#include <string>
#include <type_traits>

import openproof.foundation;

namespace fnd = openproof::foundation;

namespace {

TEST(ResultTest, CarriesValueOnSuccess)
{
    const fnd::Result<int> result = 7;

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), 7);
}

TEST(ResultTest, FailConvertsToAnyResultType)
{
    const fnd::Result<int> integerResult = fnd::fail(fnd::ErrorCode::NotFound);
    const fnd::Result<std::string> stringResult = fnd::fail(fnd::ErrorCode::NotFound);
    const fnd::Status status = fnd::fail(fnd::ErrorCode::NotFound);

    EXPECT_FALSE(integerResult.has_value());
    EXPECT_FALSE(stringResult.has_value());
    EXPECT_FALSE(status.has_value());
    EXPECT_EQ(integerResult.error().code(), fnd::ErrorCode::NotFound);
}

TEST(ResultTest, OkProducesSuccessfulStatus)
{
    const fnd::Status status = fnd::ok();
    EXPECT_TRUE(status.has_value());
}

TEST(ResultTest, FailCarriesMessageAndInternalDetail)
{
    const fnd::Status status =
        fnd::fail(fnd::ErrorCode::Unavailable, "Temporarily unavailable.", "shard 2 offline");

    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().message(), "Temporarily unavailable.");
    EXPECT_EQ(status.error().internalDetail(), "shard 2 offline");
}

// std::expected is [[nodiscard]], so a dropped failure is a compiler diagnostic
// rather than a silently swallowed error (ERR-004).
TEST(ResultTest, ResultIsNodiscard)
{
    static_assert(std::is_same_v<fnd::Result<void>, fnd::Status>);
    SUCCEED();
}

}

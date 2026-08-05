#include <gtest/gtest.h>

#include <chrono>
#include <string>

import openproof.foundation;

namespace fnd = openproof::foundation;

namespace {

constexpr fnd::Instant kEpoch{std::chrono::milliseconds{0}};

TEST(TimeTest, FormatsEpochAsRfc3339Utc)
{
    EXPECT_EQ(fnd::toIso8601(kEpoch), "1970-01-01T00:00:00.000Z");
}

TEST(TimeTest, FormatsMillisecondPrecision)
{
    const fnd::Instant instant{std::chrono::milliseconds{1'770'000'123'456}};
    const std::string formatted = fnd::toIso8601(instant);

    EXPECT_EQ(formatted.size(), 24U);
    EXPECT_EQ(formatted.back(), 'Z');
    EXPECT_EQ(formatted.substr(19), ".456Z");
}

TEST(TimeTest, ManualClockDoesNotAdvanceOnItsOwn)
{
    const fnd::ManualClockSource clock{kEpoch};

    EXPECT_EQ(clock.now(), kEpoch);
    EXPECT_EQ(clock.now(), kEpoch);
}

TEST(TimeTest, ManualClockAdvancesByExactlyTheRequestedAmount)
{
    fnd::ManualClockSource clock{kEpoch};

    clock.advance(std::chrono::milliseconds{1500});
    EXPECT_EQ(clock.now(), kEpoch + std::chrono::milliseconds{1500});

    clock.advance(std::chrono::milliseconds{500});
    EXPECT_EQ(clock.now(), kEpoch + std::chrono::milliseconds{2000});
}

TEST(TimeTest, ManualClockCanBeSetAbsolutely)
{
    fnd::ManualClockSource clock{kEpoch};
    const fnd::Instant target{std::chrono::milliseconds{1'770'000'000'000}};

    clock.set(target);
    EXPECT_EQ(clock.now(), target);
}

TEST(TimeTest, SystemClockIsMonotonicallyReadable)
{
    const fnd::SystemClockSource clock;

    const fnd::Instant first = clock.now();
    const fnd::Instant second = clock.now();

    EXPECT_GE(second, first);
    EXPECT_GT(first, kEpoch);
}

// The clock is injected so that expiry, nonce windows and session lifetimes can
// be tested without sleeping.
TEST(TimeTest, ClockSourceIsUsableThroughItsInterface)
{
    fnd::ManualClockSource concrete{kEpoch};
    const fnd::ClockSource& injected = concrete;

    concrete.advance(std::chrono::milliseconds{10});
    EXPECT_EQ(injected.now(), kEpoch + std::chrono::milliseconds{10});
}

}

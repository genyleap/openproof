#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

import openproof.foundation;

namespace fnd = openproof::foundation;

namespace {

struct SessionIdTag {};
using SessionId = fnd::StrongId<SessionIdTag>;

struct OrganizationIdTag {};
using OrganizationId = fnd::StrongId<OrganizationIdTag>;

// Primitive obsession is the defect this type exists to prevent: two identifiers
// that are both "a string" must not be interchangeable, or a handler will
// eventually pass an organization key where a session key belongs.
static_assert(!std::is_same_v<SessionId, OrganizationId>);
static_assert(!std::is_convertible_v<SessionId, OrganizationId>);
static_assert(!std::is_convertible_v<std::string, SessionId>,
              "StrongId construction must be explicit.");

TEST(StrongIdTest, DefaultConstructsEmpty)
{
    const SessionId id;
    EXPECT_TRUE(id.empty());
    EXPECT_EQ(id.value(), "");
}

TEST(StrongIdTest, CarriesItsValueVerbatim)
{
    const SessionId id{"sess_01H..."};

    EXPECT_EQ(id.value(), "sess_01H...");
    EXPECT_EQ(id.str(), "sess_01H...");
    EXPECT_FALSE(id.empty());
}

TEST(StrongIdTest, ComparesByValue)
{
    const SessionId left{"a"};
    const SessionId right{"a"};
    const SessionId other{"b"};

    EXPECT_EQ(left, right);
    EXPECT_NE(left, other);
    EXPECT_LT(left, other);
}

TEST(StrongIdTest, WorksAsAnUnorderedContainerKey)
{
    std::unordered_map<SessionId, int> sessions;
    sessions.emplace(SessionId{"one"}, 1);
    sessions.emplace(SessionId{"two"}, 2);

    EXPECT_EQ(sessions.at(SessionId{"one"}), 1);
    EXPECT_EQ(sessions.at(SessionId{"two"}), 2);
    EXPECT_EQ(sessions.count(SessionId{"three"}), 0U);
}

TEST(StrongIdTest, WorksAsAnOrderedContainerKey)
{
    std::vector<SessionId> ids{SessionId{"c"}, SessionId{"a"}, SessionId{"b"}};
    std::sort(ids.begin(), ids.end());

    EXPECT_EQ(ids.front().value(), "a");
    EXPECT_EQ(ids.back().value(), "c");
}

TEST(StrongIdTest, PlatformIdentifiersAreDistinctTypes)
{
    static_assert(!std::is_same_v<fnd::RequestId, fnd::CorrelationId>);

    const fnd::RequestId requestId{"req-1"};
    const fnd::CorrelationId correlationId{"corr-1"};

    EXPECT_EQ(requestId.value(), "req-1");
    EXPECT_EQ(correlationId.value(), "corr-1");
}

}

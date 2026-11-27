#include <gtest/gtest.h>
#include "../../apps/opp/runtime_capacity.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {
namespace capacity = openproof::app::runtime_capacity;

TEST(RuntimeCapacityTest, StrictQuotaParsingAndBoundedWorkers)
{
    EXPECT_EQ(capacity::quotaWorkers("200000", "100000"), 2U);
    EXPECT_EQ(capacity::quotaWorkers("150000", "100000"), 2U);
    EXPECT_EQ(capacity::quotaWorkers("1", "100000"), 1U);
    EXPECT_FALSE(capacity::quotaWorkers("max", "100000"));
    EXPECT_FALSE(capacity::quotaWorkers("1000", "0"));
    EXPECT_FALSE(capacity::quotaWorkers("-1", "100000"));
    EXPECT_FALSE(capacity::quotaWorkers("1000x", "100000"));
    EXPECT_FALSE(capacity::positiveCount({}));
    EXPECT_FALSE(capacity::positiveCount("99999999999999999999999999999999"));
    EXPECT_EQ(capacity::effectiveWorkers(64U, 8U, 2U), 2U);
    EXPECT_EQ(capacity::effectiveWorkers(64U, std::nullopt, std::nullopt), 32U);
    EXPECT_EQ(capacity::effectiveWorkers(0U, std::nullopt, std::nullopt), 2U);
    EXPECT_EQ(capacity::effectiveWorkers(8U, 1U, 3U), 1U);
}

TEST(RuntimeCapacityTest, TightestCgroupAncestorWinsAndTraversalIsRejected)
{
    const auto prefix = (std::filesystem::temp_directory_path()
        / "openproof-capacity-XXXXXX").string();
    std::vector<char> buffer(prefix.begin(), prefix.end());
    buffer.push_back('\0');
    const char* directory = ::mkdtemp(buffer.data());
    ASSERT_NE(directory, nullptr);
    struct Cleanup final {
        std::filesystem::path root;
        ~Cleanup() { std::error_code error; std::filesystem::remove_all(root, error); }
    } fixture{directory};
    std::filesystem::create_directories(fixture.root / "a/b");
    std::ofstream{fixture.root / "cgroup.controllers"} << "cpu";
    std::ofstream{fixture.root / "cpu.max"} << "400000 100000\n";
    std::ofstream{fixture.root / "a/cpu.max"} << "150000 100000\n";
    std::ofstream{fixture.root / "a/b/cpu.max"} << "max 100000\n";
    EXPECT_EQ(capacity::hierarchyQuota(fixture.root, "a/b"), 2U);
    EXPECT_EQ(capacity::hierarchyQuota(fixture.root, ""), 4U);
    EXPECT_FALSE(capacity::hierarchyQuota(fixture.root, "../escape"));
    EXPECT_FALSE(capacity::hierarchyQuota(fixture.root, "/absolute"));
    EXPECT_FALSE(capacity::hierarchyQuota(fixture.root, "missing"));
}
}

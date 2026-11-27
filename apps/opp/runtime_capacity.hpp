#pragma once

// Startup-only deployment capacity discovery. No filesystem work on an
// HTTP reactor. Linux cgroup v2 discovery is best effort for the conventional
// mount; missing or inaccessible quotas never invent a CPU restriction.
#include <algorithm>
#include <charconv>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#if defined(__linux__)
#include <sched.h>
#endif

namespace openproof::app::runtime_capacity {

[[nodiscard]] inline std::optional<std::size_t> positiveCount(
    std::string_view value) noexcept
{
    std::size_t count{};
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), count);
    if (value.empty() || parsed.ec != std::errc{}
        || parsed.ptr != value.data() + value.size() || count == 0U)
        return std::nullopt;
    return count;
}

// cpu.max: quota and period in microseconds. "max" is unlimited.
// Round a fractional core up (at least one worker), never overflow.
[[nodiscard]] inline std::optional<std::size_t> quotaWorkers(
    std::string_view quota, std::string_view period) noexcept
{
    const auto limit = positiveCount(quota);
    const auto interval = positiveCount(period);
    if (!limit || !interval) return std::nullopt;
    return *limit / *interval + static_cast<std::size_t>(*limit % *interval != 0U);
}

[[nodiscard]] inline std::size_t effectiveWorkers(
    std::size_t hardware, std::optional<std::size_t> affinity,
    std::optional<std::size_t> quota) noexcept
{
    auto count = hardware == 0U ? 2U : hardware;
    if (affinity && *affinity > 0U) count = std::min(count, *affinity);
    if (quota && *quota > 0U) count = std::min(count, *quota);
    return std::clamp<std::size_t>(count, 1U, 32U);
}

// Walk from the process's cgroup to its ancestors, applying the tightest
// finite limit. Refuse traversal and cap the number of filesystem reads.
// A cgroup namespace whose mount root is not visible falls back to affinity.
[[nodiscard]] inline std::optional<std::size_t> hierarchyQuota(
    const std::filesystem::path& root, const std::filesystem::path& relative)
{
    if (relative.is_absolute()) return std::nullopt;
    std::size_t depth{};
    for (const auto& part : relative) {
        if (part == ".." || part == "." || ++depth > 64U) return std::nullopt;
    }
    std::error_code error;
    if (!std::filesystem::is_regular_file(root / "cgroup.controllers", error))
        return std::nullopt;
    auto current = root / relative;
    if (relative.empty()) current = root;
    if (!std::filesystem::is_directory(current, error)) return std::nullopt;
    std::optional<std::size_t> tightest;
    for (;;) {
        std::ifstream input{current / "cpu.max"};
        std::string quota, period, extra;
        if (input >> quota >> period && !(input >> extra)) {
            if (const auto cap = quotaWorkers(quota, period))
                tightest = tightest ? std::min(*tightest, *cap) : *cap;
        }
        if (current == root) break;
        const auto parent = current.parent_path();
        if (parent == current || parent.empty()) return std::nullopt;
        current = parent;
    }
    return tightest;
}

struct Capacity final {
    std::optional<std::size_t> affinity;
    std::optional<std::size_t> quota;
    std::size_t workers;
};

[[nodiscard]] inline Capacity detect(std::size_t hardware)
{
    std::optional<std::size_t> affinity, quota;
#if defined(__linux__)
    cpu_set_t mask;
    CPU_ZERO(&mask);
    if (::sched_getaffinity(0, sizeof(mask), &mask) == 0) {
        const auto count = CPU_COUNT(&mask);
        if (count > 0) affinity = static_cast<std::size_t>(count);
    }
    // A unified cgroup membership is 0::<absolute path>. The conventional
    // v2 mount is explicitly checked by hierarchyQuota; v1/nonstandard
    // layouts are not guessed.
    std::ifstream memberships{"/proc/self/cgroup"};
    std::string line;
    while (std::getline(memberships, line)) {
        if (line.starts_with("0::/")) {
            const std::filesystem::path relative{line.substr(4)};
            quota = hierarchyQuota("/sys/fs/cgroup", relative);
            break;
        }
    }
#endif
    return Capacity{affinity, quota, effectiveWorkers(hardware, affinity, quota)};
}

} // namespace openproof::app::runtime_capacity

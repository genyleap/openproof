#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace {

constexpr std::size_t kMapSize = 1U << 16U;
std::array<std::uint8_t, kMapSize> coverage{};

}

extern "C" void __sanitizer_cov_trace_pc() noexcept
{
    const auto address = reinterpret_cast<std::uintptr_t>(
        __builtin_extract_return_addr(__builtin_return_address(0)));
    const std::size_t index = static_cast<std::size_t>(
        ((address >> 4U) ^ (address >> 20U)) & (kMapSize - 1U));
    coverage[index] = 1U;
}

namespace openproof::fuzzing {

void resetCoverage() noexcept
{
    coverage.fill(0U);
}

std::span<const std::uint8_t> currentCoverage() noexcept
{
    return coverage;
}

}

#pragma once

#include <algorithm>
#include <cstddef>
#include <ranges>
#include <string_view>

namespace openproof::provider::enterprise::detail {

inline constexpr std::size_t kDisplayNameMaximum = 256U;

[[nodiscard]] inline bool safePresentationText(
    std::string_view value, std::size_t maximum = kDisplayNameMaximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::none_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           });
}

} // namespace openproof::provider::enterprise::detail

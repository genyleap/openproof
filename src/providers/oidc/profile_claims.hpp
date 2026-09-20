#pragma once

#include <algorithm>
#include <cstddef>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>

namespace openproof::provider::oidc::detail {

[[nodiscard]] inline bool safeProfileText(
    std::string_view value, std::size_t maximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::none_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           });
}

[[nodiscard]] inline std::optional<std::string> displayName(
    std::optional<std::string_view> name,
    std::optional<std::string_view> givenName,
    std::optional<std::string_view> familyName)
{
    if (name && safeProfileText(*name, 512U)) {
        return std::string{*name};
    }

    const bool givenSafe = givenName && safeProfileText(*givenName, 256U);
    const bool familySafe = familyName && safeProfileText(*familyName, 256U);
    if (!givenSafe && !familySafe) return std::nullopt;

    std::string combined;
    if (givenSafe) combined.assign(*givenName);
    if (familySafe) {
        if (!combined.empty()) combined.push_back(' ');
        combined.append(*familyName);
    }
    if (!safeProfileText(combined, 512U)) return std::nullopt;
    return combined;
}

} // namespace openproof::provider::oidc::detail

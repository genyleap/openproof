#pragma once

#include <algorithm>
#include <cstddef>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>

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

[[nodiscard]] inline bool samlAudienceRestrictionsPermit(
    const std::vector<std::vector<std::string>>& restrictions,
    std::string_view expectedAudience) noexcept
{
    if (restrictions.empty() || expectedAudience.empty()) return false;
    return std::ranges::all_of(restrictions, [&](const auto& audiences) {
        return std::ranges::any_of(audiences, [&](const std::string& audience) {
            return audience == expectedAudience;
        });
    });
}

[[nodiscard]] inline bool validSamlEntityIssuer(
    std::string_view issuer,
    const std::optional<std::string>& format,
    std::string_view expectedIssuer) noexcept
{
    constexpr std::string_view kEntityFormat{
        "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"};
    return issuer == expectedIssuer
        && (!format || *format == kEntityFormat);
}

} // namespace openproof::provider::enterprise::detail

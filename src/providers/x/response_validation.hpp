#pragma once

#include <algorithm>
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <ranges>
#include <string_view>

namespace openproof::provider::x::detail {

constexpr std::size_t kSubjectMaximum = 128U;
constexpr std::size_t kPreferredUsernameMaximum = 128U;
constexpr std::size_t kDisplayNameMaximum = 256U;
constexpr std::size_t kPictureUrlMaximum = 2048U;
constexpr std::size_t kAccessTokenMaximum = 4096U;
constexpr std::size_t kScopeMaximum = 4096U;

[[nodiscard]] inline bool safeProfileText(
    std::string_view value, std::size_t maximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::none_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           });
}

[[nodiscard]] inline bool validBearerCredential(std::string_view value) noexcept
{
    if (value.empty() || value.size() > kAccessTokenMaximum) return false;
    bool padding = false;
    for (char symbol : value) {
        if (symbol == '=') {
            padding = true;
            continue;
        }
        if (padding) return false;
        const auto byte = static_cast<unsigned char>(symbol);
        const bool allowed = std::isalnum(byte) != 0
            || symbol == '-' || symbol == '.' || symbol == '_'
            || symbol == '~' || symbol == '+' || symbol == '/';
        if (!allowed) return false;
    }
    return true;
}

[[nodiscard]] inline bool validScopeResponse(std::string_view value) noexcept
{
    return !value.empty() && value.size() <= kScopeMaximum
        && std::ranges::all_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte >= 0x20U && byte <= 0x7EU;
           });
}

[[nodiscard]] inline bool hasScope(
    std::string_view granted, std::string_view expected) noexcept
{
    std::size_t begin = 0U;
    while (begin <= granted.size()) {
        const auto end = granted.find(' ', begin);
        const auto scope = granted.substr(
            begin, end == std::string_view::npos ? granted.size() - begin : end - begin);
        if (scope == expected) return true;
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    return false;
}

} // namespace openproof::provider::x::detail

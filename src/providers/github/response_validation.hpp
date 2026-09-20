#pragma once

#include <cctype>
#include <cstddef>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>

#include <boost/json.hpp>

namespace openproof::provider::github::detail {

constexpr std::size_t kPreferredUsernameMaximum = 128U;
constexpr std::size_t kDisplayNameMaximum = 256U;
constexpr std::size_t kEmailMaximum = 320U;
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
    return value.size() <= kScopeMaximum
        && std::ranges::all_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte >= 0x20U && byte <= 0x7EU;
           });
}

[[nodiscard]] inline bool hasEmailScope(std::string_view granted) noexcept
{
    std::size_t begin = 0U;
    while (begin <= granted.size()) {
        const auto end = granted.find_first_of(", ", begin);
        const auto scope = granted.substr(
            begin, end == std::string_view::npos ? granted.size() - begin : end - begin);
        if (scope == "user:email" || scope == "user") return true;
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    return false;
}

[[nodiscard]] inline bool plausibleEmail(std::string_view value) noexcept
{
    if (!safeProfileText(value, kEmailMaximum)
        || std::ranges::any_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte <= 0x20U || byte == 0x7FU;
           })) {
        return false;
    }
    const auto firstAt = value.find('@');
    return firstAt != std::string_view::npos
        && firstAt != 0U
        && firstAt + 1U < value.size()
        && firstAt == value.rfind('@');
}

[[nodiscard]] inline std::optional<std::string> uniqueVerifiedPrimaryEmail(
    const boost::json::array& values)
{
    std::optional<std::string> selected;
    for (const auto& item : values) {
        if (!item.is_object()) continue;
        const auto& object = item.as_object();
        const auto* primary = object.if_contains("primary");
        const auto* verified = object.if_contains("verified");
        if (primary == nullptr || verified == nullptr
            || !primary->is_bool() || !verified->is_bool()
            || !primary->as_bool() || !verified->as_bool()) {
            continue;
        }

        const auto* email = object.if_contains("email");
        if (email == nullptr || !email->is_string()) return std::nullopt;
        const std::string_view address{email->as_string().data(), email->as_string().size()};
        if (!plausibleEmail(address) || selected) return std::nullopt;
        selected = std::string{address};
    }
    return selected;
}

} // namespace openproof::provider::github::detail

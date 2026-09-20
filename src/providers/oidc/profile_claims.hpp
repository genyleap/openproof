#pragma once

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstddef>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>

#include <boost/json.hpp>

namespace openproof::provider::oidc::detail {

inline constexpr std::size_t kDisplayNameMaximum = 256U;
inline constexpr std::size_t kPreferredUsernameMaximum = 128U;
inline constexpr std::size_t kPictureUrlMaximum = 2048U;

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
    if (name && safeProfileText(*name, kDisplayNameMaximum)) {
        return std::string{*name};
    }

    const bool givenSafe = givenName && safeProfileText(*givenName, kDisplayNameMaximum);
    const bool familySafe = familyName && safeProfileText(*familyName, kDisplayNameMaximum);
    if (!givenSafe && !familySafe) return std::nullopt;

    std::string combined;
    if (givenSafe) combined.assign(*givenName);
    if (familySafe) {
        if (!combined.empty()) combined.push_back(' ');
        combined.append(*familyName);
    }
    if (!safeProfileText(combined, kDisplayNameMaximum)) return std::nullopt;
    return combined;
}

[[nodiscard]] inline bool validHttpsProfileUrl(std::string_view value) noexcept
{
    constexpr std::string_view scheme{"https://"};
    if (!value.starts_with(scheme) || value.size() > kPictureUrlMaximum
        || value.contains('#') || value.contains('\\')
        || std::ranges::any_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte <= 0x20U || byte == 0x7FU;
           })) {
        return false;
    }

    value.remove_prefix(scheme.size());
    const auto slash = value.find('/');
    const auto query = value.find('?');
    const auto authorityEnd = std::min(
        slash == std::string_view::npos ? value.size() : slash,
        query == std::string_view::npos ? value.size() : query);
    const auto authority = value.substr(0U, authorityEnd);
    if (authority.empty() || authority.contains('@')
        || authority.contains('[') || authority.contains(']')) {
        return false;
    }

    std::string_view host = authority;
    if (const auto colon = authority.rfind(':'); colon != std::string_view::npos) {
        host = authority.substr(0U, colon);
        const auto portText = authority.substr(colon + 1U);
        unsigned int port{};
        const auto parsed = std::from_chars(
            portText.data(), portText.data() + portText.size(), port);
        if (portText.empty() || parsed.ec != std::errc{}
            || parsed.ptr != portText.data() + portText.size()
            || port == 0U || port > 65535U) {
            return false;
        }
    }

    if (!safeProfileText(host, 253U) || host.contains(':')) return false;
    return authorityEnd == value.size()
        || value[authorityEnd] == '/' || value[authorityEnd] == '?';
}

[[nodiscard]] inline bool knownCredentialedProfilePictureUrl(
    std::string_view value) noexcept
{
    constexpr std::string_view scheme{"https://"};
    if (!value.starts_with(scheme)) return false;
    value.remove_prefix(scheme.size());

    const auto authorityEnd = value.find_first_of("/?");
    auto authority = value.substr(
        0U, authorityEnd == std::string_view::npos ? value.size() : authorityEnd);
    if (const auto colon = authority.rfind(':'); colon != std::string_view::npos) {
        authority = authority.substr(0U, colon);
    }
    constexpr std::string_view graphHost{"graph.microsoft.com"};
    if (authority.size() != graphHost.size()) return false;
    for (std::size_t index = 0U; index < authority.size(); ++index) {
        if (static_cast<char>(
                std::tolower(static_cast<unsigned char>(authority[index])))
            != graphHost[index]) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] inline bool validPresentationPictureUrl(
    std::string_view value) noexcept
{
    return validHttpsProfileUrl(value)
        && !knownCredentialedProfilePictureUrl(value);
}

[[nodiscard]] inline bool validBearerAccessToken(std::string_view value) noexcept
{
    if (value.empty() || value.size() > 4096U) return false;

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

[[nodiscard]] inline bool bearerTokenType(std::string_view value) noexcept
{
    constexpr std::string_view expected{"bearer"};
    if (value.size() != expected.size()) return false;
    for (std::size_t index = 0U; index < value.size(); ++index) {
        if (static_cast<char>(
                std::tolower(static_cast<unsigned char>(value[index])))
            != expected[index]) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] inline bool userInfoSubjectMatches(
    const boost::json::object& userInfo, std::string_view expectedSubject) noexcept
{
    const auto* value = userInfo.if_contains("sub");
    if (value == nullptr || !value->is_string()) return false;
    const std::string_view subject{
        value->as_string().data(), value->as_string().size()};
    return subject == expectedSubject;
}

} // namespace openproof::provider::oidc::detail

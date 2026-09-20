#pragma once

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>

namespace openproof::authentication::http::detail {

[[nodiscard]] inline bool safePresentationText(
    std::string_view value, std::size_t maximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::none_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           });
}

[[nodiscard]] inline std::optional<std::string> presentationText(
    std::optional<std::string> value, std::size_t maximum)
{
    if (!value || !safePresentationText(*value, maximum)) return std::nullopt;
    return value;
}

[[nodiscard]] inline bool validHttpsPresentationUrl(std::string_view value) noexcept
{
    constexpr std::string_view scheme{"https://"};
    if (!value.starts_with(scheme) || value.size() > 2048U
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
    if (!safePresentationText(host, 253U) || host.contains(':')) return false;
    return authorityEnd == value.size()
        || value[authorityEnd] == '/' || value[authorityEnd] == '?';
}

[[nodiscard]] inline std::optional<std::string> presentationPictureUrl(
    std::optional<std::string> value)
{
    if (!value || !validHttpsPresentationUrl(*value)) return std::nullopt;
    return value;
}

} // namespace openproof::authentication::http::detail

#pragma once

#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>

#include <boost/json.hpp>

namespace openproof::provider::oidc::detail {

[[nodiscard]] inline bool authorizedPartyMatches(
    std::optional<std::string_view> authorizedParty,
    std::string_view clientId) noexcept
{
    return !authorizedParty || *authorizedParty == clientId;
}

[[nodiscard]] inline bool jwkPermitsRs256Verification(
    const boost::json::object& key, std::string_view expectedKeyId)
{
    const auto requiredString = [&key](
        std::string_view name, std::string_view expected) {
        const auto* value = key.if_contains(name);
        return value != nullptr && value->is_string()
            && std::string_view{value->as_string().data(), value->as_string().size()}
                == expected;
    };
    const auto optionalStringMatches = [&key](
        std::string_view name, std::string_view expected) {
        const auto* value = key.if_contains(name);
        return value == nullptr
            || (value->is_string()
                && std::string_view{value->as_string().data(), value->as_string().size()}
                    == expected);
    };

    if (!requiredString("kid", expectedKeyId)
        || !requiredString("kty", "RSA")
        || !optionalStringMatches("alg", "RS256")
        || !optionalStringMatches("use", "sig")) {
        return false;
    }

    const auto* operations = key.if_contains("key_ops");
    if (operations == nullptr) return true;
    if (!operations->is_array()) return false;

    bool permitsVerification = false;
    std::vector<std::string> seen;
    seen.reserve(operations->as_array().size());
    for (const auto& operation : operations->as_array()) {
        if (!operation.is_string() || operation.as_string().empty()
            || operation.as_string().size() > 128U) {
            return false;
        }
        std::string value{operation.as_string()};
        if (std::ranges::find(seen, value) != seen.end()) return false;
        if (value == "verify") permitsVerification = true;
        seen.push_back(std::move(value));
    }
    return permitsVerification;
}

[[nodiscard]] inline bool discoveryAdvertisesRs256IdTokens(
    const boost::json::object& metadata)
{
    const auto* algorithms = metadata.if_contains(
        "id_token_signing_alg_values_supported");
    if (algorithms == nullptr || !algorithms->is_array()
        || algorithms->as_array().empty()) {
        return false;
    }

    bool hasRs256 = false;
    for (const auto& algorithm : algorithms->as_array()) {
        if (!algorithm.is_string() || algorithm.as_string().empty()
            || algorithm.as_string().size() > 128U) {
            return false;
        }
        const std::string_view value{
            algorithm.as_string().data(), algorithm.as_string().size()};
        if (value == "RS256") hasRs256 = true;
    }
    return hasRs256;
}

[[nodiscard]] inline bool discoverySupportsAuthorizationCodeFlow(
    const boost::json::object& metadata)
{
    const auto contains = [](const boost::json::value* field,
                             std::string_view required,
                             bool optional) {
        if (field == nullptr) return optional;
        if (!field->is_array() || field->as_array().empty()) return false;

        bool found = false;
        for (const auto& item : field->as_array()) {
            if (!item.is_string() || item.as_string().empty()
                || item.as_string().size() > 128U) {
                return false;
            }
            const std::string_view value{
                item.as_string().data(), item.as_string().size()};
            if (value == required) found = true;
        }
        return found;
    };

    return contains(metadata.if_contains("response_types_supported"), "code", false)
        && contains(metadata.if_contains("grant_types_supported"),
                    "authorization_code", true);
}

} // namespace openproof::provider::oidc::detail

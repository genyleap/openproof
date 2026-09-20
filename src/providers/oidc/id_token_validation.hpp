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

} // namespace openproof::provider::oidc::detail

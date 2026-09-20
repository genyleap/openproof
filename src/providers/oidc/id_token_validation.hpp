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

[[nodiscard]] inline bool validSubjectIdentifier(std::string_view subject) noexcept
{
    return !subject.empty() && subject.size() <= 255U
        && std::ranges::all_of(subject, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte >= 0x20U && byte <= 0x7EU;
           });
}

[[nodiscard]] inline bool audienceMatchesClientExclusively(
    const boost::json::object& payload, std::string_view clientId)
{
    const auto* audience = payload.if_contains("aud");
    if (audience == nullptr) return false;
    if (audience->is_string()) {
        const auto& value = audience->as_string();
        return std::string_view{value.data(), value.size()} == clientId;
    }
    if (!audience->is_array() || audience->as_array().size() != 1U) {
        return false;
    }
    const auto& value = audience->as_array().front();
    if (!value.is_string()) return false;
    const auto& text = value.as_string();
    return std::string_view{text.data(), text.size()} == clientId;
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

[[nodiscard]] inline bool discoveryOptionalArraySupports(
    const boost::json::object& metadata, std::string_view fieldName,
    std::string_view required)
{
    const auto* field = metadata.if_contains(fieldName);
    if (field == nullptr) return true;
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
}

[[nodiscard]] inline bool discoverySupportsResponseMode(
    const boost::json::object& metadata, std::string_view required)
{
    const auto* field = metadata.if_contains("response_modes_supported");
    if (field == nullptr) {
        return required == "query" || required == "fragment";
    }
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
}

[[nodiscard]] inline bool discoveryHasSupportedSubjectType(
    const boost::json::object& metadata)
{
    const auto* field = metadata.if_contains("subject_types_supported");
    if (field == nullptr || !field->is_array() || field->as_array().empty()) {
        return false;
    }

    bool supported = false;
    for (const auto& item : field->as_array()) {
        if (!item.is_string() || item.as_string().empty()
            || item.as_string().size() > 128U) {
            return false;
        }
        const std::string_view value{
            item.as_string().data(), item.as_string().size()};
        if (value == "public" || value == "pairwise") supported = true;
    }
    return supported;
}

[[nodiscard]] inline bool accessTokenHashClaimMatches(
    const boost::json::object& payload, std::string_view expected) noexcept
{
    const auto* value = payload.if_contains("at_hash");
    if (value == nullptr) return true;
    if (!value->is_string() || value->as_string().empty()
        || value->as_string().size() > 128U) {
        return false;
    }
    const std::string_view claimed{
        value->as_string().data(), value->as_string().size()};
    return claimed == expected;
}

[[nodiscard]] inline bool joseHeaderUsesSupportedExtensions(
    const boost::json::object& header) noexcept
{
    return !header.contains("crit") && !header.contains("b64");
}

struct Rs256VerificationKey final {
    std::string modulus;
    std::string exponent;
};

[[nodiscard]] inline std::optional<Rs256VerificationKey>
uniqueRs256VerificationKey(const boost::json::array& keys,
                           std::string_view expectedKeyId)
{
    std::optional<Rs256VerificationKey> selected;
    for (const auto& value : keys) {
        if (!value.is_object()) continue;
        const auto& key = value.as_object();
        if (!jwkPermitsRs256Verification(key, expectedKeyId)) continue;

        const auto* modulus = key.if_contains("n");
        const auto* exponent = key.if_contains("e");
        if (modulus == nullptr || exponent == nullptr
            || !modulus->is_string() || !exponent->is_string()
            || modulus->as_string().empty() || exponent->as_string().empty()
            || modulus->as_string().size() > 2048U
            || exponent->as_string().size() > 128U) {
            return std::nullopt;
        }

        Rs256VerificationKey candidate{
            std::string{modulus->as_string()},
            std::string{exponent->as_string()}};
        if (selected) {
            return std::nullopt;
        }
        selected = std::move(candidate);
    }
    return selected;
}

} // namespace openproof::provider::oidc::detail

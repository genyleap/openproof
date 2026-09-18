module;

#include <optional>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.oidc;

import openproof.identity.provider;

namespace openproof::oidc {
namespace {

[[nodiscard]] bool validPort(std::string_view value) noexcept
{
    if (value.empty() || value.size() > 5U) return false;
    unsigned int port = 0U;
    for (char symbol : value) {
        if (symbol < '0' || symbol > '9') return false;
        port = (port * 10U) + static_cast<unsigned int>(symbol - '0');
    }
    return port > 0U && port <= 65535U;
}

[[nodiscard]] bool validIssuerAuthority(
    std::string_view value, std::string_view scheme, bool loopbackOnly) noexcept
{
    if (!value.starts_with(scheme)) return false;
    const auto rest = value.substr(scheme.size());
    const auto end = rest.find('/');
    const auto authority = rest.substr(0U, end);
    if (authority.empty() || authority.contains('@')) return false;

    std::string_view host;
    std::string_view port;
    if (authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == std::string_view::npos) return false;
        host = authority.substr(0U, close + 1U);
        if (close + 1U < authority.size()) {
            if (authority[close + 1U] != ':') return false;
            port = authority.substr(close + 2U);
            if (!validPort(port)) return false;
        }
    } else {
        const auto colon = authority.rfind(':');
        if (colon == std::string_view::npos) {
            host = authority;
        } else {
            host = authority.substr(0U, colon);
            port = authority.substr(colon + 1U);
            if (host.empty() || host.contains(':') || !validPort(port)) return false;
        }
    }
    if (host.empty()) return false;
    if (!loopbackOnly) return true;
    return host == "127.0.0.1" || host == "localhost" || host == "[::1]";
}

[[nodiscard]] bool validIssuerUri(std::string_view value) noexcept
{
    return validIssuerAuthority(value, "https://", false)
        || validIssuerAuthority(value, "http://", true);
}

[[nodiscard]] std::string q(std::string_view value)
{
    return std::string{"\""} + foundation::escapeJsonString(value) + "\"";
}

[[nodiscard]] std::int64_t seconds(foundation::Instant instant) noexcept
{
    return std::chrono::duration_cast<std::chrono::seconds>(
        instant.time_since_epoch()).count();
}

[[nodiscard]] std::string amrJson(const oauth::RedeemedAuthorization& authorization)
{
    std::string result{"["};
    bool comma = false;
    auto append = [&](std::string_view value) {
        if (comma) result.push_back(',');
        result.append(q(value));
        comma = true;
    };
    const auto& strength = authorization.strength();
    const auto factors = strength.factors();
    if (identity::provider::containsFactor(
            factors, identity::provider::AuthenticationFactor::Knowledge)) {
        append("pwd");
    }
    if (identity::provider::containsFactor(
            factors, identity::provider::AuthenticationFactor::Possession)) {
        append("otp");
    }
    if (identity::provider::containsFactor(
            factors, identity::provider::AuthenticationFactor::Inherence)) {
        append("bio");
    }
    if (strength.isPhishingResistant()) append("phr");
    result.push_back(']');
    return result;
}

[[nodiscard]] std::string joinUrl(std::string_view issuer, std::string_view path)
{
    return std::string{issuer} + std::string{path};
}

}

Issuer::Issuer(const Issuer& other) : m_value(other.m_value) {}
Issuer::Issuer(Issuer&& other) : m_value(std::move(other.m_value)) {}
Issuer& Issuer::operator=(const Issuer& other)
{
    if (this != &other) m_value = other.m_value;
    return *this;
}
Issuer& Issuer::operator=(Issuer&& other)
{
    if (this != &other) m_value = std::move(other.m_value);
    return *this;
}
Issuer::~Issuer() {}

OidcPolicy::OidcPolicy(const OidcPolicy& other)
    : m_idTokenLifetime(other.m_idTokenLifetime) {}
OidcPolicy::OidcPolicy(OidcPolicy&& other)
    : m_idTokenLifetime(other.m_idTokenLifetime) {}
OidcPolicy& OidcPolicy::operator=(const OidcPolicy& other)
{
    if (this != &other) m_idTokenLifetime = other.m_idTokenLifetime;
    return *this;
}
OidcPolicy& OidcPolicy::operator=(OidcPolicy&& other)
{
    if (this != &other) m_idTokenLifetime = other.m_idTokenLifetime;
    return *this;
}
OidcPolicy::~OidcPolicy() {}

PublishedVerificationJwk::PublishedVerificationJwk(
    const PublishedVerificationJwk& other) : m_json(other.m_json) {}
PublishedVerificationJwk::PublishedVerificationJwk(
    PublishedVerificationJwk&& other) : m_json(std::move(other.m_json)) {}
PublishedVerificationJwk& PublishedVerificationJwk::operator=(
    const PublishedVerificationJwk& other)
{
    if (this != &other) m_json = other.m_json;
    return *this;
}
PublishedVerificationJwk& PublishedVerificationJwk::operator=(
    PublishedVerificationJwk&& other)
{
    if (this != &other) m_json = std::move(other.m_json);
    return *this;
}
PublishedVerificationJwk::~PublishedVerificationJwk() {}

PublishedVerificationJwk::PublishedVerificationJwk(std::string json)
    : m_json(std::move(json)) {}

foundation::Result<PublishedVerificationJwk> PublishedVerificationJwk::create(
    std::string_view publicKeyPem, std::string keyId)
{
    auto jwk = security::rsaPublicJwkJson(publicKeyPem, std::move(keyId));
    if (!jwk) return foundation::fail(jwk.error());
    return PublishedVerificationJwk{std::move(jwk).value()};
}

Issuer::Issuer(std::string value) : m_value(std::move(value)) {}
foundation::Result<Issuer> Issuer::create(std::string value)
{
    if (value.empty() || value.size() > 512U || value.back() == '/'
        || value.contains('#') || value.contains('?')
        || !validIssuerUri(value)
        || std::ranges::any_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte <= 0x20U || byte == 0x7FU || symbol == '\\';
           })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The OpenID Provider issuer is invalid.");
    }
    return Issuer{std::move(value)};
}
std::string_view Issuer::value() const noexcept { return m_value; }

OidcPolicy::OidcPolicy(foundation::Duration lifetime) : m_idTokenLifetime(lifetime) {}
foundation::Result<OidcPolicy> OidcPolicy::create(foundation::Duration lifetime)
{
    if (lifetime <= foundation::Duration::zero() || lifetime > std::chrono::hours{1}) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The ID Token lifetime is invalid.");
    }
    return OidcPolicy{lifetime};
}
foundation::Duration OidcPolicy::idTokenLifetime() const noexcept { return m_idTokenLifetime; }

OpenIdProvider::OpenIdProvider(
    Issuer issuer, const foundation::ClockSource& clock,
    security::RsaSha256Signer signer,
    identity::profile::IdentityProfileRepository& profiles, OidcPolicy policy,
    std::vector<PublishedVerificationJwk> publishedVerificationJwks)
    : m_issuer(std::move(issuer)), m_clock(&clock), m_signer(std::move(signer)),
      m_publishedVerificationJwks(std::move(publishedVerificationJwks)),
      m_profiles(&profiles), m_policy(policy) {}

std::string OpenIdProvider::discoveryDocument() const
{
    const auto issuer = m_issuer.value();
    return std::string{"{"}
        + "\"issuer\":" + q(issuer)
        + ",\"authorization_endpoint\":" + q(joinUrl(issuer, "/oauth/authorize"))
        + ",\"token_endpoint\":" + q(joinUrl(issuer, "/oauth/token"))
        + ",\"pushed_authorization_request_endpoint\":" + q(joinUrl(issuer, "/oauth/par"))
        + ",\"device_authorization_endpoint\":" + q(joinUrl(issuer, "/oauth/device_authorization"))
        + ",\"userinfo_endpoint\":" + q(joinUrl(issuer, "/oauth/userinfo"))
        + ",\"revocation_endpoint\":" + q(joinUrl(issuer, "/oauth/revoke"))
        + ",\"introspection_endpoint\":" + q(joinUrl(issuer, "/oauth/introspect"))
        + ",\"jwks_uri\":" + q(joinUrl(issuer, "/.well-known/jwks.json"))
        + ",\"response_types_supported\":[\"code\"]"
        + ",\"response_modes_supported\":[\"query\",\"query.jwt\"]"
        + ",\"request_parameter_supported\":true"
        + ",\"request_uri_parameter_supported\":true"
        + ",\"require_request_uri_registration\":false"
        + ",\"request_object_signing_alg_values_supported\":[\"RS256\"]"
        + ",\"authorization_signing_alg_values_supported\":[\"RS256\"]"
        + ",\"grant_types_supported\":[\"authorization_code\",\"refresh_token\",\"client_credentials\",\"urn:ietf:params:oauth:grant-type:device_code\",\"urn:ietf:params:oauth:grant-type:token-exchange\"]"
        + ",\"subject_types_supported\":[\"public\"]"
        + ",\"id_token_signing_alg_values_supported\":[\"RS256\"]"
        + ",\"scopes_supported\":[\"openid\",\"profile\",\"email\",\"phone\",\"offline_access\",\"account\"]"
        + ",\"token_endpoint_auth_methods_supported\":[\"client_secret_post\",\"none\"]"
        + ",\"code_challenge_methods_supported\":[\"S256\"]"
        + ",\"dpop_signing_alg_values_supported\":[\"RS256\"]"
        + ",\"authorization_response_iss_parameter_supported\":true"
        + "}";
}

foundation::Result<std::string> OpenIdProvider::jwksDocument() const
{
    auto jwk = m_signer.publicJwkJson();
    if (!jwk.has_value()) return foundation::fail(jwk.error());
    std::string document{"{\"keys\":["};
    document += jwk.value();
    for (const auto& published : m_publishedVerificationJwks) {
        document.push_back(',');
        document += published.m_json;
    }
    document += "]}";
    return document;
}

foundation::Result<std::string> OpenIdProvider::issueIdToken(
    const oauth::RedeemedAuthorization& authorization) const
{
    bool openid = false;
    for (const auto& scope : authorization.scopes()) {
        if (scope.value() == "openid") { openid = true; break; }
    }
    if (!openid) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An ID Token requires the openid scope.");
    }
    const auto now = m_clock->now();
    const auto expires = now + m_policy.idTokenLifetime();
    std::string payload{"{"};
    payload += "\"iss\":" + q(m_issuer.value());
    payload += ",\"sub\":" + q(authorization.identity().value());
    payload += ",\"aud\":" + q(authorization.clientId().value());
    payload += ",\"iat\":" + std::to_string(seconds(now));
    payload += ",\"exp\":" + std::to_string(seconds(expires));
    payload += ",\"auth_time\":" + std::to_string(seconds(authorization.authenticatedAt()));
    payload += ",\"acr\":" + q(identity::provider::assuranceLevelName(authorization.assurance()));
    payload += ",\"amr\":" + amrJson(authorization);
    if (authorization.nonce().has_value()) {
        payload += ",\"nonce\":" + q(authorization.nonce().value());
    }
    payload.push_back('}');
    return m_signer.signJwt(payload);
}

foundation::Result<std::string> OpenIdProvider::issueAuthorizationResponse(
    const client::ClientId& clientId, std::optional<std::string_view> code,
    std::optional<std::string_view> state, std::optional<std::string_view> error) const
{
    if (clientId.empty() || (code.has_value() == error.has_value())) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A JARM response requires exactly one result.");
    }
    const auto now = m_clock->now();
    const auto expires = now + std::chrono::minutes{5};
    auto jwtId = security::randomTokenBase64Url(18U);
    if (!jwtId) return foundation::fail(jwtId.error());
    std::string payload{"{"};
    payload += "\"iss\":" + q(m_issuer.value());
    payload += ",\"aud\":" + q(clientId.value());
    payload += ",\"iat\":" + std::to_string(seconds(now));
    payload += ",\"exp\":" + std::to_string(seconds(expires));
    payload += ",\"jti\":" + q(jwtId.value());
    if (code) payload += ",\"code\":" + q(*code);
    if (error) payload += ",\"error\":" + q(*error);
    if (state) payload += ",\"state\":" + q(*state);
    payload.push_back('}');
    return m_signer.signJwt(payload);
}

foundation::Result<std::string> OpenIdProvider::userInfo(
    const token::TokenClaims& claims) const
{
    if (!claims.active() || !claims.context().permits("openid")) {
        return foundation::fail(foundation::ErrorCode::PermissionDenied,
                                "The access token cannot access UserInfo.");
    }
    std::string result{"{\"sub\":" + q(claims.context().identity().value())};
    auto profile = m_profiles->find(claims.context().identity());
    if (!profile.has_value()) return foundation::fail(profile.error());
    if (profile->has_value()) {
        const auto& value = profile->value();
        if (claims.context().permits("profile")) {
            if (value.displayName()) result += ",\"name\":" + q(*value.displayName());
            if (value.preferredUsername()) result += ",\"preferred_username\":" + q(*value.preferredUsername());
            if (value.locale()) result += ",\"locale\":" + q(*value.locale());
            if (value.pictureUrl()) result += ",\"picture\":" + q(*value.pictureUrl());
        }
        if (claims.context().permits("email") && value.email()) {
            result += ",\"email\":" + q(*value.email());
            result += std::string{",\"email_verified\":"} + (value.emailVerified() ? "true" : "false");
        }
    }
    result.push_back('}');
    return result;
}

std::string_view OpenIdProvider::issuer() const noexcept { return m_issuer.value(); }

}

module;

#include <array>

#include <chrono>
#include <cstddef>
#include <algorithm>
#include <compare>
#include <memory>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.oauth;

namespace openproof::oauth {
namespace {

[[nodiscard]] bool validOpaque(std::string_view value, std::size_t maximum) noexcept
{
    if (value.empty() || value.size() > maximum) return false;
    return std::ranges::none_of(value, [](char symbol) {
        const auto byte = static_cast<unsigned char>(symbol);
        return byte < 0x20U || byte == 0x7FU;
    });
}

[[nodiscard]] bool base64UrlCharacter(char symbol) noexcept
{
    return (symbol >= 'A' && symbol <= 'Z') || (symbol >= 'a' && symbol <= 'z')
        || (symbol >= '0' && symbol <= '9') || symbol == '-' || symbol == '_';
}

}

PkceChallenge::PkceChallenge(const PkceChallenge& other) : m_value(other.m_value) {}
PkceChallenge::PkceChallenge(PkceChallenge&& other) : m_value(std::move(other.m_value)) {}
PkceChallenge& PkceChallenge::operator=(const PkceChallenge& other)
{
    if (this != &other) m_value = other.m_value;
    return *this;
}
PkceChallenge& PkceChallenge::operator=(PkceChallenge&& other)
{
    if (this != &other) m_value = std::move(other.m_value);
    return *this;
}
PkceChallenge::~PkceChallenge() {}

PkceChallenge::PkceChallenge(std::string value) : m_value(std::move(value)) {}

foundation::Result<PkceChallenge> PkceChallenge::create(std::string value)
{
    if (value.size() != 43U || !std::ranges::all_of(value, base64UrlCharacter)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Only PKCE S256 challenges are accepted.");
    }
    return PkceChallenge{std::move(value)};
}

std::string_view PkceChallenge::value() const noexcept { return m_value; }

struct AuthorizationRequest::StateData final {
    client::ClientId clientId;
    std::string redirectUri;
    std::vector<client::Scope> scopes;
    PkceChallenge codeChallenge;
    std::optional<std::string> state;
    std::optional<std::string> nonce;
    std::optional<foundation::Duration> maximumAuthenticationAge;
    std::optional<std::string> resource;
    AuthorizationResponseMode responseMode{AuthorizationResponseMode::Query};
};

AuthorizationRequest::AuthorizationRequest(
    client::ClientId clientId, std::string redirectUri,
    std::vector<client::Scope> scopes, PkceChallenge codeChallenge,
    std::optional<std::string> state, std::optional<std::string> nonce,
    std::optional<foundation::Duration> maximumAuthenticationAge,
    std::optional<std::string> resource, AuthorizationResponseMode responseMode)
    : m_data(std::make_shared<StateData>(StateData{
          .clientId = std::move(clientId),
          .redirectUri = std::move(redirectUri),
          .scopes = std::move(scopes),
          .codeChallenge = std::move(codeChallenge),
          .state = std::move(state),
          .nonce = std::move(nonce),
          .maximumAuthenticationAge = maximumAuthenticationAge,
          .resource = std::move(resource),
          .responseMode = responseMode}))
{
}

foundation::Result<AuthorizationRequest> AuthorizationRequest::create(
    client::ClientId clientId, std::string redirectUri,
    std::vector<client::Scope> scopes, PkceChallenge codeChallenge,
    std::optional<std::string> state, std::optional<std::string> nonce,
    std::optional<foundation::Duration> maximumAuthenticationAge,
    std::optional<std::string> resource, AuthorizationResponseMode responseMode)
{
    if (clientId.empty() || redirectUri.empty() || redirectUri.size() > 2048U
        || scopes.empty() || scopes.size() > 64U
        || (state.has_value() && !validOpaque(*state, 512U))
        || (nonce.has_value() && !validOpaque(*nonce, 512U))
        || (maximumAuthenticationAge.has_value()
            && *maximumAuthenticationAge < foundation::Duration::zero())
        || (resource.has_value() && !validOpaque(*resource, 2048U))) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The authorization request is invalid.");
    }
    std::ranges::sort(scopes);
    if (std::ranges::adjacent_find(scopes) != scopes.end()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The authorization scope list contains duplicates.");
    }
    return AuthorizationRequest{std::move(clientId), std::move(redirectUri),
                                std::move(scopes), std::move(codeChallenge),
                                std::move(state), std::move(nonce),
                                maximumAuthenticationAge, std::move(resource), responseMode};
}

const client::ClientId& AuthorizationRequest::clientId() const noexcept { return m_data->clientId; }
std::string_view AuthorizationRequest::redirectUri() const noexcept { return m_data->redirectUri; }
const std::vector<client::Scope>& AuthorizationRequest::scopes() const noexcept { return m_data->scopes; }
const PkceChallenge& AuthorizationRequest::codeChallenge() const noexcept { return m_data->codeChallenge; }
const std::optional<std::string>& AuthorizationRequest::state() const noexcept { return m_data->state; }
const std::optional<std::string>& AuthorizationRequest::nonce() const noexcept { return m_data->nonce; }
const std::optional<foundation::Duration>& AuthorizationRequest::maximumAuthenticationAge() const noexcept
{ return m_data->maximumAuthenticationAge; }
const std::optional<std::string>& AuthorizationRequest::resource() const noexcept
{ return m_data->resource; }
AuthorizationResponseMode AuthorizationRequest::responseMode() const noexcept
{ return m_data->responseMode; }

struct AuthorizationCode::StateData final {
    CodeDigest digest;
    client::ClientId clientId;
    identity::core::IdentityId identity;
    std::string redirectUri;
    std::vector<client::Scope> scopes;
    PkceChallenge codeChallenge;
    std::optional<std::string> nonce;
    std::optional<std::string> resource;
    identity::provider::ProviderId provider;
    identity::provider::AssuranceLevel assurance{identity::provider::AssuranceLevel::Ial0};
    identity::provider::AuthenticationStrength strength;
    foundation::Instant authenticatedAt{};
    foundation::Instant issuedAt{};
    foundation::Instant expiresAt{};
};

AuthorizationCode::AuthorizationCode(
    CodeDigest digest, client::ClientId clientId, identity::core::IdentityId identity,
    std::string redirectUri, std::vector<client::Scope> scopes,
    PkceChallenge codeChallenge, std::optional<std::string> nonce,
    identity::provider::ProviderId provider,
    identity::provider::AssuranceLevel assurance,
    identity::provider::AuthenticationStrength strength,
    foundation::Instant authenticatedAt, foundation::Instant issuedAt,
    foundation::Instant expiresAt, std::optional<std::string> resource)
    : m_data(std::make_shared<StateData>(StateData{
          .digest = std::move(digest),
          .clientId = std::move(clientId),
          .identity = std::move(identity),
          .redirectUri = std::move(redirectUri),
          .scopes = std::move(scopes),
          .codeChallenge = std::move(codeChallenge),
          .nonce = std::move(nonce),
          .resource = std::move(resource),
          .provider = std::move(provider),
          .assurance = assurance,
          .strength = std::move(strength),
          .authenticatedAt = authenticatedAt,
          .issuedAt = issuedAt,
          .expiresAt = expiresAt}))
{
}

foundation::Result<AuthorizationCode> AuthorizationCode::create(
    CodeDigest digest, client::ClientId clientId, identity::core::IdentityId identity,
    std::string redirectUri, std::vector<client::Scope> scopes,
    PkceChallenge codeChallenge, std::optional<std::string> nonce,
    identity::provider::ProviderId provider,
    identity::provider::AssuranceLevel assurance,
    identity::provider::AuthenticationStrength strength, foundation::Instant authenticatedAt,
    foundation::Instant issuedAt, foundation::Duration lifetime,
    std::optional<std::string> resource)
{
    if (clientId.empty() || identity.empty() || redirectUri.empty() || scopes.empty()
        || lifetime <= foundation::Duration::zero() || authenticatedAt > issuedAt
        || (nonce.has_value() && !validOpaque(*nonce, 512U))
        || (resource.has_value() && !validOpaque(*resource, 2048U))) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The authorization code state is invalid.");
    }
    return AuthorizationCode{std::move(digest), std::move(clientId),
                             std::move(identity), std::move(redirectUri),
                             std::move(scopes), std::move(codeChallenge),
                             std::move(nonce), std::move(provider), assurance, strength, authenticatedAt,
                             issuedAt, issuedAt + lifetime, std::move(resource)};
}

foundation::Result<AuthorizationCode> AuthorizationCode::restore(
    CodeDigest digest, client::ClientId clientId, identity::core::IdentityId identity,
    std::string redirectUri, std::vector<client::Scope> scopes,
    PkceChallenge codeChallenge, std::optional<std::string> nonce,
    identity::provider::ProviderId provider,
    identity::provider::AssuranceLevel assurance,
    identity::provider::AuthenticationStrength strength, foundation::Instant authenticatedAt,
    foundation::Instant issuedAt, foundation::Instant expiresAt,
    std::optional<std::string> resource)
{
    if (expiresAt <= issuedAt) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "Stored authorization code timestamps are invalid.");
    }
    auto restored = create(
        std::move(digest), std::move(clientId), std::move(identity),
        std::move(redirectUri), std::move(scopes), std::move(codeChallenge),
        std::move(nonce), std::move(provider), assurance, strength,
        authenticatedAt, issuedAt, expiresAt - issuedAt, std::move(resource));
    if (!restored) {
        return foundation::fail(
            foundation::ErrorCode::Internal,
            "Stored authorization code state is invalid.",
            std::string{restored.error().message()});
    }
    return restored;
}

const CodeDigest& AuthorizationCode::digest() const noexcept { return m_data->digest; }
const client::ClientId& AuthorizationCode::clientId() const noexcept { return m_data->clientId; }
const identity::core::IdentityId& AuthorizationCode::identity() const noexcept { return m_data->identity; }
std::string_view AuthorizationCode::redirectUri() const noexcept { return m_data->redirectUri; }
const std::vector<client::Scope>& AuthorizationCode::scopes() const noexcept { return m_data->scopes; }
const PkceChallenge& AuthorizationCode::codeChallenge() const noexcept { return m_data->codeChallenge; }
const std::optional<std::string>& AuthorizationCode::nonce() const noexcept { return m_data->nonce; }
const std::optional<std::string>& AuthorizationCode::resource() const noexcept { return m_data->resource; }
const identity::provider::ProviderId& AuthorizationCode::provider() const noexcept { return m_data->provider; }
identity::provider::AssuranceLevel AuthorizationCode::assurance() const noexcept { return m_data->assurance; }
const identity::provider::AuthenticationStrength& AuthorizationCode::strength() const noexcept { return m_data->strength; }
foundation::Instant AuthorizationCode::authenticatedAt() const noexcept { return m_data->authenticatedAt; }
foundation::Instant AuthorizationCode::issuedAt() const noexcept { return m_data->issuedAt; }
foundation::Instant AuthorizationCode::expiresAt() const noexcept { return m_data->expiresAt; }
bool AuthorizationCode::expiredAt(foundation::Instant now) const noexcept { return now >= m_data->expiresAt; }

AuthorizationGrant::AuthorizationGrant(AuthorizationGrant&& other) noexcept
    : m_code(std::move(other.m_code))
    , m_redirectUri(std::move(other.m_redirectUri))
    , m_state(std::move(other.m_state))
{
}
AuthorizationGrant& AuthorizationGrant::operator=(AuthorizationGrant&& other) noexcept
{
    if (this != &other) {
        m_code = std::move(other.m_code);
        m_redirectUri = std::move(other.m_redirectUri);
        m_state = std::move(other.m_state);
    }
    return *this;
}
AuthorizationGrant::~AuthorizationGrant() {}

AuthorizationGrant::AuthorizationGrant(foundation::SecretString code,
                                       std::string redirectUri,
                                       std::optional<std::string> state)
    : m_code(std::move(code)), m_redirectUri(std::move(redirectUri)), m_state(std::move(state))
{
}

const foundation::SecretString& AuthorizationGrant::code() const noexcept { return m_code; }
std::string_view AuthorizationGrant::redirectUri() const noexcept { return m_redirectUri; }
const std::optional<std::string>& AuthorizationGrant::state() const noexcept { return m_state; }

}

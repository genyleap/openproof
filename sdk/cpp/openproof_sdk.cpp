module;

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.sdk;

import openproof.security;

namespace openproof::sdk {
namespace {

[[nodiscard]] std::string encode(std::string_view input)
{
    constexpr char hex[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(input.size() * 3U);
    for (char rawValue : input) {
        const auto value = static_cast<unsigned char>(rawValue);
        const bool unreserved = std::isalnum(value) != 0 || value == '-'
            || value == '.' || value == '_' || value == '~';
        if (unreserved) output.push_back(static_cast<char>(value));
        else {
            output.push_back('%');
            output.push_back(hex[(value >> 4U) & 0x0FU]);
            output.push_back(hex[value & 0x0FU]);
        }
    }
    return output;
}

[[nodiscard]] std::string joinScopes(const std::vector<std::string>& scopes)
{
    std::string output;
    for (const auto& scope : scopes) {
        if (!output.empty()) output.push_back(' ');
        output.append(scope);
    }
    return output;
}

[[nodiscard]] bool validText(std::string_view value, std::size_t maximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::none_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x21U || byte == 0x7FU;
           });
}

}

ClientConfig::ClientConfig(const ClientConfig& other)
    : m_issuer(other.m_issuer)
    , m_clientId(other.m_clientId)
    , m_redirectUri(other.m_redirectUri)
    , m_scopes(other.m_scopes)
{
}
ClientConfig::ClientConfig(ClientConfig&& other)
    : m_issuer(std::move(other.m_issuer))
    , m_clientId(std::move(other.m_clientId))
    , m_redirectUri(std::move(other.m_redirectUri))
    , m_scopes(std::move(other.m_scopes))
{
}
ClientConfig& ClientConfig::operator=(const ClientConfig& other)
{
    if (this != &other) {
        m_issuer = other.m_issuer;
        m_clientId = other.m_clientId;
        m_redirectUri = other.m_redirectUri;
        m_scopes = other.m_scopes;
    }
    return *this;
}
ClientConfig& ClientConfig::operator=(ClientConfig&& other)
{
    if (this != &other) {
        m_issuer = std::move(other.m_issuer);
        m_clientId = std::move(other.m_clientId);
        m_redirectUri = std::move(other.m_redirectUri);
        m_scopes = std::move(other.m_scopes);
    }
    return *this;
}
ClientConfig::~ClientConfig() {}

ClientConfig::ClientConfig(std::string issuer, std::string clientId,
                           std::string redirectUri, std::vector<std::string> scopes)
    : m_issuer(std::move(issuer)), m_clientId(std::move(clientId)),
      m_redirectUri(std::move(redirectUri)), m_scopes(std::move(scopes))
{
}

foundation::Result<ClientConfig> ClientConfig::create(
    std::string issuer, std::string clientId, std::string redirectUri,
    std::vector<std::string> scopes)
{
    if (issuer.ends_with('/')) issuer.pop_back();
    if ((!issuer.starts_with("https://") && !issuer.starts_with("http://127.0.0.1")
         && !issuer.starts_with("http://localhost"))
        || !validText(clientId, 256U) || !validText(redirectUri, 2048U)
        || scopes.empty() || scopes.size() > 64U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The OpenProof SDK client configuration is invalid.");
    }
    std::ranges::sort(scopes);
    if (std::ranges::adjacent_find(scopes) != scopes.end()
        || std::ranges::any_of(scopes, [](const std::string& scope) {
               return !validText(scope, 128U) || scope.contains(' ');
           })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The OpenProof SDK scopes are invalid.");
    }
    return ClientConfig{std::move(issuer), std::move(clientId),
                        std::move(redirectUri), std::move(scopes)};
}
std::string_view ClientConfig::issuer() const noexcept { return m_issuer; }
std::string_view ClientConfig::clientId() const noexcept { return m_clientId; }
std::string_view ClientConfig::redirectUri() const noexcept { return m_redirectUri; }
const std::vector<std::string>& ClientConfig::scopes() const noexcept { return m_scopes; }

AuthorizationSession::AuthorizationSession(AuthorizationSession&& other) noexcept
    : m_authorizationUrl(std::move(other.m_authorizationUrl))
    , m_codeVerifier(std::move(other.m_codeVerifier))
    , m_state(std::move(other.m_state))
    , m_nonce(std::move(other.m_nonce))
{
}
AuthorizationSession& AuthorizationSession::operator=(AuthorizationSession&& other) noexcept
{
    if (this != &other) {
        m_authorizationUrl = std::move(other.m_authorizationUrl);
        m_codeVerifier = std::move(other.m_codeVerifier);
        m_state = std::move(other.m_state);
        m_nonce = std::move(other.m_nonce);
    }
    return *this;
}
AuthorizationSession::~AuthorizationSession() {}

HttpRequest::HttpRequest(HttpRequest&& other) noexcept
    : method(std::move(other.method))
    , url(std::move(other.url))
    , contentType(std::move(other.contentType))
    , body(std::move(other.body))
    , authorizationScheme(std::move(other.authorizationScheme))
    , authorizationCredential(std::move(other.authorizationCredential))
{
}
HttpRequest& HttpRequest::operator=(HttpRequest&& other) noexcept
{
    if (this != &other) {
        method = std::move(other.method);
        url = std::move(other.url);
        contentType = std::move(other.contentType);
        body = std::move(other.body);
        authorizationScheme = std::move(other.authorizationScheme);
        authorizationCredential = std::move(other.authorizationCredential);
    }
    return *this;
}
HttpRequest::~HttpRequest() {}

AuthorizationSession::AuthorizationSession(
    std::string authorizationUrl, foundation::SecretString codeVerifier,
    foundation::SecretString state, std::string nonce)
    : m_authorizationUrl(std::move(authorizationUrl)),
      m_codeVerifier(std::move(codeVerifier)), m_state(std::move(state)),
      m_nonce(std::move(nonce))
{
}
std::string_view AuthorizationSession::authorizationUrl() const noexcept { return m_authorizationUrl; }
const foundation::SecretString& AuthorizationSession::codeVerifier() const noexcept { return m_codeVerifier; }
const foundation::SecretString& AuthorizationSession::state() const noexcept { return m_state; }
std::string_view AuthorizationSession::nonce() const noexcept { return m_nonce; }

HttpRequest::HttpRequest(
    std::string methodValue, std::string urlValue, std::string contentTypeValue,
    foundation::SecretString bodyValue, std::string authorizationSchemeValue,
    foundation::SecretString authorizationCredentialValue)
    : method(std::move(methodValue))
    , url(std::move(urlValue))
    , contentType(std::move(contentTypeValue))
    , body(std::move(bodyValue))
    , authorizationScheme(std::move(authorizationSchemeValue))
    , authorizationCredential(std::move(authorizationCredentialValue))
{
}

IdentityClient::IdentityClient(ClientConfig config) : m_config(std::move(config)) {}

foundation::Result<AuthorizationSession> IdentityClient::beginLogin() const
{
    auto verifier = security::randomTokenBase64Url(32U);
    auto state = security::randomTokenBase64Url(32U);
    auto nonce = security::randomTokenBase64Url(24U);
    if (!verifier || !state || !nonce) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "A secure authorization transaction could not be created.");
    }
    auto verifierDigest = security::sha256(verifier.value());
    if (!verifierDigest) return foundation::fail(verifierDigest.error());
    const std::string challenge = foundation::toBase64Url(verifierDigest.value());
    std::string url = std::string{m_config.issuer()} + "/oauth/authorize"
        + "?response_type=code&client_id=" + encode(m_config.clientId())
        + "&redirect_uri=" + encode(m_config.redirectUri())
        + "&scope=" + encode(joinScopes(m_config.scopes()))
        + "&code_challenge=" + encode(challenge)
        + "&code_challenge_method=S256"
        + "&state=" + encode(state.value())
        + "&nonce=" + encode(nonce.value());
    return AuthorizationSession{std::move(url),
        foundation::SecretString{std::move(verifier).value()},
        foundation::SecretString{std::move(state).value()}, std::move(nonce).value()};
}

foundation::Result<HttpRequest> IdentityClient::authorizationCodeRequest(
    std::string_view code, const AuthorizationSession& session,
    std::string_view returnedState, std::string_view returnedIssuer) const
{
    if (!validText(code, 256U)
        || !security::constantTimeEquals(session.state().expose(), returnedState)
        || returnedIssuer != m_config.issuer()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The authorization callback is invalid.");
    }
    return HttpRequest{
        "POST", std::string{m_config.issuer()} + "/oauth/token",
        "application/x-www-form-urlencoded",
        foundation::SecretString{
            "grant_type=authorization_code&client_id=" + encode(m_config.clientId())
            + "&code=" + encode(code) + "&redirect_uri=" + encode(m_config.redirectUri())
            + "&code_verifier=" + encode(session.codeVerifier().expose())},
        {}, foundation::SecretString{}};
}

foundation::Result<HttpRequest> IdentityClient::refreshRequest(
    const foundation::SecretString& refreshToken) const
{
    if (refreshToken.empty()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    return HttpRequest{
        "POST", std::string{m_config.issuer()} + "/oauth/token",
        "application/x-www-form-urlencoded",
        foundation::SecretString{
            "grant_type=refresh_token&client_id=" + encode(m_config.clientId())
            + "&refresh_token=" + encode(refreshToken.expose())},
        {}, foundation::SecretString{}};
}

foundation::Result<HttpRequest> IdentityClient::userInfoRequest(
    const foundation::SecretString& accessToken) const
{
    if (accessToken.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An access token is required for UserInfo.");
    }
    return HttpRequest{
        "GET", std::string{m_config.issuer()} + "/oauth/userinfo", {},
        foundation::SecretString{}, "Bearer", accessToken.clone()};
}

}

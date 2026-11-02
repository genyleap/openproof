module;

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <boost/asio/detail/call_stack.hpp>
#include "../../gateway/asio_thread_context_extern.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/json.hpp>
#include <openssl/ssl.h>

#include "response_validation.hpp"
#include "../http/async_https.hpp"

module openproof.provider.github;

import openproof.security;

namespace openproof::provider::github {
namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace json = boost::json;
namespace idp = identity::provider;
using Tcp = asio::ip::tcp;

constexpr std::string_view kAuthorizationEndpoint{"https://github.com/login/oauth/authorize"};
constexpr std::string_view kTokenHost{"github.com"};
constexpr std::string_view kApiHost{"api.github.com"};
constexpr std::string_view kApiVersion{"2026-03-10"};
constexpr std::size_t kMaximumResponseBytes = 2U * 1024U * 1024U;

[[nodiscard]] foundation::Error authFailure(std::string detail)
{
    return foundation::Error{
        foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(foundation::ErrorCode::AuthenticationFailed)},
        std::move(detail)};
}

[[nodiscard]] bool safeText(std::string_view value, std::size_t maximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::none_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           });
}

[[nodiscard]] bool validHttpsUrl(std::string_view value) noexcept
{
    constexpr std::string_view scheme{"https://"};
    const bool visibleAscii = std::ranges::all_of(value, [](char symbol) {
        const auto byte = static_cast<unsigned char>(symbol);
        return byte >= 0x21U && byte <= 0x7EU;
    });
    if (!value.starts_with(scheme) || value.size() > 4096U || !visibleAscii
        || value.contains('#') || value.contains('\\')) {
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

    if (host.empty() || host.size() > 253U || host.contains(':')
        || !std::ranges::all_of(host, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return std::isalnum(byte) != 0 || symbol == '.' || symbol == '-';
           })) {
        return false;
    }
    if (authorityEnd == value.size()) return true;
    return value[authorityEnd] == '/' || value[authorityEnd] == '?';
}

[[nodiscard]] std::string percentEncode(std::string_view input)
{
    constexpr char hex[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(input.size() * 3U);
    for (const char symbol : input) {
        const auto byte = static_cast<unsigned char>(symbol);
        const bool unreserved = (byte >= static_cast<unsigned char>('A')
                && byte <= static_cast<unsigned char>('Z'))
            || (byte >= static_cast<unsigned char>('a')
                && byte <= static_cast<unsigned char>('z'))
            || (byte >= static_cast<unsigned char>('0')
                && byte <= static_cast<unsigned char>('9'))
            || byte == static_cast<unsigned char>('-')
            || byte == static_cast<unsigned char>('.')
            || byte == static_cast<unsigned char>('_')
            || byte == static_cast<unsigned char>('~');
        if (unreserved) output.push_back(static_cast<char>(byte));
        else {
            output.push_back('%');
            output.push_back(hex[(byte >> 4U) & 0x0FU]);
            output.push_back(hex[byte & 0x0FU]);
        }
    }
    return output;
}

[[nodiscard]] std::string appendQuery(std::string base, std::string_view key,
                                      std::string_view value)
{
    base.push_back(base.contains('?') ? '&' : '?');
    base.append(percentEncode(key));
    base.push_back('=');
    base.append(percentEncode(value));
    return base;
}

struct HttpResponse final {
    unsigned int status{};
    std::string body;
};

// Legacy OAuth entry points retain a synchronous completion contract, but
// always use the same native coroutine HTTPS transport as async providers.
[[nodiscard]] asio::awaitable<foundation::Result<HttpResponse>> httpsRequestAsync(
    openproof::provider::http::async_detail::AsyncHttpsClient& client,
    std::string_view host, std::string_view target, http::verb method,
    std::string body, std::string_view contentType,
    std::optional<std::string_view> bearer,
    std::chrono::steady_clock::time_point absoluteDeadline);

[[nodiscard]] foundation::Result<HttpResponse> httpsRequest(
    std::string_view host, std::string_view target, http::verb method,
    std::string body, std::string_view contentType,
    std::optional<std::string_view> bearer, std::string_view caFile)
{
    try {
        asio::io_context io;
        openproof::provider::http::async_detail::AsyncHttpsClient client{
            std::string{caFile}, kMaximumResponseBytes, 32768U};
        auto completion = asio::co_spawn(io,
            httpsRequestAsync(client, host, target, method, std::move(body),
                contentType, bearer,
                std::chrono::steady_clock::now() + std::chrono::seconds{10}),
            asio::use_future);
        io.run();
        return completion.get();
    } catch (...) {
        // Never return OAuth credentials, token URLs or TLS internals.
        return foundation::fail(foundation::ErrorCode::Unavailable,
                                "The GitHub HTTPS request failed.");
    }
}

// The coroutine-native counterpart shares the exact GitHub endpoint and
// security policy but never calls the blocking legacy HTTPS implementation.
[[nodiscard]] asio::awaitable<foundation::Result<HttpResponse>> httpsRequestAsync(
    openproof::provider::http::async_detail::AsyncHttpsClient& client,
    std::string_view host, std::string_view target, http::verb method,
    std::string body, std::string_view contentType,
    std::optional<std::string_view> bearer,
    std::chrono::steady_clock::time_point absoluteDeadline)
{
    using Request = openproof::provider::http::async_detail::HttpsRequest;
    Request request;
    request.host = std::string{host};
    request.target = std::string{target};
    request.method = method == http::verb::post
        ? Request::Method::Post : Request::Method::Get;
    request.timeout = std::chrono::seconds{10};
    request.absoluteDeadline = absoluteDeadline;
    request.headers.emplace_back("accept", host == kTokenHost
        ? "application/json" : "application/vnd.github+json");
    request.headers.emplace_back("X-GitHub-Api-Version", std::string{kApiVersion});
    if (bearer) {
        request.headers.emplace_back("authorization", "Bearer " + std::string{*bearer});
    }
    if (!body.empty()) {
        request.headers.emplace_back("content-type", std::string{contentType});
        request.body = std::move(body);
    }
    const auto result = co_await client.exchange(std::move(request));
    if (!result.success) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
                                   "The GitHub HTTPS request failed.");
    }
    co_return HttpResponse{result.response.status, std::move(result.response.body)};
}

[[nodiscard]] foundation::Result<json::value> parseJson(std::string_view body)
{
    boost::system::error_code error;
    auto parsed = json::parse(body, error);
    if (error) return foundation::fail(authFailure("The GitHub JSON response is malformed."));
    return parsed;
}

[[nodiscard]] std::optional<std::string> stringValue(
    const json::object& object, std::string_view name)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr || !value->is_string()) return std::nullopt;
    return std::string{value->as_string()};
}

[[nodiscard]] std::optional<std::uint64_t> unsignedValue(
    const json::object& object, std::string_view name)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr) return std::nullopt;
    if (value->is_uint64()) return value->as_uint64();
    if (value->is_int64() && value->as_int64() >= 0) {
        return static_cast<std::uint64_t>(value->as_int64());
    }
    return std::nullopt;
}

[[nodiscard]] foundation::Result<std::string> derived(
    const foundation::SecretString& key, std::string_view label,
    const idp::ChallengeId& challenge)
{
    std::string material{label};
    material.push_back(':');
    material.append(challenge.value());
    auto digest = security::hmacSha256(key, material);
    if (!digest) return foundation::fail(digest.error());
    return foundation::toBase64Url(digest.value());
}

[[nodiscard]] std::optional<std::string_view> credential(
    const idp::SecretAttributeMap& values, std::string_view name)
{
    const auto found = values.find(name);
    if (found == values.end() || found->second.empty()) return std::nullopt;
    return found->second.expose();
}

[[nodiscard]] bool bearerTokenType(std::string_view value) noexcept
{
    constexpr std::string_view expected{"bearer"};
    if (value.size() != expected.size()) return false;
    for (std::size_t index = 0U; index < value.size(); ++index) {
        if (static_cast<char>(std::tolower(static_cast<unsigned char>(value[index])))
            != expected[index]) return false;
    }
    return true;
}

} // namespace

class GitHubAuthenticationProvider::Implementation final {
public:
    Implementation(GitHubProviderConfig providerConfig,
                   const foundation::ClockSource& clockSource,
                   std::string certificateAuthorityFile)
        : config(std::move(providerConfig)), clock(&clockSource),
          caFile(std::move(certificateAuthorityFile)),
          asyncClient(caFile) {}

    GitHubProviderConfig config;
    const foundation::ClockSource* clock;
    std::string caFile;
    // Construct before any asynchronous request so CA loading cannot suspend
    // a provider coroutine. Only immutable TLS context data is shared.
    openproof::provider::http::async_detail::AsyncHttpsClient asyncClient;
};

GitHubProviderConfig::GitHubProviderConfig(
    std::string clientId, foundation::SecretString clientSecret,
    std::string callbackUri, foundation::SecretString derivationKey,
    foundation::Duration challengeLifetime)
    : m_clientId(std::move(clientId)), m_clientSecret(std::move(clientSecret)),
      m_callbackUri(std::move(callbackUri)), m_derivationKey(std::move(derivationKey)),
      m_challengeLifetime(challengeLifetime) {}

foundation::Result<GitHubProviderConfig> GitHubProviderConfig::create(
    std::string clientId, foundation::SecretString clientSecret,
    std::string callbackUri, foundation::SecretString derivationKey,
    foundation::Duration challengeLifetime)
{
    if (!safeText(clientId, 512U) || clientSecret.empty() || clientSecret.size() > 4096U
        || !validHttpsUrl(callbackUri) || derivationKey.size() < 32U
        || challengeLifetime <= foundation::Duration::zero()
        || challengeLifetime > std::chrono::minutes{15}) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The GitHub provider configuration is invalid.");
    }
    return GitHubProviderConfig{std::move(clientId), std::move(clientSecret),
                                std::move(callbackUri), std::move(derivationKey),
                                challengeLifetime};
}

std::string_view GitHubProviderConfig::clientId() const noexcept { return m_clientId; }
const foundation::SecretString& GitHubProviderConfig::clientSecret() const noexcept { return m_clientSecret; }
std::string_view GitHubProviderConfig::callbackUri() const noexcept { return m_callbackUri; }
const foundation::SecretString& GitHubProviderConfig::derivationKey() const noexcept { return m_derivationKey; }
foundation::Duration GitHubProviderConfig::challengeLifetime() const noexcept { return m_challengeLifetime; }

GitHubAuthenticationProvider::GitHubAuthenticationProvider(
    GitHubProviderConfig config, const foundation::ClockSource& clock, std::string caFile)
    : m_implementation(std::make_unique<Implementation>(std::move(config), clock, std::move(caFile))) {}

GitHubAuthenticationProvider::~GitHubAuthenticationProvider() = default;

idp::ProviderId GitHubAuthenticationProvider::id() const { return idp::ProviderId{"github"}; }
idp::InteractionModel GitHubAuthenticationProvider::interactionModel() const noexcept
{ return idp::InteractionModel::Redirect; }
idp::AssuranceLevel GitHubAuthenticationProvider::maximumClaimableAssurance() const noexcept
{ return idp::AssuranceLevel::Ial1; }

foundation::Result<idp::AuthenticationChallenge>
GitHubAuthenticationProvider::beginAuthentication(const idp::AuthenticationRequest& request)
{
    if (request.provider() != id()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The GitHub authentication request targets another provider.");
    }
    auto random = security::randomTokenBase64Url(24U);
    if (!random) return foundation::fail(random.error());
    idp::ChallengeId challengeId{"ghc_" + std::move(random).value()};
    auto state = derived(m_implementation->config.derivationKey(), "state", challengeId);
    auto verifier = derived(m_implementation->config.derivationKey(), "pkce", challengeId);
    if (!state || !verifier) return foundation::fail(foundation::ErrorCode::Internal);
    auto digest = security::sha256(verifier.value());
    if (!digest) return foundation::fail(digest.error());
    std::string url{kAuthorizationEndpoint};
    url = appendQuery(std::move(url), "client_id", m_implementation->config.clientId());
    url = appendQuery(std::move(url), "redirect_uri", m_implementation->config.callbackUri());
    url = appendQuery(std::move(url), "scope", "user:email");
    url = appendQuery(std::move(url), "state", state.value());
    url = appendQuery(std::move(url), "code_challenge", foundation::toBase64Url(digest.value()));
    url = appendQuery(std::move(url), "code_challenge_method", "S256");
    idp::AuthenticationChallenge challenge{
        challengeId, m_implementation->clock->now() + m_implementation->config.challengeLifetime()};
    challenge.setParameter("authorization_url", std::move(url));
    return challenge;
}

foundation::Result<idp::AuthenticationOutcome>
GitHubAuthenticationProvider::completeAuthentication(const idp::AuthenticationResponse& response)
{
    const auto code = credential(response.parameters(), "code");
    const auto state = credential(response.parameters(), "state");
    if (!code || !state || code->size() > 4096U || state->size() > 512U) {
        return foundation::fail(authFailure("The GitHub callback is incomplete."));
    }
    auto expectedState = derived(m_implementation->config.derivationKey(), "state", response.challengeId());
    auto verifier = derived(m_implementation->config.derivationKey(), "pkce", response.challengeId());
    if (!expectedState || !verifier || !security::constantTimeEquals(*state, expectedState.value())) {
        return foundation::fail(authFailure("The GitHub state binding is invalid."));
    }

    std::string form;
    const auto append = [&form](std::string_view key, std::string_view value) {
        if (!form.empty()) form.push_back('&');
        form.append(percentEncode(key));
        form.push_back('=');
        form.append(percentEncode(value));
    };
    append("client_id", m_implementation->config.clientId());
    append("client_secret", m_implementation->config.clientSecret().expose());
    append("code", *code);
    append("redirect_uri", m_implementation->config.callbackUri());
    append("code_verifier", verifier.value());
    auto tokenResponse = httpsRequest(kTokenHost, "/login/oauth/access_token", http::verb::post,
                                      std::move(form), "application/x-www-form-urlencoded",
                                      std::nullopt, m_implementation->caFile);
    if (!tokenResponse) {
        // Keep transport failures distinct from GitHub HTTP rejections in
        // operator-only diagnostics; never log the code, secret or response body.
        return foundation::fail(authFailure("The GitHub token exchange transport failed."));
    }
    if (tokenResponse->status != 200U) {
        // HTTP status is public protocol metadata; OAuth response bodies may
        // carry credentials and must not be copied into diagnostics.
        return foundation::fail(authFailure(
            "The GitHub token exchange returned HTTP "
            + std::to_string(tokenResponse->status) + "."));
    }
    auto tokenJson = parseJson(tokenResponse->body);
    if (!tokenJson || !tokenJson->is_object()) {
        return foundation::fail(authFailure("The GitHub token response is malformed."));
    }
    const auto accessToken = stringValue(tokenJson->as_object(), "access_token");
    const auto grantedScopes = stringValue(tokenJson->as_object(), "scope");
    const auto tokenType = stringValue(tokenJson->as_object(), "token_type");
    if (!accessToken || !detail::validBearerCredential(*accessToken)
        || !grantedScopes || !detail::validScopeResponse(*grantedScopes)
        || !tokenType || !bearerTokenType(*tokenType)) {
        return foundation::fail(authFailure("The GitHub token response is invalid."));
    }

    auto userResponse = httpsRequest(kApiHost, "/user", http::verb::get, {}, {},
                                     *accessToken, m_implementation->caFile);
    if (!userResponse || userResponse->status != 200U) {
        return foundation::fail(authFailure("The GitHub authenticated-user endpoint failed."));
    }
    auto userJson = parseJson(userResponse->body);
    if (!userJson || !userJson->is_object()) {
        return foundation::fail(authFailure("The GitHub user response is malformed."));
    }
    const auto accountId = unsignedValue(userJson->as_object(), "id");
    const auto login = stringValue(userJson->as_object(), "login");
    if (!accountId || *accountId == 0U || !login
        || !detail::safeProfileText(*login, detail::kPreferredUsernameMaximum)) {
        return foundation::fail(authFailure("The GitHub user identity is incomplete."));
    }

    std::optional<std::string> verifiedPrimaryEmail;
    if (detail::hasEmailScope(*grantedScopes)) {
        auto emailResponse = httpsRequest(
            kApiHost, "/user/emails?per_page=100", http::verb::get, {}, {},
            *accessToken, m_implementation->caFile);
        if (emailResponse && emailResponse->status == 200U) {
            auto emailJson = parseJson(emailResponse->body);
            if (emailJson && emailJson->is_array()) {
                verifiedPrimaryEmail =
                    detail::uniqueVerifiedPrimaryEmail(emailJson->as_array());
            }
        }
    }

    idp::VerifiedClaims claims;
    claims.set(idp::ClaimName::PreferredUsername, *login);
    if (verifiedPrimaryEmail) {
        claims.set(idp::ClaimName::Email, *verifiedPrimaryEmail);
        claims.set(idp::ClaimName::EmailVerified, "true");
    }
    if (const auto name = stringValue(userJson->as_object(), "name");
        name && detail::safeProfileText(*name, detail::kDisplayNameMaximum)) {
        claims.set(idp::ClaimName::DisplayName, *name);
    }
    if (const auto avatar = stringValue(userJson->as_object(), "avatar_url");
        avatar && avatar->size() <= detail::kPictureUrlMaximum
        && validHttpsUrl(*avatar)) {
        claims.set(idp::ClaimName::PictureUrl, *avatar);
    }
    idp::ProviderEvidence evidence;
    evidence.add("protocol", "github_oauth_authorization_code_pkce");
    evidence.add("github_account_id", std::to_string(*accountId));
    evidence.add("login", *login);
    return idp::AuthenticationOutcome::create(
        id(), idp::ExternalSubject{std::to_string(*accountId)}, std::move(claims),
        idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{idp::AuthenticationFactor::None, false},
        std::move(evidence), m_implementation->clock->now());
}

asio::awaitable<foundation::Result<idp::AuthenticationChallenge>>
GitHubAuthenticationProvider::beginAuthenticationAsync(idp::AuthenticationRequest request)
{
    // GitHub challenge generation is entirely local cryptography, unlike the
    // discovery/request-token flows of other federated providers.
    co_return beginAuthentication(request);
}

asio::awaitable<foundation::Result<idp::AuthenticationOutcome>>
GitHubAuthenticationProvider::completeAuthenticationAsync(idp::AuthenticationResponse response)
{
    // The three outbound hops share one deadline; each individual exchange
    // also retains its smaller per-request limit.
    const auto deadline = std::chrono::steady_clock::now()
        + std::chrono::seconds{15};
    const auto code = credential(response.parameters(), "code");
    const auto state = credential(response.parameters(), "state");
    if (!code || !state || code->size() > 4096U || state->size() > 512U) {
        co_return foundation::fail(authFailure("The GitHub callback is incomplete."));
    }
    auto expectedState = derived(m_implementation->config.derivationKey(), "state", response.challengeId());
    auto verifier = derived(m_implementation->config.derivationKey(), "pkce", response.challengeId());
    if (!expectedState || !verifier || !security::constantTimeEquals(*state, expectedState.value())) {
        co_return foundation::fail(authFailure("The GitHub state binding is invalid."));
    }

    std::string form;
    const auto append = [&form](std::string_view key, std::string_view value) {
        if (!form.empty()) form.push_back('&');
        form.append(percentEncode(key));
        form.push_back('=');
        form.append(percentEncode(value));
    };
    append("client_id", m_implementation->config.clientId());
    append("client_secret", m_implementation->config.clientSecret().expose());
    append("code", *code);
    append("redirect_uri", m_implementation->config.callbackUri());
    append("code_verifier", verifier.value());
    auto tokenResponse = co_await httpsRequestAsync(m_implementation->asyncClient,
        kTokenHost, "/login/oauth/access_token", http::verb::post,
                                      std::move(form), "application/x-www-form-urlencoded",
                                      std::nullopt, deadline);
    if (!tokenResponse) {
        // Keep transport failures distinct from GitHub HTTP rejections in
        // operator-only diagnostics; never log the code, secret or response body.
        co_return foundation::fail(authFailure("The GitHub token exchange transport failed."));
    }
    if (tokenResponse->status != 200U) {
        // HTTP status is public protocol metadata; OAuth response bodies may
        // carry credentials and must not be copied into diagnostics.
        co_return foundation::fail(authFailure(
            "The GitHub token exchange returned HTTP "
            + std::to_string(tokenResponse->status) + "."));
    }
    auto tokenJson = parseJson(tokenResponse->body);
    if (!tokenJson || !tokenJson->is_object()) {
        co_return foundation::fail(authFailure("The GitHub token response is malformed."));
    }
    const auto accessToken = stringValue(tokenJson->as_object(), "access_token");
    const auto grantedScopes = stringValue(tokenJson->as_object(), "scope");
    const auto tokenType = stringValue(tokenJson->as_object(), "token_type");
    if (!accessToken || !detail::validBearerCredential(*accessToken)
        || !grantedScopes || !detail::validScopeResponse(*grantedScopes)
        || !tokenType || !bearerTokenType(*tokenType)) {
        co_return foundation::fail(authFailure("The GitHub token response is invalid."));
    }

    auto userResponse = co_await httpsRequestAsync(m_implementation->asyncClient,
        kApiHost, "/user", http::verb::get, {}, {},
                                     *accessToken, deadline);
    if (!userResponse || userResponse->status != 200U) {
        co_return foundation::fail(authFailure("The GitHub authenticated-user endpoint failed."));
    }
    auto userJson = parseJson(userResponse->body);
    if (!userJson || !userJson->is_object()) {
        co_return foundation::fail(authFailure("The GitHub user response is malformed."));
    }
    const auto accountId = unsignedValue(userJson->as_object(), "id");
    const auto login = stringValue(userJson->as_object(), "login");
    if (!accountId || *accountId == 0U || !login
        || !detail::safeProfileText(*login, detail::kPreferredUsernameMaximum)) {
        co_return foundation::fail(authFailure("The GitHub user identity is incomplete."));
    }

    std::optional<std::string> verifiedPrimaryEmail;
    if (detail::hasEmailScope(*grantedScopes)) {
        auto emailResponse = co_await httpsRequestAsync(m_implementation->asyncClient,
            kApiHost, "/user/emails?per_page=100", http::verb::get, {}, {},
            *accessToken, deadline);
        if (emailResponse && emailResponse->status == 200U) {
            auto emailJson = parseJson(emailResponse->body);
            if (emailJson && emailJson->is_array()) {
                verifiedPrimaryEmail =
                    detail::uniqueVerifiedPrimaryEmail(emailJson->as_array());
            }
        }
    }

    idp::VerifiedClaims claims;
    claims.set(idp::ClaimName::PreferredUsername, *login);
    if (verifiedPrimaryEmail) {
        claims.set(idp::ClaimName::Email, *verifiedPrimaryEmail);
        claims.set(idp::ClaimName::EmailVerified, "true");
    }
    if (const auto name = stringValue(userJson->as_object(), "name");
        name && detail::safeProfileText(*name, detail::kDisplayNameMaximum)) {
        claims.set(idp::ClaimName::DisplayName, *name);
    }
    if (const auto avatar = stringValue(userJson->as_object(), "avatar_url");
        avatar && avatar->size() <= detail::kPictureUrlMaximum
        && validHttpsUrl(*avatar)) {
        claims.set(idp::ClaimName::PictureUrl, *avatar);
    }
    idp::ProviderEvidence evidence;
    evidence.add("protocol", "github_oauth_authorization_code_pkce");
    evidence.add("github_account_id", std::to_string(*accountId));
    evidence.add("login", *login);
    co_return idp::AuthenticationOutcome::create(
        id(), idp::ExternalSubject{std::to_string(*accountId)}, std::move(claims),
        idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{idp::AuthenticationFactor::None, false},
        std::move(evidence), m_implementation->clock->now());
}

} // namespace openproof::provider::github

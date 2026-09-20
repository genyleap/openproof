module;

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/json.hpp>
#include <openssl/ssl.h>

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

enum class ChallengeConsumption : std::uint8_t { Accepted, Unknown, Expired };

class OneTimeChallengeStore final {
public:
    [[nodiscard]] bool remember(
        const idp::ChallengeId& challenge, foundation::Instant expiresAt,
        foundation::Instant now)
    {
        const std::lock_guard<std::mutex> guard{m_mutex};
        for (auto pending = m_pending.begin(); pending != m_pending.end();) {
            if (now >= pending->second) pending = m_pending.erase(pending);
            else ++pending;
        }
        return m_pending.emplace(challenge, expiresAt).second;
    }

    [[nodiscard]] ChallengeConsumption consume(
        const idp::ChallengeId& challenge, foundation::Instant now)
    {
        const std::lock_guard<std::mutex> guard{m_mutex};
        const auto found = m_pending.find(challenge);
        if (found == m_pending.end()) return ChallengeConsumption::Unknown;
        const auto expiresAt = found->second;
        m_pending.erase(found);
        return now >= expiresAt ? ChallengeConsumption::Expired
                                : ChallengeConsumption::Accepted;
    }

private:
    std::mutex m_mutex;
    std::map<idp::ChallengeId, foundation::Instant> m_pending;
};

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

[[nodiscard]] foundation::Result<HttpResponse> httpsRequest(
    std::string_view host, std::string_view target, http::verb method,
    std::string body, std::string_view contentType,
    std::optional<std::string_view> bearer, std::string_view caFile)
{
    try {
        asio::io_context io;
        asio::ssl::context context{asio::ssl::context::tls_client};
        context.set_verify_mode(asio::ssl::verify_peer);
        if (caFile.empty()) context.set_default_verify_paths();
        else context.load_verify_file(std::string{caFile});
        Tcp::resolver resolver{io};
        beast::ssl_stream<beast::tcp_stream> stream{io, context};
        std::string hostname{host};
        if (SSL_ctrl(stream.native_handle(), SSL_CTRL_SET_TLSEXT_HOSTNAME,
                     static_cast<long>(TLSEXT_NAMETYPE_host_name), hostname.data()) <= 0L) {
            return foundation::fail(foundation::ErrorCode::Unavailable,
                                    "The GitHub TLS peer could not be configured.");
        }
        stream.set_verify_callback(asio::ssl::host_name_verification(hostname));
        auto endpoints = resolver.resolve(hostname, "443");
        beast::get_lowest_layer(stream).expires_after(std::chrono::seconds{10});
        beast::get_lowest_layer(stream).connect(endpoints);
        stream.handshake(asio::ssl::stream_base::client);

        http::request<http::string_body> request{method, std::string{target}, 11};
        request.set(http::field::host, hostname);
        request.set(http::field::user_agent, "OpenProof/1");
        request.set(http::field::accept,
                    host == kTokenHost ? "application/json" : "application/vnd.github+json");
        request.set(http::field::cache_control, "no-store");
        request.set("X-GitHub-Api-Version", kApiVersion);
        if (bearer) request.set(http::field::authorization, "Bearer " + std::string{*bearer});
        if (!body.empty()) {
            request.set(http::field::content_type, contentType);
            request.body() = std::move(body);
            request.prepare_payload();
        }
        http::write(stream, request);
        beast::flat_buffer buffer;
        http::response_parser<http::string_body> parser;
        parser.body_limit(kMaximumResponseBytes);
        http::read(stream, buffer, parser);
        auto response = parser.release();
        beast::error_code ignored;
        stream.shutdown(ignored);
        return HttpResponse{response.result_int(), std::move(response.body())};
    } catch (...) {
        return foundation::fail(foundation::ErrorCode::Unavailable,
                                "The GitHub HTTPS request failed.");
    }
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

[[nodiscard]] bool booleanValue(const json::object& object, std::string_view name)
{
    const auto* value = object.if_contains(name);
    return value != nullptr && value->is_bool() && value->as_bool();
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

[[nodiscard]] std::vector<std::string> scopes(std::string_view value)
{
    std::vector<std::string> output;
    std::size_t begin = 0U;
    while (begin <= value.size()) {
        const auto end = value.find_first_of(", ", begin);
        auto scope = value.substr(begin, end == std::string_view::npos ? value.size() - begin : end - begin);
        if (!scope.empty()) output.emplace_back(scope);
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    return output;
}

[[nodiscard]] bool hasEmailScope(std::string_view granted)
{
    const auto values = scopes(granted);
    return std::ranges::any_of(values, [](const std::string& value) {
        const std::string_view scope{value};
        return scope == "user:email" || scope == "user";
    });
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
          caFile(std::move(certificateAuthorityFile)) {}

    GitHubProviderConfig config;
    const foundation::ClockSource* clock;
    std::string caFile;
    OneTimeChallengeStore challenges;
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
    url = appendQuery(std::move(url), "scope", "read:user user:email");
    url = appendQuery(std::move(url), "state", state.value());
    url = appendQuery(std::move(url), "code_challenge", foundation::toBase64Url(digest.value()));
    url = appendQuery(std::move(url), "code_challenge_method", "S256");
    const auto now = m_implementation->clock->now();
    const auto expiresAt = now + m_implementation->config.challengeLifetime();
    if (!m_implementation->challenges.remember(challengeId, expiresAt, now)) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The GitHub authentication challenge could not be created.");
    }
    idp::AuthenticationChallenge challenge{challengeId, expiresAt};
    challenge.setParameter("authorization_url", std::move(url));
    return challenge;
}

foundation::Result<idp::AuthenticationOutcome>
GitHubAuthenticationProvider::completeAuthentication(const idp::AuthenticationResponse& response)
{
    const auto now = m_implementation->clock->now();
    switch (m_implementation->challenges.consume(response.challengeId(), now)) {
    case ChallengeConsumption::Unknown:
        return foundation::fail(authFailure(
            "The GitHub authentication challenge is unknown or already used."));
    case ChallengeConsumption::Expired:
        return foundation::fail(authFailure(
            "The GitHub authentication challenge expired."));
    case ChallengeConsumption::Accepted:
        break;
    }
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
    if (!tokenResponse || tokenResponse->status != 200U) {
        return foundation::fail(authFailure("The GitHub token exchange failed."));
    }
    auto tokenJson = parseJson(tokenResponse->body);
    if (!tokenJson || !tokenJson->is_object()) {
        return foundation::fail(authFailure("The GitHub token response is malformed."));
    }
    const auto accessToken = stringValue(tokenJson->as_object(), "access_token");
    const auto grantedScopes = stringValue(tokenJson->as_object(), "scope");
    const auto tokenType = stringValue(tokenJson->as_object(), "token_type");
    if (!accessToken || accessToken->empty() || accessToken->size() > 4096U
        || !grantedScopes || !hasEmailScope(*grantedScopes)
        || !tokenType || !bearerTokenType(*tokenType)) {
        return foundation::fail(authFailure("The GitHub token response did not grant the required identity scopes."));
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
    if (!accountId || *accountId == 0U || !login || !safeText(*login, 256U)) {
        return foundation::fail(authFailure("The GitHub user identity is incomplete."));
    }

    auto emailResponse = httpsRequest(kApiHost, "/user/emails?per_page=100", http::verb::get, {}, {},
                                      *accessToken, m_implementation->caFile);
    if (!emailResponse || emailResponse->status != 200U) {
        return foundation::fail(authFailure("The GitHub verified-email endpoint failed."));
    }
    auto emailJson = parseJson(emailResponse->body);
    if (!emailJson || !emailJson->is_array()) {
        return foundation::fail(authFailure("The GitHub email response is malformed."));
    }
    std::optional<std::string> verifiedPrimaryEmail;
    for (const auto& item : emailJson->as_array()) {
        if (!item.is_object()) continue;
        const auto email = stringValue(item.as_object(), "email");
        if (email && safeText(*email, 320U) && booleanValue(item.as_object(), "verified")
            && booleanValue(item.as_object(), "primary")) {
            verifiedPrimaryEmail = std::move(email);
            break;
        }
    }

    idp::VerifiedClaims claims;
    claims.set(idp::ClaimName::PreferredUsername, *login);
    if (verifiedPrimaryEmail) {
        claims.set(idp::ClaimName::Email, *verifiedPrimaryEmail);
        claims.set(idp::ClaimName::EmailVerified, "true");
    }
    if (const auto name = stringValue(userJson->as_object(), "name"); name && safeText(*name, 512U)) {
        claims.set(idp::ClaimName::DisplayName, *name);
    }
    if (const auto avatar = stringValue(userJson->as_object(), "avatar_url");
        avatar && validHttpsUrl(*avatar)) {
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
        std::move(evidence), now);
}

} // namespace openproof::provider::github

module;

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cctype>
#include <cstddef>
#include <map>
#include <memory>
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

#include "response_validation.hpp"

module openproof.provider.x;

import openproof.security;

namespace openproof::provider::x {
namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace json = boost::json;
namespace idp = identity::provider;
using Tcp = asio::ip::tcp;

constexpr std::string_view kAuthorizationEndpoint{"https://x.com/i/oauth2/authorize"};
constexpr std::string_view kApiHost{"api.x.com"};
constexpr std::string_view kTokenTarget{"/2/oauth2/token"};
constexpr std::string_view kUserTarget{"/2/users/me?user.fields=name,username,profile_image_url"};
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

[[nodiscard]] std::string formEncode(std::string_view input)
{
    constexpr char hex[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(input.size() * 3U);
    for (const char symbol : input) {
        const auto byte = static_cast<unsigned char>(symbol);
        const bool formSafe = (byte >= static_cast<unsigned char>('A')
                && byte <= static_cast<unsigned char>('Z'))
            || (byte >= static_cast<unsigned char>('a')
                && byte <= static_cast<unsigned char>('z'))
            || (byte >= static_cast<unsigned char>('0')
                && byte <= static_cast<unsigned char>('9'))
            || byte == static_cast<unsigned char>('-')
            || byte == static_cast<unsigned char>('.')
            || byte == static_cast<unsigned char>('_')
            || byte == static_cast<unsigned char>('*');
        if (formSafe) output.push_back(static_cast<char>(byte));
        else if (byte == static_cast<unsigned char>(' ')) output.push_back('+');
        else {
            output.push_back('%');
            output.push_back(hex[(byte >> 4U) & 0x0FU]);
            output.push_back(hex[byte & 0x0FU]);
        }
    }
    return output;
}

[[nodiscard]] std::string standardBase64(std::string_view input)
{
    std::vector<std::byte> bytes;
    bytes.reserve(input.size());
    for (const char value : input) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    std::string encoded = foundation::toBase64Url(bytes);
    std::ranges::replace(encoded, '-', '+');
    std::ranges::replace(encoded, '_', '/');
    while ((encoded.size() % 4U) != 0U) encoded.push_back('=');
    return encoded;
}

struct HttpResponse final {
    unsigned int status{};
    std::string body;
};

[[nodiscard]] foundation::Result<HttpResponse> httpsRequest(
    std::string_view target, http::verb method, std::string body,
    std::string_view contentType, std::string_view authorization,
    std::string_view caFile)
{
    try {
        asio::io_context io;
        asio::ssl::context context{asio::ssl::context::tls_client};
        context.set_verify_mode(asio::ssl::verify_peer);
        if (caFile.empty()) context.set_default_verify_paths();
        else context.load_verify_file(std::string{caFile});
        Tcp::resolver resolver{io};
        beast::ssl_stream<beast::tcp_stream> stream{io, context};
        std::string hostname{kApiHost};
        if (SSL_ctrl(stream.native_handle(), SSL_CTRL_SET_TLSEXT_HOSTNAME,
                     static_cast<long>(TLSEXT_NAMETYPE_host_name), hostname.data()) <= 0L) {
            return foundation::fail(foundation::ErrorCode::Unavailable,
                                    "The X TLS peer could not be configured.");
        }
        stream.set_verify_callback(asio::ssl::host_name_verification(hostname));
        auto endpoints = resolver.resolve(hostname, "443");
        beast::get_lowest_layer(stream).expires_after(std::chrono::seconds{10});
        beast::get_lowest_layer(stream).connect(endpoints);
        stream.handshake(asio::ssl::stream_base::client);

        http::request<http::string_body> request{method, std::string{target}, 11};
        request.set(http::field::host, hostname);
        request.set(http::field::user_agent, "OpenProof/1");
        request.set(http::field::accept, "application/json");
        request.set(http::field::cache_control, "no-store");
        if (!authorization.empty()) {
            request.set(http::field::authorization, authorization);
        }
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
                                "The X HTTPS request failed.");
    }
}

[[nodiscard]] foundation::Result<json::value> parseJson(std::string_view body)
{
    boost::system::error_code error;
    auto parsed = json::parse(body, error);
    if (error) return foundation::fail(authFailure("The X JSON response is malformed."));
    return parsed;
}

[[nodiscard]] std::optional<std::string> stringValue(
    const json::object& object, std::string_view name)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr || !value->is_string()) return std::nullopt;
    return std::string{value->as_string()};
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

class XAuthenticationProvider::Implementation final {
public:
    Implementation(XProviderConfig providerConfig,
                   const foundation::ClockSource& clockSource,
                   std::string certificateAuthorityFile)
        : config(std::move(providerConfig)), clock(&clockSource),
          caFile(std::move(certificateAuthorityFile)) {}

    XProviderConfig config;
    const foundation::ClockSource* clock;
    std::string caFile;
};

XProviderConfig::XProviderConfig(
    std::string clientId, foundation::SecretString clientSecret,
    std::string callbackUri, foundation::SecretString derivationKey,
    foundation::Duration challengeLifetime)
    : m_clientId(std::move(clientId)), m_clientSecret(std::move(clientSecret)),
      m_callbackUri(std::move(callbackUri)), m_derivationKey(std::move(derivationKey)),
      m_challengeLifetime(challengeLifetime) {}

foundation::Result<XProviderConfig> XProviderConfig::create(
    std::string clientId, foundation::SecretString clientSecret,
    std::string callbackUri, foundation::SecretString derivationKey,
    foundation::Duration challengeLifetime)
{
    if (!safeText(clientId, 512U) || clientSecret.empty() || clientSecret.size() > 4096U
        || !validHttpsUrl(callbackUri) || derivationKey.size() < 32U
        || challengeLifetime <= foundation::Duration::zero()
        || challengeLifetime > std::chrono::minutes{15}) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The X provider configuration is invalid.");
    }
    return XProviderConfig{std::move(clientId), std::move(clientSecret),
                           std::move(callbackUri), std::move(derivationKey),
                           challengeLifetime};
}

std::string_view XProviderConfig::clientId() const noexcept { return m_clientId; }
const foundation::SecretString& XProviderConfig::clientSecret() const noexcept { return m_clientSecret; }
std::string_view XProviderConfig::callbackUri() const noexcept { return m_callbackUri; }
const foundation::SecretString& XProviderConfig::derivationKey() const noexcept { return m_derivationKey; }
foundation::Duration XProviderConfig::challengeLifetime() const noexcept { return m_challengeLifetime; }

XAuthenticationProvider::XAuthenticationProvider(
    XProviderConfig config, const foundation::ClockSource& clock, std::string caFile)
    : m_implementation(std::make_unique<Implementation>(
          std::move(config), clock, std::move(caFile))) {}

XAuthenticationProvider::~XAuthenticationProvider() = default;

idp::ProviderId XAuthenticationProvider::id() const { return idp::ProviderId{"x"}; }
idp::InteractionModel XAuthenticationProvider::interactionModel() const noexcept
{ return idp::InteractionModel::Redirect; }
idp::AssuranceLevel XAuthenticationProvider::maximumClaimableAssurance() const noexcept
{ return idp::AssuranceLevel::Ial1; }

foundation::Result<idp::AuthenticationChallenge>
XAuthenticationProvider::beginAuthentication(const idp::AuthenticationRequest& request)
{
    if (request.provider() != id()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The X authentication request targets another provider.");
    }
    auto random = security::randomTokenBase64Url(24U);
    if (!random) return foundation::fail(random.error());
    idp::ChallengeId challengeId{"xc_" + std::move(random).value()};
    auto state = derived(m_implementation->config.derivationKey(), "state", challengeId);
    auto verifier = derived(m_implementation->config.derivationKey(), "pkce", challengeId);
    if (!state || !verifier) return foundation::fail(foundation::ErrorCode::Internal);
    auto digest = security::sha256(verifier.value());
    if (!digest) return foundation::fail(digest.error());

    std::string url{kAuthorizationEndpoint};
    url = appendQuery(std::move(url), "response_type", "code");
    url = appendQuery(std::move(url), "client_id", m_implementation->config.clientId());
    url = appendQuery(std::move(url), "redirect_uri", m_implementation->config.callbackUri());
    url = appendQuery(std::move(url), "scope", "users.read tweet.read");
    url = appendQuery(std::move(url), "state", state.value());
    url = appendQuery(std::move(url), "code_challenge", foundation::toBase64Url(digest.value()));
    url = appendQuery(std::move(url), "code_challenge_method", "S256");

    idp::AuthenticationChallenge challenge{
        challengeId, m_implementation->clock->now() + m_implementation->config.challengeLifetime()};
    challenge.setParameter("authorization_url", std::move(url));
    return challenge;
}

foundation::Result<idp::AuthenticationOutcome>
XAuthenticationProvider::completeAuthentication(const idp::AuthenticationResponse& response)
{
    const auto code = credential(response.parameters(), "code");
    const auto state = credential(response.parameters(), "state");
    if (!code || !state || code->size() > 4096U || state->size() > 512U) {
        return foundation::fail(authFailure("The X callback is incomplete."));
    }

    auto expectedState = derived(
        m_implementation->config.derivationKey(), "state", response.challengeId());
    auto verifier = derived(
        m_implementation->config.derivationKey(), "pkce", response.challengeId());
    if (!expectedState || !verifier
        || !security::constantTimeEquals(*state, expectedState.value())) {
        return foundation::fail(authFailure("The X state binding is invalid."));
    }

    std::string form;
    const auto append = [&form](std::string_view key, std::string_view value) {
        if (!form.empty()) form.push_back('&');
        form.append(formEncode(key));
        form.push_back('=');
        form.append(formEncode(value));
    };
    append("grant_type", "authorization_code");
    append("code", *code);
    append("redirect_uri", m_implementation->config.callbackUri());
    append("code_verifier", verifier.value());

    std::string credentials = formEncode(m_implementation->config.clientId());
    credentials.push_back(':');
    credentials.append(formEncode(m_implementation->config.clientSecret().expose()));
    const std::string basicAuthorization{"Basic " + standardBase64(credentials)};
    std::ranges::fill(credentials, '\0');

    auto tokenResponse = httpsRequest(
        kTokenTarget, http::verb::post, std::move(form),
        "application/x-www-form-urlencoded", basicAuthorization,
        m_implementation->caFile);
    if (!tokenResponse || tokenResponse->status != 200U) {
        return foundation::fail(authFailure("The X token exchange failed."));
    }
    auto tokenJson = parseJson(tokenResponse->body);
    if (!tokenJson || !tokenJson->is_object()) {
        return foundation::fail(authFailure("The X token response is malformed."));
    }
    const auto accessToken = stringValue(tokenJson->as_object(), "access_token");
    const auto grantedScopes = stringValue(tokenJson->as_object(), "scope");
    const auto tokenType = stringValue(tokenJson->as_object(), "token_type");
    if (!accessToken || !detail::validBearerCredential(*accessToken)
        || !grantedScopes || !detail::validScopeResponse(*grantedScopes)
        || !detail::hasScope(*grantedScopes, "users.read")
        || !tokenType || !bearerTokenType(*tokenType)) {
        return foundation::fail(authFailure("The X token response is invalid."));
    }

    const std::string bearerAuthorization{"Bearer " + *accessToken};
    auto userResponse = httpsRequest(
        kUserTarget, http::verb::get, {}, {}, bearerAuthorization,
        m_implementation->caFile);
    if (!userResponse || userResponse->status != 200U) {
        return foundation::fail(authFailure("The X authenticated-user endpoint failed."));
    }
    auto userJson = parseJson(userResponse->body);
    if (!userJson || !userJson->is_object()) {
        return foundation::fail(authFailure("The X user response is malformed."));
    }
    const auto* dataValue = userJson->as_object().if_contains("data");
    if (dataValue == nullptr || !dataValue->is_object()) {
        return foundation::fail(authFailure("The X user response is incomplete."));
    }
    const auto& user = dataValue->as_object();
    const auto accountId = stringValue(user, "id");
    const auto username = stringValue(user, "username");
    if (!accountId
        || !detail::safeProfileText(*accountId, detail::kSubjectMaximum)
        || !username
        || !detail::safeProfileText(*username, detail::kPreferredUsernameMaximum)) {
        return foundation::fail(authFailure("The X user identity is incomplete."));
    }

    idp::VerifiedClaims claims;
    claims.set(idp::ClaimName::PreferredUsername, *username);
    if (const auto name = stringValue(user, "name");
        name && detail::safeProfileText(*name, detail::kDisplayNameMaximum)) {
        claims.set(idp::ClaimName::DisplayName, *name);
    }
    if (const auto avatar = stringValue(user, "profile_image_url");
        avatar && avatar->size() <= detail::kPictureUrlMaximum
        && validHttpsUrl(*avatar)) {
        claims.set(idp::ClaimName::PictureUrl, *avatar);
    }

    idp::ProviderEvidence evidence;
    evidence.add("protocol", "x_oauth2_authorization_code_pkce");
    evidence.add("x_account_id", *accountId);
    evidence.add("username", *username);

    return idp::AuthenticationOutcome::create(
        id(), idp::ExternalSubject{*accountId}, std::move(claims),
        idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{idp::AuthenticationFactor::None, false},
        std::move(evidence), m_implementation->clock->now());
}

} // namespace openproof::provider::x

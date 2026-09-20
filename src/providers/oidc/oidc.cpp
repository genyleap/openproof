module;

#include <algorithm>
#include <charconv>
#include <cctype>
#include <chrono>
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
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/json.hpp>
#include <openssl/ssl.h>

#include "profile_claims.hpp"

module openproof.provider.oidc;

import openproof.security;

namespace openproof::provider::oidc {
namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace json = boost::json;
namespace idp = identity::provider;
using Tcp = asio::ip::tcp;

constexpr std::size_t kMaximumResponseBytes = 2U * 1024U * 1024U;
constexpr auto kClockSkew = std::chrono::seconds{60};

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

struct HttpsUrl final {
    std::string host;
    std::string port{"443"};
    std::string target{"/"};
};

[[nodiscard]] foundation::Result<HttpsUrl> parseHttpsUrl(std::string_view raw)
{
    constexpr std::string_view scheme{"https://"};
    if (!raw.starts_with(scheme) || raw.size() > 4096U || raw.contains('#')) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The OIDC endpoint URL is invalid.");
    }
    raw.remove_prefix(scheme.size());
    const auto slash = raw.find('/');
    const auto query = raw.find('?');
    const auto authorityEnd = std::min(slash == std::string_view::npos ? raw.size() : slash,
                                       query == std::string_view::npos ? raw.size() : query);
    const auto authority = raw.substr(0U, authorityEnd);
    if (authority.empty() || authority.contains('@') || authority.contains('[')
        || authority.contains(']')) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The OIDC endpoint URL authority is invalid.");
    }
    HttpsUrl parsed;
    const auto colon = authority.rfind(':');
    if (colon != std::string_view::npos) {
        parsed.host = std::string{authority.substr(0U, colon)};
        parsed.port = std::string{authority.substr(colon + 1U)};
        unsigned int port{};
        const auto converted = std::from_chars(parsed.port.data(),
            parsed.port.data() + parsed.port.size(), port);
        if (converted.ec != std::errc{} || converted.ptr != parsed.port.data() + parsed.port.size()
            || port == 0U || port > 65535U) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The OIDC endpoint port is invalid.");
        }
    } else {
        parsed.host = std::string{authority};
    }
    if (!safeText(parsed.host, 253U)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The OIDC endpoint host is invalid.");
    }
    parsed.target = authorityEnd == raw.size() ? "/" : std::string{raw.substr(authorityEnd)};
    if (parsed.target.starts_with('?')) parsed.target.insert(parsed.target.begin(), '/');
    if (!parsed.target.starts_with('/') || parsed.target.contains("\\")) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The OIDC endpoint target is invalid.");
    }
    return parsed;
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

[[nodiscard]] std::string queryAppend(std::string base, std::string_view key,
                                      std::string_view value)
{
    base.push_back(base.contains('?') ? '&' : '?');
    base.append(percentEncode(key));
    base.push_back('=');
    base.append(percentEncode(value));
    return base;
}

struct HttpResult final {
    unsigned int status{};
    std::string body;
};

[[nodiscard]] foundation::Result<HttpResult> httpsRequest(
    const HttpsUrl& endpoint, http::verb method, std::string body,
    std::string_view contentType, std::string_view caFile,
    std::string_view authorization = {})
{
    try {
        asio::io_context io;
        asio::ssl::context context{asio::ssl::context::tls_client};
        context.set_verify_mode(asio::ssl::verify_peer);
        if (caFile.empty()) context.set_default_verify_paths();
        else context.load_verify_file(std::string{caFile});
        Tcp::resolver resolver{io};
        beast::ssl_stream<beast::tcp_stream> stream{io, context};
        std::string hostname{endpoint.host};
        if (SSL_ctrl(stream.native_handle(), SSL_CTRL_SET_TLSEXT_HOSTNAME,
                     static_cast<long>(TLSEXT_NAMETYPE_host_name), hostname.data()) <= 0L) {
            return foundation::fail(foundation::ErrorCode::Unavailable,
                                    "The OIDC TLS peer could not be configured.");
        }
        stream.set_verify_callback(asio::ssl::host_name_verification(endpoint.host));
        auto endpoints = resolver.resolve(endpoint.host, endpoint.port);
        beast::get_lowest_layer(stream).expires_after(std::chrono::seconds{10});
        beast::get_lowest_layer(stream).connect(endpoints);
        stream.handshake(asio::ssl::stream_base::client);

        http::request<http::string_body> request{method, endpoint.target, 11};
        request.set(http::field::host, endpoint.host);
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
        return HttpResult{response.result_int(), std::move(response.body())};
    } catch (...) {
        return foundation::fail(foundation::ErrorCode::Unavailable,
                                "The OIDC HTTPS request failed.");
    }
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

[[nodiscard]] foundation::Result<json::object> parseJsonObject(std::string_view body)
{
    boost::system::error_code error;
    auto parsed = json::parse(body, error);
    if (error || !parsed.is_object()) {
        return foundation::fail(authFailure("The OIDC JSON response is malformed."));
    }
    return std::move(parsed).as_object();
}

[[nodiscard]] std::optional<std::string> stringValue(
    const json::object& object, std::string_view name)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr || !value->is_string()) return std::nullopt;
    return std::string{value->as_string()};
}

[[nodiscard]] std::optional<std::int64_t> integerValue(
    const json::object& object, std::string_view name)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr) return std::nullopt;
    if (value->is_int64()) return value->as_int64();
    if (value->is_uint64() && value->as_uint64() <= static_cast<std::uint64_t>(INT64_MAX)) {
        return static_cast<std::int64_t>(value->as_uint64());
    }
    return std::nullopt;
}

[[nodiscard]] foundation::Instant fromUnixSeconds(std::int64_t seconds)
{
    return foundation::Instant{std::chrono::duration_cast<foundation::Duration>(
        std::chrono::seconds{seconds})};
}

[[nodiscard]] foundation::Result<std::string> derived(
    const foundation::SecretString& key, std::string_view label,
    const idp::ChallengeId& challenge)
{
    std::string input{label};
    input.push_back(':');
    input.append(challenge.value());
    auto digest = security::hmacSha256(key, input);
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

[[nodiscard]] bool audienceContains(const json::object& payload, std::string_view clientId,
                                    bool& multiple)
{
    multiple = false;
    const auto* audience = payload.if_contains("aud");
    if (audience == nullptr) return false;
    if (audience->is_string()) return audience->as_string() == clientId;
    if (!audience->is_array()) return false;
    multiple = audience->as_array().size() > 1U;
    return std::ranges::any_of(audience->as_array(), [clientId](const json::value& value) {
        return value.is_string() && value.as_string() == clientId;
    });
}

[[nodiscard]] bool jsonBoolean(const json::object& object, std::string_view name)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr) return false;
    if (value->is_bool()) return value->as_bool();
    return value->is_string() && value->as_string() == "true";
}

[[nodiscard]] std::optional<std::string> standardDisplayName(
    const json::object& payload)
{
    const auto name = stringValue(payload, "name");
    const auto given = stringValue(payload, "given_name");
    const auto family = stringValue(payload, "family_name");
    const auto view = [](const std::optional<std::string>& value)
        -> std::optional<std::string_view> {
        if (!value) return std::nullopt;
        return std::string_view{*value};
    };
    return detail::displayName(view(name), view(given), view(family));
}

[[nodiscard]] std::optional<std::string> appleDisplayName(
    const idp::SecretAttributeMap& parameters)
{
    const auto payload = credential(parameters, "user");
    if (!payload || payload->empty() || payload->size() > 16U * 1024U) {
        return std::nullopt;
    }

    boost::system::error_code parseError;
    auto parsed = json::parse(*payload, parseError);
    if (parseError || !parsed.is_object()) return std::nullopt;
    const auto* nameValue = parsed.as_object().if_contains("name");
    if (nameValue == nullptr || !nameValue->is_object()) return std::nullopt;

    const auto& name = nameValue->as_object();
    const auto first = stringValue(name, "firstName");
    const auto last = stringValue(name, "lastName");
    const auto view = [](const std::optional<std::string>& value)
        -> std::optional<std::string_view> {
        if (!value) return std::nullopt;
        return std::string_view{*value};
    };
    return detail::displayName(std::nullopt, view(first), view(last));
}

} // namespace

class OidcAuthenticationProvider::Implementation final {
public:
    struct Discovery final {
        std::string authorizationEndpoint;
        std::string tokenEndpoint;
        std::string jwksUri;
        std::vector<std::string> tokenAuthenticationMethods;
        foundation::Instant expiresAt{};
    };

    Implementation(OidcProviderConfig providerConfig,
                   const foundation::ClockSource& clockSource,
                   std::string certificateAuthorityFile)
        : config(std::move(providerConfig)), clock(&clockSource),
          caFile(std::move(certificateAuthorityFile)) {}

    [[nodiscard]] foundation::Result<Discovery> discovery()
    {
        const auto now = clock->now();
        {
            const std::lock_guard guard{mutex};
            if (cached && cached->expiresAt > now) return *cached;
        }
        auto endpoint = parseHttpsUrl(std::string{config.issuer()} + "/.well-known/openid-configuration");
        if (!endpoint) return foundation::fail(endpoint.error());
        auto response = httpsRequest(endpoint.value(), http::verb::get, {}, {}, caFile);
        if (!response || response->status != 200U) {
            return foundation::fail(foundation::ErrorCode::Unavailable,
                                    "OIDC discovery is unavailable.");
        }
        auto object = parseJsonObject(response->body);
        if (!object) return foundation::fail(object.error());
        const auto issuer = stringValue(object.value(), "issuer");
        const auto authorization = stringValue(object.value(), "authorization_endpoint");
        const auto token = stringValue(object.value(), "token_endpoint");
        const auto jwks = stringValue(object.value(), "jwks_uri");
        if (!issuer || *issuer != config.issuer() || !authorization || !token || !jwks
            || !parseHttpsUrl(*authorization) || !parseHttpsUrl(*token) || !parseHttpsUrl(*jwks)) {
            return foundation::fail(authFailure("OIDC discovery metadata failed validation."));
        }
        const auto readStringArray = [&](std::string_view name, std::string_view detail)
            -> foundation::Result<std::vector<std::string>> {
            std::vector<std::string> values;
            const auto* field = object->if_contains(name);
            if (field == nullptr) return values;
            if (!field->is_array()) {
                return foundation::fail(authFailure(std::string{detail}));
            }
            for (const auto& value : field->as_array()) {
                if (!value.is_string() || value.as_string().empty()
                    || value.as_string().size() > 128U) {
                    return foundation::fail(authFailure(std::string{detail}));
                }
                values.emplace_back(value.as_string());
            }
            return values;
        };
        auto tokenAuthenticationMethods = readStringArray(
            "token_endpoint_auth_methods_supported",
            "OIDC discovery token authentication metadata is malformed.");
        if (!tokenAuthenticationMethods) {
            return foundation::fail(tokenAuthenticationMethods.error());
        }
        auto responseModes = readStringArray(
            "response_modes_supported",
            "OIDC discovery response-mode metadata is malformed.");
        if (!responseModes) return foundation::fail(responseModes.error());
        auto codeChallengeMethods = readStringArray(
            "code_challenge_methods_supported",
            "OIDC discovery PKCE metadata is malformed.");
        if (!codeChallengeMethods) return foundation::fail(codeChallengeMethods.error());
        const std::string_view requiredMethod =
            config.clientAuthentication()
                    == OidcClientAuthenticationMethod::ClientSecretBasic
                ? "client_secret_basic" : "client_secret_post";
        if (!tokenAuthenticationMethods->empty()
            && std::ranges::find(tokenAuthenticationMethods.value(), requiredMethod)
                == tokenAuthenticationMethods->end()) {
            return foundation::fail(authFailure(
                "OIDC discovery does not support the configured client authentication method."));
        }
        if (!codeChallengeMethods->empty()
            && std::ranges::find(codeChallengeMethods.value(), std::string_view{"S256"})
                == codeChallengeMethods->end()) {
            return foundation::fail(authFailure(
                "OIDC discovery does not support the required S256 PKCE method."));
        }
        const std::string_view requiredResponseMode =
            config.authorizationResponseMode() == OidcAuthorizationResponseMode::FormPost
                ? "form_post" : "query";
        if (!responseModes->empty()
            && std::ranges::find(responseModes.value(), requiredResponseMode)
                == responseModes->end()) {
            return foundation::fail(authFailure(
                "OIDC discovery does not support the configured authorization response mode."));
        }
        Discovery value{*authorization, *token, *jwks,
                        std::move(tokenAuthenticationMethods).value(),
                        now + std::chrono::hours{1}};
        {
            const std::lock_guard guard{mutex};
            cached = value;
        }
        return value;
    }

    OidcProviderConfig config;
    const foundation::ClockSource* clock;
    std::string caFile;
    std::mutex mutex;
    std::optional<Discovery> cached;
};

foundation::Result<foundation::SecretString> makeAppleClientSecret(
    std::string teamId, std::string clientId, std::string keyId,
    foundation::SecretString privateKeyPem, foundation::Instant now,
    foundation::Duration lifetime)
{
    constexpr auto appleMaximumLifetime = std::chrono::seconds{15'777'000};
    const auto appleIdentifier = [](std::string_view value) noexcept {
        return value.size() == 10U
            && std::ranges::all_of(value, [](char symbol) {
                   return std::isalnum(static_cast<unsigned char>(symbol)) != 0;
               });
    };
    if (!appleIdentifier(teamId) || !safeText(clientId, 512U)
        || !appleIdentifier(keyId) || lifetime <= foundation::Duration::zero()
        || lifetime > appleMaximumLifetime) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The Apple client-secret configuration is invalid.");
    }
    auto signer = security::Es256Signer::create(
        std::move(privateKeyPem), std::move(keyId));
    if (!signer) return foundation::fail(signer.error());
    const auto seconds = [](foundation::Instant value) {
        return std::chrono::duration_cast<std::chrono::seconds>(
            value.time_since_epoch()).count();
    };
    foundation::JsonObjectWriter payload;
    payload.add("iss", teamId)
        .add("iat", static_cast<std::int64_t>(seconds(now)))
        .add("exp", static_cast<std::int64_t>(seconds(now + lifetime)))
        .add("aud", "https://appleid.apple.com")
        .add("sub", clientId);
    auto token = signer->signJwt(payload.build());
    if (!token) return foundation::fail(token.error());
    return foundation::SecretString{std::move(token).value()};
}

OidcProviderConfig::OidcProviderConfig(
    idp::ProviderId providerId, std::string issuer, std::string clientId,
    foundation::SecretString clientSecret, std::string callbackUri,
    std::vector<std::string> scopes, foundation::SecretString derivationKey,
    foundation::Duration challengeLifetime,
    OidcClientAuthenticationMethod clientAuthentication,
    OidcAuthorizationResponseMode authorizationResponseMode)
    : m_providerId(std::move(providerId)), m_issuer(std::move(issuer)),
      m_clientId(std::move(clientId)), m_clientSecret(std::move(clientSecret)),
      m_callbackUri(std::move(callbackUri)), m_scopes(std::move(scopes)),
      m_derivationKey(std::move(derivationKey)), m_challengeLifetime(challengeLifetime),
      m_clientAuthentication(clientAuthentication),
      m_authorizationResponseMode(authorizationResponseMode) {}


const idp::ProviderId& OidcProviderConfig::providerId() const noexcept { return m_providerId; }
std::string_view OidcProviderConfig::issuer() const noexcept { return m_issuer; }
std::string_view OidcProviderConfig::clientId() const noexcept { return m_clientId; }
const foundation::SecretString& OidcProviderConfig::clientSecret() const noexcept { return m_clientSecret; }
foundation::Result<foundation::SecretString>
OidcProviderConfig::clientSecretAt(foundation::Instant now) const
{
    if (!m_dynamicAppleClientSecret) return m_clientSecret.clone();
    return makeAppleClientSecret(
        m_appleTeamId, m_clientId, m_appleKeyId, m_applePrivateKey.clone(), now);
}
std::string_view OidcProviderConfig::callbackUri() const noexcept { return m_callbackUri; }
const std::vector<std::string>& OidcProviderConfig::scopes() const noexcept { return m_scopes; }
const foundation::SecretString& OidcProviderConfig::derivationKey() const noexcept { return m_derivationKey; }
foundation::Duration OidcProviderConfig::challengeLifetime() const noexcept { return m_challengeLifetime; }
OidcClientAuthenticationMethod OidcProviderConfig::clientAuthentication() const noexcept
{ return m_clientAuthentication; }
OidcAuthorizationResponseMode OidcProviderConfig::authorizationResponseMode() const noexcept
{ return m_authorizationResponseMode; }

foundation::Result<OidcProviderConfig> OidcProviderConfig::create(
    idp::ProviderId providerId, std::string issuer, std::string clientId,
    foundation::SecretString clientSecret, std::string callbackUri,
    std::vector<std::string> scopes, foundation::SecretString derivationKey,
    foundation::Duration challengeLifetime,
    OidcClientAuthenticationMethod clientAuthentication,
    OidcAuthorizationResponseMode authorizationResponseMode)
{
    while (issuer.size() > 8U && issuer.ends_with('/')) issuer.pop_back();
    if (providerId.empty() || !safeText(clientId, 512U) || clientSecret.empty()
        || clientSecret.size() > 4096U || derivationKey.size() < 32U
        || challengeLifetime <= foundation::Duration::zero()
        || challengeLifetime > std::chrono::minutes{15}
        || !parseHttpsUrl(issuer) || !parseHttpsUrl(callbackUri)
        || scopes.empty() || scopes.size() > 32U
        || std::ranges::any_of(scopes, [](const std::string& scope) {
               return !safeText(scope, 128U) || scope.contains(' ');
           })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The OIDC provider configuration is invalid.");
    }
    return OidcProviderConfig{std::move(providerId), std::move(issuer),
        std::move(clientId), std::move(clientSecret), std::move(callbackUri),
        std::move(scopes), std::move(derivationKey), challengeLifetime,
        clientAuthentication, authorizationResponseMode};
}

foundation::Result<OidcProviderConfig> OidcProviderConfig::createApple(
    idp::ProviderId providerId, std::string issuer, std::string clientId,
    std::string teamId, std::string keyId, foundation::SecretString privateKeyPem,
    std::string callbackUri, std::vector<std::string> scopes,
    foundation::SecretString derivationKey, foundation::Duration challengeLifetime)
{
    if (providerId.value() != "apple") {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The Apple OIDC provider identifier is invalid.");
    }
    auto initialSecret = makeAppleClientSecret(
        teamId, clientId, keyId, privateKeyPem.clone(), foundation::Instant{},
        std::chrono::hours{1});
    if (!initialSecret) return foundation::fail(initialSecret.error());
    auto configured = create(
        std::move(providerId), std::move(issuer), std::move(clientId),
        std::move(initialSecret).value(), std::move(callbackUri), std::move(scopes),
        std::move(derivationKey), challengeLifetime,
        OidcClientAuthenticationMethod::ClientSecretPost,
        OidcAuthorizationResponseMode::FormPost);
    if (!configured) return foundation::fail(configured.error());
    configured->m_dynamicAppleClientSecret = true;
    configured->m_appleTeamId = std::move(teamId);
    configured->m_appleKeyId = std::move(keyId);
    configured->m_applePrivateKey = std::move(privateKeyPem);
    return configured;
}

OidcAuthenticationProvider::OidcAuthenticationProvider(
    OidcProviderConfig config, const foundation::ClockSource& clock, std::string caFile)
    : m_implementation(std::make_unique<Implementation>(
          std::move(config), clock, std::move(caFile))) {}

OidcAuthenticationProvider::~OidcAuthenticationProvider() = default;

idp::ProviderId OidcAuthenticationProvider::id() const
{ return m_implementation->config.providerId(); }

idp::InteractionModel OidcAuthenticationProvider::interactionModel() const noexcept
{ return idp::InteractionModel::Redirect; }

idp::AssuranceLevel OidcAuthenticationProvider::maximumClaimableAssurance() const noexcept
{ return idp::AssuranceLevel::Ial1; }

foundation::Result<idp::AuthenticationChallenge>
OidcAuthenticationProvider::beginAuthentication(const idp::AuthenticationRequest& request)
{
    if (request.provider() != m_implementation->config.providerId()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The OIDC authentication request targets another provider.");
    }
    auto metadata = m_implementation->discovery();
    if (!metadata) return foundation::fail(metadata.error());
    auto random = security::randomTokenBase64Url(24U);
    if (!random) return foundation::fail(random.error());
    idp::ChallengeId challengeId{"opc_" + std::move(random).value()};
    auto state = derived(m_implementation->config.derivationKey(), "state", challengeId);
    auto nonce = derived(m_implementation->config.derivationKey(), "nonce", challengeId);
    auto verifier = derived(m_implementation->config.derivationKey(), "pkce", challengeId);
    if (!state || !nonce || !verifier) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "OIDC challenge derivation failed.");
    }
    auto verifierDigest = security::sha256(verifier.value());
    if (!verifierDigest) return foundation::fail(verifierDigest.error());
    std::string scope;
    for (const auto& item : m_implementation->config.scopes()) {
        if (!scope.empty()) scope.push_back(' ');
        scope.append(item);
    }
    std::string url = metadata->authorizationEndpoint;
    url = queryAppend(std::move(url), "response_type", "code");
    url = queryAppend(std::move(url), "client_id", m_implementation->config.clientId());
    url = queryAppend(std::move(url), "redirect_uri", m_implementation->config.callbackUri());
    url = queryAppend(std::move(url), "scope", scope);
    url = queryAppend(std::move(url), "state", state.value());
    url = queryAppend(std::move(url), "nonce", nonce.value());
    if (m_implementation->config.authorizationResponseMode()
        == OidcAuthorizationResponseMode::FormPost) {
        url = queryAppend(std::move(url), "response_mode", "form_post");
    }
    url = queryAppend(std::move(url), "code_challenge",
                      foundation::toBase64Url(verifierDigest.value()));
    url = queryAppend(std::move(url), "code_challenge_method", "S256");
    idp::AuthenticationChallenge challenge{
        challengeId, m_implementation->clock->now() + m_implementation->config.challengeLifetime()};
    challenge.setParameter("authorization_url", std::move(url));
    return challenge;
}

foundation::Result<idp::AuthenticationOutcome>
OidcAuthenticationProvider::completeAuthentication(const idp::AuthenticationResponse& response)
{
    const auto code = credential(response.parameters(), "code");
    const auto state = credential(response.parameters(), "state");
    if (!code || !state || code->size() > 4096U || state->size() > 512U) {
        return foundation::fail(authFailure("The OIDC callback is incomplete."));
    }
    auto expectedState = derived(
        m_implementation->config.derivationKey(), "state", response.challengeId());
    auto nonce = derived(m_implementation->config.derivationKey(), "nonce", response.challengeId());
    auto verifier = derived(m_implementation->config.derivationKey(), "pkce", response.challengeId());
    if (!expectedState || !nonce || !verifier
        || !security::constantTimeEquals(*state, expectedState.value())) {
        return foundation::fail(authFailure("The OIDC state binding is invalid."));
    }
    auto metadata = m_implementation->discovery();
    if (!metadata) return foundation::fail(metadata.error());
    auto tokenEndpoint = parseHttpsUrl(metadata->tokenEndpoint);
    if (!tokenEndpoint) return foundation::fail(tokenEndpoint.error());
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
    append("client_id", m_implementation->config.clientId());
    auto clientSecret = m_implementation->config.clientSecretAt(
        m_implementation->clock->now());
    if (!clientSecret) {
        return foundation::fail(authFailure(
            "The OIDC client authentication material is unavailable."));
    }
    std::string authorization;
    if (m_implementation->config.clientAuthentication()
        == OidcClientAuthenticationMethod::ClientSecretPost) {
        append("client_secret", clientSecret->expose());
    } else {
        std::string credentials = formEncode(m_implementation->config.clientId());
        credentials.push_back(':');
        credentials.append(formEncode(clientSecret->expose()));
        authorization = "Basic " + standardBase64(credentials);
        std::ranges::fill(credentials, '\0');
    }
    append("code_verifier", verifier.value());
    auto tokenResponse = httpsRequest(tokenEndpoint.value(), http::verb::post, std::move(form),
                                      "application/x-www-form-urlencoded", m_implementation->caFile,
                                      authorization);
    if (!tokenResponse || tokenResponse->status != 200U) {
        return foundation::fail(authFailure("The OIDC token exchange failed."));
    }
    auto tokenObject = parseJsonObject(tokenResponse->body);
    if (!tokenObject) return foundation::fail(tokenObject.error());
    const auto idToken = stringValue(tokenObject.value(), "id_token");
    if (!idToken || idToken->size() > 32U * 1024U) {
        return foundation::fail(authFailure("The OIDC token response did not contain an ID Token."));
    }

    const auto firstDot = idToken->find('.');
    if (firstDot == std::string::npos) {
        return foundation::fail(authFailure("The OIDC ID Token is malformed."));
    }
    auto headerBytes = foundation::fromBase64Url(std::string_view{*idToken}.substr(0U, firstDot));
    if (!headerBytes || headerBytes->size() > 4096U) {
        return foundation::fail(authFailure("The OIDC ID Token header is malformed."));
    }
    std::string headerJson{reinterpret_cast<const char*>(headerBytes->data()), headerBytes->size()};
    auto header = parseJsonObject(headerJson);
    const auto kid = header ? stringValue(header.value(), "kid") : std::nullopt;
    const auto alg = header ? stringValue(header.value(), "alg") : std::nullopt;
    if (!header || !kid || !alg || *alg != "RS256" || kid->empty() || kid->size() > 256U) {
        return foundation::fail(authFailure("The OIDC ID Token JOSE header is invalid."));
    }

    auto jwksEndpoint = parseHttpsUrl(metadata->jwksUri);
    if (!jwksEndpoint) return foundation::fail(jwksEndpoint.error());
    auto jwksResponse = httpsRequest(jwksEndpoint.value(), http::verb::get, {}, {}, m_implementation->caFile);
    if (!jwksResponse || jwksResponse->status != 200U) {
        return foundation::fail(authFailure("The OIDC signing keys are unavailable."));
    }
    auto jwks = parseJsonObject(jwksResponse->body);
    const json::value* keysValue = jwks ? jwks->if_contains("keys") : nullptr;
    if (!jwks || keysValue == nullptr || !keysValue->is_array()) {
        return foundation::fail(authFailure("The OIDC JWKS is malformed."));
    }
    std::optional<std::string> modulus;
    std::optional<std::string> exponent;
    for (const auto& value : keysValue->as_array()) {
        if (!value.is_object()) continue;
        const auto& key = value.as_object();
        if (stringValue(key, "kid") != kid || stringValue(key, "kty") != std::optional<std::string>{"RSA"}) continue;
        if (const auto keyAlg = stringValue(key, "alg"); keyAlg && *keyAlg != "RS256") continue;
        modulus = stringValue(key, "n");
        exponent = stringValue(key, "e");
        if (modulus && exponent) break;
    }
    if (!modulus || !exponent) {
        return foundation::fail(authFailure("The OIDC signing key was not found."));
    }
    auto verified = security::verifyRs256Jwk(*modulus, *exponent, *idToken);
    if (!verified) return foundation::fail(authFailure("The OIDC ID Token signature is invalid."));
    auto payload = parseJsonObject(verified->payloadJson());
    if (!payload) return foundation::fail(payload.error());
    const auto issuer = stringValue(payload.value(), "iss");
    const auto subject = stringValue(payload.value(), "sub");
    const auto tokenNonce = stringValue(payload.value(), "nonce");
    const auto issuedAt = integerValue(payload.value(), "iat");
    const auto expiresAt = integerValue(payload.value(), "exp");
    bool multipleAudience = false;
    const bool audienceValid = audienceContains(
        payload.value(), m_implementation->config.clientId(), multipleAudience);
    const auto authorizedParty = stringValue(payload.value(), "azp");
    const auto now = m_implementation->clock->now();
    if (!issuer || *issuer != m_implementation->config.issuer()
        || !subject || !safeText(*subject, 512U) || !tokenNonce
        || !security::constantTimeEquals(*tokenNonce, nonce.value())
        || !issuedAt || !expiresAt || !audienceValid
        || (multipleAudience && (!authorizedParty || *authorizedParty != m_implementation->config.clientId()))
        || fromUnixSeconds(*issuedAt) > now + kClockSkew
        || fromUnixSeconds(*issuedAt) < now - std::chrono::hours{24}
        || fromUnixSeconds(*expiresAt) <= now - kClockSkew
        || fromUnixSeconds(*expiresAt) > now + std::chrono::hours{24}) {
        return foundation::fail(authFailure("The OIDC ID Token claims are invalid."));
    }

    idp::VerifiedClaims claims;
    const auto email = stringValue(payload.value(), "email");
    if (email && safeText(*email, 320U) && jsonBoolean(payload.value(), "email_verified")) {
        claims.set(idp::ClaimName::Email, *email);
        claims.set(idp::ClaimName::EmailVerified, "true");
    }
    const auto displayName = standardDisplayName(payload.value());
    if (displayName) {
        claims.set(idp::ClaimName::DisplayName, *displayName);
    } else if (m_implementation->config.providerId().value() == "apple") {
        const auto appleName = appleDisplayName(response.parameters());
        if (appleName) {
            claims.set(idp::ClaimName::DisplayName, *appleName);
        }
    }
    const auto username = stringValue(payload.value(), "preferred_username");
    if (username && detail::safeProfileText(
            *username, detail::kPreferredUsernameMaximum)) {
        claims.set(idp::ClaimName::PreferredUsername, *username);
    }
    const auto locale = stringValue(payload.value(), "locale");
    if (locale && safeText(*locale, 64U)) claims.set(idp::ClaimName::Locale, *locale);
    const auto picture = stringValue(payload.value(), "picture");
    if (picture && detail::validHttpsProfileUrl(*picture)) {
        claims.set(idp::ClaimName::PictureUrl, *picture);
    }

    idp::ProviderEvidence evidence;
    evidence.add("issuer", *issuer);
    evidence.add("kid", *kid);
    evidence.add("algorithm", "RS256");
    evidence.add("protocol", "oidc_authorization_code_pkce");
    return idp::AuthenticationOutcome::create(
        m_implementation->config.providerId(), idp::ExternalSubject{*subject},
        std::move(claims), idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{idp::AuthenticationFactor::None, false},
        std::move(evidence), now);
}

} // namespace openproof::provider::oidc

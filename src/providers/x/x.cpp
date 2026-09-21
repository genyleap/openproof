module;

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cctype>
#include <climits>
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
#include <vector>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/json.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>

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

constexpr std::string_view kApiHost{"api.x.com"};
constexpr std::string_view kRequestTokenTarget{"/oauth/request_token"};
constexpr std::string_view kAccessTokenTarget{"/oauth/access_token"};
constexpr std::string_view kRequestTokenUrl{"https://api.x.com/oauth/request_token"};
constexpr std::string_view kAccessTokenUrl{"https://api.x.com/oauth/access_token"};
constexpr std::string_view kAuthorizationEndpoint{"https://api.x.com/oauth/authenticate"};
constexpr std::string_view kChallengePrefix{"xo1_"};
constexpr std::string_view kChallengeAad{"openproof/x/oauth1/challenge/v1"};
constexpr std::size_t kMaximumResponseBytes = 512U * 1024U;

using Parameter = std::pair<std::string, std::string>;
using Parameters = std::vector<Parameter>;

[[nodiscard]] foundation::Error authFailure(std::string detail)
{
    return foundation::Error{
        foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(
            foundation::ErrorCode::AuthenticationFailed)},
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

[[nodiscard]] int hexValue(char symbol) noexcept
{
    if (symbol >= '0' && symbol <= '9') return symbol - '0';
    if (symbol >= 'A' && symbol <= 'F') return 10 + symbol - 'A';
    if (symbol >= 'a' && symbol <= 'f') return 10 + symbol - 'a';
    return -1;
}

[[nodiscard]] std::optional<std::string> formDecode(std::string_view input)
{
    std::string output;
    output.reserve(input.size());
    for (std::size_t index = 0U; index < input.size(); ++index) {
        if (input[index] == '+') {
            output.push_back(' ');
            continue;
        }
        if (input[index] != '%') {
            output.push_back(input[index]);
            continue;
        }
        if (index + 2U >= input.size()) return std::nullopt;
        const int high = hexValue(input[index + 1U]);
        const int low = hexValue(input[index + 2U]);
        if (high < 0 || low < 0) return std::nullopt;
        output.push_back(static_cast<char>((high << 4) | low));
        index += 2U;
    }
    return output;
}

[[nodiscard]] foundation::Result<std::map<std::string, std::string>>
parseForm(std::string_view body)
{
    if (body.empty() || body.size() > kMaximumResponseBytes) {
        return foundation::fail(authFailure("The X OAuth response is empty or oversized."));
    }
    std::map<std::string, std::string> values;
    std::size_t begin = 0U;
    while (begin <= body.size()) {
        const auto end = body.find('&', begin);
        const auto item = body.substr(
            begin, end == std::string_view::npos ? body.size() - begin : end - begin);
        const auto equals = item.find('=');
        if (equals == std::string_view::npos) {
            return foundation::fail(authFailure("The X OAuth response is malformed."));
        }
        auto key = formDecode(item.substr(0U, equals));
        auto value = formDecode(item.substr(equals + 1U));
        if (!key || !value || key->empty() || key->size() > 256U
            || value->size() > 4096U || values.contains(*key)) {
            return foundation::fail(authFailure("The X OAuth response is malformed."));
        }
        values.emplace(std::move(*key), std::move(*value));
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    return values;
}

[[nodiscard]] std::string standardBase64(std::span<const std::byte> input)
{
    std::string encoded = foundation::toBase64Url(input);
    std::ranges::replace(encoded, '-', '+');
    std::ranges::replace(encoded, '_', '/');
    while ((encoded.size() % 4U) != 0U) encoded.push_back('=');
    return encoded;
}

[[nodiscard]] foundation::Result<std::string>
hmacSha1Base64(std::string_view key, std::string_view data)
{
    if (key.empty() || key.size() > static_cast<std::size_t>(INT_MAX)) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "The X OAuth signing key is invalid.");
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digestLength{};
    const auto* result = HMAC(
        EVP_sha1(), key.data(), static_cast<int>(key.size()),
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size(), digest.data(), &digestLength);
    if (result == nullptr || digestLength == 0U
        || digestLength > digest.size()) {
        return foundation::fail(
            foundation::ErrorCode::Internal,
            "The X OAuth HMAC-SHA1 signature could not be computed.");
    }

    return standardBase64(std::as_bytes(
        std::span{digest.data(), static_cast<std::size_t>(digestLength)}));
}

[[nodiscard]] std::string normalizedParameters(const Parameters& parameters)
{
    Parameters encoded;
    encoded.reserve(parameters.size());
    for (const auto& [key, value] : parameters) {
        encoded.emplace_back(percentEncode(key), percentEncode(value));
    }
    std::ranges::sort(encoded);
    std::string normalized;
    for (const auto& [key, value] : encoded) {
        if (!normalized.empty()) normalized.push_back('&');
        normalized.append(key);
        normalized.push_back('=');
        normalized.append(value);
    }
    return normalized;
}

[[nodiscard]] foundation::Result<std::string> oauthAuthorization(
    std::string_view method, std::string_view baseUrl,
    std::string_view consumerKey, const foundation::SecretString& consumerSecret,
    std::string_view timestamp, std::string_view nonce,
    Parameters extra, std::string_view tokenSecret = {})
{
    Parameters parameters;
    parameters.reserve(extra.size() + 5U);
    parameters.emplace_back("oauth_consumer_key", consumerKey);
    parameters.emplace_back("oauth_nonce", nonce);
    parameters.emplace_back("oauth_signature_method", "HMAC-SHA1");
    parameters.emplace_back("oauth_timestamp", timestamp);
    parameters.emplace_back("oauth_version", "1.0");
    for (auto& item : extra) parameters.push_back(std::move(item));

    const std::string normalized = normalizedParameters(parameters);
    std::string signatureBase;
    signatureBase.reserve(method.size() + baseUrl.size() + normalized.size() + 16U);
    signatureBase.append(method);
    signatureBase.push_back('&');
    signatureBase.append(percentEncode(baseUrl));
    signatureBase.push_back('&');
    signatureBase.append(percentEncode(normalized));

    std::string signingKey = percentEncode(consumerSecret.expose());
    signingKey.push_back('&');
    signingKey.append(percentEncode(tokenSecret));
    auto signature = hmacSha1Base64(signingKey, signatureBase);
    std::ranges::fill(signingKey, '\0');
    if (!signature) return foundation::fail(signature.error());

    parameters.emplace_back("oauth_signature", std::move(signature).value());
    std::ranges::sort(parameters, [](const Parameter& left, const Parameter& right) {
        return left.first < right.first;
    });

    std::string header{"OAuth "};
    for (std::size_t index = 0U; index < parameters.size(); ++index) {
        if (index != 0U) header.append(", ");
        header.append(percentEncode(parameters[index].first));
        header.append("=\"");
        header.append(percentEncode(parameters[index].second));
        header.push_back('"');
    }
    return header;
}

struct HttpResponse final {
    unsigned int status{};
    std::string body;
};

[[nodiscard]] foundation::Result<HttpResponse> httpsRequest(
    std::string_view target, http::verb method,
    std::string_view authorization, std::string_view caFile)
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
                     static_cast<long>(TLSEXT_NAMETYPE_host_name),
                     hostname.data()) <= 0L) {
            return foundation::fail(
                foundation::ErrorCode::Unavailable,
                "The X TLS peer could not be configured.");
        }
        stream.set_verify_callback(asio::ssl::host_name_verification(hostname));
        auto endpoints = resolver.resolve(hostname, "443");
        beast::get_lowest_layer(stream).expires_after(std::chrono::seconds{10});
        beast::get_lowest_layer(stream).connect(endpoints);
        stream.handshake(asio::ssl::stream_base::client);

        http::request<http::string_body> request{
            method, std::string{target}, 11};
        request.set(http::field::host, hostname);
        request.set(http::field::user_agent, "OpenProof/1");
        request.set(http::field::accept, "application/x-www-form-urlencoded");
        request.set(http::field::cache_control, "no-store");
        request.set(http::field::authorization, authorization);
        if (method == http::verb::post) {
            request.set(http::field::content_type,
                        "application/x-www-form-urlencoded");
            request.body().clear();
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
        return foundation::fail(
            foundation::ErrorCode::Unavailable,
            "The X HTTPS request failed.");
    }
}

void logUpstreamFailure(std::string_view stage,
                        const foundation::Result<HttpResponse>& response)
{
    if (!response) {
        std::cerr << "openproof_x_oauth1_failure stage=" << stage
                  << " transport=failed\n";
        return;
    }

    std::string oauthProblem{"-"};
    std::string jsonCode{"-"};
    std::string jsonMessage{"-"};

    auto form = parseForm(response->body);
    if (form) {
        if (const auto found = form->find("oauth_problem");
            found != form->end() && safeText(found->second, 256U)) {
            oauthProblem = found->second;
        }
    }

    boost::system::error_code parseError;
    auto parsed = json::parse(response->body, parseError);
    if (!parseError && parsed.is_object()) {
        const auto& object = parsed.as_object();
        if (const auto* errors = object.if_contains("errors");
            errors != nullptr && errors->is_array()
            && !errors->as_array().empty()
            && errors->as_array().front().is_object()) {
            const auto& first = errors->as_array().front().as_object();
            if (const auto* code = first.if_contains("code"); code != nullptr) {
                if (code->is_int64()) jsonCode = std::to_string(code->as_int64());
                else if (code->is_uint64()) jsonCode = std::to_string(code->as_uint64());
            }
            if (const auto* message = first.if_contains("message");
                message != nullptr && message->is_string()) {
                std::string value{message->as_string()};
                if (safeText(value, 512U)) jsonMessage = std::move(value);
            }
        }
    }

    std::cerr << "openproof_x_oauth1_failure stage=" << stage
              << " status=" << response->status
              << " oauth_problem=" << oauthProblem
              << " error_code=" << jsonCode
              << " error_message=" << jsonMessage << '\n';
}

[[nodiscard]] std::string unixTimestamp(const foundation::ClockSource& clock)
{
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
        clock.now().time_since_epoch()).count();
    return std::to_string(seconds);
}

struct RequestTokenState final {
    std::string token;
    foundation::SecretString secret;
};

[[nodiscard]] foundation::Result<std::string> sealRequestToken(
    const XProviderConfig& config, std::string token,
    foundation::SecretString secret)
{
    if (!safeText(token, 1024U) || secret.empty() || secret.size() > 2048U
        || token.contains('\n') || secret.expose().contains('\n')) {
        return foundation::fail(authFailure(
            "The X OAuth request-token response is invalid."));
    }

    std::string plaintext = std::move(token);
    plaintext.push_back('\n');
    plaintext.append(secret.expose());
    auto aeadKey = security::AeadKey::create(config.derivationKey().clone());
    if (!aeadKey) return foundation::fail(aeadKey.error());
    auto sealed = security::sealAes256Gcm(
        aeadKey.value(), foundation::SecretString{std::move(plaintext)},
        kChallengeAad);
    if (!sealed) return foundation::fail(sealed.error());
    return std::string{kChallengePrefix} + foundation::toBase64Url(sealed.value());
}

[[nodiscard]] foundation::Result<RequestTokenState> openRequestToken(
    const XProviderConfig& config, const idp::ChallengeId& challenge)
{
    std::string_view value = challenge.value();
    if (!value.starts_with(kChallengePrefix)) {
        return foundation::fail(authFailure(
            "The X OAuth challenge envelope is invalid."));
    }
    value.remove_prefix(kChallengePrefix.size());
    auto envelope = foundation::fromBase64Url(value);
    if (!envelope || envelope->empty() || envelope->size() > 8192U) {
        return foundation::fail(authFailure(
            "The X OAuth challenge envelope is invalid."));
    }
    auto aeadKey = security::AeadKey::create(config.derivationKey().clone());
    if (!aeadKey) return foundation::fail(aeadKey.error());
    auto opened = security::openAes256Gcm(
        aeadKey.value(), envelope.value(), kChallengeAad);
    if (!opened) {
        return foundation::fail(authFailure(
            "The X OAuth challenge envelope could not be authenticated."));
    }

    const auto plaintext = opened->expose();
    const auto separator = plaintext.find('\n');
    if (separator == std::string_view::npos
        || plaintext.find('\n', separator + 1U) != std::string_view::npos) {
        return foundation::fail(authFailure(
            "The X OAuth challenge envelope is malformed."));
    }
    const auto token = plaintext.substr(0U, separator);
    const auto secret = plaintext.substr(separator + 1U);
    if (!safeText(token, 1024U) || secret.empty() || secret.size() > 2048U) {
        return foundation::fail(authFailure(
            "The X OAuth challenge envelope is malformed."));
    }
    return RequestTokenState{
        std::string{token}, foundation::SecretString{std::string{secret}}};
}

[[nodiscard]] std::optional<std::string_view> credential(
    const idp::SecretAttributeMap& values, std::string_view name)
{
    const auto found = values.find(name);
    if (found == values.end() || found->second.empty()) return std::nullopt;
    return found->second.expose();
}

[[nodiscard]] bool validUserId(std::string_view value) noexcept
{
    return !value.empty() && value.size() <= 32U
        && std::ranges::all_of(value, [](char symbol) {
               return symbol >= '0' && symbol <= '9';
           })
        && std::ranges::any_of(value, [](char symbol) { return symbol != '0'; });
}

[[nodiscard]] bool validScreenName(std::string_view value) noexcept
{
    return !value.empty() && value.size() <= 15U
        && std::ranges::all_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return std::isalnum(byte) != 0 || symbol == '_';
           });
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
    std::string apiKey, foundation::SecretString apiSecret,
    std::string callbackUri, foundation::SecretString derivationKey,
    foundation::Duration challengeLifetime)
    : m_apiKey(std::move(apiKey)), m_apiSecret(std::move(apiSecret)),
      m_callbackUri(std::move(callbackUri)),
      m_derivationKey(std::move(derivationKey)),
      m_challengeLifetime(challengeLifetime) {}

foundation::Result<XProviderConfig> XProviderConfig::create(
    std::string apiKey, foundation::SecretString apiSecret,
    std::string callbackUri, foundation::SecretString derivationKey,
    foundation::Duration challengeLifetime)
{
    if (!safeText(apiKey, 512U) || apiSecret.empty() || apiSecret.size() > 4096U
        || !validHttpsUrl(callbackUri) || derivationKey.size() != 32U
        || challengeLifetime <= foundation::Duration::zero()
        || challengeLifetime > std::chrono::minutes{15}) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "The X OAuth 1.0a provider configuration is invalid.");
    }
    return XProviderConfig{
        std::move(apiKey), std::move(apiSecret), std::move(callbackUri),
        std::move(derivationKey), challengeLifetime};
}

std::string_view XProviderConfig::apiKey() const noexcept { return m_apiKey; }
const foundation::SecretString& XProviderConfig::apiSecret() const noexcept
{ return m_apiSecret; }
std::string_view XProviderConfig::callbackUri() const noexcept
{ return m_callbackUri; }
const foundation::SecretString& XProviderConfig::derivationKey() const noexcept
{ return m_derivationKey; }
foundation::Duration XProviderConfig::challengeLifetime() const noexcept
{ return m_challengeLifetime; }

XAuthenticationProvider::XAuthenticationProvider(
    XProviderConfig config, const foundation::ClockSource& clock,
    std::string caFile)
    : m_implementation(std::make_unique<Implementation>(
          std::move(config), clock, std::move(caFile))) {}

XAuthenticationProvider::~XAuthenticationProvider() = default;

idp::ProviderId XAuthenticationProvider::id() const
{ return idp::ProviderId{"x"}; }

idp::InteractionModel XAuthenticationProvider::interactionModel() const noexcept
{ return idp::InteractionModel::Redirect; }

idp::AssuranceLevel XAuthenticationProvider::maximumClaimableAssurance() const noexcept
{ return idp::AssuranceLevel::Ial1; }

foundation::Result<idp::AuthenticationChallenge>
XAuthenticationProvider::beginAuthentication(
    const idp::AuthenticationRequest& request)
{
    if (request.provider() != id()) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "The X authentication request targets another provider.");
    }

    auto nonce = security::randomTokenBase64Url(18U);
    if (!nonce) return foundation::fail(nonce.error());
    Parameters extras;
    extras.emplace_back(
        "oauth_callback", m_implementation->config.callbackUri());
    auto authorization = oauthAuthorization(
        "POST", kRequestTokenUrl, m_implementation->config.apiKey(),
        m_implementation->config.apiSecret(),
        unixTimestamp(*m_implementation->clock), nonce.value(),
        std::move(extras));
    if (!authorization) return foundation::fail(authorization.error());

    auto response = httpsRequest(
        kRequestTokenTarget, http::verb::post, authorization.value(),
        m_implementation->caFile);
    if (!response || response->status != 200U) {
        logUpstreamFailure("request-token", response);
        return foundation::fail(authFailure(
            "The X OAuth request-token exchange failed."));
    }

    auto form = parseForm(response->body);
    if (!form) return foundation::fail(form.error());
    const auto token = form->find("oauth_token");
    const auto secret = form->find("oauth_token_secret");
    const auto confirmed = form->find("oauth_callback_confirmed");
    if (token == form->end() || secret == form->end()
        || confirmed == form->end() || confirmed->second != "true"
        || !safeText(token->second, 1024U)
        || secret->second.empty() || secret->second.size() > 2048U) {
        return foundation::fail(authFailure(
            "The X OAuth request-token response is invalid."));
    }

    auto sealedChallenge = sealRequestToken(
        m_implementation->config, token->second,
        foundation::SecretString{secret->second});
    if (!sealedChallenge) return foundation::fail(sealedChallenge.error());

    std::string authorizationUrl{kAuthorizationEndpoint};
    authorizationUrl.append("?oauth_token=");
    authorizationUrl.append(percentEncode(token->second));

    idp::AuthenticationChallenge challenge{
        idp::ChallengeId{std::move(sealedChallenge).value()},
        m_implementation->clock->now()
            + m_implementation->config.challengeLifetime()};
    challenge.setParameter("authorization_url", std::move(authorizationUrl));
    return challenge;
}

foundation::Result<idp::AuthenticationOutcome>
XAuthenticationProvider::completeAuthentication(
    const idp::AuthenticationResponse& response)
{
    const auto callbackToken =
        credential(response.parameters(), "oauth_token");
    const auto verifier =
        credential(response.parameters(), "oauth_verifier");
    if (!callbackToken || !verifier
        || callbackToken->size() > 1024U || verifier->size() > 1024U
        || !safeText(*callbackToken, 1024U)
        || !safeText(*verifier, 1024U)) {
        return foundation::fail(authFailure(
            "The X OAuth callback is incomplete."));
    }

    auto requestToken = openRequestToken(
        m_implementation->config, response.challengeId());
    if (!requestToken) return foundation::fail(requestToken.error());
    if (!security::constantTimeEquals(
            *callbackToken, requestToken->token)) {
        return foundation::fail(authFailure(
            "The X OAuth request-token binding is invalid."));
    }

    auto nonce = security::randomTokenBase64Url(18U);
    if (!nonce) return foundation::fail(nonce.error());
    Parameters extras;
    extras.emplace_back("oauth_token", requestToken->token);
    extras.emplace_back("oauth_verifier", *verifier);
    auto authorization = oauthAuthorization(
        "POST", kAccessTokenUrl, m_implementation->config.apiKey(),
        m_implementation->config.apiSecret(),
        unixTimestamp(*m_implementation->clock), nonce.value(),
        std::move(extras), requestToken->secret.expose());
    if (!authorization) return foundation::fail(authorization.error());

    auto tokenResponse = httpsRequest(
        kAccessTokenTarget, http::verb::post, authorization.value(),
        m_implementation->caFile);
    if (!tokenResponse || tokenResponse->status != 200U) {
        logUpstreamFailure("access-token", tokenResponse);
        return foundation::fail(authFailure(
            "The X OAuth access-token exchange failed."));
    }

    auto form = parseForm(tokenResponse->body);
    if (!form) return foundation::fail(form.error());
    const auto accessToken = form->find("oauth_token");
    const auto accessSecret = form->find("oauth_token_secret");
    const auto userId = form->find("user_id");
    const auto screenName = form->find("screen_name");
    if (accessToken == form->end() || accessSecret == form->end()
        || userId == form->end() || screenName == form->end()
        || accessToken->second.empty() || accessSecret->second.empty()
        || !validUserId(userId->second)
        || !validScreenName(screenName->second)) {
        return foundation::fail(authFailure(
            "The X OAuth access-token response is incomplete."));
    }

    idp::VerifiedClaims claims;
    claims.set(idp::ClaimName::PreferredUsername, screenName->second);

    idp::ProviderEvidence evidence;
    evidence.add("protocol", "x_oauth1_three_legged");
    evidence.add("x_account_id", userId->second);
    evidence.add("username", screenName->second);

    return idp::AuthenticationOutcome::create(
        id(), idp::ExternalSubject{userId->second}, std::move(claims),
        idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{idp::AuthenticationFactor::None, false},
        std::move(evidence), m_implementation->clock->now());
}

} // namespace openproof::provider::x

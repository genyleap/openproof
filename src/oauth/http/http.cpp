module;

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <boost/json.hpp>

module openproof.oauth.http;

import openproof.security;

namespace openproof::oauth::http {
namespace {
namespace json = boost::json;
namespace idp = identity::provider;

constexpr std::size_t kMaximumFormBody = 16U * 1024U;
constexpr std::string_view kSessionCookie = "__Host-openproof-session";
constexpr std::string_view kLoginCsrfCookie = "__Host-openproof-login-csrf";
constexpr std::string_view kConsentCsrfCookie = "__Host-openproof-consent-csrf";
constexpr std::string_view kDeviceCsrfCookie = "__Host-openproof-device-csrf";
using Parameters = std::map<std::string, std::string, std::less<>>;

[[nodiscard]] bool unreserved(unsigned char value) noexcept
{
    return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
        || (value >= '0' && value <= '9') || value == '-' || value == '.'
        || value == '_' || value == '~';
}

[[nodiscard]] std::string percentEncode(std::string_view input)
{
    constexpr char digits[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(input.size() * 3U);
    for (char rawValue : input) {
        const auto value = static_cast<unsigned char>(rawValue);
        if (unreserved(value)) output.push_back(static_cast<char>(value));
        else {
            output.push_back('%');
            output.push_back(digits[value >> 4U]);
            output.push_back(digits[value & 0x0FU]);
        }
    }
    return output;
}

[[nodiscard]] int hexValue(char value) noexcept
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

[[nodiscard]] foundation::Result<std::string> percentDecode(std::string_view input)
{
    std::string output;
    output.reserve(input.size());
    for (std::size_t index = 0U; index < input.size(); ++index) {
        const char value = input[index];
        if (value == '+') { output.push_back(' '); continue; }
        if (value != '%') { output.push_back(value); continue; }
        if (index + 2U >= input.size()) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The request encoding is invalid.");
        }
        const int high = hexValue(input[index + 1U]);
        const int low = hexValue(input[index + 2U]);
        if (high < 0 || low < 0) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The request encoding is invalid.");
        }
        const unsigned char decoded = static_cast<unsigned char>((high << 4) | low);
        if (decoded == 0U) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The request encoding is invalid.");
        }
        output.push_back(static_cast<char>(decoded));
        index += 2U;
    }
    return output;
}

[[nodiscard]] foundation::Result<Parameters> parseParameters(std::string_view encoded)
{
    Parameters output;
    std::size_t begin = 0U;
    while (begin <= encoded.size()) {
        const std::size_t end = encoded.find('&', begin);
        const auto pair = encoded.substr(begin,
            end == std::string_view::npos ? encoded.size() - begin : end - begin);
        if (!pair.empty()) {
            const std::size_t equals = pair.find('=');
            auto key = percentDecode(pair.substr(0U, equals));
            auto value = percentDecode(equals == std::string_view::npos
                ? std::string_view{} : pair.substr(equals + 1U));
            if (!key || !value || key->empty() || key->size() > 128U
                || value->size() > 16U * 1024U || output.contains(key.value())) {
                return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                        "The request parameters are invalid.");
            }
            output.emplace(std::move(key).value(), std::move(value).value());
        }
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    return output;
}

[[nodiscard]] foundation::Result<Parameters> queryParameters(const gateway::HttpRequest& request)
{
    const auto target = request.target();
    const std::size_t query = target.find('?');
    return query == std::string_view::npos ? Parameters{} : parseParameters(target.substr(query + 1U));
}

[[nodiscard]] foundation::Result<Parameters> formParameters(const gateway::HttpRequest& request)
{
    const auto type = request.header("content-type");
    if (!type || !type->starts_with("application/x-www-form-urlencoded")
        || request.body().empty() || request.body().size() > kMaximumFormBody) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request form is invalid.");
    }
    return parseParameters(request.body());
}

[[nodiscard]] foundation::Result<std::string> required(
    const Parameters& parameters, std::string_view name, std::size_t maximum = 2048U)
{
    const auto found = parameters.find(name);
    if (found == parameters.end() || found->second.empty() || found->second.size() > maximum) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request parameters are invalid.");
    }
    return found->second;
}

[[nodiscard]] std::optional<std::string> optional(
    const Parameters& parameters, std::string_view name)
{
    const auto found = parameters.find(name);
    return found == parameters.end() || found->second.empty()
        ? std::nullopt : std::optional<std::string>{found->second};
}

[[nodiscard]] foundation::Result<std::vector<client::Scope>> scopes(std::string_view input)
{
    std::vector<client::Scope> output;
    std::size_t begin = 0U;
    while (begin < input.size()) {
        while (begin < input.size() && input[begin] == ' ') ++begin;
        if (begin == input.size()) break;
        const std::size_t end = input.find(' ', begin);
        auto scope = client::Scope::create(std::string{input.substr(
            begin, end == std::string_view::npos ? input.size() - begin : end - begin)});
        if (!scope) return foundation::fail(scope.error());
        output.push_back(std::move(scope).value());
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    if (output.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "At least one OAuth scope is required.");
    }
    std::ranges::sort(output, {}, [](const client::Scope& value) { return value.value(); });
    if (std::adjacent_find(output.begin(), output.end(), [](const auto& a, const auto& b) {
            return a.value() == b.value(); }) != output.end()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "OAuth scopes must be unique.");
    }
    return output;
}

[[nodiscard]] std::string scopeString(const std::vector<std::string>& scopes)
{
    std::string output;
    for (const auto& scope : scopes) {
        if (!output.empty()) output.push_back(' ');
        output.append(scope);
    }
    return output;
}

[[nodiscard]] bool oidcOnlyScope(std::string_view scope) noexcept
{
    return scope == "openid" || scope == "profile" || scope == "email"
        || scope == "phone" || scope == "offline_access" || scope == "account";
}

[[nodiscard]] std::vector<std::string> scopeStrings(
    const std::vector<client::Scope>& scopes)
{
    std::vector<std::string> values;
    values.reserve(scopes.size());
    for (const auto& scope : scopes) values.emplace_back(scope.value());
    return values;
}

[[nodiscard]] std::vector<std::string> resourceScopeStrings(
    const std::vector<client::Scope>& scopes)
{
    std::vector<std::string> values;
    for (const auto& scope : scopes) {
        if (!oidcOnlyScope(scope.value())) values.emplace_back(scope.value());
    }
    return values;
}

[[nodiscard]] std::string consentAudience(
    const client::ClientId& clientId, const std::optional<std::string>& resource)
{
    return resource.has_value()
        ? *resource
        : std::string{"urn:openproof:client:"} + std::string{clientId.value()};
}

[[nodiscard]] std::string cookie(std::string_view name, std::string_view value,
                                 std::string_view path, std::int64_t maximumAge)
{
    return std::string{name} + "=" + std::string{value} + "; Path=" + std::string{path}
        + "; Max-Age=" + std::to_string(maximumAge)
        + "; Secure; HttpOnly; SameSite=Lax";
}

[[nodiscard]] std::optional<std::string> cookieValue(
    const gateway::HttpRequest& request, std::string_view wanted)
{
    const auto header = request.header("cookie");
    if (!header) return std::nullopt;
    std::optional<std::string> result;
    std::size_t begin = 0U;
    while (begin <= header->size()) {
        const std::size_t end = header->find(';', begin);
        auto item = header->substr(begin, end == std::string_view::npos ? header->size() - begin : end - begin);
        while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) item.remove_prefix(1U);
        const std::size_t equals = item.find('=');
        if (equals != std::string_view::npos && item.substr(0U, equals) == wanted) {
            if (result) return std::nullopt;
            result = std::string{item.substr(equals + 1U)};
        }
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    return result;
}

[[nodiscard]] std::string htmlEscape(std::string_view input)
{
    std::string output;
    for (char value : input) {
        switch (value) {
        case '&': output += "&amp;"; break;
        case '<': output += "&lt;"; break;
        case '>': output += "&gt;"; break;
        case '"': output += "&quot;"; break;
        case '\'': output += "&#39;"; break;
        default: output.push_back(value); break;
        }
    }
    return output;
}

constexpr std::string_view kDevicePageCss = R"css(
:root{color-scheme:dark light;font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0d0f14;color:#f7f7f8}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:radial-gradient(circle at 18% 0%,rgba(99,102,241,.24),transparent 34rem),linear-gradient(180deg,#11131a 0%,#090b0f 100%);display:grid;place-items:center;padding:28px}
.shell{width:min(100%,620px)}
.brand{display:flex;align-items:center;gap:12px;margin:0 0 18px 2px;color:#d9dcff;font-weight:700;letter-spacing:-.01em}
.brand-mark{width:34px;height:34px;border-radius:11px;display:grid;place-items:center;background:linear-gradient(135deg,#7479ff,#a66cff);box-shadow:0 10px 30px rgba(92,89,255,.3);color:white;font-size:17px}
.brand small{display:block;color:#8f94a6;font-size:12px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;margin-top:2px}
.card{background:rgba(24,27,36,.9);border:1px solid rgba(255,255,255,.09);border-radius:28px;padding:34px;box-shadow:0 30px 90px rgba(0,0,0,.38);backdrop-filter:blur(20px)}
.kicker{display:inline-flex;align-items:center;gap:8px;padding:7px 10px;border-radius:999px;background:rgba(110,116,255,.12);color:#bfc2ff;font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;margin-bottom:18px}
h1{font-size:clamp(28px,6vw,42px);line-height:1.05;letter-spacing:-.04em;margin:0 0 14px}
.lead{color:#aeb3c4;font-size:16px;line-height:1.6;margin:0 0 26px}
.detail-grid{display:grid;gap:10px;margin:22px 0}
.detail{display:flex;justify-content:space-between;gap:18px;align-items:center;padding:14px 16px;border:1px solid rgba(255,255,255,.07);border-radius:16px;background:rgba(255,255,255,.025)}
.detail span{color:#8f94a6;font-size:13px}
.detail strong,.detail code{font-size:14px;color:#f5f6ff;text-align:right;overflow-wrap:anywhere}
.section-label{color:#8f94a6;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin:22px 0 10px}
.scopes{display:flex;flex-wrap:wrap;gap:8px}
.scope{padding:8px 10px;border-radius:10px;background:#11141c;border:1px solid rgba(255,255,255,.08);color:#d8dbeb;font-size:12px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.hint{margin:22px 0 0;color:#858b9f;font-size:13px;line-height:1.55}
.actions{display:grid;grid-template-columns:1fr auto;gap:10px;margin-top:28px}
button{appearance:none;border:0;border-radius:14px;padding:14px 18px;font:inherit;font-weight:750;cursor:pointer}
.primary{background:linear-gradient(135deg,#7378ff,#9568ff);color:white;box-shadow:0 12px 30px rgba(105,101,255,.28)}
.secondary{background:transparent;color:#aeb3c4;border:1px solid rgba(255,255,255,.1)}
.code-input{width:100%;margin-top:8px;border:1px solid rgba(255,255,255,.12);background:#10131a;color:#fff;border-radius:14px;padding:15px 16px;font:600 16px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.08em;outline:none}
.code-input:focus{border-color:#7f84ff;box-shadow:0 0 0 3px rgba(127,132,255,.14)}
.stack{display:grid;gap:12px}
.status-icon{width:58px;height:58px;border-radius:18px;display:grid;place-items:center;background:rgba(64,201,133,.12);color:#69d7a0;font-size:30px;font-weight:800;margin-bottom:22px}
.status-icon.denied{background:rgba(241,102,113,.12);color:#ff8b94}
.footer{margin:16px 0 0;text-align:center;color:#62687a;font-size:12px}
@media (prefers-color-scheme:light){
:root{background:#f4f5f8;color:#161820}.card{background:rgba(255,255,255,.94);border-color:rgba(15,20,35,.08);box-shadow:0 28px 75px rgba(36,43,68,.13)}
body{background:radial-gradient(circle at 18% 0%,rgba(113,118,255,.18),transparent 34rem),linear-gradient(180deg,#f8f9fc,#eef0f5)}
.lead,.hint{color:#656c80}.detail{background:#f8f9fc;border-color:#e7e9f0}.detail span{color:#777e91}.detail strong,.detail code{color:#202431}.scope{background:#f5f6fa;border-color:#e2e5ee;color:#4d5365}.code-input{background:#f7f8fb;color:#171a23;border-color:#dfe2eb}.secondary{color:#555d72;border-color:#dfe2eb}.brand{color:#4b4f77}.brand small,.footer{color:#8a90a1}
}
@media (max-width:560px){body{padding:16px}.card{padding:24px;border-radius:22px}.actions{grid-template-columns:1fr}.secondary{order:2}.detail{align-items:flex-start;flex-direction:column;gap:6px}.detail strong,.detail code{text-align:left}}
)css";

[[nodiscard]] std::string devicePageCsp(std::string_view nonce)
{
    return "default-src 'none'; style-src 'nonce-" + std::string{nonce}
        + "'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
}

[[nodiscard]] std::string devicePage(
    std::string_view nonce,
    std::string_view title,
    std::string_view content)
{
    return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<meta name=\"color-scheme\" content=\"dark light\"><title>"
        + htmlEscape(title)
        + "</title><style nonce=\"" + htmlEscape(nonce) + "\">"
        + std::string{kDevicePageCss}
        + "</style></head><body><main class=\"shell\"><div class=\"brand\">"
          "<div class=\"brand-mark\">G</div><div>Genyleap<small>Secured by OpenProof</small></div>"
          "</div><section class=\"card\">"
        + std::string{content}
        + "</section><p class=\"footer\">OpenProof keeps your app session separate from your Genyleap credentials.</p>"
          "</main></body></html>";
}

[[nodiscard]] bool validReturnTarget(std::string_view target) noexcept
{
    const bool permittedPath = target.starts_with("/oauth/authorize?")
        || target == "/oauth/device" || target.starts_with("/oauth/device?");
    return permittedPath && !target.starts_with("//")
        && !target.contains('\r') && !target.contains('\n') && target.size() <= 8192U;
}

void secure(gateway::HttpResponse& response)
{
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
}

void cors(gateway::HttpResponse& response)
{
    // Bearer endpoints never use ambient browser credentials. Wildcard origin
    // support lets public browser clients exchange PKCE codes without exposing
    // OpenProof cookies to caller-controlled JavaScript.
    response.setHeader("access-control-allow-origin", "*");
    response.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
    response.setHeader("access-control-allow-headers", "authorization, content-type");
    response.setHeader("access-control-max-age", "600");
}

[[nodiscard]] gateway::HttpResponse jsonResponse(int status, foundation::JsonObjectWriter body)
{
    gateway::HttpResponse response{status, gateway::Headers{{"content-type", "application/json"}}, body.build()};
    secure(response);
    cors(response);
    return response;
}

[[nodiscard]] gateway::HttpResponse oauthErrorResponse(
    int status, std::string_view code, std::string_view description = {})
{
    foundation::JsonObjectWriter body;
    body.add("error", code);
    if (!description.empty()) {
        body.add("error_description", description);
    }
    return jsonResponse(status, std::move(body));
}

[[nodiscard]] gateway::HttpResponse invalidBearerResponse()
{
    auto response = oauthErrorResponse(401, "invalid_token",
                                       "The access token is invalid or inactive.");
    response.setHeader(
        "www-authenticate",
        "Bearer error=\"invalid_token\", error_description=\"The access token is invalid or inactive.\"");
    return response;
}

[[nodiscard]] gateway::HttpResponse redirect(std::string location, int status = 302)
{
    gateway::HttpResponse response{status, gateway::Headers{{"location", std::move(location)}}, {}};
    secure(response);
    return response;
}

[[nodiscard]] std::string appendRedirectParameter(
    std::string redirectUri, std::string_view key, std::string_view value)
{
    redirectUri.push_back(redirectUri.contains('?') ? '&' : '?');
    redirectUri.append(percentEncode(key)).push_back('=');
    redirectUri.append(percentEncode(value));
    return redirectUri;
}

[[nodiscard]] idp::ClientContext clientContext(const gateway::HttpRequest& request)
{
    idp::ClientContext context;
    context.setRemoteAddress(std::string{request.remoteAddress()});
    if (const auto agent = request.header("user-agent")) context.setUserAgent(std::string{*agent});
    return context;
}

[[nodiscard]] foundation::Result<std::uint64_t> unsignedInteger(std::string_view value)
{
    std::uint64_t output{};
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), output);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request parameters are invalid.");
    }
    return output;
}

[[nodiscard]] std::optional<std::string> jsonString(
    const json::object& object, std::string_view name)
{
    const auto found = object.find(name);
    if (found == object.end() || !found->value().is_string()) return std::nullopt;
    const auto value = found->value().as_string();
    return std::string{value.data(), value.size()};
}

[[nodiscard]] foundation::Result<Parameters> verifiedJarParameters(
    std::string_view compactJwt, const client::ClientId& expectedClient,
    std::string_view expectedAudience, JarService& jar)
{
    auto registeredKey = jar.key(expectedClient);
    if (!registeredKey) return foundation::fail(registeredKey.error());
    auto verified = jar.verify(expectedClient, compactJwt);
    if (!verified) return foundation::fail(verified.error());
    boost::system::error_code headerError;
    boost::system::error_code payloadError;
    auto headerValue = json::parse(verified->headerJson(), headerError);
    auto payloadValue = json::parse(verified->payloadJson(), payloadError);
    if (headerError || payloadError || !headerValue.is_object() || !payloadValue.is_object()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The JAR request object is malformed.");
    }
    const auto& header = headerValue.as_object();
    const auto& payload = payloadValue.as_object();
    const auto algorithm = jsonString(header, "alg");
    const auto keyId = jsonString(header, "kid");
    const auto type = jsonString(header, "typ");
    if (algorithm != std::optional<std::string>{"RS256"}
        || keyId != std::optional<std::string>{std::string{registeredKey->keyId()}}
        || (type && *type != "JWT" && *type != "oauth-authz-req+jwt")) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The JAR protected header is invalid.");
    }
    const auto issuer = jsonString(payload, "iss");
    const auto clientId = jsonString(payload, "client_id");
    const auto jwtId = jsonString(payload, "jti");
    if (issuer != std::optional<std::string>{std::string{expectedClient.value()}}
        || clientId != std::optional<std::string>{std::string{expectedClient.value()}}
        || !jwtId) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The JAR client binding is invalid.");
    }
    const auto audienceFound = payload.find("aud");
    bool audienceMatches = false;
    if (audienceFound != payload.end()) {
        if (audienceFound->value().is_string()) {
            const auto audience = audienceFound->value().as_string();
            audienceMatches = std::string_view{audience.data(), audience.size()} == expectedAudience;
        } else if (audienceFound->value().is_array()) {
            for (const auto& value : audienceFound->value().as_array()) {
                if (!value.is_string()) continue;
                const auto audience = value.as_string();
                if (std::string_view{audience.data(), audience.size()} == expectedAudience) {
                    audienceMatches = true;
                    break;
                }
            }
        }
    }
    const auto issuedFound = payload.find("iat");
    const auto expiresFound = payload.find("exp");
    if (!audienceMatches || issuedFound == payload.end() || expiresFound == payload.end()
        || !issuedFound->value().is_int64() || !expiresFound->value().is_int64()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The JAR audience or temporal claims are invalid.");
    }
    const auto issuedSeconds = issuedFound->value().as_int64();
    const auto expiresSeconds = expiresFound->value().as_int64();
    if (issuedSeconds < 0 || expiresSeconds <= issuedSeconds) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The JAR temporal claims are invalid.");
    }
    const foundation::Instant issuedAt{
        std::chrono::duration_cast<foundation::Duration>(std::chrono::seconds{issuedSeconds})};
    const foundation::Instant expiresAt{
        std::chrono::duration_cast<foundation::Duration>(std::chrono::seconds{expiresSeconds})};

    static constexpr std::string_view requiredClaims[]{
        "response_type", "redirect_uri", "scope", "code_challenge", "code_challenge_method"};
    Parameters parameters;
    parameters.emplace("client_id", std::string{expectedClient.value()});
    for (const auto name : requiredClaims) {
        auto value = jsonString(payload, name);
        if (!value) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The JAR request is missing a required authorization claim.");
        }
        parameters.emplace(std::string{name}, std::move(*value));
    }
    static constexpr std::string_view optionalClaims[]{
        "state", "nonce", "resource", "response_mode"};
    for (const auto name : optionalClaims) {
        if (auto value = jsonString(payload, name)) {
            parameters.emplace(std::string{name}, std::move(*value));
        }
    }
    if (const auto maxAge = payload.find("max_age"); maxAge != payload.end()) {
        if (!maxAge->value().is_int64() || maxAge->value().as_int64() < 0) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The JAR max_age claim is invalid.");
        }
        parameters.emplace("max_age", std::to_string(maxAge->value().as_int64()));
    }
    auto replay = jar.consumeReplay(expectedClient, *jwtId, issuedAt, expiresAt);
    if (!replay) return foundation::fail(replay.error());
    return parameters;
}

[[nodiscard]] foundation::Result<AuthorizationRequest> validatedAuthorizationRequest(
    const Parameters& parameters, client::ClientManager& clients,
    resource::ResourceRegistry& resources)
{
    auto responseType = required(parameters, "response_type", 32U);
    auto clientIdText = required(parameters, "client_id", 256U);
    auto redirectUri = required(parameters, "redirect_uri", 2048U);
    auto scopeText = required(parameters, "scope", 2048U);
    auto challengeText = required(parameters, "code_challenge", 128U);
    auto challengeMethod = required(parameters, "code_challenge_method", 16U);
    if (!responseType || !clientIdText || !redirectUri || !scopeText || !challengeText
        || !challengeMethod || responseType.value() != "code"
        || challengeMethod.value() != "S256") {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The authorization request is invalid.");
    }
    client::ClientId clientId{clientIdText.value()};
    auto registered = clients.requireActive(clientId);
    if (!registered || !registered->permitsRedirect(redirectUri.value())) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The authorization client or redirect URI is invalid.");
    }
    auto requestedScopes = scopes(scopeText.value());
    if (!requestedScopes || !registered->permitsScopes(requestedScopes.value())) {
        return foundation::fail(foundation::ErrorCode::PermissionDenied,
                                "The requested OAuth scopes are not permitted.");
    }
    auto challenge = PkceChallenge::create(challengeText.value());
    if (!challenge) return foundation::fail(challenge.error());
    std::optional<foundation::Duration> maxAge;
    if (const auto value = optional(parameters, "max_age")) {
        auto parsed = unsignedInteger(value.value());
        if (!parsed || parsed.value() > 86400U * 30U) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "max_age is invalid.");
        }
        maxAge = std::chrono::seconds{parsed.value()};
    }
    const auto requestedResource = optional(parameters, "resource");
    auto apiScopes = resourceScopeStrings(requestedScopes.value());
    if (!apiScopes.empty() && !requestedResource) {
        return foundation::fail(foundation::ErrorCode::PermissionDenied,
                                "resource is required for API scopes.");
    }
    if (requestedResource) {
        auto registeredResource = resources.requireActive(*requestedResource);
        if (!registeredResource || !registeredResource->permitsScopes(apiScopes)) {
            return foundation::fail(foundation::ErrorCode::PermissionDenied,
                                    "The requested resource is unavailable.");
        }
    }
    AuthorizationResponseMode responseMode = AuthorizationResponseMode::Query;
    if (const auto requestedMode = optional(parameters, "response_mode")) {
        if (*requestedMode == "query.jwt") responseMode = AuthorizationResponseMode::Jwt;
        else if (*requestedMode != "query") {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The requested response_mode is unsupported.");
        }
    }
    return AuthorizationRequest::create(
        std::move(clientId), redirectUri.value(), std::move(requestedScopes).value(),
        std::move(challenge).value(), optional(parameters, "state"),
        optional(parameters, "nonce"), maxAge, requestedResource, responseMode);
}

struct AccessCredential final {
    foundation::SecretString token;
    bool dpopAuthorizationScheme{};
};

[[nodiscard]] foundation::Result<AccessCredential> accessCredential(
    const gateway::HttpRequest& request)
{
    const auto authorization = request.header("authorization");
    if (!authorization) {
        return foundation::fail(foundation::ErrorCode::AuthenticationRequired,
                                "Authentication is required.");
    }
    constexpr std::string_view bearerPrefix{"Bearer "};
    constexpr std::string_view dpopPrefix{"DPoP "};
    const bool dpop = authorization->starts_with(dpopPrefix);
    const auto prefix = dpop ? dpopPrefix : bearerPrefix;
    if (!authorization->starts_with(prefix) || authorization->size() <= prefix.size()
        || authorization->substr(prefix.size()).contains(' ')
        || authorization->substr(prefix.size()).contains('\t')) {
        return foundation::fail(foundation::ErrorCode::AuthenticationRequired,
                                "Authentication is required.");
    }
    return AccessCredential{
        foundation::SecretString{std::string{authorization->substr(prefix.size())}}, dpop};
}

[[nodiscard]] std::string_view tokenType(const token::TokenContext& context) noexcept
{
    return context.senderConstraint().has_value()
            && context.senderConstraint()->kind() == token::SenderConstraintKind::Dpop
        ? std::string_view{"DPoP"} : std::string_view{"Bearer"};
}

}

OAuthHttpApi::OAuthHttpApi(
    AuthorizationService& authorization, token::TokenService& tokens,
    oidc::OpenIdProvider& oidc, client::ClientManager& clients,
    authentication::AuthenticationService& authentication,
    session::SessionService& sessions, idp::ProviderId localProvider,
    consent::ConsentService& consents, resource::ResourceRegistry& resources,
    resource::ServiceIdentityService& serviceIdentities,
    DeviceAuthorizationService& devices, PushedAuthorizationService& pushedAuthorization,
    JarService& jar, SenderProofVerifier& senderProof,
    gateway::TokenBucketRateLimiter& limiter, gateway::HttpHandler& fallback)
    : m_authorization(&authorization), m_tokens(&tokens), m_oidc(&oidc),
      m_clients(&clients), m_authentication(&authentication), m_sessions(&sessions),
      m_localProvider(std::move(localProvider)), m_consents(&consents),
      m_resources(&resources), m_serviceIdentities(&serviceIdentities),
      m_devices(&devices), m_pushedAuthorization(&pushedAuthorization),
      m_jar(&jar), m_senderProof(&senderProof), m_limiter(&limiter), m_fallback(&fallback) {}

gateway::HttpResponse OAuthHttpApi::error(
    const foundation::Error& failure, const gateway::HttpRequest& request) const
{
    gateway::HttpResponse response{foundation::errorHttpStatus(failure.code()),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(failure, request.correlation().value())};
    secure(response);
    cors(response);
    return response;
}

gateway::HttpResponse OAuthHttpApi::handle(gateway::HttpRequest request)
{
    const auto path = request.path();
    if (request.method() == gateway::HttpMethod::Options
        && (path == "/oauth/token" || path == "/oauth/par"
            || path == "/oauth/device_authorization"
            || path == "/oauth/userinfo"
            || path == "/.well-known/openid-configuration"
            || path == "/.well-known/jwks.json")) {
        gateway::HttpResponse response{204, {}, {}};
        secure(response);
        cors(response);
        return response;
    }
    if (path == "/.well-known/openid-configuration" && request.method() == gateway::HttpMethod::Get) {
        gateway::HttpResponse response{200, gateway::Headers{{"content-type", "application/json"}},
                                       m_oidc->discoveryDocument()};
        secure(response); cors(response); return response;
    }
    if (path == "/.well-known/jwks.json" && request.method() == gateway::HttpMethod::Get) {
        auto body = m_oidc->jwksDocument();
        if (!body) return error(body.error(), request);
        gateway::HttpResponse response{200, gateway::Headers{{"content-type", "application/json"}},
                                       std::move(body).value()};
        secure(response); cors(response); return response;
    }
    if (!m_limiter->allow(std::string{"oauth-ip:"} + std::string{request.remoteAddress()})) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    if (path == "/login") {
        if (request.method() == gateway::HttpMethod::Get) return loginPage(std::move(request));
        if (request.method() == gateway::HttpMethod::Post) return loginSubmit(std::move(request));
    }
    if (path == "/oauth/authorize" && request.method() == gateway::HttpMethod::Get) return authorize(std::move(request));
    if (path == "/oauth/consent" && request.method() == gateway::HttpMethod::Post) return consentSubmit(std::move(request));
    if (path == "/oauth/consents" && request.method() == gateway::HttpMethod::Get) return consents(std::move(request));
    if (path == "/oauth/consents/revoke" && request.method() == gateway::HttpMethod::Post) return revokeConsent(std::move(request));
    if (path == "/oauth/par" && request.method() == gateway::HttpMethod::Post) return pushedAuthorization(std::move(request));
    if (path == "/oauth/device_authorization" && request.method() == gateway::HttpMethod::Post) return deviceAuthorization(std::move(request));
    if (path == "/oauth/device" && (request.method() == gateway::HttpMethod::Get || request.method() == gateway::HttpMethod::Post)) return deviceVerification(std::move(request));
    if (path == "/oauth/token" && request.method() == gateway::HttpMethod::Post) return tokenEndpoint(std::move(request));
    if (path == "/oauth/userinfo" && (request.method() == gateway::HttpMethod::Get || request.method() == gateway::HttpMethod::Post)) return userInfo(std::move(request));
    if (path == "/oauth/introspect" && request.method() == gateway::HttpMethod::Post) return introspect(std::move(request));
    if (path == "/oauth/revoke" && request.method() == gateway::HttpMethod::Post) return revoke(std::move(request));
    return m_fallback->handle(std::move(request));
}

gateway::HttpResponse OAuthHttpApi::loginPage(gateway::HttpRequest request)
{
    auto parameters = queryParameters(request);
    if (!parameters) return error(parameters.error(), request);
    auto returnTarget = required(parameters.value(), "return_to", 8192U);
    if (!returnTarget || !validReturnTarget(returnTarget.value())) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    auto csrf = security::randomTokenBase64Url(32U);
    if (!csrf) return error(csrf.error(), request);
    std::string body = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>OpenProof Sign In</title></head><body><main><h1>Sign in with OpenProof</h1><form method=\"post\" action=\"/login\"><input type=\"hidden\" name=\"return_to\" value=\""
        + htmlEscape(returnTarget.value()) + "\"><input type=\"hidden\" name=\"csrf\" value=\""
        + htmlEscape(csrf.value()) + "\"><label>Account <input name=\"subject\" autocomplete=\"username\" required></label><label>Password <input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label><label>Authenticator code <input name=\"totp\" inputmode=\"numeric\" autocomplete=\"one-time-code\"></label><button type=\"submit\">Sign in</button></form></main></body></html>";
    gateway::HttpResponse response{200, gateway::Headers{{"content-type", "text/html; charset=utf-8"}}, std::move(body)};
    secure(response);
    response.setHeader("content-security-policy", "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    response.addHeader("set-cookie", cookie(kLoginCsrfCookie, csrf.value(), "/", 600));
    return response;
}

gateway::HttpResponse OAuthHttpApi::loginSubmit(gateway::HttpRequest request)
{
    auto form = formParameters(request);
    if (!form) return error(form.error(), request);
    auto returnTarget = required(form.value(), "return_to", 8192U);
    auto csrf = required(form.value(), "csrf", 128U);
    auto subject = required(form.value(), "subject", 320U);
    auto password = required(form.value(), "password", 1024U);
    const auto totp = optional(form.value(), "totp");
    const auto csrfCookie = cookieValue(request, kLoginCsrfCookie);
    if (!returnTarget || !csrf || !subject || !password || !csrfCookie
        || !validReturnTarget(returnTarget.value())
        || !security::constantTimeEquals(csrf.value(), csrfCookie.value())) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed}, request);
    }
    if (!m_limiter->allow(std::string{"oauth-login:"} + subject.value())) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    auto bindingMaterial = security::randomTokenBase64Url(32U);
    if (!bindingMaterial) return error(bindingMaterial.error(), request);
    auto binding = security::sha256(bindingMaterial.value());
    if (!binding) return error(binding.error(), request);
    idp::AuthenticationRequest authRequest{m_localProvider, clientContext(request)};
    authRequest.setParameter("subject", subject.value());
    authRequest.setRequestedAssurance(totp.has_value() ? idp::AssuranceLevel::Ial2
                                                        : idp::AssuranceLevel::Ial1);
    auto started = m_authentication->begin(authRequest, binding.value(), request.correlation());
    if (!started) return error(started.error(), request);
    idp::AuthenticationResponse authResponse{started->challenge().id(), clientContext(request)};
    authResponse.setParameter("password", idp::CredentialValue{std::move(password).value()});
    if (totp.has_value()) authResponse.setParameter("totp", idp::CredentialValue{totp.value()});
    auto verified = m_authentication->complete(started->transactionId(),
        foundation::SecretString{std::string{started->continuationToken().expose()}},
        binding.value(), authResponse);
    if (!verified) return error(verified.error(), request);
    auto sessionGrant = m_sessions->issue(verified.value(), clientContext(request));
    if (!sessionGrant) return error(sessionGrant.error(), request);
    auto response = redirect(returnTarget.value(), 303);
    response.addHeader("set-cookie", cookie(kSessionCookie, sessionGrant->token().expose(), "/", 8 * 60 * 60));
    response.addHeader("set-cookie", cookie(kLoginCsrfCookie, "", "/", 0));
    return response;
}

gateway::HttpResponse OAuthHttpApi::authorize(gateway::HttpRequest request)
{
    auto parameters = queryParameters(request);
    if (!parameters) return error(parameters.error(), request);
    if (const auto requestObject = optional(parameters.value(), "request")) {
        if (parameters->size() != 2U || !parameters->contains("client_id")) {
            return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
        }
        auto clientIdText = required(parameters.value(), "client_id", 256U);
        if (!clientIdText) return error(clientIdText.error(), request);
        const client::ClientId clientId{clientIdText.value()};
        auto jarParameters = verifiedJarParameters(
            *requestObject, clientId, m_oidc->issuer(), *m_jar);
        if (!jarParameters) return error(jarParameters.error(), request);
        auto jarRequest = validatedAuthorizationRequest(
            jarParameters.value(), *m_clients, *m_resources);
        if (!jarRequest) return error(jarRequest.error(), request);
        auto pushed = m_pushedAuthorization->push(std::move(jarRequest).value());
        if (!pushed) return error(pushed.error(), request);
        std::string target{"/oauth/authorize?client_id="};
        target.append(percentEncode(clientId.value()));
        target.append("&request_uri=");
        target.append(percentEncode(pushed->requestUri()));
        return redirect(std::move(target), 303);
    }
    std::optional<std::string> pushedRequestUri;
    auto authorizationRequest = [&]() -> foundation::Result<AuthorizationRequest> {
        if (const auto requestUri = optional(parameters.value(), "request_uri")) {
            if (parameters->size() != 2U || !parameters->contains("client_id")) {
                return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                        "PAR cannot be combined with front-channel request parameters.");
            }
            auto clientIdText = required(parameters.value(), "client_id", 256U);
            if (!clientIdText) return foundation::fail(clientIdText.error());
            pushedRequestUri = *requestUri;
            return m_pushedAuthorization->find(
                *requestUri, client::ClientId{clientIdText.value()});
        }
        return validatedAuthorizationRequest(
            parameters.value(), *m_clients, *m_resources);
    }();
    if (!authorizationRequest) return error(authorizationRequest.error(), request);
    const client::ClientId clientId = authorizationRequest->clientId();
    auto registered = m_clients->requireActive(clientId);
    if (!registered || !registered->permitsRedirect(authorizationRequest->redirectUri())
        || !registered->permitsScopes(authorizationRequest->scopes())) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    const auto apiScopes = resourceScopeStrings(authorizationRequest->scopes());
    if (authorizationRequest->resource()) {
        auto registeredResource = m_resources->requireActive(*authorizationRequest->resource());
        if (!registeredResource || !registeredResource->permitsScopes(apiScopes)) {
            return error(foundation::Error{foundation::ErrorCode::PermissionDenied}, request);
        }
    } else if (!apiScopes.empty()) {
        return error(foundation::Error{foundation::ErrorCode::PermissionDenied}, request);
    }
    const auto sessionCookie = cookieValue(request, kSessionCookie);
    if (!sessionCookie) {
        return redirect(std::string{"/login?return_to="} + percentEncode(request.target()));
    }
    auto authenticated = m_sessions->authenticate(foundation::SecretString{sessionCookie.value()});
    if (!authenticated) {
        return redirect(std::string{"/login?return_to="} + percentEncode(request.target()));
    }
    const auto consentScopes = scopeStrings(authorizationRequest->scopes());
    const std::string audience = consentAudience(
        authorizationRequest->clientId(), authorizationRequest->resource());
    auto covered = m_consents->covers(
        authenticated->session().identity(), authorizationRequest->clientId(),
        audience, consentScopes);
    if (!covered) return error(covered.error(), request);
    if (!covered.value()) {
        auto csrf = security::randomTokenBase64Url(32U);
        if (!csrf) return error(csrf.error(), request);
        std::string scopeList;
        for (const auto& scope : consentScopes) {
            if (!scopeList.empty()) scopeList.append(", ");
            scopeList.append(htmlEscape(scope));
        }
        std::string body =
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>Authorize access</title></head><body><main><h1>Authorize "
            + htmlEscape(registered->displayName())
            + "</h1><p>Requested access: " + scopeList
            + "</p><form method=\"post\" action=\"/oauth/consent\">"
              "<input type=\"hidden\" name=\"return_to\" value=\""
            + htmlEscape(request.target())
            + "\"><input type=\"hidden\" name=\"csrf\" value=\""
            + htmlEscape(csrf.value())
            + "\"><button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button>"
              "<button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button>"
              "</form></main></body></html>";
        gateway::HttpResponse response{
            200, gateway::Headers{{"content-type", "text/html; charset=utf-8"}},
            std::move(body)};
        secure(response);
        response.setHeader(
            "content-security-policy",
            "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
        response.addHeader(
            "set-cookie", cookie(kConsentCsrfCookie, csrf.value(), "/", 600));
        return response;
    }
    AuthorizationRequest finalRequest = authorizationRequest.value();
    if (pushedRequestUri) {
        auto consumed = m_pushedAuthorization->consume(*pushedRequestUri, clientId);
        if (!consumed) return error(consumed.error(), request);
        finalRequest = std::move(consumed).value();
    }
    const auto requestedResponseMode = finalRequest.responseMode();
    auto grant = m_authorization->authorize(
        authenticated.value(), std::move(finalRequest));
    if (!grant) return error(grant.error(), request);
    if (requestedResponseMode == AuthorizationResponseMode::Jwt) {
        auto responseJwt = m_oidc->issueAuthorizationResponse(
            clientId, grant->code().expose(),
            grant->state() ? std::optional<std::string_view>{*grant->state()} : std::nullopt);
        if (!responseJwt) return error(responseJwt.error(), request);
        return redirect(appendRedirectParameter(
            std::string{grant->redirectUri()}, "response", responseJwt.value()));
    }
    std::string location = appendRedirectParameter(
        std::string{grant->redirectUri()}, "code", grant->code().expose());
    if (grant->state()) {
        location = appendRedirectParameter(
            std::move(location), "state", grant->state().value());
    }
    location = appendRedirectParameter(std::move(location), "iss", m_oidc->issuer());
    return redirect(std::move(location));
}

gateway::HttpResponse OAuthHttpApi::consentSubmit(gateway::HttpRequest request)
{
    auto form = formParameters(request);
    if (!form) return error(form.error(), request);
    auto returnTarget = required(form.value(), "return_to", 8192U);
    auto csrf = required(form.value(), "csrf", 128U);
    auto decision = required(form.value(), "decision", 16U);
    auto csrfCookie = cookieValue(request, kConsentCsrfCookie);
    if (!returnTarget || !csrf || !decision || !csrfCookie
        || !validReturnTarget(returnTarget.value())
        || !security::constantTimeEquals(csrf.value(), csrfCookie.value())
        || (decision.value() != "approve" && decision.value() != "deny")) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed}, request);
    }
    auto sessionCookie = cookieValue(request, kSessionCookie);
    if (!sessionCookie) {
        return redirect(std::string{"/login?return_to="} + percentEncode(returnTarget.value()));
    }
    auto authenticated = m_sessions->authenticate(
        foundation::SecretString{sessionCookie.value()});
    if (!authenticated) {
        return redirect(std::string{"/login?return_to="} + percentEncode(returnTarget.value()));
    }
    const std::size_t query = returnTarget->find('?');
    if (query == std::string::npos) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    auto parameters = parseParameters(std::string_view{*returnTarget}.substr(query + 1U));
    if (!parameters) return error(parameters.error(), request);
    std::optional<std::string> pushedRequestUri;
    auto authorizationRequest = [&]() -> foundation::Result<AuthorizationRequest> {
        if (const auto requestUri = optional(parameters.value(), "request_uri")) {
            auto clientIdText = required(parameters.value(), "client_id", 256U);
            if (!clientIdText || parameters->size() != 2U) {
                return foundation::fail(foundation::ErrorCode::InvalidArgument);
            }
            pushedRequestUri = *requestUri;
            return m_pushedAuthorization->find(
                *requestUri, client::ClientId{clientIdText.value()});
        }
        return validatedAuthorizationRequest(parameters.value(), *m_clients, *m_resources);
    }();
    if (!authorizationRequest) return error(authorizationRequest.error(), request);
    const client::ClientId clientId = authorizationRequest->clientId();
    auto registered = m_clients->requireActive(clientId);
    if (!registered || !registered->permitsRedirect(authorizationRequest->redirectUri())
        || !registered->permitsScopes(authorizationRequest->scopes())) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    if (decision.value() == "deny") {
        if (pushedRequestUri) {
            auto consumed = m_pushedAuthorization->consume(*pushedRequestUri, clientId);
            if (!consumed) return error(consumed.error(), request);
            authorizationRequest = std::move(consumed);
        }
        std::string location;
        if (authorizationRequest->responseMode() == AuthorizationResponseMode::Jwt) {
            auto responseJwt = m_oidc->issueAuthorizationResponse(
                clientId, std::nullopt,
                authorizationRequest->state()
                    ? std::optional<std::string_view>{*authorizationRequest->state()}
                    : std::nullopt,
                std::string_view{"access_denied"});
            if (!responseJwt) return error(responseJwt.error(), request);
            location = appendRedirectParameter(
                std::string{authorizationRequest->redirectUri()}, "response", responseJwt.value());
        } else {
            location = appendRedirectParameter(
                std::string{authorizationRequest->redirectUri()}, "error", "access_denied");
            if (authorizationRequest->state()) {
                location = appendRedirectParameter(
                    std::move(location), "state", *authorizationRequest->state());
            }
        }
        auto response = redirect(std::move(location), 303);
        response.addHeader("set-cookie", cookie(kConsentCsrfCookie, "", "/", 0));
        return response;
    }
    const auto apiScopes = resourceScopeStrings(authorizationRequest->scopes());
    if (authorizationRequest->resource()) {
        auto registeredResource = m_resources->requireActive(*authorizationRequest->resource());
        if (!registeredResource || !registeredResource->permitsScopes(apiScopes)) {
            return error(foundation::Error{foundation::ErrorCode::PermissionDenied}, request);
        }
    } else if (!apiScopes.empty()) {
        return error(foundation::Error{foundation::ErrorCode::PermissionDenied}, request);
    }
    auto granted = m_consents->grant(
        authenticated->session().identity(), clientId,
        consentAudience(clientId, authorizationRequest->resource()),
        scopeStrings(authorizationRequest->scopes()));
    if (!granted) return error(granted.error(), request);
    auto response = redirect(returnTarget.value(), 303);
    response.addHeader("set-cookie", cookie(kConsentCsrfCookie, "", "/", 0));
    return response;
}

gateway::HttpResponse OAuthHttpApi::consents(gateway::HttpRequest request)
{
    auto sessionCookie = cookieValue(request, kSessionCookie);
    if (!sessionCookie) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationRequired}, request);
    }
    auto authenticated = m_sessions->authenticate(
        foundation::SecretString{sessionCookie.value()});
    if (!authenticated) return error(authenticated.error(), request);
    auto values = m_consents->list(authenticated->session().identity());
    if (!values) return error(values.error(), request);
    auto csrf = security::randomTokenBase64Url(32U);
    if (!csrf) return error(csrf.error(), request);
    std::string body{"{\"csrf\":\"" + foundation::escapeJsonString(csrf.value())
        + "\",\"consents\":["};
    bool first = true;
    for (const auto& value : values.value()) {
        if (!first) body.push_back(',');
        first = false;
        body += "{\"id\":\"" + foundation::escapeJsonString(value.id().value())
            + "\",\"client_id\":\""
            + foundation::escapeJsonString(value.client().value())
            + "\",\"audience\":\""
            + foundation::escapeJsonString(value.audience()) + "\",\"scope\":\""
            + foundation::escapeJsonString(scopeString(value.scopes())) + "\",\"active\":"
            + std::string{m_consents->active(value) ? "true" : "false"}
            + "}";
    }
    body += "]}";
    gateway::HttpResponse response{
        200, gateway::Headers{{"content-type", "application/json"}}, std::move(body)};
    secure(response);
    response.addHeader("set-cookie", cookie(kConsentCsrfCookie, csrf.value(), "/", 600));
    return response;
}

gateway::HttpResponse OAuthHttpApi::revokeConsent(gateway::HttpRequest request)
{
    auto sessionCookie = cookieValue(request, kSessionCookie);
    if (!sessionCookie) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationRequired}, request);
    }
    auto authenticated = m_sessions->authenticate(
        foundation::SecretString{sessionCookie.value()});
    if (!authenticated) return error(authenticated.error(), request);
    auto form = formParameters(request);
    if (!form) return error(form.error(), request);
    auto id = required(form.value(), "consent_id", 200U);
    auto csrf = required(form.value(), "csrf", 128U);
    const auto csrfCookie = cookieValue(request, kConsentCsrfCookie);
    if (!id || !csrf || !csrfCookie
        || !security::constantTimeEquals(csrf.value(), csrfCookie.value())) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed}, request);
    }
    auto status = m_consents->revoke(
        consent::ConsentId{std::move(id).value()}, authenticated->session().identity());
    if (!status) return error(status.error(), request);
    gateway::HttpResponse response{204, {}, {}};
    secure(response);
    response.addHeader("set-cookie", cookie(kConsentCsrfCookie, "", "/", 0));
    return response;
}

gateway::HttpResponse OAuthHttpApi::pushedAuthorization(gateway::HttpRequest request)
{
    auto form = formParameters(request);
    if (!form) {
        return oauthErrorResponse(400, "invalid_request", "The PAR request is malformed.");
    }
    static constexpr std::string_view supported[]{
        "response_type", "client_id", "client_secret", "redirect_uri", "scope",
        "code_challenge", "code_challenge_method", "state", "nonce", "max_age",
        "resource", "response_mode", "request"};
    for (const auto& [name, value] : form.value()) {
        (void)value;
        if (std::ranges::find(supported, name) == std::ranges::end(supported)) {
            return oauthErrorResponse(400, "invalid_request", "The PAR request contains an unsupported parameter.");
        }
    }
    auto clientIdText = required(form.value(), "client_id", 256U);
    if (!clientIdText) return oauthErrorResponse(400, "invalid_request", "client_id is required.");
    client::ClientId clientId{clientIdText.value()};
    std::optional<foundation::SecretString> clientSecret;
    if (const auto secret = optional(form.value(), "client_secret")) {
        clientSecret.emplace(secret.value());
    }
    auto authenticatedClient = m_clients->authenticate(clientId, clientSecret);
    if (!authenticatedClient) {
        return oauthErrorResponse(401, "invalid_client", "Client authentication failed.");
    }
    Parameters requestParameters;
    if (const auto requestObject = optional(form.value(), "request")) {
        const std::size_t expectedParameterCount = clientSecret ? 3U : 2U;
        if (form->size() != expectedParameterCount) {
            return oauthErrorResponse(400, "invalid_request",
                                      "A JAR request object cannot be combined with authorization parameters at PAR.");
        }
        auto verified = verifiedJarParameters(
            *requestObject, clientId, m_oidc->issuer(), *m_jar);
        if (!verified) {
            return oauthErrorResponse(400, "invalid_request",
                                      "The JAR request object is invalid.");
        }
        requestParameters = std::move(verified).value();
    } else {
        requestParameters = form.value();
        requestParameters.erase("client_secret");
    }
    auto authorizationRequest = validatedAuthorizationRequest(
        requestParameters, *m_clients, *m_resources);
    if (!authorizationRequest) {
        return oauthErrorResponse(400, "invalid_request", "The pushed authorization request is invalid.");
    }
    auto grant = m_pushedAuthorization->push(std::move(authorizationRequest).value());
    if (!grant) {
        return oauthErrorResponse(500, "server_error", "The pushed authorization request could not be stored.");
    }
    foundation::JsonObjectWriter body;
    body.add("request_uri", grant->requestUri())
        .add("expires_in", static_cast<std::int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(grant->expiresIn()).count()));
    return jsonResponse(201, std::move(body));
}

gateway::HttpResponse OAuthHttpApi::deviceAuthorization(gateway::HttpRequest request)
{
    auto form = formParameters(request);
    if (!form) {
        return oauthErrorResponse(400, "invalid_request",
                                  "The device authorization request is malformed.");
    }
    auto clientIdText = required(form.value(), "client_id", 256U);
    auto scopeText = required(form.value(), "scope", 2048U);
    if (!clientIdText || !scopeText) {
        return oauthErrorResponse(400, "invalid_request", "client_id and scope are required.");
    }
    client::ClientId clientId{clientIdText.value()};
    std::optional<foundation::SecretString> clientSecret;
    if (const auto secret = optional(form.value(), "client_secret")) {
        clientSecret.emplace(secret.value());
    }
    auto authenticatedClient = m_clients->authenticate(clientId, clientSecret);
    if (!authenticatedClient) {
        return oauthErrorResponse(401, "invalid_client", "Client authentication failed.");
    }
    auto requestedScopes = scopes(scopeText.value());
    if (!requestedScopes || !authenticatedClient->permitsScopes(requestedScopes.value())) {
        return oauthErrorResponse(400, "invalid_scope", "The requested scopes are not permitted.");
    }
    const auto requestedResource = optional(form.value(), "resource");
    auto apiScopes = resourceScopeStrings(requestedScopes.value());
    if (!apiScopes.empty() && !requestedResource) {
        return oauthErrorResponse(400, "invalid_target", "resource is required for API scopes.");
    }
    if (requestedResource) {
        auto registeredResource = m_resources->requireActive(*requestedResource);
        if (!registeredResource || !registeredResource->permitsScopes(apiScopes)) {
            return oauthErrorResponse(400, "invalid_target", "The requested resource is unavailable.");
        }
    }
    auto grant = m_devices->begin(
        clientId, std::move(requestedScopes).value(), requestedResource);
    if (!grant) {
        return oauthErrorResponse(400, "invalid_request",
                                  "The device authorization could not be created.");
    }
    const auto expiresIn = std::chrono::duration_cast<std::chrono::seconds>(
        grant->expiresIn()).count();
    const auto interval = std::chrono::duration_cast<std::chrono::seconds>(
        grant->interval()).count();
    const std::string verificationUri = std::string{m_oidc->issuer()} + "/oauth/device";
    foundation::JsonObjectWriter body;
    body.add("device_code", grant->deviceCode().expose())
        .add("user_code", grant->userCode())
        .add("verification_uri", verificationUri)
        .add("verification_uri_complete",
             verificationUri + "?user_code=" + percentEncode(grant->userCode()))
        .add("expires_in", static_cast<std::int64_t>(expiresIn))
        .add("interval", static_cast<std::int64_t>(interval));
    return jsonResponse(200, std::move(body));
}

gateway::HttpResponse OAuthHttpApi::deviceVerification(gateway::HttpRequest request)
{
    if (request.method() == gateway::HttpMethod::Get) {
        auto parameters = queryParameters(request);
        if (!parameters) return error(parameters.error(), request);
        const auto userCode = optional(parameters.value(), "user_code");

        auto styleNonce = security::randomTokenBase64Url(18U);
        if (!styleNonce) return error(styleNonce.error(), request);

        if (!userCode) {
            const std::string content =
                "<span class=\"kicker\">Device authorization</span>"
                "<h1>Connect a device</h1>"
                "<p class=\"lead\">Enter the one-time code shown by the app that wants to use your Genyleap identity.</p>"
                "<form method=\"get\" class=\"stack\">"
                "<label class=\"section-label\" for=\"user_code\">Device code</label>"
                "<input class=\"code-input\" id=\"user_code\" name=\"user_code\" autocomplete=\"one-time-code\" "
                "autocapitalize=\"characters\" spellcheck=\"false\" placeholder=\"ABCD-EFGH\" required>"
                "<button class=\"primary\" type=\"submit\">Continue securely</button></form>"
                "<p class=\"hint\">Only approve codes you initiated yourself. OpenProof never asks the app for your Genyleap password.</p>";
            gateway::HttpResponse response{
                200, gateway::Headers{{"content-type", "text/html; charset=utf-8"}},
                devicePage(styleNonce.value(), "Connect a device", content)};
            secure(response);
            response.setHeader("content-security-policy", devicePageCsp(styleNonce.value()));
            return response;
        }

        auto authorization = m_devices->find(*userCode);
        if (!authorization) {
            return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
        }
        const std::string returnTarget =
            std::string{"/oauth/device?user_code="} + percentEncode(*userCode);
        auto sessionCookie = cookieValue(request, kSessionCookie);
        if (!sessionCookie) {
            return redirect(std::string{"/login?return_to="} + percentEncode(returnTarget));
        }
        auto authenticated = m_sessions->authenticate(
            foundation::SecretString{sessionCookie.value()});
        if (!authenticated) {
            return redirect(std::string{"/login?return_to="} + percentEncode(returnTarget));
        }

        auto registered = m_clients->requireActive(authorization->clientId());
        if (!registered) return error(registered.error(), request);

        auto csrf = security::randomTokenBase64Url(32U);
        if (!csrf) return error(csrf.error(), request);

        std::string scopeBadges;
        for (const auto& scope : scopeStrings(authorization->scopes())) {
            scopeBadges += "<span class=\"scope\">" + htmlEscape(scope) + "</span>";
        }

        std::string detail =
            "<span class=\"kicker\">Genyleap sign-in</span>"
            "<h1>Approve " + htmlEscape(registered->displayName()) + "</h1>"
            "<p class=\"lead\">This device is asking OpenProof to use your Genyleap identity. "
            "Your password and browser session are never copied into the app.</p>"
            "<div class=\"detail-grid\"><div class=\"detail\"><span>Application</span><strong>"
            + htmlEscape(registered->displayName())
            + "</strong></div><div class=\"detail\"><span>Device code</span><code>"
            + htmlEscape(*userCode) + "</code></div>";
        if (authorization->resource()) {
            detail += "<div class=\"detail\"><span>Resource</span><code>"
                + htmlEscape(*authorization->resource()) + "</code></div>";
        }
        detail += "</div><div class=\"section-label\">Permissions requested</div><div class=\"scopes\">"
            + scopeBadges
            + "</div><p class=\"hint\">For Genycaster, OpenProof proves which Genyleap identity you own. "
              "Farcaster is a separate linked connection; Genycaster checks that connection before enabling your Farcaster account.</p>"
              "<form method=\"post\" class=\"actions\"><input type=\"hidden\" name=\"user_code\" value=\""
            + htmlEscape(*userCode) + "\"><input type=\"hidden\" name=\"csrf\" value=\""
            + htmlEscape(csrf.value())
            + "\"><button class=\"primary\" name=\"decision\" value=\"approve\" type=\"submit\">Approve Genycaster</button>"
              "<button class=\"secondary\" name=\"decision\" value=\"deny\" type=\"submit\">Deny</button></form>";

        gateway::HttpResponse response{
            200, gateway::Headers{{"content-type", "text/html; charset=utf-8"}},
            devicePage(styleNonce.value(), "Approve device", detail)};
        secure(response);
        response.setHeader("content-security-policy", devicePageCsp(styleNonce.value()));
        response.addHeader("set-cookie", cookie(kDeviceCsrfCookie, csrf.value(), "/", 600));
        return response;
    }

    auto form = formParameters(request);
    if (!form) return error(form.error(), request);
    auto userCode = required(form.value(), "user_code", 64U);
    auto csrf = required(form.value(), "csrf", 128U);
    auto decision = required(form.value(), "decision", 16U);
    const auto csrfCookie = cookieValue(request, kDeviceCsrfCookie);
    if (!userCode || !csrf || !decision || !csrfCookie
        || !security::constantTimeEquals(csrf.value(), csrfCookie.value())
        || (decision.value() != "approve" && decision.value() != "deny")) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed}, request);
    }
    auto sessionCookie = cookieValue(request, kSessionCookie);
    if (!sessionCookie) {
        const std::string returnTarget =
            std::string{"/oauth/device?user_code="} + percentEncode(userCode.value());
        return redirect(std::string{"/login?return_to="} + percentEncode(returnTarget));
    }
    auto authenticated = m_sessions->authenticate(
        foundation::SecretString{sessionCookie.value()});
    if (!authenticated) return error(authenticated.error(), request);

    auto styleNonce = security::randomTokenBase64Url(18U);
    if (!styleNonce) return error(styleNonce.error(), request);

    foundation::Status action = foundation::ok();
    std::optional<oauth::DeviceAuthorization> approvedAuthorization;
    if (decision.value() == "deny") {
        action = m_devices->deny(userCode.value());
    } else {
        auto approved = m_devices->approve(userCode.value(), authenticated.value());
        if (!approved) action = foundation::fail(approved.error());
        else approvedAuthorization = std::move(approved).value();
    }
    if (!action) return error(action.error(), request);

    if (approvedAuthorization) {
        const auto audience = consentAudience(
            approvedAuthorization->clientId(), approvedAuthorization->resource());
        [[maybe_unused]] auto remembered = m_consents->grant(
            authenticated->session().identity(), approvedAuthorization->clientId(),
            audience, scopeStrings(approvedAuthorization->scopes()));
    }

    const bool approved = decision.value() == "approve";
    const std::string content = approved
        ? "<div class=\"status-icon\">&#10003;</div><span class=\"kicker\">Approved</span>"
          "<h1>Device approved</h1><p class=\"lead\">Genycaster can now finish sign-in securely. "
          "You may close this tab and return to the app.</p>"
          "<p class=\"hint\">If your Genyleap identity does not yet have a Farcaster connection, "
          "Genycaster will ask you to link one as the next step.</p>"
        : "<div class=\"status-icon denied\">×</div><span class=\"kicker\">Not approved</span>"
          "<h1>Device denied</h1><p class=\"lead\">No access was granted to this device. "
          "You can close this tab and return to Genycaster.</p>";

    gateway::HttpResponse response{
        200, gateway::Headers{{"content-type", "text/html; charset=utf-8"}},
        devicePage(styleNonce.value(), approved ? "Device approved" : "Device denied", content)};
    secure(response);
    response.setHeader("content-security-policy", devicePageCsp(styleNonce.value()));
    response.addHeader("set-cookie", cookie(kDeviceCsrfCookie, "", "/", 0));
    return response;
}

gateway::HttpResponse OAuthHttpApi::tokenEndpoint(gateway::HttpRequest request)
{
    auto form = formParameters(request);
    if (!form) {
        return oauthErrorResponse(400, "invalid_request",
                                  "The token request is malformed.");
    }

    auto grantType = required(form.value(), "grant_type", 64U);
    auto clientIdText = required(form.value(), "client_id", 256U);
    if (!grantType || !clientIdText) {
        return oauthErrorResponse(400, "invalid_request",
                                  "grant_type and client_id are required.");
    }

    client::ClientId clientId{clientIdText.value()};
    std::optional<foundation::SecretString> clientSecret;
    if (const auto rawSecret = optional(form.value(), "client_secret")) {
        clientSecret.emplace(rawSecret.value());
    }
    auto authenticatedClient = m_clients->authenticate(clientId, clientSecret);
    if (!authenticatedClient) {
        return oauthErrorResponse(401, "invalid_client",
                                  "Client authentication failed.");
    }

    auto senderConstraint = m_senderProof->tokenEndpointConstraint(request);
    if (!senderConstraint) {
        return oauthErrorResponse(400, "invalid_dpop_proof",
                                  "The sender-constraining proof is invalid.");
    }

    if (grantType.value() == "urn:ietf:params:oauth:grant-type:device_code") {
        auto deviceCode = required(form.value(), "device_code", 512U);
        if (!deviceCode) {
            return oauthErrorResponse(400, "invalid_request", "device_code is required.");
        }
        auto polled = m_devices->poll(
            foundation::SecretString{deviceCode.value()}, clientId);
        if (!polled) {
            return oauthErrorResponse(400, "invalid_grant", "The device code is invalid.");
        }
        switch (polled->disposition()) {
        case DevicePollDisposition::Pending:
            return oauthErrorResponse(400, "authorization_pending",
                                      "The user has not completed authorization.");
        case DevicePollDisposition::SlowDown:
            return oauthErrorResponse(400, "slow_down",
                                      "Polling is faster than the permitted interval.");
        case DevicePollDisposition::Denied:
            return oauthErrorResponse(400, "access_denied", "The user denied authorization.");
        case DevicePollDisposition::Expired:
            return oauthErrorResponse(400, "expired_token", "The device code has expired.");
        case DevicePollDisposition::Approved:
            break;
        }
        if (!polled->authorization()) {
            return oauthErrorResponse(400, "invalid_grant", "The device grant is invalid.");
        }
        auto tokenGrant = m_tokens->issueDeviceAuthorization(
            *polled->authorization(), senderConstraint.value());
        if (!tokenGrant) {
            return oauthErrorResponse(500, "server_error",
                                      "The authorization server could not complete the request.");
        }
        foundation::JsonObjectWriter body;
        body.add("access_token", tokenGrant->accessToken().expose())
            .add("token_type", tokenType(tokenGrant->context()))
            .add("expires_in", static_cast<std::int64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    tokenGrant->expiresIn()).count()))
            .add("refresh_token", tokenGrant->refreshToken().expose())
            .add("scope", scopeString(tokenGrant->context().scopes()));
        return jsonResponse(200, std::move(body));
    }

    if (grantType.value() == "authorization_code") {
        auto code = required(form.value(), "code", 256U);
        auto redirectUri = required(form.value(), "redirect_uri", 2048U);
        auto verifier = required(form.value(), "code_verifier", 256U);
        if (!code || !redirectUri || !verifier) {
            return oauthErrorResponse(400, "invalid_request",
                                      "code, redirect_uri and code_verifier are required.");
        }

        auto redeemed = m_authorization->redeem(
            foundation::SecretString{code.value()}, clientId,
            redirectUri.value(), verifier.value());
        if (!redeemed) {
            return oauthErrorResponse(400, "invalid_grant",
                                      "The authorization grant is invalid or expired.");
        }

        std::optional<std::string> idToken;
        if (std::ranges::any_of(
                redeemed->scopes(), [](const client::Scope& scope) {
                    return scope.value() == "openid";
                })) {
            auto signedIdToken = m_oidc->issueIdToken(redeemed.value());
            if (!signedIdToken) {
                return oauthErrorResponse(500, "server_error",
                                          "The authorization server could not complete the request.");
            }
            idToken = std::move(signedIdToken).value();
        }

        auto tokenGrant = m_tokens->issue(redeemed.value(), senderConstraint.value());
        if (!tokenGrant) {
            return oauthErrorResponse(500, "server_error",
                                      "The authorization server could not complete the request.");
        }

        foundation::JsonObjectWriter body;
        body.add("access_token", tokenGrant->accessToken().expose())
            .add("token_type", tokenType(tokenGrant->context()))
            .add("expires_in", static_cast<std::int64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    tokenGrant->expiresIn()).count()))
            .add("refresh_token", tokenGrant->refreshToken().expose())
            .add("scope", scopeString(tokenGrant->context().scopes()));
        if (idToken.has_value()) {
            body.add("id_token", idToken.value());
        }
        return jsonResponse(200, std::move(body));
    }

    if (grantType.value() == "client_credentials") {
        if (authenticatedClient->kind() != client::ClientKind::Service) {
            return oauthErrorResponse(400, "unauthorized_client",
                                      "Only service clients may use client_credentials.");
        }
        auto audience = required(form.value(), "resource", 2048U);
        if (!audience) {
            return oauthErrorResponse(400, "invalid_target", "resource is required.");
        }
        std::vector<std::string> requested;
        if (const auto requestedScope = optional(form.value(), "scope")) {
            auto parsed = scopes(*requestedScope);
            if (!parsed) return oauthErrorResponse(400, "invalid_scope", "scope is invalid.");
            requested = scopeStrings(parsed.value());
        }
        auto service = m_serviceIdentities->requireActive(clientId, audience.value(), requested);
        if (!service) {
            return oauthErrorResponse(400, "invalid_scope",
                                      "The service identity does not permit the requested grant.");
        }
        if (requested.empty()) requested = service->scopes();
        auto registeredResource = m_resources->requireActive(audience.value());
        if (!registeredResource || !registeredResource->permitsScopes(requested)) {
            return oauthErrorResponse(400, "invalid_target",
                                      "The requested resource is unavailable.");
        }
        auto grant = m_tokens->issueClientCredentials(
            service.value(), audience.value(), std::move(requested), senderConstraint.value());
        if (!grant) {
            return oauthErrorResponse(500, "server_error",
                                      "The authorization server could not complete the request.");
        }
        foundation::JsonObjectWriter body;
        body.add("access_token", grant->accessToken().expose())
            .add("token_type", tokenType(grant->context()))
            .add("expires_in", static_cast<std::int64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(grant->expiresIn()).count()))
            .add("scope", scopeString(grant->context().scopes()));
        return jsonResponse(200, std::move(body));
    }

    if (grantType.value() == "urn:ietf:params:oauth:grant-type:token-exchange") {
        auto subjectToken = required(form.value(), "subject_token", 512U);
        auto subjectType = required(form.value(), "subject_token_type", 256U);
        auto audience = required(form.value(), "resource", 2048U);
        if (!subjectToken || !subjectType || !audience
            || subjectType.value() != "urn:ietf:params:oauth:token-type:access_token") {
            return oauthErrorResponse(400, "invalid_request",
                                      "A supported subject token and resource are required.");
        }
        auto registeredResource = m_resources->requireActive(audience.value());
        if (!registeredResource) {
            return oauthErrorResponse(400, "invalid_target",
                                      "The requested resource is unavailable.");
        }
        std::vector<std::string> requested;
        if (const auto requestedScope = optional(form.value(), "scope")) {
            auto parsed = scopes(*requestedScope);
            if (!parsed) return oauthErrorResponse(400, "invalid_scope", "scope is invalid.");
            requested = scopeStrings(parsed.value());
            if (!registeredResource->permitsScopes(requested)) {
                return oauthErrorResponse(400, "invalid_scope", "scope is not permitted by the resource.");
            }
        }
        auto grant = m_tokens->issueTokenExchange(
            clientId, foundation::SecretString{subjectToken.value()},
            audience.value(), std::move(requested), senderConstraint.value());
        if (!grant) {
            return oauthErrorResponse(400, "invalid_grant",
                                      "The token exchange would widen or invalidate the subject grant.");
        }
        foundation::JsonObjectWriter body;
        body.add("access_token", grant->accessToken().expose())
            .add("issued_token_type", "urn:ietf:params:oauth:token-type:access_token")
            .add("token_type", tokenType(grant->context()))
            .add("expires_in", static_cast<std::int64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(grant->expiresIn()).count()))
            .add("scope", scopeString(grant->context().scopes()));
        return jsonResponse(200, std::move(body));
    }

    if (grantType.value() == "refresh_token") {
        auto refresh = required(form.value(), "refresh_token", 256U);
        if (!refresh) {
            return oauthErrorResponse(400, "invalid_request",
                                      "refresh_token is required.");
        }
        auto tokenGrant = m_tokens->refresh(
            clientId, foundation::SecretString{refresh.value()}, senderConstraint.value());
        if (!tokenGrant) {
            return oauthErrorResponse(400, "invalid_grant",
                                      "The refresh token is invalid or inactive.");
        }
        foundation::JsonObjectWriter body;
        body.add("access_token", tokenGrant->accessToken().expose())
            .add("token_type", tokenType(tokenGrant->context()))
            .add("expires_in", static_cast<std::int64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    tokenGrant->expiresIn()).count()))
            .add("refresh_token", tokenGrant->refreshToken().expose())
            .add("scope", scopeString(tokenGrant->context().scopes()));
        return jsonResponse(200, std::move(body));
    }

    return oauthErrorResponse(400, "unsupported_grant_type",
                              "The requested grant type is not supported.");
}

gateway::HttpResponse OAuthHttpApi::userInfo(gateway::HttpRequest request)
{
    auto access = accessCredential(request);
    if (!access) {
        return invalidBearerResponse();
    }
    auto claims = m_tokens->introspect(access->token);
    if (!claims) {
        return invalidBearerResponse();
    }
    if (claims->context().senderConstraint().has_value()) {
        auto verified = m_senderProof->verifyTokenConstraint(
            request, *claims->context().senderConstraint(), access->token,
            access->dpopAuthorizationScheme);
        if (!verified) return invalidBearerResponse();
    } else if (access->dpopAuthorizationScheme) {
        return invalidBearerResponse();
    }
    auto body = m_oidc->userInfo(claims.value());
    if (!body) {
        return invalidBearerResponse();
    }
    gateway::HttpResponse response{
        200, gateway::Headers{{"content-type", "application/json"}},
        std::move(body).value()};
    secure(response);
    cors(response);
    return response;
}

gateway::HttpResponse OAuthHttpApi::introspect(gateway::HttpRequest request)
{
    auto form = formParameters(request);
    if (!form) return error(form.error(), request);
    auto clientIdText = required(form.value(), "client_id", 256U);
    auto secretText = required(form.value(), "client_secret", 512U);
    auto rawToken = required(form.value(), "token", 256U);
    if (!clientIdText || !secretText || !rawToken) return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    client::ClientId clientId{clientIdText.value()};
    std::optional<foundation::SecretString> secret{foundation::SecretString{secretText.value()}};
    auto caller = m_clients->authenticate(clientId, secret);
    if (!caller || client::clientIsPublic(caller->kind())) return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed}, request);
    auto claims = m_tokens->introspect(foundation::SecretString{rawToken.value()});
    if (!claims) {
        foundation::JsonObjectWriter inactive; inactive.add("active", false);
        return jsonResponse(200, std::move(inactive));
    }
    foundation::JsonObjectWriter body;
    body.add("active", true)
        .add("client_id", claims->context().client().value())
        .add("sub", claims->context().identity().value())
        .add("scope", scopeString(claims->context().scopes()))
        .add("aud", scopeString(claims->context().audiences()))
        .add("iat", static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(claims->issuedAt().time_since_epoch()).count()))
        .add("exp", static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(claims->expiresAt().time_since_epoch()).count()));
    return jsonResponse(200, std::move(body));
}

gateway::HttpResponse OAuthHttpApi::revoke(gateway::HttpRequest request)
{
    auto form = formParameters(request);
    if (!form) return error(form.error(), request);
    auto clientIdText = required(form.value(), "client_id", 256U);
    auto rawToken = required(form.value(), "token", 256U);
    if (!clientIdText || !rawToken) return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    client::ClientId clientId{clientIdText.value()};
    std::optional<foundation::SecretString> secret;
    if (const auto rawSecret = optional(form.value(), "client_secret")) secret.emplace(rawSecret.value());
    auto caller = m_clients->authenticate(clientId, secret);
    if (!caller) return error(caller.error(), request);
    const auto status = m_tokens->revokeForClient(
        clientId, foundation::SecretString{rawToken.value()});
    if (!status) return error(status.error(), request);
    gateway::HttpResponse response{200, {}, {}}; secure(response); return response;
}

}

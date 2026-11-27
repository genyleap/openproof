#include <boost/json.hpp>
#include <algorithm>
#include <charconv>
#include <limits>
#include <map>
#include <memory>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "coroutine_token_read_http.hpp"

import openproof.security;
import openproof.client;

namespace openproof::oauth::http {
namespace asio=boost::asio;
namespace {
using E=foundation::ErrorCode;
using Method=gateway::HttpMethod;
bool loginRoute(const gateway::HttpRequest& r) noexcept {
    return r.path()=="/login" && (r.method()==Method::Get || r.method()==Method::Post);
}
bool tokenRoute(const gateway::HttpRequest& r) noexcept {
    return r.path()=="/oauth/token" && (r.method()==Method::Post || r.method()==Method::Options);
}
bool userInfoRoute(const gateway::HttpRequest& r) {
    return r.path()=="/oauth/userinfo" &&
        (r.method()==Method::Get || r.method()==Method::Post || r.method()==Method::Options);
}
bool introspectRoute(const gateway::HttpRequest& r) {
    return r.path()=="/oauth/introspect" && r.method()==Method::Post;
}
bool revokeRoute(const gateway::HttpRequest& r) {
    return r.path()=="/oauth/revoke" && r.method()==Method::Post;
}
void scrub(gateway::HttpRequest& r) noexcept {
    r.wipeAuthorizationHeader(); r.wipeCookieHeader(); r.wipeBody(); r.wipeTargetQuery();
}
struct Scrub final {
    gateway::HttpRequest& request;
    ~Scrub() { scrub(request); }
};
void secure(gateway::HttpResponse& r) {
    r.setHeader("cache-control","no-store");
    r.setHeader("pragma","no-cache");
    r.setHeader("x-content-type-options","nosniff");
    r.setHeader("referrer-policy","no-referrer");
    r.setHeader("access-control-allow-origin","*");
    r.setHeader("access-control-allow-methods","GET, POST, OPTIONS");
    r.setHeader("access-control-allow-headers","authorization, content-type");
    r.setHeader("access-control-max-age","600");
}
gateway::HttpResponse json(int status,foundation::JsonObjectWriter body) {
    gateway::HttpResponse r{status, gateway::Headers{{"content-type","application/json"}},body.build()};
    secure(r); return r;
}
gateway::HttpResponse fail(E code,const gateway::HttpRequest& r) {
    gateway::HttpResponse response{foundation::errorHttpStatus(code),
        gateway::Headers{{"content-type","application/json"}},
        foundation::toClientJson(foundation::Error{code},r.correlation().value())};
    secure(response); return response;
}
gateway::HttpResponse invalidBearer() {
    foundation::JsonObjectWriter body;
    body.add("error","invalid_token").add("error_description","The access token is invalid or inactive.");
    auto response=json(401,std::move(body));
    response.setHeader("www-authenticate",
        "Bearer error=\"invalid_token\", error_description=\"The access token is invalid or inactive.\"");
    return response;
}
std::string joined(const std::vector<std::string>& values) {
    std::string result;
    for (const auto& v:values) {
        if (!result.empty()) result.push_back(' ');
        result.append(v);
    }
    return result;
}
int hex(char c) {
    if (c>='0' && c<='9') return c-'0';
    if (c>='a' && c<='f') return c-'a'+10;
    if (c>='A' && c<='F') return c-'A'+10;
    return -1;
}
// Decode into a wiping owner even on invalid percent encoding.
foundation::Result<foundation::SecretString> decode(std::string_view input,std::size_t max) {
    std::string result;
    struct Wipe { std::string& s; ~Wipe(){ foundation::secureWipe(s.data(),s.size()); } } wipe{result};
    result.reserve(std::min(input.size(),max));
    for (std::size_t i=0;i<input.size();++i) {
        char c=input[i];
        if (c=='+') c=' ';
        else if (c=='%') {
            if (input.size()-i<3U) return foundation::fail(E::InvalidArgument);
            const auto a=hex(input[i+1]),b=hex(input[i+2]);
            if (a<0 || b<0) return foundation::fail(E::InvalidArgument);
            c=static_cast<char>((a<<4)|b); i+=2U;
        }
        if (static_cast<unsigned char>(c)<0x20U || static_cast<unsigned char>(c)==0x7fU
            || result.size()>=max) return foundation::fail(E::InvalidArgument);
        result.push_back(c);
    }
    return foundation::SecretString{std::move(result)};
}
// Classify only the grant_type field, without copying other raw credentials.
// The legacy token endpoint independently denies migrated grants.
bool grantRoute(const gateway::HttpRequest& r,std::string_view grantType) noexcept {
    if (r.path()!="/oauth/token" || r.method()!=Method::Post || r.body().size()>16U*1024U)
        return false;
    try {
        auto input=std::string_view{r.body()};
        while (!input.empty()) {
            const auto amp=input.find('&');
            const auto part=input.substr(0,amp);
            if (amp==std::string_view::npos) input={}; else input.remove_prefix(amp+1U);
            const auto eq=part.find('=');
            if (eq==std::string_view::npos) continue;
            auto key=decode(part.substr(0,eq),128U);
            if (key && key->expose()=="grant_type") {
                auto value=decode(part.substr(eq+1U),64U);
                if (value && value->expose()==grantType) return true;
            }
        }
    } catch (...) {}
    return false;
}
bool refreshRoute(const gateway::HttpRequest& r) noexcept {
    return grantRoute(r,"refresh_token");
}
bool codeRoute(const gateway::HttpRequest& r) noexcept {
    return grantRoute(r,"authorization_code");
}
constexpr std::string_view kDeviceGrant="urn:ietf:params:oauth:grant-type:device_code";
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
          "<div class=\"brand-mark\">O</div><div>OpenProof<small>Identity security</small></div>"
          "</div><section class=\"card\">"
        + std::string{content}
        + "</section><p class=\"footer\">OpenProof keeps your application session separate from your identity-provider session.</p>"
          "</main></body></html>";
}

constexpr std::string_view kBrowserDeviceCsrf="__Host-openproof-device-csrf";
constexpr std::string_view kBrowserSession="__Host-openproof-session";
bool deviceBrowserRoute(const gateway::HttpRequest& r) noexcept {
    return r.path()=="/oauth/device" && (r.method()==Method::Get || r.method()==Method::Post);
}
std::optional<foundation::SecretString> browserCookie(const gateway::HttpRequest& r,std::string_view key) {
    auto header=r.header("cookie");
    if (!header) return std::nullopt;
    std::optional<foundation::SecretString> value;
    auto remaining=*header;
    while (!remaining.empty()) {
        const auto semi=remaining.find(';');
        auto part=remaining.substr(0,semi);
        if (semi==std::string_view::npos) remaining={}; else remaining.remove_prefix(semi+1U);
        while (!part.empty() && (part.front()==' ' || part.front()=='\t')) part.remove_prefix(1U);
        const auto equal=part.find('=');
        if (equal==std::string_view::npos || part.substr(0,equal)!=key) continue;
        auto raw=part.substr(equal+1U);
        if (value || raw.empty() || raw.size()>512U) return std::nullopt;
        value.emplace(std::string{raw});
    }
    return value;
}
struct DeviceBrowserForm final {
    std::optional<foundation::SecretString> code,csrf;
    bool approve=false;
};
foundation::Result<DeviceBrowserForm> browserForm(const gateway::HttpRequest& r) {
    const bool post=r.method()==Method::Post;
    auto input=std::string_view{r.target()};
    if (post) {
        const auto type=r.header("content-type");
        if (!type || (*type!="application/x-www-form-urlencoded" &&
            !type->starts_with("application/x-www-form-urlencoded;")))
            return foundation::fail(E::InvalidArgument);
        input=r.body();
    } else {
        const auto query=input.find('?');
        input=query==std::string_view::npos?std::string_view{}:input.substr(query+1U);
    }
    if (input.size()>4096U) return foundation::fail(E::InvalidArgument);
    DeviceBrowserForm result;
    std::optional<foundation::SecretString> decision;
    while (!input.empty()) {
        const auto amp=input.find('&');
        const auto part=input.substr(0,amp);
        if (amp==std::string_view::npos) input={}; else input.remove_prefix(amp+1U);
        if (part.empty()) continue;
        const auto equal=part.find('=');
        if (equal==std::string_view::npos) return foundation::fail(E::InvalidArgument);
        auto key=decode(part.substr(0,equal),64U);
        if (!key) return foundation::fail(key.error());
        auto* dest=key->expose()=="user_code"?&result.code:
            post && key->expose()=="csrf"?&result.csrf:
            post && key->expose()=="decision"?&decision:nullptr;
        if (!dest || dest->has_value()) return foundation::fail(E::InvalidArgument);
        auto value=decode(part.substr(equal+1U),dest==&result.csrf?128U:64U);
        if (!value || value->empty()) return foundation::fail(E::InvalidArgument);
        dest->emplace(std::move(value).value());
    }
    if (post && (!result.code || !result.csrf || !decision ||
        (decision->expose()!="approve" && decision->expose()!="deny")))
        return foundation::fail(E::AuthenticationFailed);
    result.approve=decision && decision->expose()=="approve";
    return result;
}
gateway::HttpResponse browserPage(std::string_view nonce,std::string_view title,std::string_view content) {
    gateway::HttpResponse response{200,gateway::Headers{{"content-type","text/html; charset=utf-8"}},
        devicePage(nonce,title,content)};
    response.setHeader("cache-control","no-store");
    response.setHeader("pragma","no-cache");
    response.setHeader("x-content-type-options","nosniff");
    response.setHeader("referrer-policy","no-referrer");
    response.setHeader("content-security-policy",devicePageCsp(nonce));
    return response;
}
std::string deviceCsrfCookie(std::string_view value,int age) {
    return std::string{kBrowserDeviceCsrf}+"="+std::string{value}+
        "; Path=/; Max-Age="+std::to_string(age)+"; Secure; HttpOnly; SameSite=Lax";
}
foundation::Result<std::string> deviceCsrf(const foundation::SecretString& key,
    const session::Session& actor,std::string_view digest,std::string_view nonce) {
    const auto mac=security::hmacSha256(key,"device-browser:"+std::string{actor.id().value()}+
        ":"+std::string{digest}+":"+std::string{nonce});
    if (!mac) return foundation::fail(mac.error());
    return std::string{nonce}+"."+foundation::toHex(mac.value());
}
using Parameters=std::map<std::string,std::string,std::less<>>;
std::optional<std::string> optionalPar(const Parameters& values,std::string_view key) {
    auto it=values.find(key);
    return it==values.end() || it->second.empty()?std::nullopt:std::optional<std::string>{it->second};
}
foundation::Result<AuthorizationRequest> parseParAuthorization(const Parameters& values) {
    auto type=optionalPar(values,"response_type"),id=optionalPar(values,"client_id"),
        redirect=optionalPar(values,"redirect_uri"),scope=optionalPar(values,"scope"),
        challenge=optionalPar(values,"code_challenge"),method=optionalPar(values,"code_challenge_method");
    if (!type || *type!="code" || !id || id->size()>256U || !redirect || redirect->size()>2048U
        || !scope || scope->size()>2048U || !challenge || !method || *method!="S256")
        return foundation::fail(E::InvalidArgument);
    auto pkce=PkceChallenge::create(*challenge);
    if (!pkce) return foundation::fail(pkce.error());
    std::vector<client::Scope> scopes;
    std::string_view rest{*scope};
    while (!rest.empty()) {
        const auto space=rest.find(' ');
        const auto item=rest.substr(0,space);
        if (space==std::string_view::npos) rest={}; else rest.remove_prefix(space+1U);
        if (item.empty()) continue;
        auto parsed=client::Scope::create(std::string{item});
        if (!parsed || scopes.size()>=64U) return foundation::fail(E::InvalidArgument);
        scopes.push_back(std::move(parsed).value());
    }
    std::optional<foundation::Duration> age;
    if (auto value=optionalPar(values,"max_age")) {
        std::uint64_t seconds{};
        const auto parsed=std::from_chars(value->data(),value->data()+value->size(),seconds);
        if (parsed.ec!=std::errc{} || parsed.ptr!=value->data()+value->size() || seconds>86400U*30U)
            return foundation::fail(E::InvalidArgument);
        age=std::chrono::seconds{seconds};
    }
    auto mode=AuthorizationResponseMode::Query;
    if (auto requested=optionalPar(values,"response_mode")) {
        if (*requested=="query.jwt") mode=AuthorizationResponseMode::Jwt;
        else if (*requested!="query") return foundation::fail(E::InvalidArgument);
    }
    return AuthorizationRequest::create(client::ClientId{*id},*redirect,std::move(scopes),
        std::move(pkce).value(),optionalPar(values,"state"),optionalPar(values,"nonce"),
        age,optionalPar(values,"resource"),mode);
}
std::optional<std::string> jsonString(const boost::json::object& object,std::string_view name) {
    const auto found=object.find(name);
    if (found==object.end() || !found->value().is_string()) return std::nullopt;
    const auto& value=found->value().as_string();
    return std::string{value.data(),value.size()};
}
[[nodiscard]] foundation::Result<NativeJarAuthorization> verifyNativeJar(
    std::string_view compactJwt, const client::ClientId& expectedClient,
    std::string_view expectedAudience,std::string_view expectedKeyId,std::string_view pem,foundation::Instant now)
{
    auto verified = security::verifyRs256Jwt(pem,compactJwt);
    if (!verified) return foundation::fail(verified.error());
    boost::system::error_code headerError;
    boost::system::error_code payloadError;
    auto headerValue = boost::json::parse(verified->headerJson(), headerError);
    auto payloadValue = boost::json::parse(verified->payloadJson(), payloadError);
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
        || keyId != std::optional<std::string>{std::string{expectedKeyId}}
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
    if (issuedSeconds < 0 || expiresSeconds <= issuedSeconds || expiresSeconds > std::numeric_limits<std::int64_t>::max()/1000) {
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
    if (jwtId->empty() || jwtId->size()>256U || expiresAt<=now
        || issuedAt>now+std::chrono::seconds{60} || issuedAt<now-std::chrono::minutes{10}
        || expiresAt-issuedAt>std::chrono::minutes{10})
        return foundation::fail(E::AuthenticationFailed);
    auto request=parseParAuthorization(parameters);
    if (!request) return foundation::fail(request.error());
    return NativeJarAuthorization{std::move(request).value(),*jwtId,issuedAt,expiresAt};
}


bool authorizationBrowserRoute(const gateway::HttpRequest& r) noexcept {
    return (r.path()=="/oauth/authorize" && r.method()==Method::Get)
        || (r.path()=="/oauth/consent" && r.method()==Method::Post);
}
foundation::Result<Parameters> browserParameters(std::string_view input,std::size_t maximum) {
    if (input.empty() || input.size()>maximum) return foundation::fail(E::InvalidArgument);
    Parameters result;
    while (!input.empty()) {
        const auto amp=input.find('&');
        const auto item=input.substr(0,amp);
        if (amp==std::string_view::npos) input={}; else input.remove_prefix(amp+1U);
        if (item.empty()) continue;
        const auto eq=item.find('=');
        if (eq==std::string_view::npos) return foundation::fail(E::InvalidArgument);
        auto key=decode(item.substr(0,eq),64U);
        auto value=decode(item.substr(eq+1U),key && key->expose()=="request"?24U*1024U:
            key && key->expose()=="return_to"?8192U:2048U);
        if (!key || !value || result.size()>=16U ||
            !result.emplace(std::string{key->expose()},std::string{value->expose()}).second)
            return foundation::fail(E::InvalidArgument);
    }
    return result;
}
constexpr std::string_view kLoginCsrfCookie="__Host-openproof-login-csrf";
std::string loginCookie(std::string_view name,std::string_view value,int age) {
    return std::string{name}+"="+std::string{value}+
        "; Path=/; Max-Age="+std::to_string(age)+"; Secure; HttpOnly; SameSite=Lax";
}
bool validLoginTarget(std::string_view target) noexcept {
    return (target.starts_with("/oauth/authorize?") || target=="/oauth/device"
        || target.starts_with("/oauth/device?") || target=="/admin/console" || target=="/account/security")
        && target.size()<=8192U
        && std::ranges::none_of(target,[](unsigned char c){return c<0x20U || c==0x7fU;});
}
foundation::Result<std::string> loginCsrf(const foundation::SecretString& key,std::string_view target,std::string_view nonce) {
    auto digest=security::sha256(target);
    if (!digest) return foundation::fail(digest.error());
    auto mac=security::hmacSha256(key,"oauth-login:"+foundation::toHex(digest.value())+":"+std::string{nonce});
    if (!mac) return foundation::fail(mac.error());
    return std::string{nonce}+"."+foundation::toHex(mac.value());
}
gateway::HttpResponse renderLoginPage(std::string_view target,std::string_view csrf,
    const std::string& pageNonce,bool totpEnrolled,bool authenticationFailed) {
    std::string body = R"HTML(<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark"><title>Sign in · OpenProof</title>
<style nonce=")HTML" + pageNonce + R"HTML(">
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#090b10;color:#f7f7fb}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 15% 0%,rgba(105,92,255,.22),transparent 34rem),linear-gradient(180deg,#10131b,#080a0f);padding:24px}
.shell{width:min(100%,560px)}.brand{display:flex;align-items:center;gap:13px;margin:0 4px 24px;color:#e5e6ff;font-weight:800;font-size:21px}.brand-mark{width:44px;height:44px;border-radius:14px;display:grid;place-items:center;background:linear-gradient(135deg,#7478ff,#9c68ff);box-shadow:0 16px 38px rgba(102,92,255,.28)}.brand small{display:block;margin-top:2px;color:#8c91a4;font-size:11px;letter-spacing:.11em;text-transform:uppercase}
.card{background:rgba(23,26,35,.96);border:1px solid rgba(255,255,255,.09);border-radius:30px;padding:clamp(26px,6vw,40px);box-shadow:0 30px 100px rgba(0,0,0,.4)}.kicker{display:inline-flex;padding:8px 12px;border-radius:999px;background:rgba(111,107,255,.15);color:#c9c9ff;font-size:12px;font-weight:800;letter-spacing:.07em;text-transform:uppercase}
h1{font-size:clamp(34px,8vw,50px);line-height:1.02;letter-spacing:-.05em;margin:18px 0 12px}.lead{color:#aeb3c4;line-height:1.65;margin:0 0 25px}.field{display:grid;gap:8px;margin:15px 0}.field>span{font-size:12px;color:#a8adbf;font-weight:750;text-transform:uppercase;letter-spacing:.06em}.field small{font-weight:600;text-transform:none;letter-spacing:0;color:#71778a}
input{width:100%;border:1px solid rgba(255,255,255,.13);border-radius:15px;background:#0d1016;color:#fff;padding:14px 15px;font:inherit;outline:none}input:focus{border-color:#7d82ff;box-shadow:0 0 0 3px rgba(125,130,255,.15)}.code{font-variant-numeric:tabular-nums;letter-spacing:.14em}
button{width:100%;appearance:none;border:0;border-radius:14px;background:linear-gradient(135deg,#7076ff,#9568ff);color:#fff;padding:14px 17px;font:750 15px inherit;cursor:pointer;margin-top:10px}.hint{color:#777e91;font-size:12px;line-height:1.6;margin:17px 0 0}.hint strong{color:#aeb3c4}.text-link{color:#b8bbff;text-decoration:none;font-weight:700}.text-link:hover{text-decoration:underline}.notice{margin:0 0 18px;padding:13px 14px;border-radius:14px;font-size:13px;line-height:1.55}.notice.info{background:rgba(99,102,241,.11);border:1px solid rgba(129,140,248,.28);color:#d8dbff}.notice.error{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.28);color:#fecaca}.footer{text-align:center;color:#666d80;font-size:12px;line-height:1.55;margin:18px 12px 0}
@media(max-width:560px){body{padding:16px}.card{border-radius:23px}}
</style></head><body><main class="shell"><div class="brand"><span class="brand-mark">O</span><span>OpenProof<small>Identity security</small></span></div>
<section class="card"><span class="kicker">Secure sign in</span><h1>Sign in with OpenProof</h1>
<p class="lead">Use your OpenProof account credentials. If you already enabled an authenticator, enter its current 6-digit code for an IAL2 session.</p>)HTML";
    if (totpEnrolled) {
        body += R"HTML(<div class="notice info"><strong>Authenticator enabled.</strong> The 6-digit code used during setup has already been consumed. Wait until your authenticator shows a <strong>new</strong> code, then sign in with that new code.</div>)HTML";
    }
    if (authenticationFailed) {
        body += R"HTML(<div class="notice error"><strong>Sign-in failed.</strong> Use the same account email you used for password recovery, your new password, and the current 6-digit authenticator code. If you just enabled the authenticator, wait for the code to change before trying again.</div>)HTML";
    }
    body += R"HTML(<form method="post" action="/login"><input type="hidden" name="return_to" value=")HTML"
        + htmlEscape(target) + R"HTML("><input type="hidden" name="csrf" value=")HTML"
        + htmlEscape(csrf) + R"HTML(">
<label class="field"><span>Account</span><input name="subject" autocomplete="username" required></label>
<label class="field"><span>Password</span><input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label>
<label class="field"><span>Authenticator code <small>only if enabled</small></span><input class="code" name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="000000"></label>
<button type="submit">Sign in securely</button>
<p class="hint"><strong>No authenticator yet?</strong> Leave the code empty. For owner administration, OpenProof will take you to Account Security to set one up.</p>
<p class="hint"><strong>Forgot your password?</strong> <a class="text-link" href="/account/recover">Reset it securely</a>.</p>
</form></section><p class="footer">OpenProof keeps your application sessions separate from your identity-provider session.</p></main></body></html>)HTML";

    gateway::HttpResponse response{
        200,
        gateway::Headers{{"content-type", "text/html; charset=utf-8"}},
        std::move(body)};
    secure(response);
    response.setHeader(
        "content-security-policy",
        "default-src 'none'; style-src 'nonce-" + pageNonce
            + "'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    response.addHeader("set-cookie", loginCookie(kLoginCsrfCookie, csrf, 600));
    return response;
}
struct LoginForm final {
    std::string target,subject;
    foundation::SecretString csrf,password;
    std::optional<foundation::SecretString> totp;
};
foundation::Result<LoginForm> parseLoginForm(gateway::HttpRequest& r) {
    const auto media=r.header("content-type");
    if (!media || (*media!="application/x-www-form-urlencoded" &&
        !media->starts_with("application/x-www-form-urlencoded;")) || r.body().size()>16U*1024U)
        return foundation::fail(E::InvalidArgument);
    std::optional<foundation::SecretString> target,subject,csrf,password,totp;
    auto input=std::string_view{r.body()};
    while (!input.empty()) {
        const auto amp=input.find('&');
        const auto part=input.substr(0,amp);
        if (amp==std::string_view::npos) input={}; else input.remove_prefix(amp+1U);
        if (part.empty()) continue;
        const auto equal=part.find('=');
        if (equal==std::string_view::npos) return foundation::fail(E::InvalidArgument);
        auto name=decode(part.substr(0,equal),64U);
        if (!name) return foundation::fail(name.error());
        const auto key=name->expose();
        auto* dest=key=="return_to"?&target:key=="subject"?&subject:key=="csrf"?&csrf:
            key=="password"?&password:key=="totp"?&totp:nullptr;
        if (!dest || dest->has_value()) return foundation::fail(E::InvalidArgument);
        auto value=decode(part.substr(equal+1U),key=="return_to"?8192U:key=="subject"?320U:
            key=="password"?1024U:key=="csrf"?128U:6U);
        if (!value) return foundation::fail(value.error());
        dest->emplace(std::move(value).value());
    }
    if (!target || !validLoginTarget(target->expose()) || !subject || subject->empty()
        || !csrf || csrf->empty() || !password || password->empty())
        return foundation::fail(E::AuthenticationFailed);
    if (totp && totp->empty()) totp.reset();
    if (totp && (totp->expose().size()!=6U || !std::ranges::all_of(totp->expose(),[](char ch){return ch>='0' && ch<='9';})))
        return foundation::fail(E::AuthenticationFailed);
    LoginForm result{std::string{target->expose()},std::string{subject->expose()},
        std::move(*csrf),std::move(*password),std::move(totp)};
    r.wipeBody();
    return result;
}
bool validAuthorizationTarget(std::string_view target) noexcept {
    return target.starts_with("/oauth/authorize?") && target.size()<=8192U
        && std::ranges::none_of(target,[](unsigned char c){return c<0x20U || c==0x7fU;});
}
std::string authorizationCookie(std::string_view value,int age) {
    return "__Host-openproof-consent-csrf="+std::string{value}+
        "; Path=/; Max-Age="+std::to_string(age)+"; Secure; HttpOnly; SameSite=Lax";
}
foundation::Result<std::string> authorizationCsrf(const foundation::SecretString& key,
    const session::Session& actor,std::string_view target,std::string_view nonce) {
    auto digest=security::sha256(target);
    if (!digest) return foundation::fail(digest.error());
    auto mac=security::hmacSha256(key,"authorization-browser:"+std::string{actor.id().value()}+
        ":"+foundation::toHex(digest.value())+":"+std::string{nonce});
    if (!mac) return foundation::fail(mac.error());
    return std::string{nonce}+"."+foundation::toHex(mac.value());
}
gateway::HttpResponse browserRedirect(std::string location,int status=302) {
    gateway::HttpResponse response{status,gateway::Headers{{"location",std::move(location)},
        {"cache-control","no-store"},{"pragma","no-cache"},{"referrer-policy","no-referrer"},
        {"x-content-type-options","nosniff"}},{}};
    return response;
}
std::string authorizationParameter(std::string uri,std::string_view name,std::string_view value) {
    uri.push_back(uri.contains('?')?'&':'?');
    uri.append(percentEncode(name)).push_back('=');
    uri.append(percentEncode(value));
    return uri;
}
bool parRoute(const gateway::HttpRequest& r) noexcept {
    return r.path()=="/oauth/par" && (r.method()==Method::Post || r.method()==Method::Options);
}
bool beginDeviceRoute(const gateway::HttpRequest& r) noexcept {
    return r.path()=="/oauth/device_authorization" &&
        (r.method()==Method::Post || r.method()==Method::Options);
}
bool deviceRoute(const gateway::HttpRequest& r) noexcept {
    return grantRoute(r,kDeviceGrant);
}
constexpr std::string_view kExchangeGrant="urn:ietf:params:oauth:grant-type:token-exchange";
constexpr std::string_view kAccessType="urn:ietf:params:oauth:token-type:access_token";
bool machineRoute(const gateway::HttpRequest& r) noexcept {
    return grantRoute(r,"client_credentials") || grantRoute(r,kExchangeGrant);
}
struct MachineForm final {
    std::string clientId,audience;
    foundation::SecretString secret;
    std::optional<foundation::SecretString> subject;
    std::vector<std::string> scopes;
};
foundation::Result<MachineForm> machineForm(gateway::HttpRequest& r) {
    const auto type=r.header("content-type");
    if (!type || (*type!="application/x-www-form-urlencoded" &&
        !type->starts_with("application/x-www-form-urlencoded;"))
        || r.body().empty() || r.body().size()>16U*1024U)
        return foundation::fail(E::InvalidArgument);
    auto input=std::string_view{r.body()};
    std::optional<foundation::SecretString> id,secret,subject,subjectType,resource,scope,grant;
    while (!input.empty()) {
        const auto amp=input.find('&');
        const auto part=input.substr(0,amp);
        if (amp==std::string_view::npos) input={}; else input.remove_prefix(amp+1U);
        if (part.empty()) continue;
        const auto eq=part.find('=');
        if (eq==std::string_view::npos) return foundation::fail(E::InvalidArgument);
        auto key=decode(part.substr(0,eq),128U);
        if (!key) return foundation::fail(key.error());
        const auto name=key->expose();
        auto* dest=name=="client_id"?&id:name=="client_secret"?&secret:
            name=="subject_token"?&subject:name=="subject_token_type"?&subjectType:
            name=="resource"?&resource:name=="scope"?&scope:name=="grant_type"?&grant:nullptr;
        if (!dest || dest->has_value()) return foundation::fail(E::InvalidArgument);
        auto value=decode(part.substr(eq+1U),name=="scope"?8192U:name=="resource"?2048U:
            name=="client_secret"||name=="subject_token"?512U:256U);
        if (!value) return foundation::fail(value.error());
        dest->emplace(std::move(value).value());
    }
    if (!id || id->empty() || !grant) return foundation::fail(E::InvalidArgument);
    const bool exchange=grant->expose()==kExchangeGrant;
    if ((!exchange && grant->expose()!="client_credentials")
        || (exchange && (!subject || subject->empty() || !subjectType || subjectType->expose()!=kAccessType))
        || (!exchange && (subject || subjectType))) return foundation::fail(E::InvalidArgument);
    if (!resource || resource->empty()) return foundation::fail(E::NotFound);
    std::vector<std::string> scopes;
    if (scope) {
        std::string_view remaining{scope->expose()};
        while (!remaining.empty()) {
            const auto space=remaining.find(' ');
            const auto value=remaining.substr(0,space);
            if (space==std::string_view::npos) remaining={}; else remaining.remove_prefix(space+1U);
            if (value.empty()) continue;
            if (scopes.size()>=256U || !client::Scope::create(std::string{value}))
                return foundation::fail(E::PermissionDenied);
            scopes.emplace_back(value);
        }
    }
    MachineForm result{std::string{id->expose()},std::string{resource->expose()},
        secret?std::move(*secret):foundation::SecretString{},std::move(subject),std::move(scopes)};
    r.wipeBody();
    return result;
}
struct BeginDeviceForm final {
    std::string clientId;
    foundation::SecretString secret;
    std::vector<std::string> scopes;
    std::optional<std::string> resource;
};
foundation::Result<BeginDeviceForm> beginDeviceForm(gateway::HttpRequest& r) {
    const auto type=r.header("content-type");
    if (!type || (*type!="application/x-www-form-urlencoded" &&
        !type->starts_with("application/x-www-form-urlencoded;"))
        || r.body().empty() || r.body().size()>16U*1024U)
        return foundation::fail(E::InvalidArgument);
    auto input=std::string_view{r.body()};
    std::optional<foundation::SecretString> id,secret,scope,resource;
    while (!input.empty()) {
        const auto amp=input.find('&');
        const auto part=input.substr(0,amp);
        if (amp==std::string_view::npos) input={}; else input.remove_prefix(amp+1U);
        if (part.empty()) continue;
        const auto eq=part.find('=');
        if (eq==std::string_view::npos) return foundation::fail(E::InvalidArgument);
        auto key=decode(part.substr(0,eq),128U);
        if (!key) return foundation::fail(key.error());
        const auto name=key->expose();
        auto* dest=name=="client_id"?&id:name=="client_secret"?&secret:
            name=="scope"?&scope:name=="resource"?&resource:nullptr;
        if (!dest || dest->has_value()) return foundation::fail(E::InvalidArgument);
        auto value=decode(part.substr(eq+1U),name=="scope" || name=="resource"?2048U:
            name=="client_secret"?512U:256U);
        if (!value) return foundation::fail(value.error());
        dest->emplace(std::move(value).value());
    }
    if (!id || id->empty() || !scope || scope->empty()) return foundation::fail(E::InvalidArgument);
    std::vector<std::string> scopes;
    auto remaining=std::string_view{scope->expose()};
    while (!remaining.empty()) {
        const auto space=remaining.find(' ');
        const auto value=remaining.substr(0,space);
        if (space==std::string_view::npos) remaining={}; else remaining.remove_prefix(space+1U);
        if (value.empty()) continue;
        if (scopes.size()>=256U || !client::Scope::create(std::string{value}))
            return foundation::fail(E::PermissionDenied);
        scopes.emplace_back(value);
    }
    if (scopes.empty()) return foundation::fail(E::InvalidArgument);
    std::ranges::sort(scopes);
    if (std::adjacent_find(scopes.begin(),scopes.end())!=scopes.end())
        return foundation::fail(E::PermissionDenied);
    BeginDeviceForm result{std::string{id->expose()},
        secret?std::move(*secret):foundation::SecretString{},std::move(scopes),
        resource?std::optional<std::string>{std::string{resource->expose()}}:std::nullopt};
    r.wipeBody();
    return result;
}
struct CodeForm final {
    std::string clientId,redirectUri;
    foundation::SecretString secret,code,verifier;
};
foundation::Result<CodeForm> codeForm(gateway::HttpRequest& r) {
    const auto type=r.header("content-type");
    if (!type || (*type!="application/x-www-form-urlencoded" &&
        !type->starts_with("application/x-www-form-urlencoded;"))
        || r.body().empty() || r.body().size()>16U*1024U)
        return foundation::fail(E::InvalidArgument);
    auto input=std::string_view{r.body()};
    std::optional<foundation::SecretString> id,secret,code,verifier,redirect,grant;
    while (!input.empty()) {
        const auto amp=input.find('&');
        const auto part=input.substr(0,amp);
        if (amp==std::string_view::npos) input={}; else input.remove_prefix(amp+1U);
        if (part.empty()) continue;
        const auto eq=part.find('=');
        if (eq==std::string_view::npos) return foundation::fail(E::InvalidArgument);
        auto key=decode(part.substr(0,eq),128U);
        if (!key) return foundation::fail(key.error());
        const auto name=key->expose();
        auto* dest=name=="client_id"?&id:name=="client_secret"?&secret:name=="code"?&code:
            name=="code_verifier"?&verifier:name=="redirect_uri"?&redirect:
            name=="grant_type"?&grant:nullptr;
        if (!dest || dest->has_value()) return foundation::fail(E::InvalidArgument);
        const auto maximum=name=="redirect_uri"?2048U:name=="client_secret"?512U:256U;
        auto value=decode(part.substr(eq+1U),maximum);
        if (!value) return foundation::fail(value.error());
        dest->emplace(std::move(value).value());
    }
    if (!id || id->empty() || !code || code->empty() || !verifier || verifier->empty()
        || !redirect || redirect->empty() || !grant || grant->expose()!="authorization_code")
        return foundation::fail(E::InvalidArgument);
    CodeForm result{std::string{id->expose()},std::string{redirect->expose()},
        secret?std::move(*secret):foundation::SecretString{},std::move(*code),std::move(*verifier)};
    r.wipeBody();
    return result;
}
struct IntrospectionForm final {
    std::string clientId;
    foundation::SecretString secret,token;
};
foundation::Result<IntrospectionForm> form(gateway::HttpRequest& r,bool requireSecret=true,bool refresh=false,bool device=false) {
    const auto type=r.header("content-type");
    if (!type || (*type!="application/x-www-form-urlencoded" &&
            !type->starts_with("application/x-www-form-urlencoded;"))
        || r.body().empty() || r.body().size()>16U*1024U)
        return foundation::fail(E::InvalidArgument);
    auto input=std::string_view{r.body()};
    std::optional<foundation::SecretString> id,secret,token,hint,grant;
    while (!input.empty()) {
        const auto amp=input.find('&');
        const auto part=input.substr(0,amp);
        if (amp==std::string_view::npos) input={}; else input.remove_prefix(amp+1U);
        if (part.empty()) continue;
        const auto eq=part.find('=');
        if (eq==std::string_view::npos) return foundation::fail(E::InvalidArgument);
        auto key=decode(part.substr(0,eq),128U);
        if (!key) return foundation::fail(key.error());
        const auto name=key->expose();
        auto* dest=name=="client_id" ? &id : name=="client_secret" ? &secret :
            name==(device?"device_code":refresh?"refresh_token":"token") ? &token :
            (!refresh && !device && name=="token_type_hint") ? &hint :
            ((refresh || device) && name=="grant_type") ? &grant : nullptr;
        if (!dest || dest->has_value()) return foundation::fail(E::InvalidArgument);
        auto value=decode(part.substr(eq+1U),name=="client_secret" || name=="device_code"?512U:256U);
        if (!value) return foundation::fail(value.error());
        dest->emplace(std::move(value).value());
    }
    if (!id || id->empty() || (requireSecret && (!secret || secret->empty())) || !token || token->empty()
        || (refresh && (!grant || grant->expose()!="refresh_token"))
        || (device && (!grant || grant->expose()!=kDeviceGrant)))
        return foundation::fail(E::InvalidArgument);
    IntrospectionForm result{std::string{id->expose()},
        secret ? std::move(*secret) : foundation::SecretString{},std::move(*token)};
    r.wipeBody();
    return result;
}
}
CoroutineTokenReadAdapter::CoroutineTokenReadAdapter(gateway::http::CoroutineHttpHandler& fallback,
    gateway::TokenBucketRateLimiter& limiter,foundation::SecretString tokenKey,
    foundation::SecretString clientKey,ReadAccess access,AuthenticateClient client,
    ReadProfile profile,VerifySender sender,Revoke revoke,Rotate rotate,
    PrepareSender prepareSender,foundation::Duration accessLifetime,
    std::optional<CodeExchangeContext> codeExchange,IssueMachine issueMachine,
    std::optional<DevicePollContext> devicePoll,std::optional<ParContext> par,Login login,IntrospectAccess introspectAccess)
    : m_fallback(&fallback),m_limiter(&limiter),m_tokenKey(std::move(tokenKey)),
      m_clientKey(std::move(clientKey)),m_access(std::move(access)),m_client(std::move(client)),
      m_profile(std::move(profile)),m_sender(std::move(sender)),m_revoke(std::move(revoke)),
      m_rotate(std::move(rotate)),m_prepareSender(std::move(prepareSender)),m_accessLifetime(accessLifetime),
      m_codeExchange(std::move(codeExchange)),m_issueMachine(std::move(issueMachine)),
      m_devicePoll(std::move(devicePoll)),m_par(std::move(par)),m_login(std::move(login)),
      m_introspectAccess(std::move(introspectAccess)) {}
bool CoroutineTokenReadAdapter::nativeEnabledFor(const gateway::HttpRequest& r) const noexcept {
    if (userInfoRoute(r)) return m_access && m_profile && m_sender;
    if (introspectRoute(r)) return m_introspectAccess || (m_access && m_client);
    if (revokeRoute(r)) return static_cast<bool>(m_revoke);
    if (refreshRoute(r)) return m_rotate && m_prepareSender;
    if (codeRoute(r)) return m_codeExchange && m_codeExchange->exchange && m_prepareSender;
    if (machineRoute(r)) return m_issueMachine && m_prepareSender;
    if (deviceRoute(r)) return m_devicePoll && m_devicePoll->poll && m_prepareSender;
    if (beginDeviceRoute(r)) return m_devicePoll && m_devicePoll->begin && !m_devicePoll->verificationUri.empty();
    if (parRoute(r)) return m_par && m_par->push && !m_par->issuer.empty();
    if (authorizationBrowserRoute(r)) return m_par && m_par->push && m_par->complete && m_par->sign
        && m_codeExchange && m_devicePoll && m_devicePoll->authenticate;
    if (deviceBrowserRoute(r)) return m_devicePoll && m_devicePoll->authenticate
        && m_devicePoll->readApproval && m_devicePoll->decide;
    if (loginRoute(r)) return static_cast<bool>(m_login);
    if (tokenRoute(r)) return true; // Unknown/malformed grants are locally rejected.
    return m_fallback->nativeEnabledFor(r);
}
gateway::HttpResponse CoroutineTokenReadAdapter::handle(gateway::HttpRequest r) {
    scrub(r); return fail(E::Unavailable,r);
}
asio::awaitable<gateway::HttpResponse> CoroutineTokenReadAdapter::handleAsync(gateway::HttpRequest r) {
    if (!userInfoRoute(r) && !introspectRoute(r) && !revokeRoute(r) && !refreshRoute(r) && !codeRoute(r) && !machineRoute(r) && !deviceRoute(r) && !beginDeviceRoute(r) && !deviceBrowserRoute(r) && !parRoute(r) && !authorizationBrowserRoute(r) && !loginRoute(r) && !tokenRoute(r)) {
        if (m_fallback->nativeEnabledFor(r))
            co_return co_await m_fallback->handleAsync(std::move(r));
        scrub(r); co_return fail(E::Unavailable,r);
    }
    if (!nativeEnabledFor(r)) { scrub(r); co_return fail(E::Unavailable,r); }
    if (r.method()==Method::Options) {
        scrub(r);
        gateway::HttpResponse response{204,{},{}};
        secure(response); co_return response;
    }
    if (!m_limiter->allow("oauth-ip:"+std::string{r.remoteAddress()})) {
        scrub(r); co_return fail(E::RateLimited,r);
    }
    if (userInfoRoute(r)) co_return co_await userInfo(std::move(r));
    if (revokeRoute(r)) co_return co_await revoke(std::move(r));
    if (refreshRoute(r)) co_return co_await refresh(std::move(r));
    if (codeRoute(r)) co_return co_await exchangeCode(std::move(r));
    if (machineRoute(r)) co_return co_await issueMachine(std::move(r));
    if (deviceRoute(r)) co_return co_await pollDevice(std::move(r));
    if (beginDeviceRoute(r)) co_return co_await beginDevice(std::move(r));
    if (deviceBrowserRoute(r)) co_return co_await deviceBrowser(std::move(r));
    if (parRoute(r)) co_return co_await pushAuthorization(std::move(r));
    if (authorizationBrowserRoute(r)) co_return co_await authorizeBrowser(std::move(r));
    if (loginRoute(r)) co_return co_await loginBrowser(std::move(r));
    if (tokenRoute(r)) {
        const auto media=r.header("content-type");
        bool valid=false;
        if (media && (*media=="application/x-www-form-urlencoded" ||
            media->starts_with("application/x-www-form-urlencoded;"))) {
            auto input=std::string_view{r.body()};
            std::vector<std::string> names;
            bool grant=false,client=false;
            valid=!input.empty() && input.size()<=16U*1024U;
            while (valid && !input.empty()) {
                const auto amp=input.find('&');
                const auto part=input.substr(0,amp);
                if (amp==std::string_view::npos) input={}; else input.remove_prefix(amp+1U);
                if (part.empty()) continue;
                const auto eq=part.find('=');
                if (eq==std::string_view::npos) { valid=false; break; }
                auto name=decode(part.substr(0,eq),64U);
                auto value=decode(part.substr(eq+1U),2048U);
                if (!name || !value || names.size()>=16U
                    || std::ranges::find(names,name->expose())!=names.end()) { valid=false; break; }
                grant=grant || (name->expose()=="grant_type" && !value->empty() && value->expose().size()<=64U);
                client=client || (name->expose()=="client_id" && !value->empty() && value->expose().size()<=256U);
                names.emplace_back(name->expose());
            }
            valid=valid && grant && client;
        }
        scrub(r);
        foundation::JsonObjectWriter body;
        body.add("error",std::string_view{valid?"unsupported_grant_type":"invalid_request"});
        co_return json(400,std::move(body));
    }
    co_return co_await introspect(std::move(r));
}
asio::awaitable<gateway::HttpResponse> CoroutineTokenReadAdapter::userInfo(gateway::HttpRequest r) {
    Scrub wipe{r};
    const auto header=r.header("authorization");
    if (!header) co_return invalidBearer();
    const bool dpop=header->starts_with("DPoP ");
    const std::string_view prefix=dpop?"DPoP ":"Bearer ";
    if (!header->starts_with(prefix) || header->size()<=prefix.size()
        || header->size()-prefix.size()>256U
        || header->substr(prefix.size()).find_first_of(" \t\r\n")!=std::string_view::npos)
        co_return invalidBearer();
    foundation::SecretString credential{std::string{header->substr(prefix.size())}};
    r.wipeAuthorizationHeader(); r.wipeCookieHeader(); r.wipeBody();
    auto digest=security::hmacSha256(m_tokenKey,credential.expose());
    if (!digest) co_return fail(E::Unavailable,r);
    auto access=co_await m_access(foundation::toHex(digest.value()),nullptr);
    if (!access) {
        if (access.error().code()==E::Unavailable) co_return fail(E::Unavailable,r);
        co_return invalidBearer();
    }
    if (!access->permits("openid")) co_return invalidBearer();
    if (access->senderConstraint()) {
        // The verifier consumes the raw proof/token synchronously before it
        // returns the durable replay awaitable. No raw credential in replay SQL.
        auto verification=m_sender(r,*access->senderConstraint(),std::move(credential),dpop);
        auto verified=co_await std::move(verification);
        if (!verified) co_return invalidBearer();
    } else if (dpop) co_return invalidBearer();
    credential=foundation::SecretString{};
    const auto owner=access->authenticated().session().identity();
    foundation::JsonObjectWriter body;
    body.add("sub",owner.value());
    if (access->permits("profile") || access->permits("email")) {
        auto profile=co_await m_profile(owner);
        if (!profile) {
            if (profile.error().code()!=E::NotFound) co_return fail(E::Unavailable,r);
        } else {
            if (profile->identity()!=owner) co_return fail(E::Unavailable,r);
            if (access->permits("profile")) {
                if (profile->displayName()) body.add("name",*profile->displayName());
                if (profile->preferredUsername()) body.add("preferred_username",*profile->preferredUsername());
                if (profile->locale()) body.add("locale",*profile->locale());
                if (profile->pictureUrl()) body.add("picture",*profile->pictureUrl());
            }
            if (access->permits("email") && profile->email())
                body.add("email",*profile->email()).add("email_verified",profile->emailVerified());
        }
    }
    co_return json(200,std::move(body));
}
asio::awaitable<gateway::HttpResponse> CoroutineTokenReadAdapter::introspect(gateway::HttpRequest r) {
    Scrub wipe{r};
    auto input=form(r);
    if (!input) co_return fail(input.error().code(),r);
    r.wipeAuthorizationHeader(); r.wipeCookieHeader(); r.wipeTargetQuery();
    auto clientDigest=security::hmacSha256(m_clientKey,input->secret.expose());
    auto tokenDigest=security::hmacSha256(m_tokenKey,input->token.expose());
    input->secret=foundation::SecretString{};
    input->token=foundation::SecretString{};
    if (!clientDigest || !tokenDigest) co_return fail(E::Unavailable,r);
    foundation::Instant issued{};
    std::optional<session::DelegatedAccess> access;
    if (m_introspectAccess) {
        auto checked=co_await m_introspectAccess(std::move(input->clientId),
            foundation::toHex(clientDigest.value()),foundation::toHex(tokenDigest.value()),&issued);
        if (!checked) co_return fail(checked.error().code(),r);
        if (checked->has_value()) access.emplace(std::move(checked->value()));
    } else {
        // Compatibility for independently composed native adapters only.
        // The production composition supplies the shared-lease operation.
        auto caller=co_await m_client(std::move(input->clientId),foundation::toHex(clientDigest.value()));
        if (!caller) co_return fail(caller.error().code(),r);
        auto found=co_await m_access(foundation::toHex(tokenDigest.value()),&issued);
        if (found) access.emplace(std::move(found).value());
        else if (found.error().code()!=E::AuthenticationFailed && found.error().code()!=E::NotFound)
            co_return fail(E::Unavailable,r);
    }
    foundation::JsonObjectWriter body;
    if (!access) {
        body.add("active",false);
        co_return json(200,std::move(body));
    }
    const auto& session=access->authenticated().session();
    const auto seconds=[](foundation::Instant time) {
        return static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(time.time_since_epoch()).count());
    };
    body.add("active",true).add("client_id",access->clientId()).add("sub",session.identity().value())
        .add("scope",joined(access->scopes())).add("aud",joined(access->audiences()))
        .add("iat",seconds(issued)).add("exp",seconds(session.absoluteExpiresAt()));
    co_return json(200,std::move(body));
}
asio::awaitable<gateway::HttpResponse> CoroutineTokenReadAdapter::revoke(gateway::HttpRequest r) {
    Scrub wipe{r};
    auto input=form(r,false);
    if (!input) co_return fail(input.error().code(),r);
    r.wipeAuthorizationHeader(); r.wipeCookieHeader(); r.wipeTargetQuery();
    std::optional<std::string> clientDigest;
    if (!input->secret.empty()) {
        auto digest=security::hmacSha256(m_clientKey,input->secret.expose());
        if (!digest) co_return fail(E::Unavailable,r);
        clientDigest.emplace(foundation::toHex(digest.value()));
    }
    auto tokenDigest=security::hmacSha256(m_tokenKey,input->token.expose());
    input->secret=foundation::SecretString{};
    input->token=foundation::SecretString{};
    if (!tokenDigest) co_return fail(E::Unavailable,r);
    // Storage authenticates the caller and revokes only its own token in
    // one transaction. Unknown/foreign tokens have identical success output.
    auto result=co_await m_revoke(std::move(input->clientId),std::move(clientDigest),
        foundation::toHex(tokenDigest.value()));
    if (!result) co_return fail(result.error().code(),r);
    gateway::HttpResponse response{200,{},{}};
    secure(response);
    co_return response;
}
asio::awaitable<gateway::HttpResponse> CoroutineTokenReadAdapter::refresh(gateway::HttpRequest r) {
    Scrub wipe{r};
    const auto oauthError=[](int status,std::string_view code) {
        foundation::JsonObjectWriter body;
        body.add("error",code);
        return json(status,std::move(body));
    };
    auto input=form(r,false,true);
    if (!input) co_return oauthError(400,"invalid_request");
    r.wipeAuthorizationHeader(); r.wipeCookieHeader();
    std::optional<std::string> clientDigest;
    if (!input->secret.empty()) {
        auto digest=security::hmacSha256(m_clientKey,input->secret.expose());
        if (!digest) co_return oauthError(503,"temporarily_unavailable");
        clientDigest.emplace(foundation::toHex(digest.value()));
    }
    auto presented=security::hmacSha256(m_tokenKey,input->token.expose());
    input->secret=foundation::SecretString{};
    input->token=foundation::SecretString{};
    if (!presented) co_return oauthError(503,"temporarily_unavailable");
    auto proof=m_prepareSender(r);
    r.wipeTargetQuery();
    auto sender=co_await std::move(proof);
    if (!sender) co_return sender.error().code()==E::Unavailable
        ? oauthError(503,"temporarily_unavailable") : oauthError(400,"invalid_dpop_proof");
    std::optional<session::DelegatedSenderConstraint> binding;
    if (sender->has_value())
        binding.emplace(sender->value().kind()==token::SenderConstraintKind::Dpop
            ?session::DelegatedSenderConstraintKind::Dpop:session::DelegatedSenderConstraintKind::Mtls,
            std::string{sender->value().value()});
    auto accessRaw=security::randomTokenBase64Url(32U);
    if (!accessRaw) co_return oauthError(503,"temporarily_unavailable");
    foundation::SecretString access{std::string{"opa_"}+accessRaw.value()};
    foundation::secureWipe(accessRaw->data(),accessRaw->size());
    auto refreshRaw=security::randomTokenBase64Url(32U);
    if (!refreshRaw) co_return oauthError(503,"temporarily_unavailable");
    foundation::SecretString replacement{std::string{"opr_"}+refreshRaw.value()};
    foundation::secureWipe(refreshRaw->data(),refreshRaw->size());
    const auto accessDigest=security::hmacSha256(m_tokenKey,access.expose());
    const auto refreshDigest=security::hmacSha256(m_tokenKey,replacement.expose());
    if (!accessDigest || !refreshDigest) co_return oauthError(503,"temporarily_unavailable");
    auto scopes=co_await m_rotate(std::move(input->clientId),std::move(clientDigest),
        foundation::toHex(presented.value()),foundation::toHex(accessDigest.value()),
        foundation::toHex(refreshDigest.value()),std::move(binding));
    if (!scopes) {
        if (scopes.error().code()==E::AuthenticationRequired) co_return oauthError(401,"invalid_client");
        if (scopes.error().code()==E::AuthenticationFailed) co_return oauthError(400,"invalid_grant");
        co_return oauthError(503,"temporarily_unavailable");
    }
    foundation::JsonObjectWriter body;
    body.add("access_token",access.expose()).add("refresh_token",replacement.expose())
        .add("token_type",sender->has_value() && sender->value().kind()==token::SenderConstraintKind::Dpop
            ?"DPoP":"Bearer")
        .add("expires_in",static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(m_accessLifetime).count()))
        .add("scope",joined(scopes.value()));
    co_return json(200,std::move(body));
}
asio::awaitable<gateway::HttpResponse> CoroutineTokenReadAdapter::exchangeCode(gateway::HttpRequest r) {
    Scrub wipe{r};
    const auto oauthError=[](int status,std::string_view code) {
        foundation::JsonObjectWriter body;
        body.add("error",code);
        return json(status,std::move(body));
    };
    auto input=codeForm(r);
    if (!input) co_return oauthError(400,"invalid_request");
    r.wipeAuthorizationHeader(); r.wipeCookieHeader();
    const auto& verifier=input->verifier.expose();
    if (verifier.size()<43U || verifier.size()>128U || !std::ranges::all_of(verifier,[](char c) {
        return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9')
            || c=='-' || c=='.' || c=='_' || c=='~';
    })) co_return oauthError(400,"invalid_grant");
    auto pkce=security::sha256(verifier);
    auto codeDigest=security::hmacSha256(m_codeExchange->codeKey,input->code.expose());
    std::optional<std::string> clientDigest;
    if (!input->secret.empty()) {
        auto digest=security::hmacSha256(m_clientKey,input->secret.expose());
        if (!digest) co_return oauthError(503,"temporarily_unavailable");
        clientDigest.emplace(foundation::toHex(digest.value()));
    }
    input->code=foundation::SecretString{};
    input->verifier=foundation::SecretString{};
    input->secret=foundation::SecretString{};
    if (!pkce || !codeDigest) co_return oauthError(503,"temporarily_unavailable");
    auto proof=m_prepareSender(r);
    r.wipeTargetQuery();
    auto sender=co_await std::move(proof);
    if (!sender) co_return sender.error().code()==E::Unavailable
        ?oauthError(503,"temporarily_unavailable"):oauthError(400,"invalid_dpop_proof");
    std::optional<session::DelegatedSenderConstraint> binding;
    if (sender->has_value())
        binding.emplace(sender->value().kind()==token::SenderConstraintKind::Dpop
            ?session::DelegatedSenderConstraintKind::Dpop:session::DelegatedSenderConstraintKind::Mtls,
            std::string{sender->value().value()});
    auto family=security::randomTokenBase64Url(24U);
    auto accessRaw=security::randomTokenBase64Url(32U);
    if (!accessRaw) co_return oauthError(503,"temporarily_unavailable");
    foundation::SecretString access{std::string{"opa_"}+accessRaw.value()};
    foundation::secureWipe(accessRaw->data(),accessRaw->size());
    auto refreshRaw=security::randomTokenBase64Url(32U);
    if (!refreshRaw) co_return oauthError(503,"temporarily_unavailable");
    foundation::SecretString replacement{std::string{"opr_"}+refreshRaw.value()};
    foundation::secureWipe(refreshRaw->data(),refreshRaw->size());
    const auto accessDigest=security::hmacSha256(m_tokenKey,access.expose());
    const auto refreshDigest=security::hmacSha256(m_tokenKey,replacement.expose());
    if (!family || !accessDigest || !refreshDigest) co_return oauthError(503,"temporarily_unavailable");
    auto exchanged=co_await m_codeExchange->exchange(std::move(input->clientId),std::move(clientDigest),
        foundation::toHex(codeDigest.value()),std::move(input->redirectUri),foundation::toBase64Url(pkce.value()),
        std::move(family).value(),foundation::toHex(accessDigest.value()),foundation::toHex(refreshDigest.value()),
        std::move(binding));
    if (!exchanged) {
        if (exchanged.error().code()==E::AuthenticationRequired) co_return oauthError(401,"invalid_client");
        if (exchanged.error().code()==E::AuthenticationFailed) co_return oauthError(400,"invalid_grant");
        co_return oauthError(503,"temporarily_unavailable");
    }
    foundation::JsonObjectWriter body;
    body.add("access_token",access.expose()).add("refresh_token",replacement.expose())
        .add("token_type",sender->has_value() && sender->value().kind()==token::SenderConstraintKind::Dpop
            ?"DPoP":"Bearer")
        .add("expires_in",static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(m_accessLifetime).count()))
        .add("scope",joined(exchanged->scopes));
    if (exchanged->idToken) body.add("id_token",exchanged->idToken->expose());
    co_return json(200,std::move(body));
}
asio::awaitable<gateway::HttpResponse> CoroutineTokenReadAdapter::issueMachine(gateway::HttpRequest r) {
    Scrub wipe{r};
    const auto oauthError=[](int status,std::string_view code) {
        foundation::JsonObjectWriter body;
        body.add("error",code);
        return json(status,std::move(body));
    };
    auto input=machineForm(r);
    if (!input) {
        if (input.error().code()==E::NotFound) co_return oauthError(400,"invalid_target");
        if (input.error().code()==E::PermissionDenied) co_return oauthError(400,"invalid_scope");
        co_return oauthError(400,"invalid_request");
    }
    const bool exchange=input->subject.has_value();
    r.wipeAuthorizationHeader(); r.wipeCookieHeader();
    std::optional<std::string> clientDigest,subjectDigest;
    if (!input->secret.empty()) {
        auto digest=security::hmacSha256(m_clientKey,input->secret.expose());
        if (!digest) co_return oauthError(503,"temporarily_unavailable");
        clientDigest.emplace(foundation::toHex(digest.value()));
    }
    if (input->subject) {
        auto digest=security::hmacSha256(m_tokenKey,input->subject->expose());
        if (!digest) co_return oauthError(503,"temporarily_unavailable");
        subjectDigest.emplace(foundation::toHex(digest.value()));
    }
    input->secret=foundation::SecretString{};
    input->subject.reset();
    auto proof=m_prepareSender(r);
    r.wipeTargetQuery();
    auto sender=co_await std::move(proof);
    if (!sender) co_return sender.error().code()==E::Unavailable
        ?oauthError(503,"temporarily_unavailable"):oauthError(400,"invalid_dpop_proof");
    std::optional<session::DelegatedSenderConstraint> binding;
    if (sender->has_value())
        binding.emplace(sender->value().kind()==token::SenderConstraintKind::Dpop
            ?session::DelegatedSenderConstraintKind::Dpop:session::DelegatedSenderConstraintKind::Mtls,
            std::string{sender->value().value()});
    auto family=security::randomTokenBase64Url(24U);
    auto accessRaw=security::randomTokenBase64Url(32U);
    if (!accessRaw) co_return oauthError(503,"temporarily_unavailable");
    foundation::SecretString access{std::string{"opa_"}+accessRaw.value()};
    foundation::secureWipe(accessRaw->data(),accessRaw->size());
    const auto accessDigest=security::hmacSha256(m_tokenKey,access.expose());
    if (!family || !accessDigest) co_return oauthError(503,"temporarily_unavailable");
    auto issued=co_await m_issueMachine(std::move(input->clientId),std::move(clientDigest),
        std::move(subjectDigest),std::move(input->audience),std::move(input->scopes),
        std::move(family).value(),foundation::toHex(accessDigest.value()),std::move(binding));
    if (!issued) {
        switch (issued.error().code()) {
        case E::AuthenticationRequired: co_return oauthError(401,"invalid_client");
        case E::AuthenticationFailed: co_return oauthError(400,"invalid_grant");
        case E::FailedPrecondition: co_return oauthError(400,"unauthorized_client");
        case E::PermissionDenied: co_return oauthError(400,"invalid_scope");
        case E::NotFound: co_return oauthError(400,"invalid_target");
        case E::InvalidArgument: co_return oauthError(400,"invalid_request");
        default: co_return oauthError(503,"temporarily_unavailable");
        }
    }
    foundation::JsonObjectWriter body;
    body.add("access_token",access.expose())
        .add("token_type",sender->has_value() && sender->value().kind()==token::SenderConstraintKind::Dpop
            ?"DPoP":"Bearer")
        .add("expires_in",static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(issued->expiresIn).count()))
        .add("scope",joined(issued->scopes));
    if (exchange) body.add("issued_token_type",kAccessType);
    co_return json(200,std::move(body));
}
asio::awaitable<gateway::HttpResponse> CoroutineTokenReadAdapter::loginBrowser(gateway::HttpRequest r) {
    Scrub wipe{r};
    if (r.header("authorization")) co_return fail(E::AuthenticationFailed,r);
    if (r.method()==Method::Get) {
        const auto target=r.target();
        const auto query=target.find('?');
        if (query==std::string_view::npos) co_return fail(E::InvalidArgument,r);
        auto parameters=browserParameters(target.substr(query+1U),16U*1024U);
        if (!parameters) co_return fail(parameters.error().code(),r);
        auto back=optionalPar(*parameters,"return_to");
        if (!back || !validLoginTarget(*back)) co_return fail(E::InvalidArgument,r);
        auto random=security::randomTokenBase64Url(32U),style=security::randomTokenBase64Url(24U);
        if (!random || !style) co_return fail(E::Unavailable,r);
        auto csrf=loginCsrf(m_clientKey,*back,random.value());
        if (!csrf) co_return fail(E::Unavailable,r);
        scrub(r);
        co_return renderLoginPage(*back,csrf.value(),style.value(),
            optionalPar(*parameters,"notice")==std::optional<std::string>{"totp-enrolled"},
            optionalPar(*parameters,"error")==std::optional<std::string>{"authentication"});
    }
    auto input=parseLoginForm(r);
    if (!input) co_return fail(input.error().code(),r);
    auto cookie=browserCookie(r,kLoginCsrfCookie);
    const auto& token=input->csrf.expose();
    const auto dot=token.find('.');
    if (!cookie || dot!=43U || !security::constantTimeEquals(cookie->expose(),token))
        co_return fail(E::AuthenticationFailed,r);
    auto expected=loginCsrf(m_clientKey,input->target,token.substr(0,dot));
    if (!expected || !security::constantTimeEquals(expected.value(),token))
        co_return fail(E::AuthenticationFailed,r);
    input->csrf=foundation::SecretString{};
    cookie.reset();
    if (!m_limiter->allow("oauth-login:"+input->subject)) co_return fail(E::RateLimited,r);
    auto prior=browserCookie(r,kBrowserSession);
    identity::provider::ClientContext client;
    client.setRemoteAddress(std::string{r.remoteAddress()});
    if (const auto agent=r.header("user-agent")) client.setUserAgent(std::string{*agent});
    auto correlation=r.correlation();
    scrub(r);
    auto issued=co_await m_login(std::move(input->subject),std::move(input->password),
        std::move(input->totp),std::move(prior),std::move(client),std::move(correlation));
    if (!issued) {
        if (issued.error().code()==E::AuthenticationFailed)
            co_return browserRedirect("/login?return_to="+percentEncode(input->target)+"&error=authentication",303);
        co_return fail(issued.error().code(),r);
    }
    const auto& bearer=issued->token.expose();
    if (bearer.empty() || bearer.size()>128U || !std::ranges::all_of(bearer,[](char value) {
        return (value>='a' && value<='z') || (value>='A' && value<='Z')
            || (value>='0' && value<='9') || value=='-' || value=='_';
    })) co_return fail(E::Unavailable,r);
    auto response=browserRedirect(std::move(input->target),303);
    response.addHeader("set-cookie",loginCookie(kBrowserSession,bearer,8*60*60));
    response.addHeader("set-cookie",loginCookie(kLoginCsrfCookie,"",0));
    co_return response;
}
asio::awaitable<gateway::HttpResponse> CoroutineTokenReadAdapter::authorizeBrowser(gateway::HttpRequest r) {
    Scrub wipe{r};
    using Decision=NativeAuthorizationDecision;
    const bool post=r.method()==Method::Post;
    std::string target{r.target()};
    std::optional<foundation::SecretString> submittedCsrf;
    Decision decision=Decision::ExistingConsent;
    if (r.header("authorization")) co_return fail(E::AuthenticationFailed,r);
    if (post) {
        const auto media=r.header("content-type");
        if (!media || (*media!="application/x-www-form-urlencoded" &&
            !media->starts_with("application/x-www-form-urlencoded;")))
            co_return fail(E::InvalidArgument,r);
        auto form=browserParameters(r.body(),32U*1024U);
        if (!form || form->size()!=3U) co_return fail(E::InvalidArgument,r);
        auto back=optionalPar(*form,"return_to"),csrf=optionalPar(*form,"csrf"),choice=optionalPar(*form,"decision");
        auto expected=browserCookie(r,"__Host-openproof-consent-csrf");
        if (!back || !csrf || !choice || !expected || csrf->size()>128U
            || !security::constantTimeEquals(expected->expose(),*csrf)
            || (*choice!="approve" && *choice!="deny"))
            co_return fail(E::AuthenticationFailed,r);
        target=std::move(*back);
        submittedCsrf.emplace(std::move(*csrf));
        decision=*choice=="approve"?Decision::Approve:Decision::Deny;
    }
    if (!target.starts_with("/oauth/authorize?") || target.size()>32U*1024U
        || std::ranges::any_of(target,[](unsigned char c){return c<0x20U || c==0x7fU;}))
        co_return fail(E::InvalidArgument,r);
    auto parameters=browserParameters(std::string_view{target}.substr(std::string_view{"/oauth/authorize?"}.size()),32U*1024U);
    if (!parameters) co_return fail(parameters.error().code(),r);
    auto id=optionalPar(*parameters,"client_id");
    if (!id || id->size()>256U) co_return fail(E::InvalidArgument,r);
    auto credential=browserCookie(r,kBrowserSession);
    scrub(r);
    if (auto jwt=optionalPar(*parameters,"request")) {
        if (post || parameters->size()!=2U) co_return fail(E::InvalidArgument,r);
        auto signedRequest=std::make_shared<foundation::SecretString>(std::move(*jwt));
        foundation::secureWipe(parameters->at("request").data(),parameters->at("request").size());
        parameters->clear();
        foundation::secureWipe(target.data(),target.size());
        credential.reset();
        VerifyJar verify=[signedRequest,id=*id,issuer=m_par->issuer](std::string_view kid,std::string_view pem,foundation::Instant now) {
            auto result=verifyNativeJar(signedRequest->expose(),client::ClientId{id},issuer,kid,pem,now);
            *signedRequest=foundation::SecretString{};
            return result;
        };
        auto random=security::randomTokenBase64Url(32U);
        if (!random) co_return fail(E::Unavailable,r);
        foundation::SecretString uri{"urn:ietf:params:oauth:request_uri:opar_"+random.value()};
        foundation::secureWipe(random->data(),random->size());
        auto digest=security::sha256(uri.expose());
        if (!digest) co_return fail(E::Unavailable,r);
        auto stored=co_await m_par->push(*id,std::nullopt,foundation::toHex(digest.value()),
            std::nullopt,std::move(verify),true);
        if (!stored) co_return fail(stored.error().code(),r);
        co_return browserRedirect("/oauth/authorize?client_id="+percentEncode(*id)+
            "&request_uri="+percentEncode(uri.expose()),303);
    }
    if (!validAuthorizationTarget(target)) co_return fail(E::InvalidArgument,r);
    std::optional<AuthorizationRequest> direct;
    std::optional<std::string> parDigest;
    if (auto uri=optionalPar(*parameters,"request_uri")) {
        if (parameters->size()!=2U || !uri->starts_with("urn:ietf:params:oauth:request_uri:opar_")
            || uri->size()>256U) co_return fail(E::InvalidArgument,r);
        auto digest=security::sha256(*uri);
        if (!digest) co_return fail(E::Unavailable,r);
        parDigest.emplace(foundation::toHex(digest.value()));
    } else {
        constexpr std::string_view allowed[]{"response_type","client_id","redirect_uri","scope",
            "code_challenge","code_challenge_method","state","nonce","max_age","resource","response_mode"};
        for (const auto& [name,value]:*parameters) {
            (void)value;
            if (std::ranges::find(allowed,name)==std::ranges::end(allowed))
                co_return fail(E::InvalidArgument,r);
        }
        auto parsed=parseParAuthorization(*parameters);
        if (!parsed) co_return fail(parsed.error().code(),r);
        direct.emplace(std::move(parsed).value());
    }
    if (!credential) {
        if (post) co_return fail(E::AuthenticationRequired,r);
        co_return browserRedirect("/login?return_to="+percentEncode(target));
    }
    auto actor=co_await m_devicePoll->authenticate(std::move(*credential));
    if (!actor) {
        if (!post && (actor.error().code()==E::AuthenticationFailed || actor.error().code()==E::AuthenticationRequired))
            co_return browserRedirect("/login?return_to="+percentEncode(target));
        co_return fail(actor.error().code(),r);
    }
    if (post) {
        const auto token=submittedCsrf->expose();
        const auto dot=token.find('.');
        if (dot!=43U) co_return fail(E::AuthenticationFailed,r);
        const auto expected=authorizationCsrf(m_codeExchange->codeKey,actor.value(),target,token.substr(0,dot));
        if (!expected || !security::constantTimeEquals(expected.value(),token))
            co_return fail(E::AuthenticationFailed,r);
        submittedCsrf.reset();
    }
    auto random=security::randomTokenBase64Url(32U);
    if (!random) co_return fail(E::Unavailable,r);
    foundation::SecretString code{"opa_"+random.value()};
    foundation::secureWipe(random->data(),random->size());
    auto digest=security::hmacSha256(m_codeExchange->codeKey,code.expose());
    auto consent=security::randomTokenBase64Url(18U);
    if (!digest || !consent) co_return fail(E::Unavailable,r);
    auto completed=co_await m_par->complete(*id,std::move(parDigest),std::move(direct),
        actor->identity(),actor->id(),decision,"opcns_"+consent.value(),foundation::toHex(digest.value()),
        [this,&code](const AuthorizationRequest& request,bool denied) {
            return m_par->sign(request,denied,code.expose());
        });
    if (!completed) co_return fail(completed.error().code(),r);
    if (completed->consentRequired) {
        auto nonce=security::randomTokenBase64Url(32U);
        if (!nonce) co_return fail(E::Unavailable,r);
        auto csrf=authorizationCsrf(m_codeExchange->codeKey,actor.value(),target,nonce.value());
        if (!csrf) co_return fail(E::Unavailable,r);
        std::string scopeList;
        for (const auto& scope:completed->request.scopes()) {
            if (!scopeList.empty()) scopeList.append(", ");
            scopeList.append(htmlEscape(scope.value()));
        }
        std::string body="<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>Authorize access</title></head><body><main><h1>Authorize "+
            htmlEscape(completed->clientName)+"</h1><p>Requested access: "+scopeList+
            "</p><form method=\"post\" action=\"consent\"><input type=\"hidden\" name=\"return_to\" value=\""+
            htmlEscape(target)+"\"><input type=\"hidden\" name=\"csrf\" value=\""+htmlEscape(csrf.value())+
            "\"><button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button>"
            "<button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button></form></main></body></html>";
        gateway::HttpResponse response{200,gateway::Headers{{"content-type","text/html; charset=utf-8"},
            {"cache-control","no-store"},{"pragma","no-cache"},{"x-content-type-options","nosniff"},
            {"referrer-policy","no-referrer"},
            {"content-security-policy","default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"}},std::move(body)};
        response.addHeader("set-cookie",authorizationCookie(csrf.value(),600));
        co_return response;
    }
    const auto& request=completed->request;
    std::string location{request.redirectUri()};
    if (completed->signedResponse) {
        location=authorizationParameter(std::move(location),"response",completed->signedResponse->expose());
    } else {
        location=decision==Decision::Deny
            ?authorizationParameter(std::move(location),"error","access_denied")
            :authorizationParameter(std::move(location),"code",code.expose());
        if (request.state()) location=authorizationParameter(std::move(location),"state",*request.state());
        if (decision!=Decision::Deny) location=authorizationParameter(std::move(location),"iss",m_par->issuer);
    }
    auto response=browserRedirect(std::move(location),post?303:302);
    if (post) response.addHeader("set-cookie",authorizationCookie("",0));
    co_return response;
}
asio::awaitable<gateway::HttpResponse> CoroutineTokenReadAdapter::pushAuthorization(gateway::HttpRequest r) {
    Scrub wipe{r};
    const auto oauthError=[](int status,std::string_view code) {
        foundation::JsonObjectWriter body;
        body.add("error",code);
        return json(status,std::move(body));
    };
    const auto media=r.header("content-type");
    if (!media || (*media!="application/x-www-form-urlencoded" &&
        !media->starts_with("application/x-www-form-urlencoded;"))
        || r.body().empty() || r.body().size()>32U*1024U)
        co_return oauthError(400,"invalid_request");
    Parameters parameters;
    std::optional<foundation::SecretString> clientSecret,requestObject;
    auto input=std::string_view{r.body()};
    while (!input.empty()) {
        const auto amp=input.find('&');
        const auto item=input.substr(0,amp);
        if (amp==std::string_view::npos) input={}; else input.remove_prefix(amp+1U);
        if (item.empty()) continue;
        const auto eq=item.find('=');
        if (eq==std::string_view::npos) co_return oauthError(400,"invalid_request");
        auto name=decode(item.substr(0,eq),64U);
        if (!name) co_return oauthError(400,"invalid_request");
        const auto key=name->expose();
        auto value=decode(item.substr(eq+1U),key=="request"?24U*1024U:key=="client_secret"?512U:2048U);
        if (!value) co_return oauthError(400,"invalid_request");
        if (key=="client_secret" || key=="request") {
            auto& dest=key=="client_secret"?clientSecret:requestObject;
            if (dest || value->empty()) co_return oauthError(400,"invalid_request");
            dest.emplace(std::move(value).value());
        } else {
            constexpr std::string_view allowed[]{"response_type","client_id","redirect_uri","scope",
                "code_challenge","code_challenge_method","state","nonce","max_age","resource","response_mode"};
            if (std::ranges::find(allowed,key)==std::ranges::end(allowed)
                || !parameters.emplace(std::string{key},std::string{value->expose()}).second)
                co_return oauthError(400,"invalid_request");
        }
    }
    scrub(r);
    auto id=optionalPar(parameters,"client_id");
    if (!id || id->size()>256U) co_return oauthError(400,"invalid_request");
    std::optional<std::string> clientDigest;
    if (clientSecret) {
        auto digest=security::hmacSha256(m_clientKey,clientSecret->expose());
        if (!digest) co_return oauthError(503,"temporarily_unavailable");
        clientDigest.emplace(foundation::toHex(digest.value()));
        clientSecret.reset();
    }
    std::optional<AuthorizationRequest> direct;
    VerifyJar verifier;
    if (requestObject) {
        if (parameters.size()!=1U) co_return oauthError(400,"invalid_request");
        auto jwt=std::make_shared<foundation::SecretString>(std::move(*requestObject));
        requestObject.reset();
        verifier=[jwt,id=*id,issuer=m_par->issuer](std::string_view kid,std::string_view pem,foundation::Instant now) {
            auto result=verifyNativeJar(jwt->expose(),client::ClientId{id},issuer,kid,pem,now);
            *jwt=foundation::SecretString{};
            return result;
        };
    } else {
        auto parsed=parseParAuthorization(parameters);
        if (!parsed) co_return oauthError(400,"invalid_request");
        direct.emplace(std::move(parsed).value());
    }
    auto random=security::randomTokenBase64Url(32U);
    if (!random) co_return oauthError(503,"temporarily_unavailable");
    foundation::SecretString uri{"urn:ietf:params:oauth:request_uri:opar_"+random.value()};
    foundation::secureWipe(random->data(),random->size());
    auto digest=security::sha256(uri.expose());
    if (!digest) co_return oauthError(503,"temporarily_unavailable");
    auto stored=co_await m_par->push(std::move(*id),std::move(clientDigest),foundation::toHex(digest.value()),
        std::move(direct),std::move(verifier),false);
    if (!stored) {
        if (stored.error().code()==E::AuthenticationRequired) co_return oauthError(401,"invalid_client");
        if (stored.error().code()==E::InvalidArgument || stored.error().code()==E::PermissionDenied)
            co_return oauthError(400,"invalid_request");
        co_return oauthError(503,"temporarily_unavailable");
    }
    foundation::JsonObjectWriter body;
    body.add("request_uri",uri.expose()).add("expires_in",static_cast<std::int64_t>(90));
    co_return json(201,std::move(body));
}
asio::awaitable<gateway::HttpResponse> CoroutineTokenReadAdapter::deviceBrowser(gateway::HttpRequest r) {
    Scrub wipe{r};
    const bool post=r.method()==Method::Post;
    auto input=browserForm(r);
    if (!input) co_return fail(input.error().code(),r);
    auto style=security::randomTokenBase64Url(18U);
    if (!style) co_return fail(E::Unavailable,r);
    if (!input->code) {
        scrub(r);
        co_return browserPage(style.value(),"Connect a device",
            "<span class=\"kicker\">Device authorization</span><h1>Connect a device</h1>"
            "<p class=\"lead\">Enter the one-time code shown by the application requesting your OpenProof identity.</p>"
            "<form method=\"get\" class=\"stack\"><label class=\"section-label\" for=\"user_code\">Sign-in code</label>"
            "<input class=\"code-input\" id=\"user_code\" name=\"user_code\" autocomplete=\"one-time-code\" "
            "autocapitalize=\"characters\" spellcheck=\"false\" placeholder=\"ABCD-EFGH\" required>"
            "<button class=\"primary\" type=\"submit\">Continue securely</button></form>"
            "<p class=\"hint\">Only approve codes you initiated yourself. OpenProof never shares your password with the requesting application.</p>");
    }
    if (r.header("authorization")) co_return fail(E::AuthenticationFailed,r);
    auto cookie=browserCookie(r,kBrowserSession);
    if (post) {
        auto expected=browserCookie(r,kBrowserDeviceCsrf);
        if (!expected || !input->csrf ||
            !security::constantTimeEquals(expected->expose(),input->csrf->expose()))
            co_return fail(E::AuthenticationFailed,r);
    }
    const auto login=[&] {
        auto target="/oauth/device?user_code="+percentEncode(input->code->expose());
        gateway::HttpResponse response{302,gateway::Headers{{"location","/login?return_to="+percentEncode(target)},
            {"cache-control","no-store"},{"pragma","no-cache"},{"referrer-policy","no-referrer"},
            {"x-content-type-options","nosniff"}},{}};
        foundation::secureWipe(target.data(),target.size());
        return response;
    };
    scrub(r);
    if (!cookie) {
        if (post) co_return fail(E::AuthenticationRequired,r);
        co_return login();
    }
    const auto hashed=security::hmacSha256(m_devicePoll->deviceKey,input->code->expose());
    if (!hashed) co_return fail(E::Unavailable,r);
    const auto digest=foundation::toHex(hashed.value());
    auto actor=co_await m_devicePoll->authenticate(std::move(*cookie));
    if (!actor) {
        if (!post && (actor.error().code()==E::AuthenticationFailed || actor.error().code()==E::AuthenticationRequired))
            co_return login();
        co_return fail(actor.error().code(),r);
    }
    if (post) {
        const auto token=input->csrf->expose();
        const auto dot=token.find('.');
        if (dot==std::string_view::npos || dot!=43U) co_return fail(E::AuthenticationFailed,r);
        const auto expected=deviceCsrf(m_devicePoll->deviceKey,actor.value(),digest,token.substr(0,dot));
        if (!expected || !security::constantTimeEquals(expected.value(),token))
            co_return fail(E::AuthenticationFailed,r);
        input->csrf.reset(); input->code.reset();
        auto consentId=security::randomTokenBase64Url(18U);
        if (!consentId) co_return fail(E::Unavailable,r);
        auto saved=co_await m_devicePoll->decide(digest,actor->identity(),actor->id(),input->approve,
            "opcns_"+consentId.value());
        if (!saved) co_return fail(saved.error().code(),r);
        auto response=browserPage(style.value(),input->approve?"Device approved":"Device denied",
            input->approve
            ?"<div class=\"status-icon\">&#10003;</div><span class=\"kicker\">Approved</span><h1>Device approved</h1>"
             "<p class=\"lead\">The requesting application can now complete authorization. You may close this tab and return to the app.</p>"
             "<p class=\"hint\">If the application requires another linked identity, it will explain the linking steps separately.</p>"
            :"<div class=\"status-icon denied\">×</div><span class=\"kicker\">Not approved</span><h1>Device denied</h1>"
             "<p class=\"lead\">No access was granted to this device. You can close this tab and return to the requesting application.</p>");
        response.addHeader("set-cookie",deviceCsrfCookie("",0));
        co_return response;
    }
    auto grant=co_await m_devicePoll->readApproval(digest,actor->identity());
    if (!grant) co_return fail(grant.error().code(),r);
    auto nonce=security::randomTokenBase64Url(32U);
    if (!nonce) co_return fail(E::Unavailable,r);
    auto csrf=deviceCsrf(m_devicePoll->deviceKey,actor.value(),digest,nonce.value());
    if (!csrf) co_return fail(E::Unavailable,r);
    std::string badges;
    for (const auto& scope:grant->scopes) badges+="<span class=\"scope\">"+htmlEscape(scope)+"</span>";
    std::string detail="<span class=\"kicker\">Device authorization</span><h1>Approve "+
        htmlEscape(grant->clientName)+"</h1><p class=\"lead\">This application is requesting access to your OpenProof identity. "
        "Your password and browser session are never copied into the app.</p>"
        "<div class=\"detail-grid\"><div class=\"detail\"><span>Application</span><strong>"+
        htmlEscape(grant->clientName)+"</strong></div>";
    if (grant->resource) detail+="<div class=\"detail\"><span>Resource</span><code>"+
        htmlEscape(*grant->resource)+"</code></div>";
    detail+="</div><div class=\"section-label\">Permissions requested</div><div class=\"scopes\">"+badges+
        "</div><p class=\"hint\">Approve only if you recognize the application and the requested permissions. "
        "Any additional account-linking requirements belong to the requesting application.</p>"
        "<form method=\"post\" class=\"actions\"><input type=\"hidden\" name=\"user_code\" value=\""+
        htmlEscape(input->code->expose())+"\"><input type=\"hidden\" name=\"csrf\" value=\""+
        htmlEscape(csrf.value())+"\"><button class=\"primary\" name=\"decision\" value=\"approve\" type=\"submit\">"
        "Approve application</button><button class=\"secondary\" name=\"decision\" value=\"deny\" type=\"submit\">Deny</button></form>";
    auto response=browserPage(style.value(),"Approve device",detail);
    response.addHeader("set-cookie",deviceCsrfCookie(csrf.value(),600));
    foundation::secureWipe(detail.data(),detail.size());
    foundation::secureWipe(csrf->data(),csrf->size());
    co_return response;
}
asio::awaitable<gateway::HttpResponse> CoroutineTokenReadAdapter::beginDevice(gateway::HttpRequest r) {
    Scrub wipe{r};
    const auto oauthError=[](int status,std::string_view code) {
        foundation::JsonObjectWriter body;
        body.add("error",code);
        return json(status,std::move(body));
    };
    auto input=beginDeviceForm(r);
    if (!input) co_return oauthError(400,input.error().code()==E::PermissionDenied?"invalid_scope":"invalid_request");
    scrub(r);
    std::optional<std::string> clientDigest;
    if (!input->secret.empty()) {
        auto digest=security::hmacSha256(m_clientKey,input->secret.expose());
        if (!digest) co_return oauthError(503,"temporarily_unavailable");
        clientDigest.emplace(foundation::toHex(digest.value()));
    }
    input->secret=foundation::SecretString{};
    // Rejection sampling avoids modulo bias in the human-entered code.
    constexpr std::string_view alphabet="BCDFGHJKLMNPQRSTVWXYZ23456789";
    constexpr auto limit=256U-(256U%alphabet.size());
    for (unsigned attempt=0;attempt<3U;++attempt) {
        auto raw=security::randomTokenBase64Url(32U);
        if (!raw) co_return oauthError(503,"temporarily_unavailable");
        foundation::SecretString device{std::string{"opd_"}+raw.value()};
        foundation::secureWipe(raw->data(),raw->size());
        std::string userText;
        userText.reserve(9U);
        for (unsigned batch=0;batch<4U && userText.size()<9U;++batch) {
            auto random=security::randomBytes(16U);
            if (!random) co_return oauthError(503,"temporarily_unavailable");
            for (const auto byte:*random) {
                const auto index=std::to_integer<unsigned int>(byte);
                if (index>=limit) continue;
                if (userText.size()==4U) userText.push_back('-');
                userText.push_back(alphabet[index%alphabet.size()]);
                if (userText.size()==9U) break;
            }
            foundation::secureWipe(random->data(),random->size());
        }
        foundation::SecretString user{std::move(userText)};
        if (user.expose().size()!=9U) co_return oauthError(503,"temporarily_unavailable");
        const auto deviceDigest=security::hmacSha256(m_devicePoll->deviceKey,device.expose());
        const auto userDigest=security::hmacSha256(m_devicePoll->deviceKey,user.expose());
        if (!deviceDigest || !userDigest) co_return oauthError(503,"temporarily_unavailable");
        auto stored=co_await m_devicePoll->begin(input->clientId,clientDigest,
            foundation::toHex(deviceDigest.value()),foundation::toHex(userDigest.value()),
            input->scopes,input->resource);
        if (!stored) {
            switch (stored.error().code()) {
            case E::Conflict: continue;
            case E::AuthenticationRequired: co_return oauthError(401,"invalid_client");
            case E::PermissionDenied: co_return oauthError(400,"invalid_scope");
            case E::NotFound: co_return oauthError(400,"invalid_target");
            case E::InvalidArgument: co_return oauthError(400,"invalid_request");
            default: co_return oauthError(503,"temporarily_unavailable");
            }
        }
        foundation::JsonObjectWriter body;
        body.add("device_code",device.expose()).add("user_code",user.expose())
            .add("verification_uri",m_devicePoll->verificationUri)
            .add("verification_uri_complete",m_devicePoll->verificationUri+"?user_code="+std::string{user.expose()})
            .add("expires_in",static_cast<std::int64_t>(600))
            .add("interval",static_cast<std::int64_t>(5));
        co_return json(200,std::move(body));
    }
    co_return oauthError(503,"temporarily_unavailable");
}
asio::awaitable<gateway::HttpResponse> CoroutineTokenReadAdapter::pollDevice(gateway::HttpRequest r) {
    Scrub wipe{r};
    const auto oauthError=[](int status,std::string_view code) {
        foundation::JsonObjectWriter body;
        body.add("error",code);
        return json(status,std::move(body));
    };
    auto input=form(r,false,false,true);
    if (!input) co_return oauthError(400,"invalid_request");
    r.wipeAuthorizationHeader(); r.wipeCookieHeader();
    std::optional<std::string> clientDigest;
    if (!input->secret.empty()) {
        auto digest=security::hmacSha256(m_clientKey,input->secret.expose());
        if (!digest) co_return oauthError(503,"temporarily_unavailable");
        clientDigest.emplace(foundation::toHex(digest.value()));
    }
    auto presented=security::hmacSha256(m_devicePoll->deviceKey,input->token.expose());
    input->secret=foundation::SecretString{};
    input->token=foundation::SecretString{};
    if (!presented) co_return oauthError(503,"temporarily_unavailable");
    auto proof=m_prepareSender(r);
    r.wipeTargetQuery();
    auto sender=co_await std::move(proof);
    if (!sender) co_return sender.error().code()==E::Unavailable
        ? oauthError(503,"temporarily_unavailable") : oauthError(400,"invalid_dpop_proof");
    std::optional<session::DelegatedSenderConstraint> binding;
    if (sender->has_value())
        binding.emplace(sender->value().kind()==token::SenderConstraintKind::Dpop
            ?session::DelegatedSenderConstraintKind::Dpop:session::DelegatedSenderConstraintKind::Mtls,
            std::string{sender->value().value()});
    auto accessRaw=security::randomTokenBase64Url(32U);
    if (!accessRaw) co_return oauthError(503,"temporarily_unavailable");
    foundation::SecretString access{std::string{"opa_"}+accessRaw.value()};
    foundation::secureWipe(accessRaw->data(),accessRaw->size());
    auto refreshRaw=security::randomTokenBase64Url(32U);
    if (!refreshRaw) co_return oauthError(503,"temporarily_unavailable");
    foundation::SecretString replacement{std::string{"opr_"}+refreshRaw.value()};
    foundation::secureWipe(refreshRaw->data(),refreshRaw->size());
    const auto accessDigest=security::hmacSha256(m_tokenKey,access.expose());
    const auto refreshDigest=security::hmacSha256(m_tokenKey,replacement.expose());
    if (!accessDigest || !refreshDigest) co_return oauthError(503,"temporarily_unavailable");
    auto family=security::randomTokenBase64Url(24U);
    if (!family) co_return oauthError(503,"temporarily_unavailable");
    auto polled=co_await m_devicePoll->poll(std::move(input->clientId),std::move(clientDigest),
        foundation::toHex(presented.value()),std::move(family).value(),
        foundation::toHex(accessDigest.value()),foundation::toHex(refreshDigest.value()),std::move(binding));
    if (!polled) {
        if (polled.error().code()==E::AuthenticationRequired) co_return oauthError(401,"invalid_client");
        if (polled.error().code()==E::AuthenticationFailed) co_return oauthError(400,"invalid_grant");
        co_return oauthError(503,"temporarily_unavailable");
    }
    switch (polled->state) {
    case NativeDevicePollState::Pending: co_return oauthError(400,"authorization_pending");
    case NativeDevicePollState::SlowDown: co_return oauthError(400,"slow_down");
    case NativeDevicePollState::Denied: co_return oauthError(400,"access_denied");
    case NativeDevicePollState::Expired: co_return oauthError(400,"expired_token");
    case NativeDevicePollState::Issued: break;
    }
    foundation::JsonObjectWriter body;
    body.add("access_token",access.expose()).add("refresh_token",replacement.expose())
        .add("token_type",sender->has_value() && sender->value().kind()==token::SenderConstraintKind::Dpop
            ?"DPoP":"Bearer")
        .add("expires_in",static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(m_accessLifetime).count()))
        .add("scope",joined(polled->scopes));
    co_return json(200,std::move(body));
}
}

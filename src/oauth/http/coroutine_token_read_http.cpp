#include <algorithm>
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
    std::optional<DevicePollContext> devicePoll)
    : m_fallback(&fallback),m_limiter(&limiter),m_tokenKey(std::move(tokenKey)),
      m_clientKey(std::move(clientKey)),m_access(std::move(access)),m_client(std::move(client)),
      m_profile(std::move(profile)),m_sender(std::move(sender)),m_revoke(std::move(revoke)),
      m_rotate(std::move(rotate)),m_prepareSender(std::move(prepareSender)),m_accessLifetime(accessLifetime),
      m_codeExchange(std::move(codeExchange)),m_issueMachine(std::move(issueMachine)),
      m_devicePoll(std::move(devicePoll)) {}
bool CoroutineTokenReadAdapter::nativeEnabledFor(const gateway::HttpRequest& r) const noexcept {
    if (userInfoRoute(r)) return m_access && m_profile && m_sender;
    if (introspectRoute(r)) return m_access && m_client;
    if (revokeRoute(r)) return static_cast<bool>(m_revoke);
    if (refreshRoute(r)) return m_rotate && m_prepareSender;
    if (codeRoute(r)) return m_codeExchange && m_codeExchange->exchange && m_prepareSender;
    if (machineRoute(r)) return m_issueMachine && m_prepareSender;
    if (deviceRoute(r)) return m_devicePoll && m_devicePoll->poll && m_prepareSender;
    if (beginDeviceRoute(r)) return m_devicePoll && m_devicePoll->begin && !m_devicePoll->verificationUri.empty();
    if (deviceBrowserRoute(r)) return m_devicePoll && m_devicePoll->authenticate
        && m_devicePoll->readApproval && m_devicePoll->decide;
    return m_fallback->nativeEnabledFor(r);
}
gateway::HttpResponse CoroutineTokenReadAdapter::handle(gateway::HttpRequest r) {
    scrub(r); return fail(E::Unavailable,r);
}
asio::awaitable<gateway::HttpResponse> CoroutineTokenReadAdapter::handleAsync(gateway::HttpRequest r) {
    if (!userInfoRoute(r) && !introspectRoute(r) && !revokeRoute(r) && !refreshRoute(r) && !codeRoute(r) && !machineRoute(r) && !deviceRoute(r) && !beginDeviceRoute(r) && !deviceBrowserRoute(r)) {
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
    auto caller=co_await m_client(std::move(input->clientId),foundation::toHex(clientDigest.value()));
    if (!caller) co_return fail(caller.error().code(),r);
    foundation::Instant issued{};
    auto access=co_await m_access(foundation::toHex(tokenDigest.value()),&issued);
    foundation::JsonObjectWriter body;
    if (!access) {
        if (access.error().code()!=E::AuthenticationFailed && access.error().code()!=E::NotFound)
            co_return fail(E::Unavailable,r);
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

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "coroutine_token_read_http.hpp"

import openproof.security;

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
struct IntrospectionForm final {
    std::string clientId;
    foundation::SecretString secret,token;
};
foundation::Result<IntrospectionForm> form(gateway::HttpRequest& r) {
    const auto type=r.header("content-type");
    if (!type || (*type!="application/x-www-form-urlencoded" &&
            !type->starts_with("application/x-www-form-urlencoded;"))
        || r.body().empty() || r.body().size()>16U*1024U)
        return foundation::fail(E::InvalidArgument);
    auto input=std::string_view{r.body()};
    std::optional<foundation::SecretString> id,secret,token,hint;
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
            name=="token" ? &token : name=="token_type_hint" ? &hint : nullptr;
        if (!dest || dest->has_value()) return foundation::fail(E::InvalidArgument);
        auto value=decode(part.substr(eq+1U),name=="client_secret"?512U:256U);
        if (!value) return foundation::fail(value.error());
        dest->emplace(std::move(value).value());
    }
    if (!id || id->empty() || !secret || secret->empty() || !token || token->empty())
        return foundation::fail(E::InvalidArgument);
    IntrospectionForm result{std::string{id->expose()},std::move(*secret),std::move(*token)};
    r.wipeBody();
    return result;
}
}
CoroutineTokenReadAdapter::CoroutineTokenReadAdapter(gateway::http::CoroutineHttpHandler& fallback,
    gateway::TokenBucketRateLimiter& limiter,foundation::SecretString tokenKey,
    foundation::SecretString clientKey,ReadAccess access,AuthenticateClient client,
    ReadProfile profile,VerifySender sender)
    : m_fallback(&fallback),m_limiter(&limiter),m_tokenKey(std::move(tokenKey)),
      m_clientKey(std::move(clientKey)),m_access(std::move(access)),m_client(std::move(client)),
      m_profile(std::move(profile)),m_sender(std::move(sender)) {}
bool CoroutineTokenReadAdapter::nativeEnabledFor(const gateway::HttpRequest& r) const noexcept {
    if (userInfoRoute(r)) return m_access && m_profile && m_sender;
    if (introspectRoute(r)) return m_access && m_client;
    return m_fallback->nativeEnabledFor(r);
}
gateway::HttpResponse CoroutineTokenReadAdapter::handle(gateway::HttpRequest r) {
    scrub(r); return fail(E::Unavailable,r);
}
asio::awaitable<gateway::HttpResponse> CoroutineTokenReadAdapter::handleAsync(gateway::HttpRequest r) {
    if (!userInfoRoute(r) && !introspectRoute(r)) {
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
}

#include <boost/json.hpp>
#include <algorithm>
#include <string_view>
#include <chrono>
#include <string>
#include <utility>
#include "coroutine_passkey_http.hpp"

import openproof.security;
import openproof.identity.provider;

namespace openproof::authentication::http {
namespace {
namespace pk=provider::passkey;
using E=foundation::ErrorCode;
using Method=gateway::HttpMethod;
bool listing(const gateway::HttpRequest& r) noexcept {
    return r.path()=="/account/passkeys" && r.method()==Method::Get;
}
bool options(const gateway::HttpRequest& r) noexcept {
    return r.path()=="/account/passkeys/options" && r.method()==Method::Post;
}
constexpr std::string_view prefix="/account/passkeys/";
constexpr std::string_view registrationCookie="__Host-openproof-passkey-registration";
bool owned(const gateway::HttpRequest& r) noexcept {
    return r.path()=="/account/passkeys" || r.path().starts_with(prefix);
}
bool encoded(std::string_view value,std::size_t limit) {
    return !value.empty() && value.size()<=limit && std::ranges::all_of(value,[](char c){
        return (c>='A' && c<='Z') || (c>='a' && c<='z') || (c>='0' && c<='9') || c=='-' || c=='_';
    });
}
std::optional<std::string> ceremonyCookie(const gateway::HttpRequest& r) {
    auto header=r.header("cookie");
    if (!header) return std::nullopt;
    auto rest=*header;
    std::optional<std::string> found;
    while (!rest.empty()) {
        const auto end=rest.find(';');
        auto item=rest.substr(0,end);
        if (end==std::string_view::npos) rest={}; else rest.remove_prefix(end+1U);
        while (!item.empty() && (item.front()==' ' || item.front()=='\t')) item.remove_prefix(1U);
        const auto eq=item.find('=');
        if (eq!=std::string_view::npos && item.substr(0,eq)==registrationCookie) {
            auto value=item.substr(eq+1U);
            if (found || !encoded(value,256U)) return std::nullopt;
            found=std::string{value};
        }
    }
    return found;
}
foundation::Result<pk::RegistrationResponse> parseRegistration(gateway::HttpRequest& r) {
    const auto media=r.header("content-type");
    if (!media || (*media!="application/json" && !media->starts_with("application/json;"))
        || r.body().empty() || r.body().size()>128U*1024U)
        return foundation::fail(E::InvalidArgument);
    boost::system::error_code error;
    auto value=boost::json::parse(r.body(),error);
    r.wipeBody();
    if (error || !value.is_object() || value.as_object().size()!=3U)
        return foundation::fail(E::InvalidArgument);
    const auto field=[&](std::string_view name,std::size_t limit)->std::optional<std::string>{
        const auto* item=value.as_object().if_contains(name);
        if (!item || !item->is_string()) return std::nullopt;
        const auto& s=item->as_string();
        if (!encoded(std::string_view{s.data(),s.size()},limit)) return std::nullopt;
        return std::string{s.data(),s.size()};
    };
    auto id=field("credential_id",4096U),client=field("client_data_json",32U*1024U),
        attestation=field("attestation_object",128U*1024U);
    if (!id || !client || !attestation) return foundation::fail(E::InvalidArgument);
    return pk::RegistrationResponse{std::move(*id),std::move(*client),std::move(*attestation)};
}
void scrub(gateway::HttpRequest& r) noexcept {
    r.wipeBody(); r.wipeAuthorizationHeader(); r.wipeCookieHeader(); r.wipeTargetQuery();
}
struct Scrub final {gateway::HttpRequest& request; ~Scrub(){scrub(request);}};
gateway::HttpResponse response(int status,std::string body) {
    gateway::HttpResponse out{status,gateway::Headers{{"content-type","application/json"}},std::move(body)};
    out.setHeader("cache-control","no-store");
    out.setHeader("pragma","no-cache");
    out.setHeader("x-content-type-options","nosniff");
    out.setHeader("referrer-policy","no-referrer");
    return out;
}
gateway::HttpResponse fail(E code,const gateway::HttpRequest& r) {
    auto out=response(foundation::errorHttpStatus(code),
        foundation::toClientJson(foundation::Error{code},r.correlation().value()));
    if (code==E::AuthenticationRequired) out.setHeader("www-authenticate","Bearer");
    return out;
}
}
CoroutinePasskeyAccountAdapter::CoroutinePasskeyAccountAdapter(
    gateway::http::CoroutineHttpHandler& fallback,gateway::TokenBucketRateLimiter& limiter,
    const foundation::ClockSource& clock,const pk::PasskeyConfig& config,Authenticate authenticate,Read read,Mutate mutate)
    :m_fallback(&fallback),m_limiter(&limiter),m_clock(&clock),m_config(&config),
    m_authenticate(std::move(authenticate)),m_read(std::move(read)),m_mutate(std::move(mutate)) {}

bool CoroutinePasskeyAccountAdapter::nativeEnabledFor(const gateway::HttpRequest& r) const noexcept {
    return owned(r) || m_fallback->nativeEnabledFor(r);
}
gateway::HttpResponse CoroutinePasskeyAccountAdapter::handle(gateway::HttpRequest r) {
    scrub(r);
    return fail(E::Unavailable,r);
}
boost::asio::awaitable<gateway::HttpResponse> CoroutinePasskeyAccountAdapter::handleAsync(gateway::HttpRequest r) {
    const bool begin=options(r);
    const bool registration=r.path()=="/account/passkeys" && r.method()==Method::Post;
    const bool removal=r.path().starts_with(prefix) && r.method()==Method::Delete;
    if (!owned(r)) {
        if (m_fallback->nativeEnabledFor(r)) co_return co_await m_fallback->handleAsync(std::move(r));
        scrub(r); co_return fail(E::Unavailable,r);
    }
    Scrub wipe{r};
    if (!begin && !listing(r) && !registration && !removal)
        co_return response(405,R"({"error":"method_not_allowed"})");
    if (!m_authenticate || ((begin || listing(r)) && !m_read) ||
        ((registration || removal) && !m_mutate)) co_return fail(E::Unavailable,r);
    if (!m_limiter->allow("passkey:"+std::string{r.remoteAddress()}+":"+std::string{r.path()}))
        co_return fail(E::RateLimited,r);
    if (r.header("authorization").value_or("").starts_with("DPoP "))
        co_return fail(E::AuthenticationFailed,r);
    if (begin || registration || removal) {
        if (auto origin=r.header("origin"); origin && *origin!=m_config->origin())
            co_return fail(E::PermissionDenied,r);
    }
    std::optional<identity::provider::ChallengeId> registrationId;
    std::optional<pk::RegistrationResponse> registrationInput;
    std::string removeId;
    if (registration) {
        auto id=ceremonyCookie(r);
        auto parsed=parseRegistration(r);
        if (!id || !parsed) co_return fail(E::InvalidArgument,r);
        registrationId.emplace(std::move(*id));
        registrationInput.emplace(std::move(parsed).value());
    } else if (removal) {
        const auto id=r.path().substr(prefix.size());
        if (!encoded(id,4096U)) co_return fail(E::InvalidArgument,r);
        removeId=std::string{id};
    }
    auto credential=gateway::takeSessionCredential(r);
    if (!credential) co_return fail(credential.error().code(),r);
    if (!credential->has_value()) co_return fail(E::AuthenticationRequired,r);
    scrub(r);
    auto actor=co_await m_authenticate(std::move(credential->value()));
    if (!actor) co_return fail(actor.error().code(),r);
    const auto now=m_clock->now();
    if (registration || removal) {
        std::optional<pk::PasskeyCredential> verified;
        if (registration) {
            auto checked=pk::verifyRegistration(*m_config,actor->identity(),*registrationId,*registrationInput,now);
            registrationInput.reset();
            if (!checked) {
                auto out=fail(checked.error().code(),r);
                out.addHeader("set-cookie",std::string{registrationCookie}+"=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict");
                co_return out;
            }
            removeId=checked->credentialId;
            verified.emplace(std::move(checked).value());
        }
        auto changed=co_await m_mutate(actor->identity(),actor->id(),now,std::move(removeId),
            std::move(registrationId),std::move(verified));
        auto out=changed?response(registration?201:200,registration?R"({"registered":true})":R"({"removed":true})")
            :fail(changed.error().code(),r);
        if (registration) out.addHeader("set-cookie",std::string{registrationCookie}+
            "=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict");
        co_return out;
    }
    std::optional<pk::RegistrationCeremony> ceremony;
    if (begin) {
        auto random=security::randomTokenBase64Url(24U);
        if (!random || now.time_since_epoch().count()<0
            || now.time_since_epoch().count()>foundation::Duration::max().count()-m_config->ceremonyLifetime().count())
            co_return fail(E::Unavailable,r);
        ceremony.emplace(pk::RegistrationCeremony{identity::provider::ChallengeId{"pkr_"+random.value()},
            actor->identity(),now+m_config->ceremonyLifetime()});
    }
    auto credentials=co_await m_read(actor->identity(),actor->id(),now,ceremony);
    if (!credentials) co_return fail(credentials.error().code(),r);
    if (ceremony) {
        std::vector<std::string> excluded;
        for (const auto& credential:credentials.value()) excluded.push_back(credential.credentialId);
        auto started=pk::registrationOptions(*m_config,actor->identity(),ceremony->id,excluded);
        if (!started) co_return fail(started.error().code(),r);
        boost::system::error_code error;
        auto parsed=boost::json::parse(started->publicKeyOptionsJson,error);
        if (error || !parsed.is_object()) co_return fail(E::Internal,r);
        boost::json::object body;
        body["publicKey"]=std::move(parsed);
        auto out=response(200,boost::json::serialize(body));
        const auto age=std::chrono::ceil<std::chrono::seconds>(m_config->ceremonyLifetime()).count();
        out.addHeader("set-cookie","__Host-openproof-passkey-registration="+
            std::string{started->ceremonyId.value()}+"; Path=/; Max-Age="+std::to_string(age)+
            "; Secure; HttpOnly; SameSite=Strict");
        co_return out;
    }
    boost::json::array items;
    for (const auto& credential:credentials.value()) {
        items.emplace_back(boost::json::object{{"credential_id",credential.credentialId},
            {"sign_count",credential.signCount},{"created_at_ms",credential.createdAt.time_since_epoch().count()},
            {"last_used_at_ms",credential.lastUsedAt.time_since_epoch().count()}});
    }
    boost::json::object body;
    body["passkeys"]=std::move(items);
    co_return response(200,boost::json::serialize(body));
}
}

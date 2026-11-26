#include <boost/json.hpp>
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
    const foundation::ClockSource& clock,const pk::PasskeyConfig& config,Authenticate authenticate,Read read)
    :m_fallback(&fallback),m_limiter(&limiter),m_clock(&clock),m_config(&config),
    m_authenticate(std::move(authenticate)),m_read(std::move(read)) {}

bool CoroutinePasskeyAccountAdapter::nativeEnabledFor(const gateway::HttpRequest& r) const noexcept {
    return listing(r) || options(r) || m_fallback->nativeEnabledFor(r);
}
gateway::HttpResponse CoroutinePasskeyAccountAdapter::handle(gateway::HttpRequest r) {
    scrub(r);
    return fail(E::Unavailable,r);
}
boost::asio::awaitable<gateway::HttpResponse> CoroutinePasskeyAccountAdapter::handleAsync(gateway::HttpRequest r) {
    const bool begin=options(r);
    if (!begin && !listing(r)) {
        if (m_fallback->nativeEnabledFor(r)) co_return co_await m_fallback->handleAsync(std::move(r));
        scrub(r); co_return fail(E::Unavailable,r);
    }
    Scrub wipe{r};
    if (!m_authenticate || !m_read) co_return fail(E::Unavailable,r);
    if (!m_limiter->allow("passkey:"+std::string{r.remoteAddress()}+":"+std::string{r.path()}))
        co_return fail(E::RateLimited,r);
    if (r.header("authorization").value_or("").starts_with("DPoP "))
        co_return fail(E::AuthenticationFailed,r);
    if (begin) {
        if (auto origin=r.header("origin"); origin && *origin!=m_config->origin())
            co_return fail(E::PermissionDenied,r);
    }
    auto credential=gateway::takeSessionCredential(r);
    if (!credential) co_return fail(credential.error().code(),r);
    if (!credential->has_value()) co_return fail(E::AuthenticationRequired,r);
    scrub(r);
    auto actor=co_await m_authenticate(std::move(credential->value()));
    if (!actor) co_return fail(actor.error().code(),r);
    const auto now=m_clock->now();
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

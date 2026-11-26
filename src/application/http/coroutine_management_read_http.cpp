#include <algorithm>
#include <string_view>
#include <utility>
#include "coroutine_management_read_http.hpp"

import openproof.identity.provider;

namespace openproof::application::http {
namespace {
using E=foundation::ErrorCode;
using Method=gateway::HttpMethod;
std::optional<ManagementRead> operation(const gateway::HttpRequest& r) noexcept {
    if (r.method()!=Method::Get) return std::nullopt;
    if (r.path()=="/admin/applications") return ManagementRead::Applications;
    if (r.path()=="/admin/clients") return ManagementRead::Clients;
    if (r.path()=="/admin/clients/jar-key") return ManagementRead::JarKey;
    if (r.path()=="/admin/resources") return ManagementRead::Resources;
    if (r.path()=="/admin/service-identities") return ManagementRead::ServiceIdentity;
    return std::nullopt;
}
void scrub(gateway::HttpRequest& r) noexcept {
    r.wipeBody(); r.wipeAuthorizationHeader(); r.wipeCookieHeader(); r.wipeTargetQuery();
}
struct Scrub {gateway::HttpRequest& request; ~Scrub(){scrub(request);}};
gateway::HttpResponse response(int status,std::string body) {
    gateway::HttpResponse result{status,gateway::Headers{{"content-type","application/json"}},std::move(body)};
    result.setHeader("cache-control","no-store");
    result.setHeader("pragma","no-cache");
    result.setHeader("x-content-type-options","nosniff");
    result.setHeader("referrer-policy","no-referrer");
    return result;
}
gateway::HttpResponse failure(E code,const gateway::HttpRequest& r) {
    auto denied=response(foundation::errorHttpStatus(code),foundation::toClientJson(foundation::Error{code},r.correlation().value()));
    if (code==E::AuthenticationRequired) denied.setHeader("www-authenticate","Bearer");
    return denied;
}
foundation::Result<std::optional<std::string>> filter(const gateway::HttpRequest& r,ManagementRead op) {
    if (op==ManagementRead::Applications || op==ManagementRead::Resources)
        return std::optional<std::string>{};
    const auto target=r.target();
    const auto q=target.find('?');
    if (q==std::string_view::npos) return foundation::fail(E::InvalidArgument);
    const auto key=op==ManagementRead::Clients?std::string_view{"application_id="}:std::string_view{"client_id="};
    auto value=target.substr(q+1U);
    if (!value.starts_with(key)) return foundation::fail(E::InvalidArgument);
    value.remove_prefix(key.size());
    if (value.empty() || value.size()>256U || value.find_first_of("&%+")!=std::string_view::npos
        || std::ranges::any_of(value,[](unsigned char c){return c<0x20U || c==0x7fU;}))
        return foundation::fail(E::InvalidArgument);
    return std::optional<std::string>{std::string{value}};
}
}

CoroutineManagementReadAdapter::CoroutineManagementReadAdapter(
    gateway::http::CoroutineHttpHandler& fallback,gateway::TokenBucketRateLimiter& limiter,
    Authenticate authenticate,Read read)
    : m_fallback(&fallback),m_limiter(&limiter),m_authenticate(std::move(authenticate)),m_read(std::move(read)) {}

bool CoroutineManagementReadAdapter::nativeEnabledFor(const gateway::HttpRequest& r) const noexcept {
    return operation(r).has_value() || m_fallback->nativeEnabledFor(r);
}

gateway::HttpResponse CoroutineManagementReadAdapter::handle(gateway::HttpRequest r) {
    scrub(r);
    return failure(E::Unavailable,r);
}

boost::asio::awaitable<gateway::HttpResponse> CoroutineManagementReadAdapter::handleAsync(gateway::HttpRequest r) {
    const auto op=operation(r);
    if (!op) {
        if (m_fallback->nativeEnabledFor(r)) co_return co_await m_fallback->handleAsync(std::move(r));
        scrub(r);
        co_return failure(E::Unavailable,r);
    }
    Scrub wipe{r};
    if (!m_authenticate || !m_read) co_return failure(E::Unavailable,r);
    if (!m_limiter->allow("idp-admin-ip:"+std::string{r.remoteAddress()}))
        co_return failure(E::RateLimited,r);
    if (r.header("authorization").value_or("").starts_with("DPoP "))
        co_return failure(E::AuthenticationFailed,r);
    auto selected=filter(r,*op);
    if (!selected) co_return failure(selected.error().code(),r);
    auto credential=gateway::takeSessionCredential(r);
    if (!credential) co_return failure(credential.error().code(),r);
    if (!credential->has_value()) co_return failure(E::AuthenticationRequired,r);
    scrub(r);
    auto actor=co_await m_authenticate(std::move(credential->value()));
    if (!actor) co_return failure(actor.error().code(),r);
    if (!identity::provider::meetsAssurance(actor->assurance(),identity::provider::AssuranceLevel::Ial2))
        co_return failure(E::AssuranceInsufficient,r);
    if (!m_limiter->allow("idp-admin-identity:"+std::string{actor->identity().value()}))
        co_return failure(E::RateLimited,r);
    auto data=co_await m_read(*op,actor->identity(),actor->id(),std::move(selected).value());
    if (!data) co_return failure(data.error().code(),r);
    co_return response(200,std::move(data).value());
}
}

#include <exception>
#include <string>
#include <string_view>
#include <utility>
#include "coroutine_read_http.hpp"

import openproof.security;
import openproof.enterprise.scim.http;

namespace openproof::enterprise::scim::http {
namespace {
using E=foundation::ErrorCode;
bool owned(const gateway::HttpRequest& r) noexcept {
    return r.path()=="/scim/v2" || (r.method()==gateway::HttpMethod::Get && r.path().starts_with("/scim/v2/"));
}
void scrub(gateway::HttpRequest& r) noexcept {
    r.wipeBody();r.wipeAuthorizationHeader();r.wipeCookieHeader();r.wipeTargetQuery();
}
struct Scrub final {gateway::HttpRequest& request;~Scrub(){scrub(request);}};
gateway::HttpResponse failure(E code) {
    auto out=renderScimError(foundation::Error{code});
    if (code==E::AuthenticationRequired) out.setHeader("www-authenticate","Bearer realm=\"OpenProof SCIM\"");
    return out;
}
}

CoroutineReadAdapter::CoroutineReadAdapter(gateway::http::CoroutineHttpHandler& fallback,
    gateway::TokenBucketRateLimiter& limiter,foundation::SecretString bearer,Read read)
    :m_fallback(&fallback),m_limiter(&limiter),m_bearer(std::move(bearer)),m_read(std::move(read)) {}

bool CoroutineReadAdapter::nativeEnabledFor(const gateway::HttpRequest& r) const noexcept {
    return owned(r) || m_fallback->nativeEnabledFor(r);
}

gateway::HttpResponse CoroutineReadAdapter::handle(gateway::HttpRequest r) {
    scrub(r);
    return failure(E::Unavailable);
}

boost::asio::awaitable<gateway::HttpResponse> CoroutineReadAdapter::handleAsync(gateway::HttpRequest r) {
    if (!owned(r)) {
        if (m_fallback->nativeEnabledFor(r)) co_return co_await m_fallback->handleAsync(std::move(r));
        scrub(r);co_return failure(E::Unavailable);
    }
    Scrub wipe{r};
    if (!m_limiter->allow("scim-ip:"+std::string{r.remoteAddress()})) co_return failure(E::RateLimited);
    constexpr std::string_view prefix="Bearer ";
    const auto authorization=r.header("authorization");
    if (m_bearer.size()<32U || !authorization || !authorization->starts_with(prefix)
        || authorization->size()!=prefix.size()+m_bearer.size()
        || !security::constantTimeEquals(authorization->substr(prefix.size()),m_bearer.expose()))
        co_return failure(E::AuthenticationRequired);
    r.wipeAuthorizationHeader();r.wipeCookieHeader();r.wipeBody();
    if (auto discovery=renderDiscovery(r)) co_return std::move(*discovery);
    if (r.method()!=gateway::HttpMethod::Get) co_return failure(E::NotFound);
    auto requested=parseReadRequest(r);
    if (!requested) co_return failure(requested.error().code());
    if (!m_read) co_return failure(E::Unavailable);
    scrub(r);
    try {
        auto rows=co_await m_read(requested.value());
        if (!rows) co_return failure(rows.error().code());
        co_return renderReadResult(requested.value(),std::move(rows).value());
    } catch (const std::exception&) {
        co_return failure(E::Unavailable);
    }
}
}

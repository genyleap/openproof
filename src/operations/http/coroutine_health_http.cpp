#include <exception>
#include <utility>
#include "coroutine_health_http.hpp"

namespace openproof::operations::http {
namespace {
bool owned(const gateway::HttpRequest& request) noexcept {
    return request.path()=="/health/live" || request.path()=="/health/ready";
}
void scrub(gateway::HttpRequest& request) noexcept {
    request.wipeBody();
    request.wipeAuthorizationHeader();
    request.wipeCookieHeader();
    request.wipeTargetQuery();
}
gateway::HttpResponse response(int status,bool ready) {
    gateway::HttpResponse result{status,gateway::Headers{{"content-type","application/json"}},
        ready?R"({"status":"ok"})":R"({"status":"unavailable"})"};
    result.setHeader("cache-control","no-store");
    result.setHeader("x-content-type-options","nosniff");
    return result;
}
}

CoroutineHealthAdapter::CoroutineHealthAdapter(gateway::http::CoroutineHttpHandler& fallback,Check check)
    : m_fallback(&fallback),m_check(std::move(check)) {}

bool CoroutineHealthAdapter::nativeEnabledFor(const gateway::HttpRequest& request) const noexcept {
    return owned(request) || m_fallback->nativeEnabledFor(request);
}

gateway::HttpResponse CoroutineHealthAdapter::handle(gateway::HttpRequest request) {
    scrub(request);
    return response(503,false);
}

boost::asio::awaitable<gateway::HttpResponse> CoroutineHealthAdapter::handleAsync(gateway::HttpRequest request) {
    if (!owned(request)) {
        if (m_fallback->nativeEnabledFor(request))
            co_return co_await m_fallback->handleAsync(std::move(request));
        scrub(request);
        co_return response(503,false);
    }
    const bool live=request.path()=="/health/live";
    const auto method=request.method();
    scrub(request);
    if (method!=gateway::HttpMethod::Get) {
        auto denied=response(405,false);
        denied.setHeader("allow","GET");
        co_return denied;
    }
    if (live) co_return response(200,true);
    if (!m_check) co_return response(503,false);
    try {
        const auto checked=co_await m_check();
        co_return checked?response(200,true):response(503,false);
    } catch (const std::exception&) {
        co_return response(503,false);
    }
}
}

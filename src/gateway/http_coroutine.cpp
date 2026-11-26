module;

#include <chrono>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <boost/asio/detail/call_stack.hpp>
#include "asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>

module openproof.gateway.http;

namespace openproof::gateway::http {
namespace asio = boost::asio;

CoroutineRouteOverlay::CoroutineRouteOverlay(
    HttpHandler& compatibility, CoroutineHttpHandler& native,
    std::vector<std::string> exactNativePaths,
    std::vector<std::pair<std::string, HttpMethod>> methodScopedNativePaths)
    : m_compatibility(&compatibility), m_native(&native),
      m_exactNativePaths(std::move(exactNativePaths)),
      m_methodScopedNativePaths(std::move(methodScopedNativePaths))
{
}

bool CoroutineRouteOverlay::overlays(std::string_view path) const noexcept
{
    for (const auto& exact : m_exactNativePaths) {
        if (std::string_view{exact} == path) return true;
    }
    return false;
}

bool CoroutineRouteOverlay::overlays(const HttpRequest& request) const noexcept
{
    if (overlays(request.path())) return true;
    for (const auto& [path, method] : m_methodScopedNativePaths) {
        if (std::string_view{path} == request.path()
            && method == request.method()) {
            return true;
        }
    }
    return false;
}

bool CoroutineRouteOverlay::nativeEnabledFor(const HttpRequest& request) const noexcept
{
    if (!overlays(request)) return false;
    try {
        return m_native->nativeEnabledFor(request);
    } catch (...) {
        return false;
    }
}

HttpResponse CoroutineRouteOverlay::unavailable(const HttpRequest& request)
{
    HttpResponse denied{
        foundation::errorHttpStatus(foundation::ErrorCode::Unavailable),
        Headers{{"content-type", "application/json"}},
        foundation::toClientJson(
            foundation::Error{foundation::ErrorCode::Unavailable},
            request.correlation().value())};
    denied.setHeader("cache-control", "no-store");
    denied.setHeader("x-content-type-options", "nosniff");
    return denied;
}

HttpResponse CoroutineRouteOverlay::handle(HttpRequest request)
{
    if (overlays(request.path()) || nativeEnabledFor(request)) {
        // Strict path overlays ALWAYS fail closed, including unsupported
        // methods. For a method-scoped route, a native-enabled request must
        // also deny direct synchronous dispatch, never block a reactor.
        request.wipeBody();
        request.wipeAuthorizationHeader();
        request.wipeCookieHeader();
        return unavailable(request);
    }
    // A method-scoped native read may explicitly decline a credential type
    // it cannot authenticate (e.g. delegated OAuth Bearer). Only the bounded
    // synchronous compatibility worker may process that request. All strict
    // authentication overlays remain fail-closed regardless of capability.
    return m_compatibility->handle(std::move(request));
}

boost::asio::awaitable<HttpResponse>
CoroutineRouteOverlay::handleAsync(HttpRequest request)
{
    if (!nativeEnabledFor(request)) {
        // Defense in depth for callers bypassing the listener's capability
        // dispatch. Never invoke synchronous middleware on an Asio worker.
        request.wipeBody();
        request.wipeAuthorizationHeader();
        request.wipeCookieHeader();
        co_return unavailable(request);
    }
    co_return co_await m_native->handleAsync(std::move(request));
}

CoroutineMetricsAdapter::CoroutineMetricsAdapter(
    HttpHandler& metricsFacade, CoroutineHttpHandler& fallback, Observer observer)
    : m_metricsFacade(&metricsFacade), m_fallback(&fallback),
      m_observer(std::move(observer))
{
}

HttpResponse CoroutineMetricsAdapter::handle(HttpRequest request)
{
    // Only the legacy synchronous entry goes through the telemetry facade.
    return m_metricsFacade->handle(std::move(request));
}

boost::asio::awaitable<HttpResponse>
CoroutineMetricsAdapter::handleAsync(HttpRequest request)
{
    if (request.path() == "/metrics"
        || !m_fallback->nativeEnabledFor(request)) {
        // The listener routes /metrics to the authenticated synchronous
        // facade. A direct native call must not run that facade, disclose
        // metrics or bypass a revoked per-request downstream capability.
        // Even a miscomposed middleware chain therefore fails closed rather
        // than executing a synchronous service on a coroutine executor.
        // Capability rejection can precede credential extraction.
        request.wipeBody();
        request.wipeAuthorizationHeader();
        request.wipeCookieHeader();
        HttpResponse denied{
            foundation::errorHttpStatus(foundation::ErrorCode::Unavailable),
            Headers{{"content-type", "application/json"}},
            foundation::toClientJson(
                foundation::Error{foundation::ErrorCode::Unavailable},
                request.correlation().value())};
        denied.setHeader("cache-control", "no-store");
        denied.setHeader("x-content-type-options", "nosniff");
        co_return denied;
    }
    const HttpMethod method = request.method();
    const auto started = std::chrono::steady_clock::now();
    const auto observe = [this, method, started](int status) noexcept {
        const double elapsed = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - started).count();
        // Observability must never change the result or turn an application
        // error into an uncaught exception. Count all async 500 responses.
        try {
            if (m_observer) m_observer(method, status, elapsed);
        } catch (...) {}
    };
    try {
        HttpResponse result = co_await m_fallback->handleAsync(std::move(request));
        observe(result.status());
        co_return result;
    } catch (...) {
        // Beast translates the rethrown exception into a sanitized HTTP 500;
        // record that outcome just like the synchronous Metrics middleware.
        observe(500);
        throw;
    }
}

CoroutineGatewayAdapter::CoroutineGatewayAdapter(
    Gateway& gateway, BeastProxyTransport& transport)
    : m_gateway(&gateway), m_transport(&transport)
{
}

HttpResponse CoroutineGatewayAdapter::handle(HttpRequest request)
{
    // Compatibility method for legacy transport-neutral middleware.
    // Such callers are still blocking and remain subject to the release gate.
    return m_gateway->handle(std::move(request));
}

boost::asio::awaitable<HttpResponse>
CoroutineGatewayAdapter::handleAsync(HttpRequest request)
{
    // Authorization, rate limiting and context sealing are performed by the
    // exact same Gateway domain operations used by its synchronous entry.
    auto prepared = m_gateway->prepareForward(std::move(request));
    if (auto* immediate = std::get_if<HttpResponse>(&prepared)) {
        co_return std::move(*immediate);
    }
    auto& plan = std::get<GatewayForwardPlan>(prepared);
    while (auto endpoint = m_gateway->nextForwardEndpoint(plan)) {
        // The entire retry sequence shares one deadline. A failing or slow
        // upstream must not reset the budget before contacting the next peer.
        const foundation::Duration remaining = m_gateway->remainingForwardBudget(plan);
        if (remaining <= foundation::Duration::zero()) break;
        // Own a copy of the sanitized request across every suspension point.
        // Never keep borrowed header or transaction state in the coroutine.
        auto result = co_await m_transport->sendAsync(
            *endpoint, plan.request(), remaining);
        if (auto response = m_gateway->recordForwardResult(
                plan, *endpoint, std::move(result))) {
            co_return std::move(*response);
        }
    }
    co_return m_gateway->finishForward(plan);
}

CoroutineProtectedGatewayAdapter::CoroutineProtectedGatewayAdapter(
    Gateway& gateway, BeastProxyTransport& transport, CoroutineHttpHandler& fallback,
    Verify verify, Authorize authorize)
    : m_gateway(&gateway), m_transport(&transport), m_fallback(&fallback),
      m_verify(std::move(verify)), m_authorize(std::move(authorize))
{
}

bool CoroutineProtectedGatewayAdapter::nativeEnabledFor(const HttpRequest& request) const noexcept
{
    return (m_verify && m_authorize && eligible(*m_gateway, request))
        || m_fallback->nativeEnabledFor(request);
}

HttpResponse CoroutineProtectedGatewayAdapter::handle(HttpRequest request)
{
    if (eligible(*m_gateway, request))
        return reject(*m_gateway, foundation::Error{foundation::ErrorCode::Unavailable},
                      std::move(request));
    return m_fallback->handle(std::move(request));
}

asio::awaitable<HttpResponse>
CoroutineProtectedGatewayAdapter::handleAsync(HttpRequest request)
{
    if (!eligible(*m_gateway, request)) {
        if (m_fallback->nativeEnabledFor(request))
            co_return co_await m_fallback->handleAsync(std::move(request));
        co_return reject(*m_gateway, foundation::Error{foundation::ErrorCode::Unavailable},
                         std::move(request));
    }
    if (!m_verify || !m_authorize)
        co_return reject(*m_gateway, foundation::Error{foundation::ErrorCode::Unavailable},
                         std::move(request));
    auto started = begin(*m_gateway, std::move(request));
    if (auto* denied = std::get_if<HttpResponse>(&started))
        co_return std::move(*denied);
    auto pending = std::move(std::get<Pending>(started));
    auto authenticated = co_await m_verify(std::move(pending.credential));
    if (!authenticated)
        co_return reject(*m_gateway, authenticated.error(), std::move(pending.request));
    if (!admitIdentity(*m_gateway, authenticated.value()))
        co_return reject(*m_gateway, foundation::Error{foundation::ErrorCode::RateLimited},
                         std::move(pending.request));
    auto decision = co_await m_authorize(authenticated.value(), pending.route,
                                        pending.request.correlation());
    auto prepared = finish(*m_gateway, std::move(pending), authenticated.value(), decision);
    if (auto* denied = std::get_if<HttpResponse>(&prepared))
        co_return std::move(*denied);
    auto& plan = std::get<GatewayForwardPlan>(prepared);
    while (auto endpoint = m_gateway->nextForwardEndpoint(plan)) {
        const auto remaining = m_gateway->remainingForwardBudget(plan);
        if (remaining <= foundation::Duration::zero()) break;
        auto result = co_await m_transport->sendAsync(*endpoint, plan.request(), remaining);
        if (auto response = m_gateway->recordForwardResult(plan, *endpoint, std::move(result)))
            co_return std::move(*response);
    }
    co_return m_gateway->finishForward(plan);
}

} // namespace openproof::gateway::http

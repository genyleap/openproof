#include <boost/asio/awaitable.hpp>
#include <stdexcept>
#include <string>
#include <utility>

#include "coroutine_session_listener.hpp"

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;

namespace openproof::storage::postgres {
namespace asio = boost::asio;

CoroutineSessionListenerAdapter::CoroutineSessionListenerAdapter(
    CoroutineSessionHttpHandler& handler,
    gateway::http::CoroutineHttpHandler& fallback,
    bool allowCompatibilityFallback)
    : m_handler(&handler), m_fallback(&fallback),
      m_allowCompatibilityFallback(allowCompatibilityFallback) {}

bool CoroutineSessionListenerAdapter::nativeEnabledFor(
    const gateway::HttpRequest& request) const noexcept
{
    // Without explicit compatibility opt-in, retain fail-closed semantics:
    // even a disabled downstream route is handled by the native rejection
    // guard rather than silently invoking a synchronous repository.
    if (!m_allowCompatibilityFallback
        || CoroutineSessionHttpHandler::isSessionRoute(request.path())) {
        return true;
    }
    return m_fallback->nativeEnabledFor(request);
}

gateway::HttpResponse CoroutineSessionListenerAdapter::handle(
    gateway::HttpRequest request)
{
    // Only an operator-explicit compatibility stack may delegate ordinary
    // non-session routes to the bounded handler pool. Session mutations
    // always remain native and can never fall through to legacy SQL.
    if (m_allowCompatibilityFallback
        && !CoroutineSessionHttpHandler::isSessionRoute(request.path())) {
        return m_fallback->handle(std::move(request));
    }
    gateway::HttpResponse rejected{
        foundation::errorHttpStatus(foundation::ErrorCode::Unavailable),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(
            foundation::Error{foundation::ErrorCode::Unavailable},
            request.correlation().value())};
    rejected.setHeader("cache-control", "no-store");
    rejected.setHeader("x-content-type-options", "nosniff");
    return rejected;
}

asio::awaitable<gateway::HttpResponse>
CoroutineSessionListenerAdapter::handleAsync(gateway::HttpRequest request)
{
    co_return co_await m_handler->handleAsync(std::move(request));
}

CoroutineSessionListenerStack::CoroutineSessionListenerStack(
    CoroutinePostgresSessionService& sessions,
    gateway::TokenBucketRateLimiter& limiter,
    gateway::http::CoroutineHttpHandler& fallback,
    bool allowCompatibilityFallback)
    : m_application(
          sessions, limiter,
          [&fallback](gateway::HttpRequest request)
              -> asio::awaitable<gateway::HttpResponse> {
              // Native support may be revoked by a downstream capability
              // (for example, its async session issuer becoming unavailable).
              // Never call a disabled coroutine or its synchronous handler.
              if (!fallback.nativeEnabledFor(request)) {
                  gateway::HttpResponse unavailable{
                      foundation::errorHttpStatus(foundation::ErrorCode::Unavailable),
                      gateway::Headers{{"content-type", "application/json"}},
                      foundation::toClientJson(
                          foundation::Error{foundation::ErrorCode::Unavailable},
                          request.correlation().value())};
                  unavailable.setHeader("cache-control", "no-store");
                  unavailable.setHeader("x-content-type-options", "nosniff");
                  co_return unavailable;
              }
              co_return co_await fallback.handleAsync(std::move(request));
          }),
      m_network(m_application, fallback, allowCompatibilityFallback)
{
    // Keep the original fail-closed composition by default; only a caller
    // explicitly choosing a hybrid listener may provide a handler without
    // whole-handler native readiness.
    if (!allowCompatibilityFallback && !fallback.nativeEnabled()) {
        throw std::invalid_argument{
            "The coroutine session listener requires an enabled async fallback"};
    }
}

gateway::http::CoroutineHttpHandler&
CoroutineSessionListenerStack::handler() noexcept
{
    return m_network;
}

} // namespace openproof::storage::postgres

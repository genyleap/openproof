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
    CoroutineSessionHttpHandler& handler)
    : m_handler(&handler) {}

bool CoroutineSessionListenerAdapter::nativeEnabledFor(
    const gateway::HttpRequest& request) const noexcept
{
    // Force the listener down the coroutine entry even when a downstream
    // dependency's native capability is unavailable. The application-level
    // guard returns a sanitized 503; a disabled route must never fall back
    // to the Beast listener's bounded synchronous handler pool.
    (void)request;
    return true;
}

gateway::HttpResponse CoroutineSessionListenerAdapter::handle(
    gateway::HttpRequest request)
{
    // Never dispatch through a synchronous compatibility handler: not for
    // unknown paths, temporarily disabled providers, or session mutations.
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
    bool allowPartialNativeFallback)
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
      m_network(m_application)
{
    // Partial-native composition is permitted only by explicit opt-in, but
    // it never authorizes synchronous compatibility dispatch.
    if (!allowPartialNativeFallback && !fallback.nativeEnabled()) {
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

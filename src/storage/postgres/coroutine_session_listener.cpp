#include <boost/asio/awaitable.hpp>
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

gateway::HttpResponse CoroutineSessionListenerAdapter::handle(
    gateway::HttpRequest request)
{
    // Explicitly reject accidental non-coroutine dispatch, including auth
    // mutations: this is not a compatibility path to blocking SQL.
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
    gateway::http::CoroutineHttpHandler& fallback)
    : m_application(
          sessions, limiter,
          [&fallback](gateway::HttpRequest request)
              -> asio::awaitable<gateway::HttpResponse> {
              // Do not call the fallback's synchronous handle() method.
              co_return co_await fallback.handleAsync(std::move(request));
          }),
      m_network(m_application)
{
}

gateway::http::CoroutineHttpHandler&
CoroutineSessionListenerStack::handler() noexcept
{
    return m_network;
}

} // namespace openproof::storage::postgres

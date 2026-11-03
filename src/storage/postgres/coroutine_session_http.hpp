#pragma once
#include <boost/asio/awaitable.hpp>
#include <functional>
#include <string_view>
#include <utility>

#include "coroutine_session_service.hpp"

import openproof.gateway;

namespace openproof::storage::postgres {

/**
 * Transport-independent async HTTP session routes. The full network listener
 * adapter is pending; no synchronous fallback is permitted.
 * This component is NOT installed in the live application.
 */
class CoroutineSessionHttpHandler final {
public:
    using AsyncFallback = std::function<
        boost::asio::awaitable<gateway::HttpResponse>(gateway::HttpRequest)>;

    CoroutineSessionHttpHandler(CoroutinePostgresSessionService& sessions,
                                gateway::TokenBucketRateLimiter& limiter,
                                AsyncFallback fallback);

    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request);

    /** Shared route predicate for both native dispatch and compatibility.
     * Never let a synchronous handler receive one of these session mutations.
     */
    [[nodiscard]] static bool isSessionRoute(std::string_view path) noexcept;

private:
    CoroutinePostgresSessionService* m_sessions;
    gateway::TokenBucketRateLimiter* m_limiter;
    AsyncFallback m_fallback;
};

} // namespace openproof::storage::postgres

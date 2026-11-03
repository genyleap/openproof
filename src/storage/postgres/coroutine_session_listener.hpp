#pragma once

#include <boost/asio/awaitable.hpp>

#include "coroutine_session_http.hpp"

import openproof.gateway;
import openproof.gateway.http;

namespace openproof::storage::postgres {

/**
 * Opt-in adapter at the listener boundary. The live Beast server dispatches
 * this CoroutineHttpHandler through its existing native async path.
 *
 * The application fallback inside CoroutineSessionHttpHandler MUST itself
 * be awaitable for native requests. The synchronous HttpHandler method
 * rejects all session mutations and rejects all other routes by default.
 * Only an explicitly hybrid stack may run non-session compatibility
 * routes on the listener's bounded handler workers.
 *
 * The application handler, its rate limiter, session service, repository,
 * executor and fallback must outlive any request currently in flight.
 */
class CoroutineSessionListenerAdapter final
    : public gateway::http::CoroutineHttpHandler {
public:
    CoroutineSessionListenerAdapter(
        CoroutineSessionHttpHandler& handler,
        gateway::http::CoroutineHttpHandler& fallback,
        bool allowCompatibilityFallback);
    [[nodiscard]] bool nativeEnabled() const noexcept override { return true; }
    [[nodiscard]] bool nativeEnabledFor(
        const gateway::HttpRequest& request) const noexcept override;

    [[nodiscard]] gateway::HttpResponse
    handle(gateway::HttpRequest request) override;

    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request) override;

private:
    CoroutineSessionHttpHandler* m_handler;
    gateway::http::CoroutineHttpHandler* m_fallback;
    bool m_allowCompatibilityFallback{};
};

/** Owns both adapters in the correct destruction order so a live listener
 * cannot accidentally retain a pointer to a moved application handler.
 * The caller must stop and join Beast workers before destroying this object.
 * By default the non-session fallback must have whole-handler native
 * readiness; callers may explicitly opt into hybrid compatibility dispatch,
 * without ever exposing native session routes to synchronous storage.
 */
class CoroutineSessionListenerStack final {
public:
    CoroutineSessionListenerStack(
        CoroutinePostgresSessionService& sessions,
        gateway::TokenBucketRateLimiter& limiter,
        gateway::http::CoroutineHttpHandler& fallback,
        bool allowCompatibilityFallback = false);
    CoroutineSessionListenerStack(const CoroutineSessionListenerStack&) = delete;
    CoroutineSessionListenerStack& operator=(const CoroutineSessionListenerStack&) = delete;
    CoroutineSessionListenerStack(CoroutineSessionListenerStack&&) = delete;
    CoroutineSessionListenerStack& operator=(CoroutineSessionListenerStack&&) = delete;

    [[nodiscard]] gateway::http::CoroutineHttpHandler& handler() noexcept;

private:
    CoroutineSessionHttpHandler m_application;
    CoroutineSessionListenerAdapter m_network;
};

} // namespace openproof::storage::postgres

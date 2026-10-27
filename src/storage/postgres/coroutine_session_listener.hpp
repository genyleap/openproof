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
 * be awaitable. The synchronous HttpHandler method is deliberately fail-
 * closed and cannot silently invoke a blocking session repository.
 *
 * The application handler, its rate limiter, session service, repository,
 * executor and fallback must outlive any request currently in flight.
 */
class CoroutineSessionListenerAdapter final
    : public gateway::http::CoroutineHttpHandler {
public:
    explicit CoroutineSessionListenerAdapter(CoroutineSessionHttpHandler& handler);

    [[nodiscard]] gateway::HttpResponse
    handle(gateway::HttpRequest request) override;

    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request) override;

private:
    CoroutineSessionHttpHandler* m_handler;
};

/** Owns both adapters in the correct destruction order so a live listener
 * cannot accidentally retain a pointer to a moved application handler.
 * The caller must stop and join Beast workers before destroying this object.
 * The non-session fallback must already be a native CoroutineHttpHandler.
 */
class CoroutineSessionListenerStack final {
public:
    CoroutineSessionListenerStack(
        CoroutinePostgresSessionService& sessions,
        gateway::TokenBucketRateLimiter& limiter,
        gateway::http::CoroutineHttpHandler& fallback);
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

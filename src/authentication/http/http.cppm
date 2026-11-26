module;

#include <string>
#include <boost/asio/detail/call_stack.hpp>
#include "../../gateway/asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>

export module openproof.authentication.http;

import openproof.authentication;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.provider;
import openproof.session;

export namespace openproof::authentication::http {

/** HTTP auth plane mounted under /auth with a gateway fallback. */
class AuthenticationHttpApi final : public gateway::http::CoroutineHttpHandler {
public:
    // Runtime constructor: no synchronous credential, recovery or session
    // service is accepted. Other auth routes are mounted by native adapters.
    AuthenticationHttpApi(AuthenticationService& authentication,
                          session::CoroutineReplacingSessionIssuer& sessions,
                          gateway::TokenBucketRateLimiter& rateLimiter,
                          identity::provider::ProviderId provider,
                          gateway::HttpHandler& fallback);

    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;
    // This leaf owns only login/verify. Session mutations and recovery
    // are separately composed native handlers, not implicit capabilities.
    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }
    [[nodiscard]] bool nativeEnabledFor(
        const gateway::HttpRequest& request) const noexcept override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request) override;

private:
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    loginAsync(gateway::HttpRequest request);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    verifyAsync(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse error(const foundation::Error& failure,
                                              const gateway::HttpRequest& request,
                                              bool clearPreauth = false) const;

    AuthenticationService* m_authentication;
    session::CoroutineReplacingSessionIssuer* m_asyncSessions;
    gateway::TokenBucketRateLimiter* m_rateLimiter;
    identity::provider::ProviderId m_provider;
    gateway::HttpHandler* m_fallback;
};

}


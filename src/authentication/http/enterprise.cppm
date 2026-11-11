module;

#include <boost/asio/detail/call_stack.hpp>
#include "../../gateway/asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>

export module openproof.authentication.enterprise.http;

import openproof.authentication;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.provider;
import openproof.session;

export namespace openproof::authentication::http {

/** @brief Browser/API login surface for enterprise challenge-response providers such as LDAP. */
class EnterpriseAuthenticationHttpApi final : public gateway::http::CoroutineHttpHandler {
public:
    EnterpriseAuthenticationHttpApi(AuthenticationService& authentication,
                                    session::SessionService& sessions,
                                    gateway::TokenBucketRateLimiter& rateLimiter,
                                    gateway::HttpHandler& fallback,
                                    session::CoroutineReplacingSessionIssuer* asyncSessions = nullptr);

    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;
    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }
    [[nodiscard]] bool nativeEnabledFor(
        const gateway::HttpRequest& request) const noexcept override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request) override;

private:
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    startLdapAsync(gateway::HttpRequest request);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    completeLdapAsync(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse startLdap(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse completeLdap(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse error(const foundation::Error& failure,
                                              const gateway::HttpRequest& request,
                                              bool clearState = false) const;

    AuthenticationService* m_authentication;
    session::SessionService* m_sessions;
    session::CoroutineReplacingSessionIssuer* m_asyncSessions;
    gateway::TokenBucketRateLimiter* m_rateLimiter;
    gateway::HttpHandler* m_fallback;
};

} // namespace openproof::authentication::http

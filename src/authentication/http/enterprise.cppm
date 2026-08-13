module;

export module openproof.authentication.enterprise.http;

import openproof.authentication;
import openproof.foundation;
import openproof.gateway;
import openproof.identity.provider;
import openproof.session;

export namespace openproof::authentication::http {

/** @brief Browser/API login surface for enterprise challenge-response providers such as LDAP. */
class EnterpriseAuthenticationHttpApi final : public gateway::HttpHandler {
public:
    EnterpriseAuthenticationHttpApi(AuthenticationService& authentication,
                                    session::SessionService& sessions,
                                    gateway::TokenBucketRateLimiter& rateLimiter,
                                    gateway::HttpHandler& fallback);

    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;

private:
    [[nodiscard]] gateway::HttpResponse startLdap(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse completeLdap(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse error(const foundation::Error& failure,
                                              const gateway::HttpRequest& request,
                                              bool clearState = false) const;

    AuthenticationService* m_authentication;
    session::SessionService* m_sessions;
    gateway::TokenBucketRateLimiter* m_rateLimiter;
    gateway::HttpHandler* m_fallback;
};

} // namespace openproof::authentication::http

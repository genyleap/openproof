module;

#include <string>

export module openproof.authentication.federated.http;

import openproof.authentication;
import openproof.foundation;
import openproof.gateway;
import openproof.identity.provider;
import openproof.session;

export namespace openproof::authentication::http {

/** @brief Browser redirect authentication surface for registered redirect providers. */
class FederatedAuthenticationHttpApi final : public gateway::HttpHandler {
public:
    FederatedAuthenticationHttpApi(AuthenticationService& authentication,
                                   identity::provider::ProviderRegistry& providers,
                                   session::SessionService& sessions,
                                   gateway::TokenBucketRateLimiter& rateLimiter,
                                   gateway::HttpHandler& fallback);

    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;

private:
    [[nodiscard]] gateway::HttpResponse providers();
    [[nodiscard]] gateway::HttpResponse start(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse callback(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse error(const foundation::Error& failure,
                                              const gateway::HttpRequest& request,
                                              bool clearState = false) const;

    AuthenticationService* m_authentication;
    identity::provider::ProviderRegistry* m_providers;
    session::SessionService* m_sessions;
    gateway::TokenBucketRateLimiter* m_rateLimiter;
    gateway::HttpHandler* m_fallback;
};

} // namespace openproof::authentication::http

module;

export module openproof.authentication.web3.http;

import openproof.authentication;
import openproof.foundation;
import openproof.gateway;
import openproof.identity.provider;
import openproof.session;

export namespace openproof::authentication::http {

/** @brief Same-origin SIWE challenge/response surface for Ethereum and Farcaster login. */
class Web3AuthenticationHttpApi final : public gateway::HttpHandler {
public:
    Web3AuthenticationHttpApi(AuthenticationService& authentication,
                              identity::provider::ProviderRegistry& providers,
                              session::SessionService& sessions,
                              gateway::TokenBucketRateLimiter& rateLimiter,
                              gateway::HttpHandler& fallback);

    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;

private:
    [[nodiscard]] gateway::HttpResponse start(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse complete(gateway::HttpRequest request);
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

module;

#include <string>

export module openproof.authentication.http;

import openproof.authentication;
import openproof.credentials;
import openproof.foundation;
import openproof.gateway;
import openproof.identity.provider;
import openproof.session;

export namespace openproof::authentication::http {

/** HTTP auth plane mounted under /auth with a gateway fallback. */
class AuthenticationHttpApi final : public gateway::HttpHandler {
public:
    AuthenticationHttpApi(AuthenticationService& authentication,
                          session::SessionService& sessions,
                          credentials::RecoveryCodeService& recoveryCodes,
                          gateway::TokenBucketRateLimiter& rateLimiter,
                          identity::provider::ProviderId provider,
                          gateway::HttpHandler& fallback);

    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;

private:
    [[nodiscard]] gateway::HttpResponse login(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse verify(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse rotate(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse logout(gateway::HttpRequest request, bool all);
    [[nodiscard]] gateway::HttpResponse issueRecoveryCodes(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse error(const foundation::Error& failure,
                                              const gateway::HttpRequest& request,
                                              bool clearPreauth = false) const;

    AuthenticationService* m_authentication;
    session::SessionService* m_sessions;
    credentials::RecoveryCodeService* m_recoveryCodes;
    gateway::TokenBucketRateLimiter* m_rateLimiter;
    identity::provider::ProviderId m_provider;
    gateway::HttpHandler* m_fallback;
};

}


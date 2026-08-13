module;

#include <string>

export module openproof.authentication.passkey.http;

import openproof.authentication;
import openproof.foundation;
import openproof.gateway;
import openproof.identity.provider;
import openproof.provider.passkey;
import openproof.session;

export namespace openproof::authentication::http {

/** @brief Browser WebAuthn registration and assertion HTTP surface. */
class PasskeyAuthenticationHttpApi final : public gateway::HttpHandler {
public:
    PasskeyAuthenticationHttpApi(::openproof::provider::passkey::PasskeyService& passkeys,
                                 AuthenticationService& authentication,
                                 session::SessionService& sessions,
                                 gateway::TokenBucketRateLimiter& rateLimiter,
                                 gateway::HttpHandler& fallback);

    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;

private:
    [[nodiscard]] gateway::HttpResponse registrationOptions(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse registerCredential(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse listCredentials(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse removeCredential(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse assertionOptions(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse verifyAssertion(gateway::HttpRequest request);

    ::openproof::provider::passkey::PasskeyService* m_passkeys;
    AuthenticationService* m_authentication;
    session::SessionService* m_sessions;
    gateway::TokenBucketRateLimiter* m_rateLimiter;
    gateway::HttpHandler* m_fallback;
};

} // namespace openproof::authentication::http

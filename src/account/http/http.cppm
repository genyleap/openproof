module;

#include <optional>
#include <string>

export module openproof.account.http;

import openproof.account;
import openproof.authentication;
import openproof.foundation;
import openproof.gateway;
import openproof.identity.core;
import openproof.identity.profile;
import openproof.identity.provider;
import openproof.session;

export namespace openproof::account::http {

/** @brief Public account lifecycle and authenticated self-service HTTP plane. */
class AccountHttpApi final : public gateway::HttpHandler {
public:
    AccountHttpApi(AccountService& accounts, authentication::AuthenticationService& authentication,
                   session::SessionService& sessions,
                   gateway::TokenBucketRateLimiter& limiter,
                   gateway::HttpHandler& fallback,
                   session::DelegatedAccessAuthenticator* delegated = nullptr);

    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;

private:
    [[nodiscard]] foundation::Result<session::AuthenticatedSession>
    authenticate(gateway::HttpRequest& request) const;
    [[nodiscard]] foundation::Result<identity::core::IdentityId>
    authorize(gateway::HttpRequest& request) const;
    [[nodiscard]] gateway::HttpResponse signup(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse verifyEmail(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse resendEmail(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse beginEmailChange(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse completeEmailChange(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse beginPhone(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse completePhone(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse forgotPassword(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse resetPassword(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse totpStatus(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse beginTotpEnrollment(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse completeTotpEnrollment(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse disableTotp(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse getProfile(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse updateProfile(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse connections(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse disconnect(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse sessions(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse revokeSession(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse error(const foundation::Error& failure,
                                               const gateway::HttpRequest& request) const;

    AccountService* m_accounts;
    authentication::AuthenticationService* m_authentication;
    session::SessionService* m_sessions;
    session::DelegatedAccessAuthenticator* m_delegated;
    gateway::TokenBucketRateLimiter* m_limiter;
    gateway::HttpHandler* m_fallback;
};

}

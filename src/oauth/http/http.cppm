module;

#include <string>

export module openproof.oauth.http;

export import openproof.oauth.http.sender;

import openproof.authentication;
import openproof.client;
import openproof.consent;
import openproof.foundation;
import openproof.gateway;
import openproof.identity.provider;
import openproof.oauth;
import openproof.oidc;
import openproof.resource;
import openproof.session;
import openproof.token;

export namespace openproof::oauth::http {

/** @brief Browser SSO and OAuth/OIDC protocol HTTP surface. */
class OAuthHttpApi final : public gateway::HttpHandler {
public:
    OAuthHttpApi(AuthorizationService& authorization, token::TokenService& tokens,
                 oidc::OpenIdProvider& oidc, client::ClientManager& clients,
                 authentication::AuthenticationService& authentication,
                 session::SessionService& sessions,
                 identity::provider::ProviderId localProvider,
                 consent::ConsentService& consents,
                 resource::ResourceRegistry& resources,
                 resource::ServiceIdentityService& serviceIdentities,
                 DeviceAuthorizationService& devices,
                 PushedAuthorizationService& pushedAuthorization,
                 JarService& jar,
                 SenderProofVerifier& senderProof,
                 gateway::TokenBucketRateLimiter& limiter,
                 gateway::HttpHandler& fallback);

    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;

private:
    [[nodiscard]] gateway::HttpResponse authorize(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse tokenEndpoint(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse pushedAuthorization(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse deviceAuthorization(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse deviceVerification(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse consentSubmit(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse consents(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse revokeConsent(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse userInfo(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse introspect(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse revoke(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse loginPage(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse loginSubmit(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse error(const foundation::Error& failure,
                                               const gateway::HttpRequest& request) const;

    AuthorizationService* m_authorization;
    token::TokenService* m_tokens;
    oidc::OpenIdProvider* m_oidc;
    client::ClientManager* m_clients;
    authentication::AuthenticationService* m_authentication;
    session::SessionService* m_sessions;
    identity::provider::ProviderId m_localProvider;
    consent::ConsentService* m_consents;
    resource::ResourceRegistry* m_resources;
    resource::ServiceIdentityService* m_serviceIdentities;
    DeviceAuthorizationService* m_devices;
    PushedAuthorizationService* m_pushedAuthorization;
    JarService* m_jar;
    SenderProofVerifier* m_senderProof;
    gateway::TokenBucketRateLimiter* m_limiter;
    gateway::HttpHandler* m_fallback;
};

}

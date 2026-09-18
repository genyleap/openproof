module;

#include <string>
#include <string_view>

export module openproof.application.http;

import openproof.application;
import openproof.client;
import openproof.foundation;
import openproof.gateway;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.organization;
import openproof.oauth;
import openproof.resource;
import openproof.session;

export namespace openproof::application::http {

/**
 * @brief Owner-only application and OAuth client management plane.
 *
 * Secrets returned by client registration or rotation are emitted exactly once
 * and only after durable persistence succeeds.
 */
class ApplicationManagementHttpApi final : public gateway::HttpHandler {
public:
    ApplicationManagementHttpApi(
        ApplicationRegistry& applications,
        ApplicationRepository& applicationRepository,
        client::ClientManager& clients,
        client::ClientRepository& clientRepository,
        resource::ResourceRegistry& resources,
        resource::ServiceIdentityService& serviceIdentities,
        oauth::JarService& jar,
        session::SessionService& sessions,
        organization::MembershipRepository& memberships,
        gateway::TokenBucketRateLimiter& limiter,
        identity::core::OrganizationId organization,
        gateway::HttpHandler& fallback);

    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;

private:
    [[nodiscard]] foundation::Result<identity::core::IdentityId> authorize(gateway::HttpRequest& request) const;
    [[nodiscard]] gateway::HttpResponse consolePage(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse listApplications(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse createApplication(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse changeApplication(gateway::HttpRequest request, std::string_view action);
    [[nodiscard]] gateway::HttpResponse listClients(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse createClient(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse rotateClientSecret(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse changeClient(gateway::HttpRequest request, std::string_view action);
    [[nodiscard]] gateway::HttpResponse jarKey(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse registerJarKey(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse removeJarKey(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse listResources(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse createResource(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse changeResource(gateway::HttpRequest request, std::string_view action);
    [[nodiscard]] gateway::HttpResponse provisionServiceIdentity(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse serviceIdentity(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse changeServiceIdentity(gateway::HttpRequest request, bool active);
    [[nodiscard]] gateway::HttpResponse error(const foundation::Error& failure,const gateway::HttpRequest& request) const;

    ApplicationRegistry* m_applications;
    ApplicationRepository* m_applicationRepository;
    client::ClientManager* m_clients;
    client::ClientRepository* m_clientRepository;
    resource::ResourceRegistry* m_resources;
    resource::ServiceIdentityService* m_serviceIdentities;
    oauth::JarService* m_jar;
    session::SessionService* m_sessions;
    organization::MembershipRepository* m_memberships;
    gateway::TokenBucketRateLimiter* m_limiter;
    identity::core::OrganizationId m_organization;
    gateway::HttpHandler* m_fallback;
};

}

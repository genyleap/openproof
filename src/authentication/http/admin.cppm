module;

#include <string>

export module openproof.administration.http;

import openproof.administration;
import openproof.foundation;
import openproof.gateway;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.session;

export namespace openproof::administration::http {

/** Owner-only administrative HTTP plane mounted under `/admin`. */
class AdministrationHttpApi final : public gateway::HttpHandler {
public:
    AdministrationHttpApi(
        session::SessionService& sessions,
        LocalMemberProvisioner& members,
        gateway::TokenBucketRateLimiter& rateLimiter,
        identity::core::OrganizationId organization,
        identity::provider::ProviderId provider,
        const foundation::ClockSource& clock,
        gateway::HttpHandler& fallback);

    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;

private:
    [[nodiscard]] gateway::HttpResponse createLocalMember(
        gateway::HttpRequest request,
        const identity::core::IdentityId& actor);
    [[nodiscard]] gateway::HttpResponse error(
        const foundation::Error& failure,
        const gateway::HttpRequest& request) const;

    session::SessionService* m_sessions;
    LocalMemberProvisioner* m_members;
    gateway::TokenBucketRateLimiter* m_rateLimiter;
    identity::core::OrganizationId m_organization;
    identity::provider::ProviderId m_provider;
    const foundation::ClockSource* m_clock;
    gateway::HttpHandler* m_fallback;
};

}

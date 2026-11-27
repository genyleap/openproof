module;

#include <string>

export module openproof.administration.http;

import openproof.administration;
import openproof.foundation;
import openproof.gateway;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.organization;
import openproof.session;

export namespace openproof::administration::http {
/** Retired synchronous administrative HTTP ABI. All /admin requests deny
 *  without reading or mutating storage; use the native coroutine adapter.
 */
class AdministrationHttpApi final : public gateway::HttpHandler {
public:
    AdministrationHttpApi(
        session::SessionService& sessions,
        LocalMemberAdministrator& members,
        identity::core::IdentityRepository& identities,
        organization::MembershipRepository& memberships,
        gateway::TokenBucketRateLimiter& rateLimiter,
        identity::core::OrganizationId organization,
        identity::provider::ProviderId provider,
        const foundation::ClockSource& clock,
        gateway::HttpHandler& fallback);
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;
private:
    gateway::TokenBucketRateLimiter* m_rateLimiter;
    gateway::HttpHandler* m_fallback;
};
}

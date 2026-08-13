module;

#include <set>
#include <string>
#include <vector>

export module openproof.evidence.http;

import openproof.evidence;
import openproof.evidence.verifiers;
import openproof.foundation;
import openproof.gateway;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.session;
import openproof.trust;

export namespace openproof::evidence::http {

/** @brief Authenticated self-service surface for evidence verification and current trust assessment. */
class Api final : public gateway::HttpHandler {
public:
    Api(EvidenceService& evidence, EvidenceRepository& repository,
        verification::ChallengeService& challenges, trust::TrustEngine& trust,
        session::SessionService& sessions, std::set<std::string, std::less<>> providers,
        gateway::TokenBucketRateLimiter& limiter, gateway::HttpHandler& fallback);

    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;

private:
    [[nodiscard]] foundation::Result<identity::core::IdentityId>
    authorize(gateway::HttpRequest& request) const;
    [[nodiscard]] gateway::HttpResponse issueChallenge(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse verify(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse list(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse assess(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse error(const foundation::Error& failure,
                                              const gateway::HttpRequest& request) const;

    EvidenceService* m_evidence;
    EvidenceRepository* m_repository;
    verification::ChallengeService* m_challenges;
    trust::TrustEngine* m_trust;
    session::SessionService* m_sessions;
    std::set<std::string, std::less<>> m_providers;
    gateway::TokenBucketRateLimiter* m_limiter;
    gateway::HttpHandler* m_fallback;
};

} // namespace openproof::evidence::http

module;

#include <map>
#include <string>
#include <string_view>
#include <vector>

export module openproof.trust:engine;

import openproof.evidence;
import openproof.foundation;
import openproof.identity.core;
import :model;

export namespace openproof::trust {

/** @brief Weight configuration for evidence kinds used by the trust engine. */
class TrustPolicy final {
public:
    [[nodiscard]] foundation::Status
    setWeight(std::string evidenceKind, unsigned int weight);

    [[nodiscard]] unsigned int weight(std::string_view evidenceKind) const noexcept;

private:
    std::map<std::string, unsigned int, std::less<>> m_weights;
};

/**
 * @brief Computes current trust from active evidence and normalized risk input.
 *
 * No assessment is persisted by this component. Every call observes evidence
 * revocation and expiry against one clock snapshot.
 */
class TrustEngine final {
public:
    TrustEngine(evidence::EvidenceRepository& evidence,
                const foundation::ClockSource& clock, TrustPolicy policy);

    [[nodiscard]] foundation::Result<TrustAssessment>
    assess(const identity::core::IdentityId& identity,
           std::vector<RiskSignal> risks = {}) const;

private:
    evidence::EvidenceRepository* m_evidence;
    const foundation::ClockSource* m_clock;
    TrustPolicy m_policy;
};

} // namespace openproof::trust

module;

#include <map>
#include <memory>
#include <vector>

export module openproof.evidence:service;

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import :model;
import :repository;

export namespace openproof::evidence {

/** @brief Registry and persistence boundary for external evidence verifiers. */
class EvidenceService final {
public:
    EvidenceService(EvidenceRepository& repository,
                    const foundation::ClockSource& clock);

    [[nodiscard]] foundation::Status
    registerVerifier(std::unique_ptr<EvidenceVerifier> verifier);

    /**
     * @brief Verifies provider material and atomically persists its evidence set.
     *
     * Returned evidence is accepted only when every record is bound to the
     * requested canonical identity and to the verifier's own provider id.
     */
    [[nodiscard]] foundation::Result<std::vector<Evidence>> verify(
        const identity::core::IdentityId& identity,
        const identity::provider::ProviderId& provider,
        const identity::provider::AttributeMap& publicInputs,
        const identity::provider::SecretAttributeMap& secretInputs);

private:
    EvidenceRepository* m_repository;
    const foundation::ClockSource* m_clock;
    std::map<identity::provider::ProviderId, std::unique_ptr<EvidenceVerifier>> m_verifiers;
};

} // namespace openproof::evidence

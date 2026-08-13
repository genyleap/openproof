module;

#include <memory>
#include <utility>
#include <vector>

module openproof.evidence;

namespace openproof::evidence {

EvidenceService::EvidenceService(EvidenceRepository& repository,
                                 const foundation::ClockSource& clock)
    : m_repository(&repository), m_clock(&clock)
{
}

foundation::Status EvidenceService::registerVerifier(
    std::unique_ptr<EvidenceVerifier> verifier)
{
    if (!verifier) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An evidence verifier is required.");
    }
    const auto provider = verifier->provider();
    if (provider.empty() || m_verifiers.contains(provider)) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The evidence verifier is already registered.");
    }
    m_verifiers.emplace(provider, std::move(verifier));
    return foundation::ok();
}

foundation::Result<std::vector<Evidence>> EvidenceService::verify(
    const identity::core::IdentityId& identity,
    const identity::provider::ProviderId& provider,
    const identity::provider::AttributeMap& publicInputs,
    const identity::provider::SecretAttributeMap& secretInputs)
{
    if (identity.empty() || provider.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    const auto found = m_verifiers.find(provider);
    if (found == m_verifiers.end()) {
        return foundation::fail(foundation::ErrorCode::NotFound,
                                "The evidence verifier is unavailable.");
    }
    auto verified = found->second->verify(
        identity, publicInputs, secretInputs, m_clock->now());
    if (!verified) return foundation::fail(verified.error());
    if (verified->empty()) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The verifier produced no evidence.");
    }
    for (const auto& item : verified.value()) {
        if (item.identity() != identity || item.provider() != provider) {
            return foundation::fail(foundation::ErrorCode::PermissionDenied,
                                    "The verifier returned evidence outside its authority.");
        }
    }
    auto persisted = m_repository->addBatch(verified.value());
    if (!persisted) return foundation::fail(persisted.error());
    return verified;
}

} // namespace openproof::evidence

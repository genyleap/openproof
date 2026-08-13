module;

#include <algorithm>
#include <cstdint>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.trust;

namespace openproof::trust {
namespace {

[[nodiscard]] bool validEvidenceKind(std::string_view value) noexcept {
    if (value.empty() || value.size() > 128U) {
        return false;
    }

    return std::ranges::none_of(value, [](char character) {
        const auto byte = static_cast<unsigned char>(character);
        return byte < 0x20U || byte == 0x7FU;
    });
}

} // namespace

foundation::Status TrustPolicy::setWeight(std::string kind,
                                          unsigned int weight) {
    if (!validEvidenceKind(kind) || weight > 100U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The trust weight is invalid.");
    }

    m_weights.insert_or_assign(std::move(kind), weight);
    return foundation::ok();
}

unsigned int TrustPolicy::weight(std::string_view kind) const noexcept {
    const auto found = m_weights.find(kind);
    return found == m_weights.end() ? 0U : found->second;
}

TrustEngine::TrustEngine(evidence::EvidenceRepository& evidence,
                         const foundation::ClockSource& clock,
                         TrustPolicy policy)
    : m_evidence(&evidence), m_clock(&clock), m_policy(std::move(policy)) {}

foundation::Result<TrustAssessment> TrustEngine::assess(
    const identity::core::IdentityId& identity,
    std::vector<RiskSignal> risks) const {
    if (identity.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }

    auto records = m_evidence->forIdentity(identity);
    if (!records) {
        return foundation::fail(records.error());
    }

    const auto now = m_clock->now();
    std::uint64_t weightedConfidence = 0U;
    std::uint64_t totalWeight = 0U;
    std::uint64_t confidenceTotal = 0U;
    std::uint64_t evidenceCount = 0U;
    std::vector<std::string> evidenceIds;

    for (const auto& record : records.value()) {
        if (!record.activeAt(now)) {
            continue;
        }

        const auto evidenceWeight = m_policy.weight(record.kind());
        if (evidenceWeight == 0U) {
            continue;
        }

        weightedConfidence +=
            static_cast<std::uint64_t>(evidenceWeight) * record.confidence();
        totalWeight += evidenceWeight;
        confidenceTotal += record.confidence();
        ++evidenceCount;
        evidenceIds.emplace_back(record.id().value());
    }

    auto trustScore = totalWeight == 0U
                          ? 0U
                          : static_cast<unsigned int>(weightedConfidence /
                                                      totalWeight);
    const auto confidence = evidenceCount == 0U
                                ? 0U
                                : static_cast<unsigned int>(confidenceTotal /
                                                            evidenceCount);

    unsigned int riskScore = 0U;
    for (const auto& risk : risks) {
        riskScore = std::max(riskScore, risk.severity());
    }

    trustScore = trustScore > riskScore ? trustScore - riskScore : 0U;
    return TrustAssessment::create(identity, trustScore, riskScore, confidence,
                                   std::move(evidenceIds), std::move(risks));
}

} // namespace openproof::trust

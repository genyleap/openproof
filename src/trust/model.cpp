module;

#include <algorithm>
#include <memory>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.trust;

namespace openproof::trust {
namespace {

[[nodiscard]] bool hasControlCharacter(std::string_view value) noexcept {
    return std::ranges::any_of(value, [](char character) {
        const auto byte = static_cast<unsigned char>(character);
        return byte < 0x20U || byte == 0x7FU;
    });
}

[[nodiscard]] bool validEvidenceId(std::string_view value) noexcept {
    return !value.empty() && value.size() <= 256U &&
           !hasControlCharacter(value);
}

} // namespace

RiskSignal::RiskSignal(std::string kind, unsigned int severity,
                       std::string reason)
    : m_kind(std::move(kind)),
      m_severity(severity),
      m_reason(std::move(reason)) {}

foundation::Result<RiskSignal>
RiskSignal::create(std::string kind, unsigned int severity,
                   std::string reason) {
    if (kind.empty() || kind.size() > 128U || hasControlCharacter(kind) ||
        severity > 100U || reason.empty() || reason.size() > 1024U ||
        hasControlCharacter(reason)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The risk signal is invalid.");
    }

    return RiskSignal{std::move(kind), severity, std::move(reason)};
}

std::string_view RiskSignal::kind() const noexcept {
    return m_kind;
}

unsigned int RiskSignal::severity() const noexcept {
    return m_severity;
}

std::string_view RiskSignal::reason() const noexcept {
    return m_reason;
}

struct TrustAssessment::StateData final {
    identity::core::IdentityId identity;
    unsigned int trustScore{};
    unsigned int riskScore{};
    unsigned int confidence{};
    std::vector<std::string> evidenceIds;
    std::vector<RiskSignal> risks;
};

TrustAssessment::TrustAssessment(identity::core::IdentityId identity,
                                 unsigned int trustScore,
                                 unsigned int riskScore,
                                 unsigned int confidence,
                                 std::vector<std::string> evidenceIds,
                                 std::vector<RiskSignal> risks)
    : m_data(std::make_shared<StateData>(StateData{
          .identity = std::move(identity), .trustScore = trustScore,
          .riskScore = riskScore, .confidence = confidence,
          .evidenceIds = std::move(evidenceIds), .risks = std::move(risks)}))
{
}

foundation::Result<TrustAssessment> TrustAssessment::create(
    identity::core::IdentityId identity, unsigned int trustScore,
    unsigned int riskScore, unsigned int confidence,
    std::vector<std::string> evidenceIds, std::vector<RiskSignal> risks) {
    if (identity.empty() || trustScore > 100U || riskScore > 100U ||
        confidence > 100U ||
        !std::ranges::all_of(evidenceIds, validEvidenceId)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The trust assessment is invalid.");
    }

    std::ranges::sort(evidenceIds);
    if (std::ranges::adjacent_find(evidenceIds) != evidenceIds.end()) {
        return foundation::fail(foundation::ErrorCode::Conflict,
                                "The trust assessment contains duplicate evidence.");
    }

    return TrustAssessment{std::move(identity), trustScore, riskScore,
                           confidence, std::move(evidenceIds),
                           std::move(risks)};
}

const identity::core::IdentityId& TrustAssessment::identity() const noexcept { return m_data->identity; }
unsigned int TrustAssessment::trustScore() const noexcept { return m_data->trustScore; }
unsigned int TrustAssessment::riskScore() const noexcept { return m_data->riskScore; }
unsigned int TrustAssessment::confidence() const noexcept { return m_data->confidence; }
const std::vector<std::string>& TrustAssessment::evidenceIds() const noexcept { return m_data->evidenceIds; }
const std::vector<RiskSignal>& TrustAssessment::risks() const noexcept { return m_data->risks; }

} // namespace openproof::trust

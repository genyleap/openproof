module;

#include <memory>
#include <string>
#include <string_view>
#include <vector>

export module openproof.trust:model;

import openproof.foundation;
import openproof.identity.core;

export namespace openproof::trust {

/**
 * @brief A normalized risk signal that can reduce an identity trust score.
 *
 * Severity is expressed on a closed 0..100 scale. Kind and reason are
 * untrusted boundary data and are validated before the signal is accepted.
 */
class RiskSignal final {
public:
    [[nodiscard]] static foundation::Result<RiskSignal>
    create(std::string kind, unsigned int severity, std::string reason);

    [[nodiscard]] std::string_view kind() const noexcept;
    [[nodiscard]] unsigned int severity() const noexcept;
    [[nodiscard]] std::string_view reason() const noexcept;

private:
    RiskSignal(std::string kind, unsigned int severity, std::string reason);

    std::string m_kind;
    unsigned int m_severity{};
    std::string m_reason;
};

/**
 * @brief Derived trust state for one canonical OpenProof identity.
 *
 * Assessments are intentionally not durable truth. They are recomputed from
 * currently active evidence and the current trust/risk policy so revocation or
 * expiry is reflected immediately.
 */
class TrustAssessment final {
public:
    [[nodiscard]] static foundation::Result<TrustAssessment>
    create(identity::core::IdentityId identity, unsigned int trustScore,
           unsigned int riskScore, unsigned int confidence,
           std::vector<std::string> evidenceIds,
           std::vector<RiskSignal> risks);

    [[nodiscard]] const identity::core::IdentityId& identity() const noexcept;
    [[nodiscard]] unsigned int trustScore() const noexcept;
    [[nodiscard]] unsigned int riskScore() const noexcept;
    [[nodiscard]] unsigned int confidence() const noexcept;
    [[nodiscard]] const std::vector<std::string>& evidenceIds() const noexcept;
    [[nodiscard]] const std::vector<RiskSignal>& risks() const noexcept;

private:
    TrustAssessment(identity::core::IdentityId identity,
                    unsigned int trustScore, unsigned int riskScore,
                    unsigned int confidence,
                    std::vector<std::string> evidenceIds,
                    std::vector<RiskSignal> risks);

    struct StateData;
    std::shared_ptr<const StateData> m_data;
};

} // namespace openproof::trust

module;

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.evidence:model;

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

export namespace openproof::evidence {

struct EvidenceIdTag {};
using EvidenceId = foundation::StrongId<EvidenceIdTag>;

enum class EvidenceStatus {
    Verified,
    Revoked,
};

/** @brief Provider-verified fact attached to a canonical OpenProof identity. */
class Evidence final {
public:
    [[nodiscard]] static foundation::Result<Evidence> create(
        EvidenceId id, identity::core::IdentityId identity,
        identity::provider::ProviderId provider, std::string kind,
        std::string claim, std::string value, unsigned int confidence,
        foundation::Instant verifiedAt,
        std::optional<foundation::Instant> expiresAt = std::nullopt);

    /** @brief Restores a previously validated durable evidence record. */
    [[nodiscard]] static foundation::Result<Evidence> restore(
        EvidenceId id, identity::core::IdentityId identity,
        identity::provider::ProviderId provider, std::string kind,
        std::string claim, std::string value, unsigned int confidence,
        EvidenceStatus status, foundation::Instant verifiedAt,
        std::optional<foundation::Instant> expiresAt = std::nullopt);

    [[nodiscard]] const EvidenceId& id() const noexcept;
    [[nodiscard]] const identity::core::IdentityId& identity() const noexcept;
    [[nodiscard]] const identity::provider::ProviderId& provider() const noexcept;
    [[nodiscard]] std::string_view kind() const noexcept;
    [[nodiscard]] std::string_view claim() const noexcept;
    [[nodiscard]] std::string_view value() const noexcept;
    [[nodiscard]] unsigned int confidence() const noexcept;
    [[nodiscard]] EvidenceStatus status() const noexcept;
    [[nodiscard]] foundation::Instant verifiedAt() const noexcept;
    [[nodiscard]] const std::optional<foundation::Instant>& expiresAt() const noexcept;
    [[nodiscard]] bool activeAt(foundation::Instant now) const noexcept;
    [[nodiscard]] foundation::Status revoke() noexcept;

private:
    Evidence(EvidenceId id, identity::core::IdentityId identity,
             identity::provider::ProviderId provider, std::string kind,
             std::string claim, std::string value, unsigned int confidence,
             EvidenceStatus status, foundation::Instant verifiedAt,
             std::optional<foundation::Instant> expiresAt);

    struct StateData;
    std::shared_ptr<StateData> m_data;
    void detach();
};

/** @brief Extension point that converts external proof material into verified evidence. */
class EvidenceVerifier {
public:
    EvidenceVerifier(const EvidenceVerifier&) = delete;
    EvidenceVerifier& operator=(const EvidenceVerifier&) = delete;
    virtual ~EvidenceVerifier() = default;

    [[nodiscard]] virtual identity::provider::ProviderId provider() const = 0;
    [[nodiscard]] virtual foundation::Result<std::vector<Evidence>> verify(
        const identity::core::IdentityId& identity,
        const identity::provider::AttributeMap& publicInputs,
        const identity::provider::SecretAttributeMap& secretInputs,
        foundation::Instant now) = 0;

protected:
    EvidenceVerifier() = default;
};

} // namespace openproof::evidence

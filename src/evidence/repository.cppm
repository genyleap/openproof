module;

#include <memory>
#include <optional>
#include <vector>

export module openproof.evidence:repository;

import openproof.foundation;
import openproof.identity.core;
import :model;

export namespace openproof::evidence {

class EvidenceRepository {
public:
    EvidenceRepository(const EvidenceRepository&) = delete;
    EvidenceRepository& operator=(const EvidenceRepository&) = delete;
    virtual ~EvidenceRepository() = default;

    [[nodiscard]] virtual foundation::Status add(Evidence evidence) = 0;
    /** @brief Atomically persists one verifier result set. */
    [[nodiscard]] virtual foundation::Status addBatch(std::vector<Evidence> evidence) = 0;
    [[nodiscard]] virtual foundation::Status revoke(const EvidenceId& id) = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<Evidence>>
    find(const EvidenceId& id) const = 0;
    [[nodiscard]] virtual foundation::Result<std::vector<Evidence>>
    forIdentity(const identity::core::IdentityId& identity) const = 0;

protected:
    EvidenceRepository() = default;
};

class InMemoryEvidenceRepository final : public EvidenceRepository {
public:
    InMemoryEvidenceRepository();
    ~InMemoryEvidenceRepository() override;
    InMemoryEvidenceRepository(const InMemoryEvidenceRepository&) = delete;
    InMemoryEvidenceRepository& operator=(const InMemoryEvidenceRepository&) = delete;
    InMemoryEvidenceRepository(InMemoryEvidenceRepository&&) = delete;
    InMemoryEvidenceRepository& operator=(InMemoryEvidenceRepository&&) = delete;

    [[nodiscard]] foundation::Status add(Evidence evidence) override;
    [[nodiscard]] foundation::Status addBatch(std::vector<Evidence> evidence) override;
    [[nodiscard]] foundation::Status revoke(const EvidenceId& id) override;
    [[nodiscard]] foundation::Result<std::optional<Evidence>>
    find(const EvidenceId& id) const override;
    [[nodiscard]] foundation::Result<std::vector<Evidence>>
    forIdentity(const identity::core::IdentityId& identity) const override;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace openproof::evidence

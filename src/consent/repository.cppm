module;

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

export module openproof.consent:repository;

import openproof.client;
import openproof.foundation;
import openproof.identity.core;
import :model;

export namespace openproof::consent {

class ConsentRepository {
public:
    ConsentRepository(const ConsentRepository&) = delete;
    ConsentRepository& operator=(const ConsentRepository&) = delete;
    virtual ~ConsentRepository() = default;

    [[nodiscard]] virtual foundation::Status save(ConsentGrant grant) = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<ConsentGrant>> findActive(
        const identity::core::IdentityId& identity,
        const client::ClientId& client,
        std::string_view audience,
        foundation::Instant now) const = 0;
    [[nodiscard]] virtual foundation::Result<std::vector<ConsentGrant>> list(
        const identity::core::IdentityId& identity) const = 0;
    [[nodiscard]] virtual foundation::Status revoke(
        const ConsentId& id,
        const identity::core::IdentityId& identity,
        foundation::Instant now) = 0;

protected:
    ConsentRepository() = default;
};

class InMemoryConsentRepository final : public ConsentRepository {
public:
    InMemoryConsentRepository();
    ~InMemoryConsentRepository() override;

    [[nodiscard]] foundation::Status save(ConsentGrant grant) override;
    [[nodiscard]] foundation::Result<std::optional<ConsentGrant>> findActive(
        const identity::core::IdentityId& identity,
        const client::ClientId& client,
        std::string_view audience,
        foundation::Instant now) const override;
    [[nodiscard]] foundation::Result<std::vector<ConsentGrant>> list(
        const identity::core::IdentityId& identity) const override;
    [[nodiscard]] foundation::Status revoke(
        const ConsentId& id,
        const identity::core::IdentityId& identity,
        foundation::Instant now) override;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace openproof::consent

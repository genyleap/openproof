module;

#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.consent:service;

import openproof.client;
import openproof.foundation;
import openproof.identity.core;
import :model;
import :repository;

export namespace openproof::consent {

class ConsentService final {
public:
    ConsentService(
        ConsentRepository& repository,
        const foundation::ClockSource& clock);

    [[nodiscard]] foundation::Result<bool> covers(
        const identity::core::IdentityId& identity,
        const client::ClientId& client,
        std::string_view audience,
        const std::vector<std::string>& scopes) const;
    [[nodiscard]] foundation::Result<ConsentGrant> grant(
        const identity::core::IdentityId& identity,
        const client::ClientId& client,
        std::string audience,
        std::vector<std::string> scopes,
        std::optional<foundation::Duration> lifetime = std::nullopt);
    [[nodiscard]] foundation::Result<std::vector<ConsentGrant>> list(
        const identity::core::IdentityId& identity) const;
    [[nodiscard]] bool active(const ConsentGrant& grant) const noexcept;
    [[nodiscard]] foundation::Status revoke(
        const ConsentId& id,
        const identity::core::IdentityId& identity);

private:
    ConsentRepository* m_repository;
    const foundation::ClockSource* m_clock;
};

} // namespace openproof::consent

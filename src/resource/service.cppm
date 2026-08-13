module;

#include <string>
#include <string_view>
#include <vector>

export module openproof.resource:service;

import openproof.client;
import openproof.foundation;
import openproof.identity.core;
import :model;
import :repository;

export namespace openproof::resource {

/** @brief Validates resource/audience boundaries for delegated and machine grants. */
class ResourceRegistry final {
public:
    ResourceRegistry(ResourceRepository& repository, const foundation::ClockSource& clock);
    [[nodiscard]] foundation::Result<ResourceServer> registerResource(
        std::string audience, std::string displayName, std::vector<std::string> scopes);
    [[nodiscard]] foundation::Result<ResourceServer> requireActive(std::string_view audience) const;
    [[nodiscard]] foundation::Result<std::vector<ResourceServer>> list() const;
    [[nodiscard]] foundation::Result<ResourceServer> setStatus(
        std::string_view audience, ResourceStatus status);
private:
    ResourceRepository* m_repository;
    const foundation::ClockSource* m_clock;
};

/** @brief Provisions and validates canonical non-human identities for service clients. */
class ServiceIdentityService final {
public:
    ServiceIdentityService(identity::core::OrganizationId organization,
                           identity::core::IdentityRepository& identities,
                           ResourceRepository& resources,
                           client::ClientManager& clients,
                           const foundation::ClockSource& clock);
    [[nodiscard]] foundation::Result<ServiceIdentity> provision(
        const client::ClientId& clientId, std::vector<std::string> audiences,
        std::vector<std::string> scopes);
    [[nodiscard]] foundation::Result<ServiceIdentity> requireActive(
        const client::ClientId& clientId, std::string_view audience,
        const std::vector<std::string>& scopes) const;
    [[nodiscard]] foundation::Result<ServiceIdentity> find(
        const client::ClientId& clientId) const;
    [[nodiscard]] foundation::Result<ServiceIdentity> setActive(
        const client::ClientId& clientId, bool active);
private:
    identity::core::OrganizationId m_organization;
    identity::core::IdentityRepository* m_identities;
    ResourceRepository* m_resources;
    client::ClientManager* m_clients;
    const foundation::ClockSource* m_clock;
};

}

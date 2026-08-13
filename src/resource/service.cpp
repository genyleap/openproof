module;

#include <string_view>
#include <string>
#include <utility>
#include <vector>

module openproof.resource;

import openproof.security;

namespace openproof::resource {

ResourceRegistry::ResourceRegistry(
    ResourceRepository& repository,
    const foundation::ClockSource& clock)
    : m_repository(&repository)
    , m_clock(&clock)
{
}

foundation::Result<ResourceServer> ResourceRegistry::registerResource(
    std::string audience,
    std::string displayName,
    std::vector<std::string> scopes)
{
    auto random = security::randomTokenBase64Url(18U);
    if (!random) {
        return foundation::fail(random.error());
    }

    auto resource = ResourceServer::create(
        ResourceId{"opr_" + random.value()},
        std::move(audience),
        std::move(displayName),
        std::move(scopes),
        m_clock->now());
    if (!resource) {
        return foundation::fail(resource.error());
    }

    auto stored = m_repository->add(resource.value());
    if (!stored) {
        return foundation::fail(stored.error());
    }

    return resource;
}

foundation::Result<ResourceServer> ResourceRegistry::requireActive(
    std::string_view audience) const
{
    auto found = m_repository->findByAudience(audience);
    if (!found) {
        return foundation::fail(found.error());
    }
    if (!found->has_value() || !found->value().active()) {
        return foundation::fail(
            foundation::ErrorCode::PermissionDenied,
            "The requested OAuth resource is unavailable.");
    }

    return found->value();
}

foundation::Result<std::vector<ResourceServer>> ResourceRegistry::list() const
{
    return m_repository->list();
}

foundation::Result<ResourceServer> ResourceRegistry::setStatus(
    std::string_view audience,
    ResourceStatus status)
{
    auto found = m_repository->findByAudience(audience);
    if (!found) {
        return foundation::fail(found.error());
    }
    if (!found->has_value()) {
        return foundation::fail(foundation::ErrorCode::NotFound);
    }

    auto resource = found->value();
    auto changed = resource.setStatus(status, m_clock->now());
    if (!changed) {
        return foundation::fail(changed.error());
    }

    auto saved = m_repository->save(resource);
    if (!saved) {
        return foundation::fail(saved.error());
    }

    return resource;
}

ServiceIdentityService::ServiceIdentityService(
    identity::core::OrganizationId organization,
    identity::core::IdentityRepository& identities,
    ResourceRepository& resources,
    client::ClientManager& clients,
    const foundation::ClockSource& clock)
    : m_organization(std::move(organization))
    , m_identities(&identities)
    , m_resources(&resources)
    , m_clients(&clients)
    , m_clock(&clock)
{
}

foundation::Result<ServiceIdentity> ServiceIdentityService::provision(
    const client::ClientId& clientId,
    std::vector<std::string> audiences,
    std::vector<std::string> scopes)
{
    auto registered = m_clients->requireActive(clientId);
    if (!registered) {
        return foundation::fail(registered.error());
    }
    if (registered->kind() != client::ClientKind::Service) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "Only service clients can own service identities.");
    }

    for (const auto& audience : audiences) {
        auto resource = m_resources->findByAudience(audience);
        if (!resource) {
            return foundation::fail(resource.error());
        }
        if (!resource->has_value() || !resource->value().active()
            || !resource->value().permitsScopes(scopes)) {
            return foundation::fail(
                foundation::ErrorCode::PermissionDenied,
                "The service grant exceeds the resource registration.");
        }
    }

    auto existing = m_resources->serviceForClient(clientId);
    if (!existing) {
        return foundation::fail(existing.error());
    }
    if (existing->has_value()) {
        return foundation::fail(
            foundation::ErrorCode::AlreadyExists,
            "The service client already has a canonical identity.");
    }

    auto random = security::randomTokenBase64Url(24U);
    if (!random) {
        return foundation::fail(random.error());
    }

    identity::core::IdentityId identityId{"opsi_" + random.value()};
    auto identity = identity::core::Identity::create(
        identityId,
        identity::core::SubjectKind::Service,
        m_clock->now());
    if (!identity) {
        return foundation::fail(identity.error());
    }

    auto added = m_identities->add(m_organization, std::move(identity).value());
    if (!added) {
        return foundation::fail(added.error());
    }

    auto service = ServiceIdentity::create(
        identityId,
        clientId,
        std::move(audiences),
        std::move(scopes),
        m_clock->now());
    if (!service) {
        static_cast<void>(m_identities->changeStatus(
            m_organization,
            identityId,
            identity::core::IdentityStatus::Deleted));
        return foundation::fail(service.error());
    }

    auto saved = m_resources->saveService(service.value());
    if (!saved) {
        static_cast<void>(m_identities->changeStatus(
            m_organization,
            identityId,
            identity::core::IdentityStatus::Deleted));
        return foundation::fail(saved.error());
    }

    return service;
}

foundation::Result<ServiceIdentity> ServiceIdentityService::requireActive(
    const client::ClientId& clientId,
    std::string_view audience,
    const std::vector<std::string>& scopes) const
{
    auto registered = m_clients->requireActive(clientId);
    if (!registered) {
        return foundation::fail(registered.error());
    }
    if (registered->kind() != client::ClientKind::Service) {
        return foundation::fail(
            foundation::ErrorCode::AuthenticationFailed,
            "Client authentication failed.");
    }

    auto service = m_resources->serviceForClient(clientId);
    if (!service) {
        return foundation::fail(service.error());
    }
    if (!service->has_value() || !service->value().active()
        || !service->value().permitsAudience(audience)
        || !service->value().permitsScopes(scopes)) {
        return foundation::fail(
            foundation::ErrorCode::PermissionDenied,
            "The service identity does not permit the requested grant.");
    }

    auto identity = m_identities->findById(m_organization, service->value().identity());
    if (!identity) {
        return foundation::fail(identity.error());
    }
    if (!identity->has_value() || !identity->value().canAuthenticate()
        || identity->value().kind() != identity::core::SubjectKind::Service) {
        return foundation::fail(
            foundation::ErrorCode::PermissionDenied,
            "The service identity is inactive.");
    }

    return service->value();
}

foundation::Result<ServiceIdentity> ServiceIdentityService::find(
    const client::ClientId& clientId) const
{
    auto found = m_resources->serviceForClient(clientId);
    if (!found) {
        return foundation::fail(found.error());
    }
    if (!found->has_value()) {
        return foundation::fail(foundation::ErrorCode::NotFound);
    }

    return found->value();
}

foundation::Result<ServiceIdentity> ServiceIdentityService::setActive(
    const client::ClientId& clientId,
    bool active)
{
    auto found = find(clientId);
    if (!found) {
        return foundation::fail(found.error());
    }

    auto service = found.value();
    const auto status = active
        ? service.activate(m_clock->now())
        : service.deactivate(m_clock->now());
    if (!status) {
        return foundation::fail(status.error());
    }

    auto saved = m_resources->saveService(service);
    if (!saved) {
        return foundation::fail(saved.error());
    }

    return service;
}

} // namespace openproof::resource

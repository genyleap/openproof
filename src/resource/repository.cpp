module;

#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.resource;

namespace openproof::resource {

struct InMemoryResourceRepository::Impl final {
    mutable std::mutex mutex;
    std::map<std::string, ResourceServer, std::less<>> resources;
    std::map<client::ClientId, ServiceIdentity> services;
};

InMemoryResourceRepository::InMemoryResourceRepository()
    : m_impl(std::make_unique<Impl>())
{
}

InMemoryResourceRepository::~InMemoryResourceRepository() = default;

foundation::Status InMemoryResourceRepository::add(ResourceServer resource)
{
    std::scoped_lock lock{m_impl->mutex};
    if (m_impl->resources.contains(resource.audience())) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists);
    }

    m_impl->resources.emplace(std::string{resource.audience()}, std::move(resource));
    return foundation::ok();
}

foundation::Status InMemoryResourceRepository::save(const ResourceServer& resource)
{
    std::scoped_lock lock{m_impl->mutex};
    auto found = m_impl->resources.find(resource.audience());
    if (found == m_impl->resources.end()) {
        return foundation::fail(foundation::ErrorCode::NotFound);
    }

    found->second = resource;
    return foundation::ok();
}

foundation::Result<std::optional<ResourceServer>>
InMemoryResourceRepository::findByAudience(std::string_view audience) const
{
    std::scoped_lock lock{m_impl->mutex};
    auto found = m_impl->resources.find(audience);
    if (found == m_impl->resources.end()) {
        return std::optional<ResourceServer>{};
    }

    return std::optional<ResourceServer>{found->second};
}

foundation::Result<std::vector<ResourceServer>> InMemoryResourceRepository::list() const
{
    std::scoped_lock lock{m_impl->mutex};
    std::vector<ResourceServer> resources;
    resources.reserve(m_impl->resources.size());

    for (const auto& [audience, resource] : m_impl->resources) {
        static_cast<void>(audience);
        resources.push_back(resource);
    }

    return resources;
}

foundation::Status InMemoryResourceRepository::saveService(ServiceIdentity service)
{
    std::scoped_lock lock{m_impl->mutex};
    m_impl->services.insert_or_assign(service.client(), std::move(service));
    return foundation::ok();
}

foundation::Result<std::optional<ServiceIdentity>>
InMemoryResourceRepository::serviceForClient(const client::ClientId& clientId) const
{
    std::scoped_lock lock{m_impl->mutex};
    auto found = m_impl->services.find(clientId);
    if (found == m_impl->services.end()) {
        return std::optional<ServiceIdentity>{};
    }

    return std::optional<ServiceIdentity>{found->second};
}

} // namespace openproof::resource

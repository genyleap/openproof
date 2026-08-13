module;

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

export module openproof.resource:repository;

import openproof.client;
import openproof.foundation;
import :model;

export namespace openproof::resource {

/** @brief Persistence boundary for resource servers and service identities. */
class ResourceRepository {
public:
    ResourceRepository(const ResourceRepository&) = delete;
    ResourceRepository& operator=(const ResourceRepository&) = delete;
    virtual ~ResourceRepository() = default;
    [[nodiscard]] virtual foundation::Status add(ResourceServer resource) = 0;
    [[nodiscard]] virtual foundation::Status save(const ResourceServer& resource) = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<ResourceServer>>
    findByAudience(std::string_view audience) const = 0;
    [[nodiscard]] virtual foundation::Result<std::vector<ResourceServer>> list() const = 0;
    [[nodiscard]] virtual foundation::Status saveService(ServiceIdentity service) = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<ServiceIdentity>>
    serviceForClient(const client::ClientId& clientId) const = 0;
protected:
    ResourceRepository() = default;
};

class InMemoryResourceRepository final : public ResourceRepository {
public:
    InMemoryResourceRepository();
    ~InMemoryResourceRepository() override;
    [[nodiscard]] foundation::Status add(ResourceServer resource) override;
    [[nodiscard]] foundation::Status save(const ResourceServer& resource) override;
    [[nodiscard]] foundation::Result<std::optional<ResourceServer>>
    findByAudience(std::string_view audience) const override;
    [[nodiscard]] foundation::Result<std::vector<ResourceServer>> list() const override;
    [[nodiscard]] foundation::Status saveService(ServiceIdentity service) override;
    [[nodiscard]] foundation::Result<std::optional<ServiceIdentity>>
    serviceForClient(const client::ClientId& clientId) const override;
private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}

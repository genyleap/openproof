module;

#include <memory>
#include <string>
#include <string_view>
#include <vector>

export module openproof.resource:model;

import openproof.client;
import openproof.foundation;
import openproof.identity.core;

export namespace openproof::resource {

struct ResourceIdTag {};
using ResourceId = foundation::StrongId<ResourceIdTag>;

enum class ResourceStatus { Active, Suspended, Revoked };

/** @brief Registered OAuth resource server and its audience/scope boundary. */
class ResourceServer final {
public:
    [[nodiscard]] static foundation::Result<ResourceServer> create(
        ResourceId id, std::string audience, std::string displayName,
        std::vector<std::string> scopes, foundation::Instant now);
    [[nodiscard]] static foundation::Result<ResourceServer> restore(
        ResourceId id, std::string audience, std::string displayName,
        std::vector<std::string> scopes, ResourceStatus status,
        foundation::Instant createdAt, foundation::Instant updatedAt);

    [[nodiscard]] const ResourceId& id() const noexcept;
    [[nodiscard]] std::string_view audience() const noexcept;
    [[nodiscard]] std::string_view displayName() const noexcept;
    [[nodiscard]] const std::vector<std::string>& scopes() const noexcept;
    [[nodiscard]] ResourceStatus status() const noexcept;
    [[nodiscard]] bool active() const noexcept;
    [[nodiscard]] bool permitsScope(std::string_view scope) const noexcept;
    [[nodiscard]] bool permitsScopes(const std::vector<std::string>& scopes) const noexcept;
    [[nodiscard]] foundation::Instant createdAt() const noexcept;
    [[nodiscard]] foundation::Instant updatedAt() const noexcept;
    [[nodiscard]] foundation::Status setStatus(ResourceStatus status, foundation::Instant now);

private:
    struct State;
    explicit ResourceServer(std::shared_ptr<State> state);
    std::shared_ptr<State> m_state;
    void detach();
};

/** @brief Mapping from a confidential service client to one canonical service identity. */
class ServiceIdentity final {
public:
    [[nodiscard]] static foundation::Result<ServiceIdentity> create(
        identity::core::IdentityId identity, client::ClientId client,
        std::vector<std::string> audiences, std::vector<std::string> scopes,
        foundation::Instant now);
    [[nodiscard]] static foundation::Result<ServiceIdentity> restore(
        identity::core::IdentityId identity, client::ClientId client,
        std::vector<std::string> audiences, std::vector<std::string> scopes,
        bool active, foundation::Instant createdAt, foundation::Instant updatedAt);

    [[nodiscard]] const identity::core::IdentityId& identity() const noexcept;
    [[nodiscard]] const client::ClientId& client() const noexcept;
    [[nodiscard]] const std::vector<std::string>& audiences() const noexcept;
    [[nodiscard]] const std::vector<std::string>& scopes() const noexcept;
    [[nodiscard]] bool active() const noexcept;
    [[nodiscard]] bool permitsAudience(std::string_view audience) const noexcept;
    [[nodiscard]] bool permitsScopes(const std::vector<std::string>& scopes) const noexcept;
    [[nodiscard]] foundation::Instant createdAt() const noexcept;
    [[nodiscard]] foundation::Instant updatedAt() const noexcept;
    [[nodiscard]] foundation::Status deactivate(foundation::Instant now);
    [[nodiscard]] foundation::Status activate(foundation::Instant now);

private:
    struct State;
    explicit ServiceIdentity(std::shared_ptr<State> state);
    std::shared_ptr<State> m_state;
    void detach();
};

}

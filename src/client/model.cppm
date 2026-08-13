module;

#include <compare>
#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.client:model;

import openproof.application;
import openproof.foundation;

export namespace openproof::client {

struct ClientIdTag {};
using ClientId = foundation::StrongId<ClientIdTag>;

enum class ClientKind {
    Web,
    Native,
    Browser,
    Service,
};

[[nodiscard]] std::string_view clientKindName(ClientKind kind) noexcept;
[[nodiscard]] bool clientIsPublic(ClientKind kind) noexcept;

enum class ClientStatus {
    Active,
    Suspended,
    Revoked,
};

[[nodiscard]] std::string_view clientStatusName(ClientStatus status) noexcept;
[[nodiscard]] bool clientPermitsAuthorization(ClientStatus status) noexcept;

/** @brief Canonical OAuth scope token. */
class Scope final {
public:
    Scope(const Scope& other);
    Scope(Scope&& other);
    Scope& operator=(const Scope& other);
    Scope& operator=(Scope&& other);
    ~Scope();

    [[nodiscard]] static foundation::Result<Scope> create(std::string value);
    [[nodiscard]] std::string_view value() const noexcept;
    [[nodiscard]] friend bool operator==(const Scope&, const Scope&) = default;
    [[nodiscard]] friend std::strong_ordering operator<=>(const Scope&, const Scope&) = default;
private:
    explicit Scope(std::string value);
    std::string m_value;
};

/** @brief Pre-registered redirect URI compared by exact string match. */
class RedirectUri final {
public:
    RedirectUri(const RedirectUri& other);
    RedirectUri(RedirectUri&& other);
    RedirectUri& operator=(const RedirectUri& other);
    RedirectUri& operator=(RedirectUri&& other);
    ~RedirectUri();

    [[nodiscard]] static foundation::Result<RedirectUri>
    create(std::string value, ClientKind clientKind);
    [[nodiscard]] std::string_view value() const noexcept;
    [[nodiscard]] friend bool operator==(const RedirectUri&, const RedirectUri&) = default;
    [[nodiscard]] friend std::strong_ordering operator<=>(const RedirectUri&, const RedirectUri&) = default;
private:
    explicit RedirectUri(std::string value);
    std::string m_value;
};

class ClientSecretDigest final {
public:
    explicit ClientSecretDigest(std::array<std::byte, 32> digest) noexcept
        : m_digest(digest)
    {
    }

    [[nodiscard]] const std::array<std::byte, 32>& bytes() const noexcept
    {
        return m_digest;
    }

    friend bool operator==(const ClientSecretDigest& left,
                           const ClientSecretDigest& right) noexcept
    {
        return left.m_digest == right.m_digest;
    }

private:
    std::array<std::byte, 32> m_digest{};
};

/**
 * @brief One independently revocable OAuth/OIDC client registration.
 */
class Client final {
public:
    [[nodiscard]] static foundation::Result<Client>
    create(ClientId id, application::ApplicationId applicationId,
           std::string displayName, ClientKind kind,
           std::vector<RedirectUri> redirectUris, std::vector<Scope> scopes,
           std::optional<ClientSecretDigest> secretDigest,
           foundation::Instant createdAt);

    [[nodiscard]] static foundation::Result<Client>
    restore(ClientId id, application::ApplicationId applicationId,
            std::string displayName, ClientKind kind, ClientStatus status,
            std::vector<RedirectUri> redirectUris, std::vector<Scope> scopes,
            std::optional<ClientSecretDigest> secretDigest,
            foundation::Instant createdAt, foundation::Instant updatedAt);

    [[nodiscard]] const ClientId& id() const noexcept;
    [[nodiscard]] const application::ApplicationId& applicationId() const noexcept;
    [[nodiscard]] std::string_view displayName() const noexcept;
    [[nodiscard]] ClientKind kind() const noexcept;
    [[nodiscard]] ClientStatus status() const noexcept;
    [[nodiscard]] bool isPublic() const noexcept;
    [[nodiscard]] bool permitsAuthorization() const noexcept;
    [[nodiscard]] const std::vector<RedirectUri>& redirectUris() const noexcept;
    [[nodiscard]] const std::vector<Scope>& scopes() const noexcept;
    [[nodiscard]] const std::optional<ClientSecretDigest>& secretDigest() const noexcept;
    [[nodiscard]] foundation::Instant createdAt() const noexcept;
    [[nodiscard]] foundation::Instant updatedAt() const noexcept;

    [[nodiscard]] bool permitsRedirect(std::string_view redirectUri) const noexcept;
    [[nodiscard]] bool permitsScope(std::string_view scope) const noexcept;
    [[nodiscard]] bool permitsScopes(const std::vector<Scope>& requested) const noexcept;

    [[nodiscard]] foundation::Status suspend(foundation::Instant now);
    [[nodiscard]] foundation::Status activate(foundation::Instant now);
    [[nodiscard]] foundation::Status revoke(foundation::Instant now);
    [[nodiscard]] foundation::Status replaceSecret(ClientSecretDigest digest,
                                                   foundation::Instant now);

private:
    Client(ClientId id, application::ApplicationId applicationId,
           std::string displayName, ClientKind kind,
           std::vector<RedirectUri> redirectUris, std::vector<Scope> scopes,
           std::optional<ClientSecretDigest> secretDigest,
           foundation::Instant createdAt);

    struct State;
    std::shared_ptr<State> m_state;

    void detach();
};

}

module;

#include <array>
#include <cstddef>

#include <compare>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.oauth:model;

import openproof.client;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

export namespace openproof::oauth {

class CodeDigest final {
public:
    explicit CodeDigest(std::array<std::byte, 32> digest) noexcept
        : m_digest(digest)
    {
    }

    [[nodiscard]] const std::array<std::byte, 32>& bytes() const noexcept
    {
        return m_digest;
    }

    friend bool operator==(const CodeDigest& left, const CodeDigest& right) noexcept
    {
        return left.m_digest == right.m_digest;
    }

    friend std::strong_ordering
    operator<=>(const CodeDigest& left, const CodeDigest& right) noexcept
    {
        return left.m_digest <=> right.m_digest;
    }

private:
    std::array<std::byte, 32> m_digest{};
};

/** @brief Validated S256 PKCE challenge. */
class PkceChallenge final {
public:
    PkceChallenge(const PkceChallenge& other);
    PkceChallenge(PkceChallenge&& other);
    PkceChallenge& operator=(const PkceChallenge& other);
    PkceChallenge& operator=(PkceChallenge&& other);
    ~PkceChallenge();

    [[nodiscard]] static foundation::Result<PkceChallenge> create(std::string value);
    [[nodiscard]] std::string_view value() const noexcept;
private:
    explicit PkceChallenge(std::string value);
    std::string m_value;
};

enum class AuthorizationResponseMode {
    Query,
    Jwt,
};

class AuthorizationRequest final {
public:
    [[nodiscard]] static foundation::Result<AuthorizationRequest>
    create(client::ClientId clientId, std::string redirectUri,
           std::vector<client::Scope> scopes, PkceChallenge codeChallenge,
           std::optional<std::string> state, std::optional<std::string> nonce,
           std::optional<foundation::Duration> maximumAuthenticationAge = std::nullopt,
           std::optional<std::string> resource = std::nullopt,
           AuthorizationResponseMode responseMode = AuthorizationResponseMode::Query);

    [[nodiscard]] const client::ClientId& clientId() const noexcept;
    [[nodiscard]] std::string_view redirectUri() const noexcept;
    [[nodiscard]] const std::vector<client::Scope>& scopes() const noexcept;
    [[nodiscard]] const PkceChallenge& codeChallenge() const noexcept;
    [[nodiscard]] const std::optional<std::string>& state() const noexcept;
    [[nodiscard]] const std::optional<std::string>& nonce() const noexcept;
    [[nodiscard]] const std::optional<foundation::Duration>& maximumAuthenticationAge() const noexcept;
    [[nodiscard]] const std::optional<std::string>& resource() const noexcept;
    [[nodiscard]] AuthorizationResponseMode responseMode() const noexcept;

private:
    AuthorizationRequest(client::ClientId clientId, std::string redirectUri,
                         std::vector<client::Scope> scopes,
                         PkceChallenge codeChallenge,
                         std::optional<std::string> state,
                         std::optional<std::string> nonce,
                         std::optional<foundation::Duration> maximumAuthenticationAge,
                         std::optional<std::string> resource,
                         AuthorizationResponseMode responseMode);

    struct StateData;
    std::shared_ptr<const StateData> m_data;
};

/** @brief Stored single-use authorization code state; the raw code is absent. */
class AuthorizationCode final {
public:
    [[nodiscard]] static foundation::Result<AuthorizationCode>
    create(CodeDigest digest, client::ClientId clientId,
           identity::core::IdentityId identity, std::string redirectUri,
           std::vector<client::Scope> scopes, PkceChallenge codeChallenge,
           std::optional<std::string> nonce,
           identity::provider::ProviderId provider,
           identity::provider::AssuranceLevel assurance,
           identity::provider::AuthenticationStrength strength,
           foundation::Instant authenticatedAt, foundation::Instant issuedAt,
           foundation::Duration lifetime,
           std::optional<std::string> resource = std::nullopt);

    [[nodiscard]] static foundation::Result<AuthorizationCode>
    restore(CodeDigest digest, client::ClientId clientId,
            identity::core::IdentityId identity, std::string redirectUri,
            std::vector<client::Scope> scopes, PkceChallenge codeChallenge,
            std::optional<std::string> nonce,
            identity::provider::ProviderId provider,
            identity::provider::AssuranceLevel assurance,
            identity::provider::AuthenticationStrength strength,
            foundation::Instant authenticatedAt, foundation::Instant issuedAt,
            foundation::Instant expiresAt,
            std::optional<std::string> resource = std::nullopt);

    [[nodiscard]] const CodeDigest& digest() const noexcept;
    [[nodiscard]] const client::ClientId& clientId() const noexcept;
    [[nodiscard]] const identity::core::IdentityId& identity() const noexcept;
    [[nodiscard]] std::string_view redirectUri() const noexcept;
    [[nodiscard]] const std::vector<client::Scope>& scopes() const noexcept;
    [[nodiscard]] const PkceChallenge& codeChallenge() const noexcept;
    [[nodiscard]] const std::optional<std::string>& nonce() const noexcept;
    [[nodiscard]] const std::optional<std::string>& resource() const noexcept;
    [[nodiscard]] const identity::provider::ProviderId& provider() const noexcept;
    [[nodiscard]] identity::provider::AssuranceLevel assurance() const noexcept;
    [[nodiscard]] const identity::provider::AuthenticationStrength& strength() const noexcept;
    [[nodiscard]] foundation::Instant authenticatedAt() const noexcept;
    [[nodiscard]] foundation::Instant issuedAt() const noexcept;
    [[nodiscard]] foundation::Instant expiresAt() const noexcept;
    [[nodiscard]] bool expiredAt(foundation::Instant now) const noexcept;

private:
    AuthorizationCode(CodeDigest digest, client::ClientId clientId,
                      identity::core::IdentityId identity, std::string redirectUri,
                      std::vector<client::Scope> scopes, PkceChallenge codeChallenge,
                      std::optional<std::string> nonce,
                      identity::provider::ProviderId provider,
                      identity::provider::AssuranceLevel assurance,
                      identity::provider::AuthenticationStrength strength,
                      foundation::Instant authenticatedAt,
                      foundation::Instant issuedAt, foundation::Instant expiresAt,
                      std::optional<std::string> resource);

    struct StateData;
    std::shared_ptr<const StateData> m_data;
};

class AuthorizationGrant final {
public:
    ~AuthorizationGrant();
    AuthorizationGrant(const AuthorizationGrant&) = delete;
    AuthorizationGrant& operator=(const AuthorizationGrant&) = delete;
    AuthorizationGrant(AuthorizationGrant&& other) noexcept;
    AuthorizationGrant& operator=(AuthorizationGrant&& other) noexcept;

    [[nodiscard]] const foundation::SecretString& code() const noexcept;
    [[nodiscard]] std::string_view redirectUri() const noexcept;
    [[nodiscard]] const std::optional<std::string>& state() const noexcept;
private:
    friend class AuthorizationService;
    AuthorizationGrant(foundation::SecretString code, std::string redirectUri,
                       std::optional<std::string> state);
    foundation::SecretString m_code;
    std::string m_redirectUri;
    std::optional<std::string> m_state;
};

}

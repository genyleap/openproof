module;

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

export module openproof.token:service;

import openproof.client;
import openproof.foundation;
import openproof.oauth;
import openproof.resource;
import openproof.session;
import :model;
import :repository;

export namespace openproof::token {

class TokenKey final {
public:
    ~TokenKey();
    [[nodiscard]] static foundation::Result<TokenKey>
    create(foundation::SecretString secret);
    TokenKey(const TokenKey&) = delete;
    TokenKey& operator=(const TokenKey&) = delete;
    TokenKey(TokenKey&& other) noexcept;
    TokenKey& operator=(TokenKey&& other) noexcept;
private:
    friend class TokenService;
    explicit TokenKey(foundation::SecretString secret);
    foundation::SecretString m_secret;
};

class TokenPolicy final {
public:
    TokenPolicy(const TokenPolicy& other);
    TokenPolicy(TokenPolicy&& other);
    TokenPolicy& operator=(const TokenPolicy& other);
    TokenPolicy& operator=(TokenPolicy&& other);
    ~TokenPolicy();

    [[nodiscard]] static foundation::Result<TokenPolicy>
    create(foundation::Duration accessLifetime, foundation::Duration refreshLifetime);
    [[nodiscard]] foundation::Duration accessLifetime() const noexcept;
    [[nodiscard]] foundation::Duration refreshLifetime() const noexcept;
private:
    TokenPolicy(foundation::Duration accessLifetime, foundation::Duration refreshLifetime);
    foundation::Duration m_accessLifetime{};
    foundation::Duration m_refreshLifetime{};
};

/** @brief Move-only OAuth token response. */
class TokenGrant final {
public:
    ~TokenGrant();
    TokenGrant(const TokenGrant&) = delete;
    TokenGrant& operator=(const TokenGrant&) = delete;
    TokenGrant(TokenGrant&& other) noexcept;
    TokenGrant& operator=(TokenGrant&& other) noexcept;
    [[nodiscard]] const foundation::SecretString& accessToken() const noexcept;
    [[nodiscard]] const foundation::SecretString& refreshToken() const noexcept;
    [[nodiscard]] foundation::Duration expiresIn() const noexcept;
    [[nodiscard]] const TokenContext& context() const noexcept;
private:
    friend class TokenService;
    TokenGrant(foundation::SecretString access, foundation::SecretString refresh,
               foundation::Duration expiresIn, TokenContext context);
    foundation::SecretString m_access;
    foundation::SecretString m_refresh;
    foundation::Duration m_expiresIn{};
    TokenContext m_context;
};


/** @brief Access-token-only machine grant returned by client_credentials. */
class MachineTokenGrant final {
public:
    ~MachineTokenGrant();
    MachineTokenGrant(const MachineTokenGrant&) = delete;
    MachineTokenGrant& operator=(const MachineTokenGrant&) = delete;
    MachineTokenGrant(MachineTokenGrant&&) noexcept;
    MachineTokenGrant& operator=(MachineTokenGrant&&) noexcept;

    [[nodiscard]] const foundation::SecretString& accessToken() const noexcept;
    [[nodiscard]] foundation::Duration expiresIn() const noexcept;
    [[nodiscard]] const TokenContext& context() const noexcept;

private:
    friend class TokenService;
    MachineTokenGrant(foundation::SecretString access, foundation::Duration expiresIn,
                      TokenContext context);
    foundation::SecretString m_access;
    foundation::Duration m_expiresIn{};
    TokenContext m_context;
};

/** @brief Issues, rotates, introspects and revokes opaque OAuth tokens. */
class TokenService final : public session::DelegatedAccessAuthenticator {
public:
    TokenService(TokenRepository& repository, client::ClientManager& clients,
                 const foundation::ClockSource& clock, TokenKey key, TokenPolicy policy);

    [[nodiscard]] foundation::Result<TokenGrant>
    issue(const oauth::RedeemedAuthorization& authorization,
          std::optional<SenderConstraint> senderConstraint = std::nullopt);
    [[nodiscard]] foundation::Result<TokenGrant>
    refresh(const client::ClientId& clientId, const foundation::SecretString& refreshToken,
            std::optional<SenderConstraint> senderConstraint = std::nullopt);
    /** @brief Issues user tokens from an atomically consumed RFC 8628 device authorization. */
    [[nodiscard]] foundation::Result<TokenGrant> issueDeviceAuthorization(
        const oauth::DeviceAuthorization& authorization,
        std::optional<SenderConstraint> senderConstraint = std::nullopt);
    [[nodiscard]] foundation::Result<MachineTokenGrant> issueClientCredentials(
        const resource::ServiceIdentity& service, std::string audience,
        std::vector<std::string> scopes,
        std::optional<SenderConstraint> senderConstraint = std::nullopt);
    /** @brief Issues a down-scoped, access-only RFC 8693-style token exchange. */
    [[nodiscard]] foundation::Result<MachineTokenGrant> issueTokenExchange(
        const client::ClientId& clientId, const foundation::SecretString& subjectToken,
        std::string audience, std::vector<std::string> scopes,
        std::optional<SenderConstraint> senderConstraint = std::nullopt);
    [[nodiscard]] foundation::Result<TokenClaims>
    introspect(const foundation::SecretString& accessToken);
    [[nodiscard]] foundation::Status revoke(const foundation::SecretString& token);
    /** Revokes only a token issued to @p clientId; unknown/foreign tokens are a no-op. */
    [[nodiscard]] foundation::Status revokeForClient(
        const client::ClientId& clientId, const foundation::SecretString& token);
    [[nodiscard]] foundation::Result<session::DelegatedAccess>
    authenticateDelegated(const foundation::SecretString& token) override;

private:
    [[nodiscard]] foundation::Result<TokenDigest>
    digest(const foundation::SecretString& token) const;
    [[nodiscard]] foundation::Result<TokenGrant>
    makeInitial(TokenContext context);
    [[nodiscard]] foundation::Result<TokenGrant>
    makeRotation(const RefreshTokenRecord& current);

    TokenRepository& m_repository;
    client::ClientManager& m_clients;
    const foundation::ClockSource& m_clock;
    TokenKey m_key;
    TokenPolicy m_policy;
};

}

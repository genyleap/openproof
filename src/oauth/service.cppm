module;

#include <string>
#include <vector>
#include <string_view>
#include <optional>

export module openproof.oauth:service;

import openproof.client;
import openproof.foundation;
import openproof.identity.provider;
import openproof.identity.core;
import openproof.security;
import openproof.session;
import :model;
import :repository;

export namespace openproof::oauth {

class AuthorizationCodeKey final {
public:
    ~AuthorizationCodeKey();
    [[nodiscard]] static foundation::Result<AuthorizationCodeKey>
    create(foundation::SecretString key);
    AuthorizationCodeKey(const AuthorizationCodeKey&) = delete;
    AuthorizationCodeKey& operator=(const AuthorizationCodeKey&) = delete;
    AuthorizationCodeKey(AuthorizationCodeKey&& other) noexcept;
    AuthorizationCodeKey& operator=(AuthorizationCodeKey&& other) noexcept;
private:
    friend class AuthorizationService;
    explicit AuthorizationCodeKey(foundation::SecretString key);
    foundation::SecretString m_key;
};

/** @brief Successful one-time code redemption delivered to the token service. */
class RedeemedAuthorization final {
public:
    RedeemedAuthorization(const RedeemedAuthorization& other);
    RedeemedAuthorization(RedeemedAuthorization&& other);
    RedeemedAuthorization& operator=(const RedeemedAuthorization& other);
    RedeemedAuthorization& operator=(RedeemedAuthorization&& other);
    ~RedeemedAuthorization();
    [[nodiscard]] const client::ClientId& clientId() const noexcept;
    [[nodiscard]] const identity::core::IdentityId& identity() const noexcept;
    [[nodiscard]] const std::vector<client::Scope>& scopes() const noexcept;
    [[nodiscard]] const std::optional<std::string>& nonce() const noexcept;
    [[nodiscard]] const std::optional<std::string>& resource() const noexcept;
    [[nodiscard]] const identity::provider::ProviderId& provider() const noexcept;
    [[nodiscard]] identity::provider::AssuranceLevel assurance() const noexcept;
    [[nodiscard]] const identity::provider::AuthenticationStrength& strength() const noexcept;
    [[nodiscard]] foundation::Instant authenticatedAt() const noexcept;
private:
    friend class AuthorizationService;
    explicit RedeemedAuthorization(AuthorizationCode code);
    AuthorizationCode m_code;
};

class AuthorizationService final {
public:
    AuthorizationService(client::ClientManager& clients, AuthorizationCodeStore& codes,
                         const foundation::ClockSource& clock,
                         AuthorizationCodeKey key,
                         foundation::Duration codeLifetime);

    [[nodiscard]] foundation::Result<AuthorizationGrant>
    authorize(const session::AuthenticatedSession& session,
              AuthorizationRequest request);

    [[nodiscard]] foundation::Result<RedeemedAuthorization>
    redeem(const foundation::SecretString& code, const client::ClientId& clientId,
           std::string_view redirectUri, std::string_view codeVerifier);

private:
    [[nodiscard]] foundation::Result<CodeDigest>
    digest(const foundation::SecretString& code) const;
    [[nodiscard]] static foundation::Result<PkceChallenge>
    challengeForVerifier(std::string_view verifier);

    client::ClientManager* m_clients;
    AuthorizationCodeStore* m_codes;
    const foundation::ClockSource* m_clock;
    AuthorizationCodeKey m_key;
    foundation::Duration m_codeLifetime{};
};

}

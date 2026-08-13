module;

#include <array>
#include <cstddef>

#include <compare>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.token:model;

import openproof.client;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

export namespace openproof::token {

struct TokenFamilyIdTag {};
using TokenFamilyId = foundation::StrongId<TokenFamilyIdTag>;

/** @brief Server-keyed fingerprint of an opaque OAuth bearer credential. */
class TokenDigest final {
public:
    explicit TokenDigest(std::array<std::byte, 32> bytes) noexcept
        : m_bytes(bytes)
    {
    }

    [[nodiscard]] const std::array<std::byte, 32>& bytes() const noexcept
    {
        return m_bytes;
    }

    friend bool operator==(const TokenDigest& left, const TokenDigest& right) noexcept
    {
        return left.m_bytes == right.m_bytes;
    }

    friend std::strong_ordering
    operator<=>(const TokenDigest& left, const TokenDigest& right) noexcept
    {
        return left.m_bytes <=> right.m_bytes;
    }

private:
    std::array<std::byte, 32> m_bytes{};
};

/** @brief Proof-of-possession mechanism bound to an OAuth token family. */
enum class SenderConstraintKind { Dpop, Mtls };

/** @brief Immutable RFC 9449 or RFC 8705 sender binding. */
class SenderConstraint final {
public:
    [[nodiscard]] static foundation::Result<SenderConstraint> create(
        SenderConstraintKind kind, std::string value);
    [[nodiscard]] SenderConstraintKind kind() const noexcept;
    [[nodiscard]] std::string_view value() const noexcept;
private:
    SenderConstraint(SenderConstraintKind kind, std::string value);
    SenderConstraintKind m_kind{SenderConstraintKind::Dpop};
    std::string m_value;
};

/** @brief Immutable authorization context carried by access and refresh tokens. */
class TokenContext final {
public:
    TokenContext(client::ClientId client, identity::core::IdentityId identity,
                 identity::provider::ProviderId provider,
                 identity::provider::AssuranceLevel assurance,
                 identity::provider::AuthenticationStrength strength,
                 std::vector<std::string> scopes,
                 foundation::Instant authenticatedAt,
                 std::vector<std::string> audiences = {},
                 std::optional<SenderConstraint> senderConstraint = std::nullopt);

    [[nodiscard]] const client::ClientId& client() const noexcept;
    [[nodiscard]] const identity::core::IdentityId& identity() const noexcept;
    [[nodiscard]] const identity::provider::ProviderId& provider() const noexcept;
    [[nodiscard]] identity::provider::AssuranceLevel assurance() const noexcept;
    [[nodiscard]] const identity::provider::AuthenticationStrength& strength() const noexcept;
    [[nodiscard]] const std::vector<std::string>& scopes() const noexcept;
    [[nodiscard]] const std::vector<std::string>& audiences() const noexcept;
    [[nodiscard]] const std::optional<SenderConstraint>& senderConstraint() const noexcept;
    [[nodiscard]] foundation::Instant authenticatedAt() const noexcept;
    [[nodiscard]] bool permits(std::string_view scope) const noexcept;
    [[nodiscard]] bool permitsAudience(std::string_view audience) const noexcept;

private:
    struct StateData;
    std::shared_ptr<const StateData> m_data;
};

enum class AccessTokenState { Active, Revoked };
enum class RefreshTokenState { Active, Used, Revoked };

/** @brief Persistable access token record. The raw bearer value is never stored. */
class AccessTokenRecord final {
public:
    AccessTokenRecord(TokenDigest digest, TokenFamilyId family, TokenContext context,
                      foundation::Instant issuedAt, foundation::Instant expiresAt,
                      AccessTokenState state = AccessTokenState::Active,
                      std::optional<foundation::Instant> revokedAt = std::nullopt);

    [[nodiscard]] const TokenDigest& digest() const noexcept;
    [[nodiscard]] const TokenFamilyId& family() const noexcept;
    [[nodiscard]] const TokenContext& context() const noexcept;
    [[nodiscard]] foundation::Instant issuedAt() const noexcept;
    [[nodiscard]] foundation::Instant expiresAt() const noexcept;
    [[nodiscard]] AccessTokenState state() const noexcept;
    [[nodiscard]] const std::optional<foundation::Instant>& revokedAt() const noexcept;
    [[nodiscard]] bool usableAt(foundation::Instant now) const noexcept;
    void revoke(foundation::Instant now) noexcept;

private:
    struct StateData;
    std::shared_ptr<StateData> m_data;
    void detach();
};

/** @brief Persistable rotating refresh-token record. */
class RefreshTokenRecord final {
public:
    RefreshTokenRecord(TokenDigest digest, TokenFamilyId family, std::uint64_t sequence,
                       TokenContext context, foundation::Instant issuedAt,
                       foundation::Instant expiresAt,
                       RefreshTokenState state = RefreshTokenState::Active,
                       std::optional<foundation::Instant> changedAt = std::nullopt);

    [[nodiscard]] const TokenDigest& digest() const noexcept;
    [[nodiscard]] const TokenFamilyId& family() const noexcept;
    [[nodiscard]] std::uint64_t sequence() const noexcept;
    [[nodiscard]] const TokenContext& context() const noexcept;
    [[nodiscard]] foundation::Instant issuedAt() const noexcept;
    [[nodiscard]] foundation::Instant expiresAt() const noexcept;
    [[nodiscard]] RefreshTokenState state() const noexcept;
    [[nodiscard]] const std::optional<foundation::Instant>& changedAt() const noexcept;
    [[nodiscard]] bool usableAt(foundation::Instant now) const noexcept;
    void markUsed(foundation::Instant now) noexcept;
    void revoke(foundation::Instant now) noexcept;

private:
    struct StateData;
    std::shared_ptr<StateData> m_data;
    void detach();
};

/** @brief Public introspection result for an access token. */
class TokenClaims final {
public:
    TokenClaims(bool active, TokenContext context, foundation::Instant issuedAt,
                foundation::Instant expiresAt);
    [[nodiscard]] bool active() const noexcept;
    [[nodiscard]] const TokenContext& context() const noexcept;
    [[nodiscard]] foundation::Instant issuedAt() const noexcept;
    [[nodiscard]] foundation::Instant expiresAt() const noexcept;
private:
    struct StateData;
    std::shared_ptr<const StateData> m_data;
};

}

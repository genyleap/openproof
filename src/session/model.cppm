module;

#include <compare>
#include <optional>
#include <string>
#include <string_view>

export module openproof.session:model;

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.security;

export namespace openproof::session {

struct SessionIdTag {};
using SessionId = foundation::StrongId<SessionIdTag>;

/** @brief Server-keyed fingerprint of an opaque bearer token. */
class TokenDigest final {
public:
    explicit TokenDigest(security::Sha256Digest bytes) noexcept;
    TokenDigest(const TokenDigest& other) noexcept;
    TokenDigest& operator=(const TokenDigest& other) noexcept;
    TokenDigest(TokenDigest&& other) noexcept;
    TokenDigest& operator=(TokenDigest&& other) noexcept;
    ~TokenDigest() noexcept;

    [[nodiscard]] const security::Sha256Digest& bytes() const noexcept;
    friend bool operator==(const TokenDigest& left, const TokenDigest& right) noexcept;
    friend std::strong_ordering operator<=>(const TokenDigest& left, const TokenDigest& right) noexcept;

private:
    security::Sha256Digest m_bytes{};
};

enum class SessionState {
    Active,
    Revoked,
    Expired,
};

[[nodiscard]] std::string_view sessionStateName(SessionState state) noexcept;

/**
 * @brief One revocable login session bound to a canonical identity.
 *
 * The raw bearer token is never retained. Absolute and idle expiry are both
 * inclusive, so a token presented exactly at either deadline is rejected.
 */
class Session final {
public:
    Session(const Session& other);
    Session& operator=(const Session& other);
    Session(Session&& other) noexcept;
    Session& operator=(Session&& other) noexcept;
    ~Session();

    [[nodiscard]] static foundation::Result<Session>
    create(SessionId id, identity::core::IdentityId identity,
           identity::provider::ProviderId provider,
           identity::provider::AssuranceLevel assurance,
           identity::provider::AuthenticationStrength strength,
           foundation::Instant authenticatedAt, TokenDigest tokenDigest,
           foundation::Instant issuedAt, foundation::Duration absoluteLifetime,
           foundation::Duration idleTimeout,
           std::optional<std::string> userAgent = std::nullopt,
           std::optional<std::string> remoteAddress = std::nullopt);

    [[nodiscard]] static foundation::Result<Session>
    restore(SessionId id, identity::core::IdentityId identity,
            identity::provider::ProviderId provider,
            identity::provider::AssuranceLevel assurance,
            identity::provider::AuthenticationStrength strength,
            SessionState state, foundation::Instant authenticatedAt,
            TokenDigest tokenDigest, foundation::Instant issuedAt,
            foundation::Instant lastSeenAt,
            foundation::Instant absoluteExpiresAt,
            foundation::Duration idleTimeout,
            std::optional<foundation::Instant> revokedAt,
            std::optional<std::string> userAgent = std::nullopt,
            std::optional<std::string> remoteAddress = std::nullopt);

    [[nodiscard]] const SessionId& id() const noexcept;
    [[nodiscard]] const identity::core::IdentityId& identity() const noexcept;
    [[nodiscard]] const identity::provider::ProviderId& provider() const noexcept;
    [[nodiscard]] identity::provider::AssuranceLevel assurance() const noexcept;
    [[nodiscard]] const identity::provider::AuthenticationStrength& strength() const noexcept;
    [[nodiscard]] SessionState state() const noexcept;
    [[nodiscard]] foundation::Instant authenticatedAt() const noexcept;
    [[nodiscard]] foundation::Instant issuedAt() const noexcept;
    [[nodiscard]] foundation::Instant lastSeenAt() const noexcept;
    [[nodiscard]] foundation::Instant absoluteExpiresAt() const noexcept;
    [[nodiscard]] foundation::Instant idleExpiresAt() const noexcept;
    [[nodiscard]] foundation::Duration idleTimeout() const noexcept;
    [[nodiscard]] const TokenDigest& tokenDigest() const noexcept;
    [[nodiscard]] const std::optional<foundation::Instant>& revokedAt() const noexcept;
    [[nodiscard]] const std::optional<std::string>& userAgent() const noexcept;
    [[nodiscard]] const std::optional<std::string>& remoteAddress() const noexcept;

    [[nodiscard]] bool isExpiredAt(foundation::Instant now) const noexcept;
    [[nodiscard]] foundation::Status use(const TokenDigest& presented, foundation::Instant now);
    [[nodiscard]] foundation::Status rotateToken(const TokenDigest& expected, TokenDigest replacement, foundation::Instant now);
    [[nodiscard]] foundation::Status revoke(foundation::Instant now);
    void markExpired() noexcept;

private:
    Session(SessionId id, identity::core::IdentityId identity,
            identity::provider::ProviderId provider,
            identity::provider::AssuranceLevel assurance,
            identity::provider::AuthenticationStrength strength,
            foundation::Instant authenticatedAt, TokenDigest tokenDigest,
            foundation::Instant issuedAt, foundation::Instant absoluteExpiresAt,
            foundation::Duration idleTimeout,
            std::optional<std::string> userAgent,
            std::optional<std::string> remoteAddress);

    SessionId m_id;
    identity::core::IdentityId m_identity;
    identity::provider::ProviderId m_provider;
    identity::provider::AssuranceLevel m_assurance{identity::provider::AssuranceLevel::Ial0};
    identity::provider::AuthenticationStrength m_strength;
    SessionState m_state{SessionState::Active};
    foundation::Instant m_authenticatedAt{};
    TokenDigest m_tokenDigest{security::Sha256Digest{}};
    foundation::Instant m_issuedAt{};
    foundation::Instant m_lastSeenAt{};
    foundation::Instant m_absoluteExpiresAt{};
    foundation::Duration m_idleTimeout{};
    std::optional<foundation::Instant> m_revokedAt;
    std::optional<std::string> m_userAgent;
    std::optional<std::string> m_remoteAddress;
};

}

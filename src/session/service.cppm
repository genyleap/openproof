module;

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.session:service;

import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

import :model;
import :repository;

export namespace openproof::session {

class SessionKey final {
public:
    [[nodiscard]] static foundation::Result<SessionKey>
    create(foundation::SecretString secret);

    SessionKey(const SessionKey&) = delete;
    SessionKey& operator=(const SessionKey&) = delete;
    SessionKey(SessionKey&&) noexcept = default;
    SessionKey& operator=(SessionKey&&) noexcept = default;

private:
    friend class SessionService;
    explicit SessionKey(foundation::SecretString secret);
    foundation::SecretString m_secret;
};

class SessionPolicy final {
public:
    [[nodiscard]] static foundation::Result<SessionPolicy>
    create(foundation::Duration absoluteLifetime, foundation::Duration idleTimeout);

    [[nodiscard]] foundation::Duration absoluteLifetime() const noexcept;
    [[nodiscard]] foundation::Duration idleTimeout() const noexcept;

private:
    SessionPolicy(foundation::Duration absoluteLifetime, foundation::Duration idleTimeout) noexcept;
    foundation::Duration m_absoluteLifetime{};
    foundation::Duration m_idleTimeout{};
};

class SessionGrant final {
public:
    SessionGrant(const SessionGrant&) = delete;
    SessionGrant& operator=(const SessionGrant&) = delete;
    SessionGrant(SessionGrant&&) noexcept = default;
    SessionGrant& operator=(SessionGrant&&) noexcept = default;

    [[nodiscard]] const SessionId& id() const noexcept;
    [[nodiscard]] const foundation::SecretString& token() const noexcept;

private:
    friend class SessionService;
    SessionGrant(SessionId id, foundation::SecretString token);
    SessionId m_id;
    foundation::SecretString m_token;
};

/** @brief Session accepted by the repository after expiry and revocation checks. */
class AuthenticatedSession final {
public:
    [[nodiscard]] static foundation::Result<AuthenticatedSession>
    fromDelegatedAccess(identity::core::IdentityId identity,
                        identity::provider::ProviderId provider,
                        identity::provider::AssuranceLevel assurance,
                        identity::provider::AuthenticationStrength strength,
                        foundation::Instant authenticatedAt,
                        foundation::Instant now,
                        foundation::Instant expiresAt);

    [[nodiscard]] const Session& session() const noexcept;

private:
    friend class SessionService;
    explicit AuthenticatedSession(Session session);
    Session m_session;
};

/** @brief Sender-constraining mechanism carried by delegated OAuth access. */
enum class DelegatedSenderConstraintKind { Dpop, Mtls };

/** @brief Trusted proof-of-possession binding attached to a delegated token family. */
class DelegatedSenderConstraint final {
public:
    DelegatedSenderConstraint(DelegatedSenderConstraintKind kind, std::string value);
    [[nodiscard]] DelegatedSenderConstraintKind kind() const noexcept;
    [[nodiscard]] std::string_view value() const noexcept;
private:
    DelegatedSenderConstraintKind m_kind{DelegatedSenderConstraintKind::Dpop};
    std::string m_value;
};

/** @brief Trusted delegated OAuth access accepted by the gateway. */
class DelegatedAccess final {
public:
    DelegatedAccess(AuthenticatedSession authenticated, std::string clientId,
                    std::vector<std::string> scopes,
                    std::vector<std::string> audiences = {},
                    std::optional<DelegatedSenderConstraint> senderConstraint = std::nullopt);

    [[nodiscard]] const AuthenticatedSession& authenticated() const noexcept;
    [[nodiscard]] std::string_view clientId() const noexcept;
    [[nodiscard]] const std::vector<std::string>& scopes() const noexcept;
    [[nodiscard]] const std::vector<std::string>& audiences() const noexcept;
    [[nodiscard]] const std::optional<DelegatedSenderConstraint>& senderConstraint() const noexcept;
    [[nodiscard]] bool permits(std::string_view scope) const noexcept;
    [[nodiscard]] bool permitsAudience(std::string_view audience) const noexcept;

private:
    AuthenticatedSession m_authenticated;
    std::string m_clientId;
    std::vector<std::string> m_scopes;
    std::vector<std::string> m_audiences;
    std::optional<DelegatedSenderConstraint> m_senderConstraint;
};

/** @brief Port implemented by token services that authenticate delegated bearer access. */
class DelegatedAccessAuthenticator {
public:
    DelegatedAccessAuthenticator(const DelegatedAccessAuthenticator&) = delete;
    DelegatedAccessAuthenticator& operator=(const DelegatedAccessAuthenticator&) = delete;
    virtual ~DelegatedAccessAuthenticator() = default;

    [[nodiscard]] virtual foundation::Result<DelegatedAccess>
    authenticateDelegated(const foundation::SecretString& token) = 0;

protected:
    DelegatedAccessAuthenticator() = default;
};

class SessionService final {
public:
    SessionService(SessionRepository& sessions, const foundation::ClockSource& clock, SessionKey key, SessionPolicy policy);
    SessionService(const SessionService&) = delete;
    SessionService& operator=(const SessionService&) = delete;
    SessionService(SessionService&&) = delete;
    SessionService& operator=(SessionService&&) = delete;

    [[nodiscard]] foundation::Result<SessionGrant>
    issue(const authentication::VerifiedAuthentication& authentication);
    [[nodiscard]] foundation::Result<SessionGrant>
    issue(const authentication::VerifiedAuthentication& authentication,
          const identity::provider::ClientContext& client);
    [[nodiscard]] foundation::Result<AuthenticatedSession>
    authenticate(const foundation::SecretString& token);
    /**
     * @brief Accepts either an OpenProof session or delegated OAuth access.
     *
     * Native account APIs use this overload so a bearer is accepted only when
     * its token family carries the explicitly required scope. Session cookies
     * remain first-party and are not scope-limited.
     */
    [[nodiscard]] foundation::Result<AuthenticatedSession>
    authenticate(const foundation::SecretString& token,
                 DelegatedAccessAuthenticator* delegated,
                 std::string_view requiredScope);
    [[nodiscard]] foundation::Result<SessionGrant>
    rotate(const foundation::SecretString& token);
    [[nodiscard]] foundation::Status revoke(const SessionId& id);
    [[nodiscard]] foundation::Result<std::size_t>
    revokeAll(const identity::core::IdentityId& identity);
    [[nodiscard]] foundation::Result<std::vector<Session>>
    list(const identity::core::IdentityId& identity) const;
    [[nodiscard]] foundation::Status
    revokeOwned(const identity::core::IdentityId& identity, const SessionId& id);

private:
    [[nodiscard]] foundation::Result<TokenDigest>
    digest(const foundation::SecretString& token) const;

    SessionRepository& m_sessions;
    const foundation::ClockSource& m_clock;
    SessionKey m_key;
    SessionPolicy m_policy;
};

}

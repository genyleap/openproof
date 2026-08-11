module;

#include <cstddef>

export module openproof.session:service;

import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;

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
    SessionPolicy(foundation::Duration absoluteLifetime,
                  foundation::Duration idleTimeout) noexcept;
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
    [[nodiscard]] const Session& session() const noexcept;

private:
    friend class SessionService;
    explicit AuthenticatedSession(Session session);
    Session m_session;
};

class SessionService final {
public:
    SessionService(SessionRepository& sessions, const foundation::ClockSource& clock,
                   SessionKey key, SessionPolicy policy);

    SessionService(const SessionService&) = delete;
    SessionService& operator=(const SessionService&) = delete;
    SessionService(SessionService&&) = delete;
    SessionService& operator=(SessionService&&) = delete;

    [[nodiscard]] foundation::Result<SessionGrant>
    issue(const authentication::VerifiedAuthentication& authentication);
    [[nodiscard]] foundation::Result<AuthenticatedSession>
    authenticate(const foundation::SecretString& token);
    [[nodiscard]] foundation::Result<SessionGrant>
    rotate(const foundation::SecretString& token);
    [[nodiscard]] foundation::Status revoke(const SessionId& id);
    [[nodiscard]] foundation::Result<std::size_t>
    revokeAll(const identity::core::IdentityId& identity);

private:
    [[nodiscard]] foundation::Result<TokenDigest>
    digest(const foundation::SecretString& token) const;

    SessionRepository& m_sessions;
    const foundation::ClockSource& m_clock;
    SessionKey m_key;
    SessionPolicy m_policy;
};

}

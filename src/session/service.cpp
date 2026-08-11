module;

#include <chrono>
#include <cstddef>
#include <string>
#include <utility>

module openproof.session;

import openproof.security;

namespace openproof::session {

namespace {

constexpr std::size_t kMinimumKeyBytes = 32U;
constexpr std::size_t kTokenEntropyBytes = 32U;
constexpr std::size_t kIdentifierEntropyBytes = 32U;

[[nodiscard]] foundation::Error invalidToken(std::string detail)
{
    return foundation::Error{
        foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(
            foundation::ErrorCode::AuthenticationFailed)},
        std::move(detail)};
}

}

SessionKey::SessionKey(foundation::SecretString secret)
    : m_secret(std::move(secret))
{
}

foundation::Result<SessionKey> SessionKey::create(foundation::SecretString secret)
{
    if (secret.expose().size() < kMinimumKeyBytes) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A session key must contain at least 32 bytes.");
    }
    return SessionKey{std::move(secret)};
}

SessionPolicy::SessionPolicy(foundation::Duration absoluteLifetime,
                             foundation::Duration idleTimeout) noexcept
    : m_absoluteLifetime(absoluteLifetime)
    , m_idleTimeout(idleTimeout)
{
}

foundation::Result<SessionPolicy> SessionPolicy::create(
    foundation::Duration absoluteLifetime, foundation::Duration idleTimeout)
{
    if (absoluteLifetime <= foundation::Duration::zero()
        || idleTimeout <= foundation::Duration::zero()
        || idleTimeout > absoluteLifetime) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "Session lifetimes must be positive and idle timeout must not exceed absolute lifetime.");
    }
    return SessionPolicy{absoluteLifetime, idleTimeout};
}

foundation::Duration SessionPolicy::absoluteLifetime() const noexcept
{
    return m_absoluteLifetime;
}

foundation::Duration SessionPolicy::idleTimeout() const noexcept
{
    return m_idleTimeout;
}

SessionGrant::SessionGrant(SessionId id, foundation::SecretString token)
    : m_id(std::move(id))
    , m_token(std::move(token))
{
}

const SessionId& SessionGrant::id() const noexcept { return m_id; }
const foundation::SecretString& SessionGrant::token() const noexcept { return m_token; }

AuthenticatedSession::AuthenticatedSession(Session session)
    : m_session(std::move(session))
{
}

const Session& AuthenticatedSession::session() const noexcept { return m_session; }

SessionService::SessionService(SessionRepository& sessions,
                               const foundation::ClockSource& clock,
                               SessionKey key, SessionPolicy policy)
    : m_sessions(sessions)
    , m_clock(clock)
    , m_key(std::move(key))
    , m_policy(policy)
{
}

foundation::Result<TokenDigest>
SessionService::digest(const foundation::SecretString& token) const
{
    if (token.empty()) {
        return foundation::fail(invalidToken("An empty session token was presented."));
    }
    foundation::Result<security::Sha256Digest> calculated =
        security::hmacSha256(m_key.m_secret, token.expose());
    if (!calculated.has_value()) {
        return foundation::fail(calculated.error());
    }
    return TokenDigest{calculated.value()};
}

foundation::Result<SessionGrant> SessionService::issue(
    const authentication::VerifiedAuthentication& authentication)
{
    foundation::Result<std::string> generatedId =
        security::randomTokenBase64Url(kIdentifierEntropyBytes);
    if (!generatedId.has_value()) {
        return foundation::fail(generatedId.error());
    }
    foundation::Result<std::string> generatedToken =
        security::randomTokenBase64Url(kTokenEntropyBytes);
    if (!generatedToken.has_value()) {
        return foundation::fail(generatedToken.error());
    }

    SessionId id{std::move(generatedId).value()};
    foundation::SecretString token{std::move(generatedToken).value()};
    foundation::Result<TokenDigest> fingerprint = digest(token);
    if (!fingerprint.has_value()) {
        return foundation::fail(fingerprint.error());
    }
    const foundation::Instant now = m_clock.now();
    const identity::provider::AuthenticationOutcome& outcome = authentication.outcome();
    foundation::Result<Session> session = Session::create(
        id, authentication.identity(), outcome.provider(), outcome.claimedAssurance(),
        outcome.strength(), outcome.verifiedAt(), fingerprint.value(), now,
        m_policy.absoluteLifetime(), m_policy.idleTimeout());
    if (!session.has_value()) {
        return foundation::fail(session.error());
    }
    const foundation::Status stored = m_sessions.add(std::move(session).value());
    if (!stored.has_value()) {
        return foundation::fail(stored.error());
    }
    return SessionGrant{std::move(id), std::move(token)};
}

foundation::Result<AuthenticatedSession> SessionService::authenticate(
    const foundation::SecretString& token)
{
    foundation::Result<TokenDigest> fingerprint = digest(token);
    if (!fingerprint.has_value()) {
        return foundation::fail(fingerprint.error());
    }
    foundation::Result<Session> session = m_sessions.use(fingerprint.value(), m_clock.now());
    if (!session.has_value()) {
        return foundation::fail(session.error());
    }
    return AuthenticatedSession{std::move(session).value()};
}

foundation::Result<SessionGrant> SessionService::rotate(
    const foundation::SecretString& token)
{
    foundation::Result<TokenDigest> oldFingerprint = digest(token);
    if (!oldFingerprint.has_value()) {
        return foundation::fail(oldFingerprint.error());
    }
    foundation::Result<Session> current =
        m_sessions.use(oldFingerprint.value(), m_clock.now());
    if (!current.has_value()) {
        return foundation::fail(current.error());
    }
    foundation::Result<std::string> generated =
        security::randomTokenBase64Url(kTokenEntropyBytes);
    if (!generated.has_value()) {
        return foundation::fail(generated.error());
    }
    foundation::SecretString replacement{std::move(generated).value()};
    foundation::Result<TokenDigest> replacementFingerprint = digest(replacement);
    if (!replacementFingerprint.has_value()) {
        return foundation::fail(replacementFingerprint.error());
    }
    const foundation::Status rotated =
        m_sessions.rotate(current->id(), oldFingerprint.value(),
                          replacementFingerprint.value(), m_clock.now());
    if (!rotated.has_value()) {
        return foundation::fail(rotated.error());
    }
    return SessionGrant{current->id(), std::move(replacement)};
}

foundation::Status SessionService::revoke(const SessionId& id)
{
    return m_sessions.revoke(id, m_clock.now());
}

foundation::Result<std::size_t>
SessionService::revokeAll(const identity::core::IdentityId& identity)
{
    return m_sessions.revokeAll(identity, m_clock.now());
}

}

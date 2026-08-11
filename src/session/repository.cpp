module;

#include <cstddef>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

module openproof.session;

namespace openproof::session {

namespace {

[[nodiscard]] foundation::Error unknownSession(std::string detail)
{
    return foundation::Error{
        foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(
            foundation::ErrorCode::AuthenticationFailed)},
        std::move(detail)};
}

}

foundation::Status InMemorySessionRepository::add(Session session)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    if (m_sessions.contains(session.id()) || m_tokens.contains(session.tokenDigest())) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The session could not be created.");
    }
    const SessionId id = session.id();
    const TokenDigest digest = session.tokenDigest();
    m_sessions.emplace(id, std::move(session));
    m_tokens.emplace(digest, id);
    return foundation::ok();
}

foundation::Result<Session> InMemorySessionRepository::use(const TokenDigest& token,
                                                           foundation::Instant now)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    const auto indexed = m_tokens.find(token);
    if (indexed == m_tokens.end()) {
        return foundation::fail(unknownSession("Session token is unknown."));
    }
    const auto position = m_sessions.find(indexed->second);
    if (position == m_sessions.end()) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "The session store is inconsistent.");
    }
    const foundation::Status used = position->second.use(token, now);
    if (!used.has_value()) {
        return foundation::fail(used.error());
    }
    Session snapshot{position->second};
    return foundation::Result<Session>{std::move(snapshot)};
}

foundation::Status InMemorySessionRepository::rotate(
    const SessionId& id, const TokenDigest& expected,
    TokenDigest replacement, foundation::Instant now)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    const auto position = m_sessions.find(id);
    if (position == m_sessions.end()) {
        return foundation::fail(unknownSession("Session rotation refused: unknown id."));
    }
    if (m_tokens.contains(replacement)) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The session token could not be rotated.");
    }
    const TokenDigest old = position->second.tokenDigest();
    const foundation::Status rotated =
        position->second.rotateToken(expected, replacement, now);
    if (!rotated.has_value()) {
        return foundation::fail(rotated.error());
    }
    m_tokens.erase(old);
    m_tokens.emplace(std::move(replacement), id);
    return foundation::ok();
}

foundation::Status InMemorySessionRepository::revoke(const SessionId& id,
                                                      foundation::Instant now)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    const auto position = m_sessions.find(id);
    if (position == m_sessions.end()) {
        return foundation::fail(foundation::ErrorCode::NotFound,
                                "That session was not found.");
    }
    return position->second.revoke(now);
}

foundation::Result<std::size_t> InMemorySessionRepository::revokeAll(
    const identity::core::IdentityId& identity, foundation::Instant now)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    std::size_t revoked = 0;
    for (auto& [id, session] : m_sessions) {
        static_cast<void>(id);
        if (session.identity() == identity && session.state() == SessionState::Active) {
            const foundation::Status status = session.revoke(now);
            if (!status.has_value()) {
                return foundation::fail(status.error());
            }
            ++revoked;
        }
    }
    return revoked;
}

foundation::Result<std::optional<Session>>
InMemorySessionRepository::find(const SessionId& id) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    const auto position = m_sessions.find(id);
    if (position == m_sessions.end()) {
        return std::optional<Session>{};
    }
    return std::optional<Session>{position->second};
}

std::size_t InMemorySessionRepository::purgeExpired(foundation::Instant now)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    std::size_t removed = 0;
    for (auto position = m_sessions.begin(); position != m_sessions.end();) {
        if (position->second.isExpiredAt(now)) {
            m_tokens.erase(position->second.tokenDigest());
            position = m_sessions.erase(position);
            ++removed;
        } else {
            ++position;
        }
    }
    return removed;
}

std::size_t InMemorySessionRepository::size() const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    return m_sessions.size();
}

}

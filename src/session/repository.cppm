module;

#include <cstddef>
#include <map>
#include <mutex>
#include <optional>
#include <vector>

export module openproof.session:repository;

import openproof.foundation;
import openproof.identity.core;

import :model;

export namespace openproof::session {

/**
 * @brief Atomic persistence contract for revocable sessions.
 *
 * Token lookup and last-seen update are one operation. Rotation invalidates the
 * old digest and installs the new one under the same lock/transaction.
 */
class SessionRepository {
public:
    SessionRepository(const SessionRepository&) = delete;
    SessionRepository& operator=(const SessionRepository&) = delete;
    SessionRepository(SessionRepository&&) = delete;
    SessionRepository& operator=(SessionRepository&&) = delete;
    virtual ~SessionRepository() = default;

    [[nodiscard]] virtual foundation::Status add(Session session) = 0;
    [[nodiscard]] virtual foundation::Result<Session>
    use(const TokenDigest& token, foundation::Instant now) = 0;
    [[nodiscard]] virtual foundation::Status
    rotate(const SessionId& id, const TokenDigest& expected, TokenDigest replacement, foundation::Instant now) = 0;
    [[nodiscard]] virtual foundation::Status revoke(const SessionId& id, foundation::Instant now) = 0;
    [[nodiscard]] virtual foundation::Result<std::size_t>
    revokeAll(const identity::core::IdentityId& identity, foundation::Instant now) = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<Session>> find(const SessionId& id) const = 0;
    [[nodiscard]] virtual foundation::Result<std::vector<Session>>
    list(const identity::core::IdentityId& identity) const = 0;
    [[nodiscard]] virtual std::size_t purgeExpired(foundation::Instant now) = 0;
    [[nodiscard]] virtual std::size_t size() const = 0;

protected:
    SessionRepository() = default;
};

class InMemorySessionRepository final : public SessionRepository {
public:
    [[nodiscard]] foundation::Status add(Session session) override;
    [[nodiscard]] foundation::Result<Session>
    use(const TokenDigest& token, foundation::Instant now) override;
    [[nodiscard]] foundation::Status
    rotate(const SessionId& id, const TokenDigest& expected, TokenDigest replacement, foundation::Instant now) override;
    [[nodiscard]] foundation::Status revoke(const SessionId& id, foundation::Instant now) override;
    [[nodiscard]] foundation::Result<std::size_t>
    revokeAll(const identity::core::IdentityId& identity, foundation::Instant now) override;
    [[nodiscard]] foundation::Result<std::optional<Session>>
    find(const SessionId& id) const override;
    [[nodiscard]] foundation::Result<std::vector<Session>>
    list(const identity::core::IdentityId& identity) const override;
    [[nodiscard]] std::size_t purgeExpired(foundation::Instant now) override;
    [[nodiscard]] std::size_t size() const override;

private:
    mutable std::mutex m_mutex;
    std::map<SessionId, Session> m_sessions;
    std::map<TokenDigest, SessionId> m_tokens;
};

}

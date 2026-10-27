#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <optional>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

// The complete standard/Asio include set must precede GCC 16 module imports.
#include "coroutine_session_service.hpp"

import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.security;
import openproof.session;

namespace openproof::storage::postgres {
namespace asio = boost::asio;
namespace {
constexpr std::size_t kEntropyBytes = 32U;

struct PreparedIssue final {
    session::Session session;
    CoroutineSessionGrant grant;
};

foundation::Result<PreparedIssue> prepareIssue(
    const authentication::VerifiedAuthentication& authentication,
    const identity::provider::ClientContext& client,
    const foundation::SecretString& key,
    const session::SessionPolicy& policy,
    foundation::Instant now)
{
    auto identifier = security::randomTokenBase64Url(kEntropyBytes);
    if (!identifier) return foundation::fail(identifier.error());
    auto randomBearer = security::randomTokenBase64Url(kEntropyBytes);
    if (!randomBearer) return foundation::fail(randomBearer.error());

    session::SessionId id{std::move(identifier).value()};
    foundation::SecretString bearer{std::move(randomBearer).value()};
    auto fingerprint = security::hmacSha256(key, bearer.expose());
    if (!fingerprint) return foundation::fail(fingerprint.error());
    const auto& outcome = authentication.outcome();
    auto value = session::Session::create(
        id, authentication.identity(), outcome.provider(),
        outcome.claimedAssurance(), outcome.strength(),
        outcome.verifiedAt(), session::TokenDigest{fingerprint.value()}, now,
        policy.absoluteLifetime(), policy.idleTimeout(),
        client.userAgent().empty()
            ? std::nullopt
            : std::optional<std::string>{std::string{client.userAgent()}},
        client.remoteAddress().empty()
            ? std::nullopt
            : std::optional<std::string>{std::string{client.remoteAddress()}});
    if (!value) return foundation::fail(value.error());

    return PreparedIssue{std::move(value).value(),
                         CoroutineSessionGrant{std::move(id), std::move(bearer)}};
}

[[gnu::noinline]] asio::awaitable<foundation::Result<CoroutineSessionGrant>> persistIssue(
    CoroutinePostgresSessionRepository& repo,
    foundation::Result<PreparedIssue> prepared)
{
    if (!prepared) co_return foundation::fail(prepared.error());
    auto item = std::move(prepared).value();
    auto saved = co_await repo.add(std::move(item.session));
    if (!saved) co_return foundation::fail(saved.error());
    co_return std::move(item.grant);
}

[[gnu::noinline]] asio::awaitable<foundation::Result<CoroutineSessionGrant>> persistReplacing(
    CoroutinePostgresSessionRepository& repo,
    const foundation::ClockSource& clock,
    foundation::Result<PreparedIssue> prepared,
    std::optional<session::TokenDigest> oldDigest)
{
    if (!prepared) co_return foundation::fail(prepared.error());
    std::optional<session::SessionId> previousId;
    if (oldDigest) {
        auto previous = co_await repo.use(*oldDigest, clock.now());
        if (previous) {
            previousId = previous->id();
        } else if (previous.error().code()
                   != foundation::ErrorCode::AuthenticationFailed) {
            // An unavailable database or invalid persisted row is not an
            // "invalid old cookie"; don't issue a new bearer on uncertainty.
            co_return foundation::fail(previous.error());
        }
    }

    auto item = std::move(prepared).value();
    auto saved = co_await repo.add(std::move(item.session));
    if (!saved) co_return foundation::fail(saved.error());
    if (previousId && *previousId != item.grant.id()) {
        auto revoked = co_await repo.revoke(*previousId, clock.now());
        if (!revoked) {
            // Never disclose the newly persisted bearer when replacement of
            // the previous browser session was unsuccessful.
            static_cast<void>(co_await repo.revoke(item.grant.id(), clock.now()));
            co_return foundation::fail(revoked.error());
        }
    }
    co_return std::move(item.grant);
}

asio::awaitable<foundation::Result<CoroutineSessionGrant>> rotateDigest(
    CoroutinePostgresSessionRepository& repo,
    const foundation::ClockSource& clock,
    const foundation::SecretString& key,
    session::TokenDigest previous)
{
    auto active = co_await repo.use(previous, clock.now());
    if (!active) co_return foundation::fail(active.error());

    auto randomBearer = security::randomTokenBase64Url(kEntropyBytes);
    if (!randomBearer) co_return foundation::fail(randomBearer.error());
    foundation::SecretString replacement{std::move(randomBearer).value()};
    auto next = security::hmacSha256(key, replacement.expose());
    if (!next) co_return foundation::fail(next.error());

    session::SessionId id = active->id();
    auto rotated = co_await repo.rotate(
        id, std::move(previous), session::TokenDigest{next.value()},
        clock.now());
    if (!rotated) co_return foundation::fail(rotated.error());
    co_return CoroutineSessionGrant{std::move(id), std::move(replacement)};
}

asio::awaitable<foundation::Result<std::vector<session::Session>>>
listActiveSessions(
    CoroutinePostgresSessionRepository& repo,
    const foundation::ClockSource& clock,
    identity::core::IdentityId identity)
{
    auto values = co_await repo.list(std::move(identity));
    if (!values) co_return foundation::fail(values.error());
    const auto now = clock.now();
    std::erase_if(values.value(), [now](const session::Session& value) {
        return value.state() != session::SessionState::Active
            || value.isExpiredAt(now);
    });
    std::ranges::sort(values.value(),
                      [](const session::Session& left, const session::Session& right) {
        return left.lastSeenAt() > right.lastSeenAt();
    });
    co_return values;
}

asio::awaitable<foundation::Status> revokeOwnedSession(
    CoroutinePostgresSessionRepository& repo,
    const foundation::ClockSource& clock,
    identity::core::IdentityId identity,
    session::SessionId id)
{
    auto found = co_await repo.find(id);
    if (!found) co_return foundation::fail(found.error());
    if (!found->has_value() || found->value().identity() != identity) {
        // Do not disclose the existence of another identity's session.
        co_return foundation::fail(
            foundation::ErrorCode::NotFound, "That session was not found.");
    }
    co_return co_await repo.revoke(std::move(id), clock.now());
}
} // namespace

CoroutineSessionGrant::CoroutineSessionGrant(
    session::SessionId id, foundation::SecretString bearer)
    : m_id(std::move(id)), m_bearer(std::move(bearer)) {}

const session::SessionId& CoroutineSessionGrant::id() const noexcept
{
    return m_id;
}
const foundation::SecretString& CoroutineSessionGrant::token() const noexcept
{
    return m_bearer;
}

CoroutinePostgresSessionService::CoroutinePostgresSessionService(
    CoroutinePostgresSessionRepository& repository,
    const foundation::ClockSource& clock,
    foundation::SecretString key,
    session::SessionPolicy policy)
    : m_repository(&repository), m_clock(&clock), m_key(std::move(key)),
      m_policy(std::move(policy)),
      m_authenticator(repository, clock, m_key.clone()) {}

asio::awaitable<foundation::Result<CoroutineSessionGrant>>
CoroutinePostgresSessionService::issue(
    const authentication::VerifiedAuthentication& verification,
    const identity::provider::ClientContext& client)
{
    return persistIssue(*m_repository, prepareIssue(
        verification, client, m_key, m_policy, m_clock->now()));
}

asio::awaitable<foundation::Result<CoroutineSessionGrant>>
CoroutinePostgresSessionService::issueReplacing(
    const authentication::VerifiedAuthentication& verification,
    const identity::provider::ClientContext& client,
    const foundation::SecretString* previousToken)
{
    auto prepared = prepareIssue(
        verification, client, m_key, m_policy, m_clock->now());
    if (!prepared) return persistIssue(*m_repository, std::move(prepared));
    std::optional<session::TokenDigest> previous;
    if (previousToken && !previousToken->empty()) {
        auto fingerprint = security::hmacSha256(m_key, previousToken->expose());
        if (!fingerprint) {
            // This must not produce a new session on cryptographic failure.
            return persistIssue(*m_repository,
                foundation::fail(fingerprint.error()));
        }
        previous.emplace(session::TokenDigest{fingerprint.value()});
    }
    return persistReplacing(
        *m_repository, *m_clock, std::move(prepared), std::move(previous));
}

asio::awaitable<foundation::Result<session::Session>>
CoroutinePostgresSessionService::authenticate(foundation::SecretString bearer)
{
    return m_authenticator.authenticate(std::move(bearer));
}

asio::awaitable<foundation::Result<CoroutineSessionGrant>>
CoroutinePostgresSessionService::rotate(foundation::SecretString bearer)
{
    if (bearer.empty()) {
        return persistIssue(*m_repository,
            foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                             "The session token is invalid."));
    }
    auto fingerprint = security::hmacSha256(m_key, bearer.expose());
    if (!fingerprint) {
        return persistIssue(*m_repository, foundation::fail(fingerprint.error()));
    }
    return rotateDigest(*m_repository, *m_clock, m_key,
                        session::TokenDigest{fingerprint.value()});
}

asio::awaitable<foundation::Status>
CoroutinePostgresSessionService::revoke(session::SessionId id)
{
    return m_repository->revoke(std::move(id), m_clock->now());
}

asio::awaitable<foundation::Result<std::size_t>>
CoroutinePostgresSessionService::revokeAll(identity::core::IdentityId identity)
{
    return m_repository->revokeAll(std::move(identity), m_clock->now());
}

asio::awaitable<foundation::Result<std::vector<session::Session>>>
CoroutinePostgresSessionService::list(identity::core::IdentityId identity)
{
    return listActiveSessions(*m_repository, *m_clock, std::move(identity));
}

asio::awaitable<foundation::Status>
CoroutinePostgresSessionService::revokeOwned(
    identity::core::IdentityId identity, session::SessionId id)
{
    return revokeOwnedSession(
        *m_repository, *m_clock, std::move(identity), std::move(id));
}

} // namespace openproof::storage::postgres

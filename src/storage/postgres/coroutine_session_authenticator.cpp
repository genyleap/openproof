#include "async_connection.hpp"

#include <boost/asio/awaitable.hpp>

#include <stdexcept>
#include <string>
#include <utility>

// Keep transitive standard/Asio includes before C++ module imports.
#include "coroutine_session_authenticator.hpp"

import openproof.foundation;
import openproof.security;
import openproof.session;

namespace openproof::storage::postgres {
namespace asio = boost::asio;

namespace {
asio::awaitable<foundation::Result<session::Session>> rejectBearer()
{
    co_return foundation::fail(
        foundation::ErrorCode::AuthenticationFailed,
        "The session token is invalid.");
}

asio::awaitable<foundation::Result<session::Session>> rejectCryptoFailure()
{
    // A crypto-provider failure is not evidence that a bearer was invalid.
    // It is an internal service failure, not an authentication decision.
    co_return foundation::fail(
        foundation::ErrorCode::Internal,
        "The session fingerprint could not be calculated.");
}
} // namespace

CoroutineSessionAuthenticator::CoroutineSessionAuthenticator(
    CoroutinePostgresSessionRepository& repository,
    const foundation::ClockSource& clock,
    foundation::SecretString sessionKey)
    : m_repository(&repository),
      m_clock(&clock),
      m_key(std::move(sessionKey))
{
    // Same minimum key strength required by session::SessionKey::create().
    if (m_key.expose().size() < 32U) {
        throw std::invalid_argument{"A session key must contain at least 32 bytes"};
    }
}

asio::awaitable<foundation::Result<session::Session>>
CoroutineSessionAuthenticator::authenticate(foundation::SecretString bearer) const
{
    if (bearer.empty()) {
        return rejectBearer();
    }

    // The synchronous cryptographic calculation intentionally runs before
    // entering the coroutine. The raw bearer never survives an I/O suspend.
    const auto fingerprint = security::hmacSha256(m_key, bearer.expose());
    if (!fingerprint) {
        return rejectCryptoFailure();
    }
    return authorizeDigest(session::TokenDigest{fingerprint.value()},
                           m_clock->now());
}

asio::awaitable<foundation::Result<session::Session>>
CoroutineSessionAuthenticator::authorizeDigest(
    session::TokenDigest digest, foundation::Instant now) const
{
    // This awaits the real nonblocking pool and libpq transport. Unlike a
    // posted synchronous callback, no repository worker is blocked on SQL.
    co_return co_await m_repository->use(std::move(digest), now);
}

} // namespace openproof::storage::postgres

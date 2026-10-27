#pragma once

// Native asynchronous bearer-to-session boundary. No raw bearer or HMAC key
// enters libpq, structured error messages, or public protocol serialization.
// The caller must keep repository, clock and this authenticator alive until
// every awaitable returned by authenticate() has completed.
#include "coroutine_session_repository.hpp"

namespace openproof::storage::postgres {

class CoroutineSessionAuthenticator final {
public:
    CoroutineSessionAuthenticator(
        CoroutinePostgresSessionRepository& repository,
        const foundation::ClockSource& clock,
        foundation::SecretString sessionKey);
    CoroutineSessionAuthenticator(const CoroutineSessionAuthenticator&) = delete;
    CoroutineSessionAuthenticator& operator=(const CoroutineSessionAuthenticator&) = delete;
    CoroutineSessionAuthenticator(CoroutineSessionAuthenticator&&) = delete;
    CoroutineSessionAuthenticator& operator=(CoroutineSessionAuthenticator&&) = delete;

    // Own the raw bearer until its HMAC is calculated (before suspension).
    // Return the real domain Session, validated by the native SQL repository.
    // The public SessionService / HTTP path is NOT wired to this yet.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<session::Session>>
    authenticate(foundation::SecretString bearer) const;

private:
    [[nodiscard]] boost::asio::awaitable<foundation::Result<session::Session>>
    authorizeDigest(session::TokenDigest digest,
                    foundation::Instant now) const;

    CoroutinePostgresSessionRepository* m_repository;
    const foundation::ClockSource* m_clock;
    foundation::SecretString m_key;
};

} // namespace openproof::storage::postgres

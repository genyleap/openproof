#pragma once

// Transitional coroutine application service, deliberately outside the
// protocol's portable C++ modules. Never call legacy blocking PostgreSQL
// repositories from an Asio worker.
#include <boost/asio/awaitable.hpp>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "coroutine_session_authenticator.hpp"

import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.session;

namespace openproof::storage::postgres {

class CoroutineSessionGrant final {
public:
    CoroutineSessionGrant(session::SessionId id,
                          foundation::SecretString bearer);
    CoroutineSessionGrant(const CoroutineSessionGrant&) = delete;
    CoroutineSessionGrant& operator=(const CoroutineSessionGrant&) = delete;
    CoroutineSessionGrant(CoroutineSessionGrant&&) noexcept = default;
    CoroutineSessionGrant& operator=(CoroutineSessionGrant&&) noexcept = default;

    [[nodiscard]] const session::SessionId& id() const noexcept;
    [[nodiscard]] const foundation::SecretString& token() const noexcept;

private:
    session::SessionId m_id;
    foundation::SecretString m_bearer;
};

/**
 * Nonblocking first-party session service backed by the native libpq
 * coroutine repository. Mirrors the security-relevant legacy SessionService
 * behavior, without implementing the delegated OAuth fallback.
 *
 * Not wired to live HTTP yet. Repository, clock and this service must
 * outlive every outstanding coroutine.
 */
class CoroutinePostgresSessionService final {
public:
    CoroutinePostgresSessionService(
        CoroutinePostgresSessionRepository& repository,
        const foundation::ClockSource& clock,
        foundation::SecretString key,
        session::SessionPolicy policy);
    CoroutinePostgresSessionService(const CoroutinePostgresSessionService&) = delete;
    CoroutinePostgresSessionService& operator=(const CoroutinePostgresSessionService&) = delete;
    CoroutinePostgresSessionService(CoroutinePostgresSessionService&&) = delete;
    CoroutinePostgresSessionService& operator=(CoroutinePostgresSessionService&&) = delete;

    [[nodiscard]] boost::asio::awaitable<foundation::Result<CoroutineSessionGrant>>
    issue(const authentication::VerifiedAuthentication& verification,
          const identity::provider::ClientContext& client);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<CoroutineSessionGrant>>
    issueReplacing(const authentication::VerifiedAuthentication& verification,
                   const identity::provider::ClientContext& client,
                   const foundation::SecretString* previousToken);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<session::Session>>
    authenticate(foundation::SecretString bearer);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<CoroutineSessionGrant>>
    rotate(foundation::SecretString bearer);

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    revoke(session::SessionId id);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::size_t>>
    revokeAll(identity::core::IdentityId identity);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::vector<session::Session>>>
    list(identity::core::IdentityId identity);

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    revokeOwned(identity::core::IdentityId identity, session::SessionId id);

private:
    CoroutinePostgresSessionRepository* m_repository;
    const foundation::ClockSource* m_clock;
    foundation::SecretString m_key;
    session::SessionPolicy m_policy;
    CoroutineSessionAuthenticator m_authenticator;
};

} // namespace openproof::storage::postgres

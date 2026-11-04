#include <memory>
#include <utility>

#include "coroutine_account_session_bridge.hpp"

namespace openproof::storage::postgres {

std::unique_ptr<account::http::CoroutineAccountSessionAdapter>
makeCoroutinePostgresAccountSessionAdapter(
    CoroutinePostgresSessionService& sessions,
    gateway::HttpHandler& legacyAccount,
    gateway::http::CoroutineHttpHandler& asyncFallback,
    gateway::TokenBucketRateLimiter& limiter)
{
    // The native session service already applies token fingerprinting,
    // bounded asynchronous PostgreSQL operations and identity ownership.
    // Never wrap its synchronous SessionService counterpart in a co_spawn:
    // such a bridge would still occupy a handler worker during SQL I/O.
    return std::make_unique<account::http::CoroutineAccountSessionAdapter>(
        legacyAccount, asyncFallback, limiter,
        [&sessions](foundation::SecretString bearer) {
            return sessions.authenticate(std::move(bearer));
        },
        [&sessions](identity::core::IdentityId identity) {
            return sessions.list(std::move(identity));
        },
        [&sessions](identity::core::IdentityId identity, session::SessionId id) {
            return sessions.revokeOwned(std::move(identity), std::move(id));
        });
}

} // namespace openproof::storage::postgres

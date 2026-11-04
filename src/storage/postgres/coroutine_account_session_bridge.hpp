#pragma once

#include <memory>

#include "coroutine_session_service.hpp"
#include "../../account/http/coroutine_session_http.hpp"

namespace openproof::storage::postgres {

/** Explicit dependency-injection boundary for native account session routes.
 * The Account HTTP package never imports libpq or names PostgreSQL.
 * The session service, legacy handler, downstream handler and limiter must
 * outlive all in-flight coroutine requests. This is NOT production wiring.
 */
[[nodiscard]] std::unique_ptr<account::http::CoroutineAccountSessionAdapter>
makeCoroutinePostgresAccountSessionAdapter(
    CoroutinePostgresSessionService& sessions,
    gateway::HttpHandler& legacyAccount,
    gateway::http::CoroutineHttpHandler& asyncFallback,
    gateway::TokenBucketRateLimiter& limiter);

} // namespace openproof::storage::postgres

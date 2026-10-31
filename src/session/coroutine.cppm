module;

// Keep Asio's coroutine frame declarations out of the platform-neutral
// session model partitions, and preserve the GCC16 thread context boundary.
#include <boost/asio/detail/call_stack.hpp>
#include "../gateway/asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>

export module openproof.session:coroutine;

import openproof.authentication;
import openproof.foundation;
import openproof.identity.provider;
import :model;

export namespace openproof::session {

/** A bearer that was persisted by a native asynchronous session service. */
struct CoroutineIssuedSession final {
    SessionId id;
    foundation::SecretString token;
};

/**
 * Provider-neutral capability for persisting an authenticated session without
 * synchronous repository calls on the HTTP handler executor.
 *
 * The implementation must persist the session before returning credentials,
 * fail closed on storage errors, and outlive all outstanding awaitables.
 * A synchronous SessionService is deliberately not an implementation.
 */
class CoroutineSessionIssuer {
public:
    CoroutineSessionIssuer(const CoroutineSessionIssuer&) = delete;
    CoroutineSessionIssuer& operator=(const CoroutineSessionIssuer&) = delete;
    virtual ~CoroutineSessionIssuer() = default;

    [[nodiscard]] virtual boost::asio::awaitable<
        foundation::Result<CoroutineIssuedSession>>
    issueAsync(const authentication::VerifiedAuthentication& verification,
               identity::provider::ClientContext client) = 0;

protected:
    CoroutineSessionIssuer() = default;
};

} // namespace openproof::session

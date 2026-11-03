module;

// Keep Asio's coroutine frame declarations out of the platform-neutral
// session model partitions, and preserve the GCC16 thread context boundary.
#include <boost/asio/detail/call_stack.hpp>
#include "../gateway/asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>
#include <optional>

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

/** Additional optional capability: atomic session replacement.
 *
 * Keeping this separate from CoroutineSessionIssuer preserves the original
 * SPI vtable and existing native issuers (e.g. wallet handoff). A handler
 * that requires browser re-login replacement must explicitly request this
 * stronger capability rather than assuming any issuer is sufficient.
 */
class CoroutineReplacingSessionIssuer : public CoroutineSessionIssuer {
public:
    CoroutineReplacingSessionIssuer(const CoroutineReplacingSessionIssuer&) = delete;
    CoroutineReplacingSessionIssuer& operator=(const CoroutineReplacingSessionIssuer&) = delete;
    ~CoroutineReplacingSessionIssuer() override = default;

    /** Commits the new grant and retirement of an authenticated old session
     * atomically, or creates a fresh grant if the previous bearer is invalid.
     */
    [[nodiscard]] virtual boost::asio::awaitable<
        foundation::Result<CoroutineIssuedSession>>
    issueReplacingAsync(const authentication::VerifiedAuthentication& verification,
                        identity::provider::ClientContext client,
                        std::optional<foundation::SecretString> previousToken) = 0;

protected:
    CoroutineReplacingSessionIssuer() = default;
};

} // namespace openproof::session

#pragma once

// Provider/storage-neutral native /auth/recovery-codes route. Inject ONLY
// actual awaitable session-authentication and eligibility checks: synchronous
// SPI callbacks must never be wrapped in co_return on the I/O executor.
#include <boost/asio/awaitable.hpp>

#include <functional>

#include "../../credentials/coroutine_recovery_codes.hpp"

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.session;

namespace openproof::authentication::http {

class CoroutineRecoveryCodeHttpAdapter final
    : public gateway::http::CoroutineHttpHandler {
public:
    using Authenticate = std::function<boost::asio::awaitable<
        foundation::Result<session::Session>>(foundation::SecretString)>;

    // A positive result must prove active canonical identity, an attached
    // configured local provider, existing local password and enabled TOTP
    // credentials; the second check must read fresh committed state.
    using Eligible = std::function<boost::asio::awaitable<
        foundation::Result<bool>>(identity::core::IdentityId)>;

    CoroutineRecoveryCodeHttpAdapter(
        gateway::http::CoroutineHttpHandler& nativeFallback,
        gateway::TokenBucketRateLimiter& rateLimiter,
        credentials::CoroutineRecoveryCodeService& recoveryCodes,
        Authenticate authenticate, Eligible eligible);

    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }

    [[nodiscard]] bool nativeEnabledFor(
        const gateway::HttpRequest& request) const noexcept override;

    // There is NO synchronous recovery-code compatibility path here. Existing
    // AuthenticationHttpApi still owns legacy routes on their bounded workers.
    [[nodiscard]] gateway::HttpResponse
    handle(gateway::HttpRequest request) override;

    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request) override;

private:
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    issue(gateway::HttpRequest request);

    [[nodiscard]] static gateway::HttpResponse fail(
        const foundation::Error& reason, const gateway::HttpRequest& request);

    gateway::http::CoroutineHttpHandler* m_nativeFallback;
    gateway::TokenBucketRateLimiter* m_rateLimiter;
    credentials::CoroutineRecoveryCodeService* m_recoveryCodes;
    Authenticate m_authenticate;
    Eligible m_eligible;
};

} // namespace openproof::authentication::http

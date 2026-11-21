#pragma once

// Native GET /auth/federated/start path. The legacy callback and connection
// ceremonies remain on the compatibility worker until they have equivalent
// native session issuance and full OAuth E2E acceptance.
#include <boost/asio/awaitable.hpp>

import openproof.authentication;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.provider;

namespace openproof::authentication::http {

class CoroutineFederatedStartAdapter final
    : public gateway::http::CoroutineHttpHandler {
public:
    CoroutineFederatedStartAdapter(
        AuthenticationService& authentication,
        identity::provider::ProviderRegistry& providers,
        gateway::TokenBucketRateLimiter& limiter,
        gateway::http::CoroutineHttpHandler& fallback);

    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }
    [[nodiscard]] bool nativeEnabledFor(
        const gateway::HttpRequest& request) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request) override;

private:
    AuthenticationService* m_authentication;
    identity::provider::ProviderRegistry* m_providers;
    gateway::TokenBucketRateLimiter* m_limiter;
    gateway::http::CoroutineHttpHandler* m_fallback;
};

} // namespace openproof::authentication::http

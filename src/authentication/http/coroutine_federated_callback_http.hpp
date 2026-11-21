#pragma once

// Native OAuth2 browser callback. This adapter never falls back to blocking
// provider, canonical identity or session repositories on the reactor.
#include <boost/asio/awaitable.hpp>

import openproof.authentication;
import openproof.gateway;
import openproof.gateway.http;
import openproof.session;

namespace openproof::authentication::http {

class CoroutineFederatedCallbackAdapter final
    : public gateway::http::CoroutineHttpHandler {
public:
    CoroutineFederatedCallbackAdapter(
        AuthenticationService& authentication,
        session::CoroutineReplacingSessionIssuer& sessions,
        gateway::http::CoroutineHttpHandler& fallback);

    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }
    [[nodiscard]] bool nativeEnabledFor(
        const gateway::HttpRequest& request) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request) override;

private:
    AuthenticationService* m_authentication;
    session::CoroutineReplacingSessionIssuer* m_sessions;
    gateway::http::CoroutineHttpHandler* m_fallback;
};

} // namespace openproof::authentication::http

#pragma once

// Native OAuth2 login and connection start, including single-use browser
// handoff. Delegated authentication and other provider families retain their
// compatibility paths pending full coroutine acceptance.
#include <functional>
#include <optional>
#include <string>
#include <boost/asio/awaitable.hpp>

import openproof.authentication;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.provider;
import openproof.identity.core;
import openproof.session;

namespace openproof::authentication::http {

class CoroutineFederatedStartAdapter final
    : public gateway::http::CoroutineHttpHandler {
public:
    using Authenticate = std::function<boost::asio::awaitable<
        foundation::Result<session::Session>>(foundation::SecretString)>;
    CoroutineFederatedStartAdapter(
        AuthenticationService& authentication,
        identity::provider::ProviderRegistry& providers,
        gateway::TokenBucketRateLimiter& limiter,
        gateway::http::CoroutineHttpHandler& fallback, Authenticate authenticate = {});

    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }
    [[nodiscard]] bool nativeEnabledFor(
        const gateway::HttpRequest& request) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request) override;

private:
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> startPrepared(
        gateway::HttpRequest request, identity::provider::ProviderId provider,
        std::string returnTarget, std::optional<identity::core::IdentityId> connectionTarget);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> issueHandoff(gateway::HttpRequest request);
    AuthenticationService* m_authentication;
    identity::provider::ProviderRegistry* m_providers;
    gateway::TokenBucketRateLimiter* m_limiter;
    gateway::http::CoroutineHttpHandler* m_fallback;
    Authenticate m_authenticate;
};

} // namespace openproof::authentication::http

#pragma once

// Provider-neutral, opt-in coroutine HTTP entry for account session management.
// Keep the existing AccountHttpApi and every non-session account route intact.
// Native callbacks can be bound to any real asynchronous session repository:
// this contract never imports PostgreSQL, a vendor, or an operator product.
#include <boost/asio/awaitable.hpp>

#include <functional>
#include <string>
#include <vector>

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.session;

namespace openproof::account::http {

class CoroutineAccountSessionAdapter final : public gateway::http::CoroutineHttpHandler {
public:
    using Authenticate = std::function<boost::asio::awaitable<
        foundation::Result<session::Session>>(foundation::SecretString)>;
    using List = std::function<boost::asio::awaitable<
        foundation::Result<std::vector<session::Session>>>(
            identity::core::IdentityId)>;
    using RevokeOwned = std::function<boost::asio::awaitable<foundation::Status>(
        identity::core::IdentityId, session::SessionId)>;

    CoroutineAccountSessionAdapter(
        gateway::HttpHandler& legacyAccount,
        gateway::http::CoroutineHttpHandler& asyncFallback,
        gateway::TokenBucketRateLimiter& limiter,
        Authenticate authenticate, List list, RevokeOwned revokeOwned);

    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }
    [[nodiscard]] bool nativeEnabledFor(
        const gateway::HttpRequest& request) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(
        gateway::HttpRequest request) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> handleAsync(
        gateway::HttpRequest request) override;

private:
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> sessionList(
        gateway::HttpRequest request);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> sessionRevoke(
        gateway::HttpRequest request);
    [[nodiscard]] static gateway::HttpResponse fail(
        const foundation::Error& failure, const gateway::HttpRequest& request);
    gateway::HttpHandler* m_legacyAccount;
    gateway::http::CoroutineHttpHandler* m_asyncFallback;
    gateway::TokenBucketRateLimiter* m_limiter;
    Authenticate m_authenticate;
    List m_list;
    RevokeOwned m_revokeOwned;
};

} // namespace openproof::account::http

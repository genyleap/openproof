#pragma once

#include <boost/asio/awaitable.hpp>
#include <functional>

import openproof.administration;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.session;

namespace openproof::administration::http {

// The SQL adapter must check owner membership and return the same actor in
// one tenant-scoped snapshot. No synchronous storage SPI is accepted here.
class CoroutineAdministrationReadAdapter final : public gateway::http::CoroutineHttpHandler {
public:
    using Authenticate = std::function<boost::asio::awaitable<
        foundation::Result<session::Session>>(foundation::SecretString)>;
    using Read = std::function<boost::asio::awaitable<
        foundation::Result<MemberListing>>(identity::core::IdentityId)>;

    CoroutineAdministrationReadAdapter(gateway::http::CoroutineHttpHandler& fallback,
        gateway::TokenBucketRateLimiter& limiter, Authenticate authenticate, Read read);
    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }
    [[nodiscard]] bool nativeEnabledFor(const gateway::HttpRequest& request) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request) override;

private:
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    list(gateway::HttpRequest request);
    [[nodiscard]] static gateway::HttpResponse fail(
        const foundation::Error& failure, const gateway::HttpRequest& request);
    gateway::http::CoroutineHttpHandler* m_fallback;
    gateway::TokenBucketRateLimiter* m_limiter;
    Authenticate m_authenticate;
    Read m_read;
};

} // namespace openproof::administration::http

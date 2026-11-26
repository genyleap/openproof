#pragma once

#include <boost/asio/awaitable.hpp>
#include <functional>
#include <vector>

import openproof.consent;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.session;

namespace openproof::oauth::http {

/** First-party browser consent management only. No delegated bearer access.
 * The callbacks must perform native storage I/O and tenant checks.
 */
class CoroutineConsentAdapter final : public gateway::http::CoroutineHttpHandler {
public:
    using Authenticate = std::function<boost::asio::awaitable<
        foundation::Result<session::Session>>(foundation::SecretString)>;
    using List = std::function<boost::asio::awaitable<
        foundation::Result<std::vector<consent::ConsentGrant>>>(identity::core::IdentityId)>;
    using Revoke = std::function<boost::asio::awaitable<foundation::Status>(
        consent::ConsentId, identity::core::IdentityId, foundation::Instant)>;

    CoroutineConsentAdapter(gateway::http::CoroutineHttpHandler& fallback,
        gateway::TokenBucketRateLimiter& limiter, const foundation::ClockSource& clock,
        Authenticate authenticate, List list, Revoke revoke);
    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }
    [[nodiscard]] bool nativeEnabledFor(const gateway::HttpRequest& request) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request) override;
private:
    gateway::http::CoroutineHttpHandler* m_fallback;
    gateway::TokenBucketRateLimiter* m_limiter;
    const foundation::ClockSource* m_clock;
    Authenticate m_authenticate;
    List m_list;
    Revoke m_revoke;
};

}

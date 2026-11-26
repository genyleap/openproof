#pragma once
#include <functional>
#include <optional>
#include <string>
#include <boost/asio/detail/call_stack.hpp>
#include "../../gateway/asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>

import openproof.application;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.session;

namespace openproof::application::http {
class CoroutineManagementReadAdapter final : public gateway::http::CoroutineHttpHandler {
public:
    using Authenticate=std::function<boost::asio::awaitable<foundation::Result<session::Session>>(foundation::SecretString)>;
    using Read=std::function<boost::asio::awaitable<foundation::Result<std::string>>(
        ManagementRead,identity::core::IdentityId,session::SessionId,std::optional<std::string>)>;
    CoroutineManagementReadAdapter(gateway::http::CoroutineHttpHandler& fallback,
        gateway::TokenBucketRateLimiter& limiter,Authenticate authenticate,Read read);
    [[nodiscard]] bool nativeEnabledFor(const gateway::HttpRequest&) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> handleAsync(gateway::HttpRequest) override;
private:
    gateway::http::CoroutineHttpHandler* m_fallback;
    gateway::TokenBucketRateLimiter* m_limiter;
    Authenticate m_authenticate;
    Read m_read;
};
}

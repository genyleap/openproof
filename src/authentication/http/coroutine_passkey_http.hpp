#pragma once
#include <functional>
#include <optional>
#include <vector>
#include <boost/asio/detail/call_stack.hpp>
#include "../../gateway/asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.provider.passkey;
import openproof.session;

namespace openproof::authentication::http {
class CoroutinePasskeyAccountAdapter final : public gateway::http::CoroutineHttpHandler {
public:
    using Authenticate=std::function<boost::asio::awaitable<foundation::Result<session::Session>>(foundation::SecretString)>;
    using Read=std::function<boost::asio::awaitable<foundation::Result<std::vector<provider::passkey::CredentialSummary>>>(
        identity::core::IdentityId,session::SessionId,foundation::Instant,
        std::optional<provider::passkey::RegistrationCeremony>)>;
    CoroutinePasskeyAccountAdapter(gateway::http::CoroutineHttpHandler& fallback,
        gateway::TokenBucketRateLimiter& limiter,const foundation::ClockSource& clock,
        const provider::passkey::PasskeyConfig& config,Authenticate authenticate,Read read);
    [[nodiscard]] bool nativeEnabledFor(const gateway::HttpRequest&) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> handleAsync(gateway::HttpRequest) override;
private:
    gateway::http::CoroutineHttpHandler* m_fallback;
    gateway::TokenBucketRateLimiter* m_limiter;
    const foundation::ClockSource* m_clock;
    const provider::passkey::PasskeyConfig* m_config;
    Authenticate m_authenticate;
    Read m_read;
};
}

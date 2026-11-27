#pragma once
#include <functional>
#include <memory>
#include <vector>
#include <boost/asio/detail/call_stack.hpp>
#include "../../gateway/asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>

import openproof.evidence;
import openproof.evidence.verifiers;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.session;
import openproof.trust;

namespace openproof::evidence::http {
class CoroutineEvidenceAdapter final : public gateway::http::CoroutineHttpHandler {
public:
    using Authenticate=std::function<boost::asio::awaitable<foundation::Result<session::Session>>(foundation::SecretString)>;
    using Store=std::function<boost::asio::awaitable<foundation::Result<std::vector<Evidence>>>(
        identity::core::IdentityId,session::SessionId,foundation::Instant,verification::AccountCommand)>;
    CoroutineEvidenceAdapter(gateway::http::CoroutineHttpHandler& fallback,
        gateway::TokenBucketRateLimiter& limiter,const foundation::ClockSource& clock,
        std::vector<std::unique_ptr<EvidenceVerifier>> verifiers,trust::TrustPolicy policy,
        Authenticate authenticate,Store store);
    ~CoroutineEvidenceAdapter() override;
    [[nodiscard]] bool nativeEnabledFor(const gateway::HttpRequest&) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> handleAsync(gateway::HttpRequest) override;
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
    gateway::http::CoroutineHttpHandler* m_fallback;
    gateway::TokenBucketRateLimiter* m_limiter;
    const foundation::ClockSource* m_clock;
    trust::TrustPolicy m_policy;
    Authenticate m_authenticate;
    Store m_store;
};
}

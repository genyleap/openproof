#pragma once
#include <functional>
#include <boost/asio/detail/call_stack.hpp>
#include "../../../gateway/asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.enterprise.scim;

namespace openproof::enterprise::scim::http {
class CoroutineReadAdapter final : public gateway::http::CoroutineHttpHandler {
public:
    using Read=std::function<boost::asio::awaitable<foundation::Result<ReadResult>>(ReadRequest)>;
    using Mutate=std::function<boost::asio::awaitable<foundation::Result<ReadResult>>(MutationRequest)>;
    CoroutineReadAdapter(gateway::http::CoroutineHttpHandler& fallback,
        gateway::TokenBucketRateLimiter& limiter,foundation::SecretString bearer,Read read,Mutate mutate);
    [[nodiscard]] bool nativeEnabledFor(const gateway::HttpRequest&) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> handleAsync(gateway::HttpRequest) override;
private:
    gateway::http::CoroutineHttpHandler* m_fallback;
    gateway::TokenBucketRateLimiter* m_limiter;
    foundation::SecretString m_bearer;
    Read m_read;
    Mutate m_mutate;
};
}

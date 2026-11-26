#pragma once
#include <functional>
#include <boost/asio/detail/call_stack.hpp>
#include "../../gateway/asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;

namespace openproof::operations::http {

// A readiness probe must exercise the native database pool; liveness
// remains independent of storage. No synchronous readiness fallback.
class CoroutineHealthAdapter final : public gateway::http::CoroutineHttpHandler {
public:
    using Check=std::function<boost::asio::awaitable<foundation::Status>()>;
    CoroutineHealthAdapter(gateway::http::CoroutineHttpHandler& fallback,Check check);
    [[nodiscard]] bool nativeEnabledFor(const gateway::HttpRequest&) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> handleAsync(gateway::HttpRequest) override;
private:
    gateway::http::CoroutineHttpHandler* m_fallback;
    Check m_check;
};
}

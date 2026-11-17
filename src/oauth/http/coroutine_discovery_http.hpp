#pragma once

// Read-only OAuth/OIDC discovery entry point for the native HTTP listener.
// The documents are snapshotted from the configured OpenIdProvider at server
// startup, before any request can be dispatched onto an Asio reactor.
#include <boost/asio/awaitable.hpp>

#include <string>
#include <string_view>

import openproof.gateway;
import openproof.gateway.http;

namespace openproof::oauth::http {

class CoroutineOidcDiscoveryAdapter final
    : public gateway::http::CoroutineHttpHandler {
public:
    CoroutineOidcDiscoveryAdapter(
        gateway::http::CoroutineHttpHandler& nativeFallback,
        std::string discoveryJson, std::string jwksJson);

    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }
    [[nodiscard]] bool nativeEnabledFor(
        const gateway::HttpRequest& request) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(
        gateway::HttpRequest request) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request) override;

private:
    [[nodiscard]] static bool readOnlyRoute(
        const gateway::HttpRequest& request) noexcept;
    [[nodiscard]] static gateway::HttpResponse denied();

    gateway::http::CoroutineHttpHandler* m_fallback;
    std::string m_discoveryJson;
    std::string m_jwksJson;
};

} // namespace openproof::oauth::http

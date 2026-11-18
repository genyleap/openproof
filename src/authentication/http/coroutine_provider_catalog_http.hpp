#pragma once

// Read-only public federated provider discovery. Data is snapshotted after
// registry construction and before HTTP workers start; the reactor never
// enters provider registry locks, authentication, SQL, or an HTTPS facade.
#include <boost/asio/awaitable.hpp>
#include <string>

import openproof.gateway;
import openproof.gateway.http;

namespace openproof::authentication::http {

class CoroutineProviderCatalogAdapter final
    : public gateway::http::CoroutineHttpHandler {
public:
    CoroutineProviderCatalogAdapter(
        gateway::http::CoroutineHttpHandler& fallback,
        std::string catalogJson);

    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }
    [[nodiscard]] bool nativeEnabledFor(
        const gateway::HttpRequest& request) const noexcept override;
    [[nodiscard]] gateway::HttpResponse
    handle(gateway::HttpRequest request) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request) override;

private:
    gateway::http::CoroutineHttpHandler* m_fallback;
    std::string m_catalogJson;
};

} // namespace openproof::authentication::http

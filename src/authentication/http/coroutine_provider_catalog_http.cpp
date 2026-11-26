#include "coroutine_provider_catalog_http.hpp"

#include <boost/asio/awaitable.hpp>

#include <string>
#include <utility>

namespace openproof::authentication::http {
namespace asio = boost::asio;

namespace {
[[nodiscard]] bool isCatalogRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method() == gateway::HttpMethod::Get
        && request.path() == "/auth/providers";
}

[[nodiscard]] gateway::HttpResponse denied()
{
    gateway::HttpResponse response{503, {}, {}};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    return response;
}
} // namespace

CoroutineProviderCatalogAdapter::CoroutineProviderCatalogAdapter(
    gateway::http::CoroutineHttpHandler& fallback, std::string catalogJson)
    : m_fallback(&fallback), m_catalogJson(std::move(catalogJson))
{
}

bool CoroutineProviderCatalogAdapter::nativeEnabledFor(
    const gateway::HttpRequest& request) const noexcept
{
    return isCatalogRoute(request) || m_fallback->nativeEnabledFor(request);
}

gateway::HttpResponse CoroutineProviderCatalogAdapter::handle(
    gateway::HttpRequest request)
{
    // The listener's synchronous compatibility chain is separate; a direct
    // call to this native-only wrapper must never invoke it on the reactor.
    request.wipeBody();
    request.wipeAuthorizationHeader();
    request.wipeCookieHeader();
    request.wipeTargetQuery();
    return denied();
}

asio::awaitable<gateway::HttpResponse>
CoroutineProviderCatalogAdapter::handleAsync(gateway::HttpRequest request)
{
    if (isCatalogRoute(request)) {
        // Public discovery does not need client credentials or a request body.
        request.wipeBody();
        request.wipeAuthorizationHeader();
        request.wipeCookieHeader();
        request.wipeTargetQuery();
        gateway::HttpResponse response{
            200, gateway::Headers{{"content-type", "application/json"}},
            m_catalogJson};
        response.setHeader("cache-control", "no-store");
        response.setHeader("pragma", "no-cache");
        response.setHeader("x-content-type-options", "nosniff");
        response.setHeader("referrer-policy", "no-referrer");
        co_return response;
    }
    if (!m_fallback->nativeEnabledFor(request)) {
        request.wipeBody();
        request.wipeAuthorizationHeader();
        request.wipeCookieHeader();
        request.wipeTargetQuery();
        co_return denied();
    }
    // Provider/native login credentials must survive delegation unchanged.
    co_return co_await m_fallback->handleAsync(std::move(request));
}

} // namespace openproof::authentication::http

#include "coroutine_discovery_http.hpp"

#include <boost/asio/awaitable.hpp>

#include <string>
#include <utility>

namespace openproof::oauth::http {
namespace asio = boost::asio;

CoroutineOidcDiscoveryAdapter::CoroutineOidcDiscoveryAdapter(
    gateway::http::CoroutineHttpHandler& nativeFallback,
    std::string discoveryJson, std::string jwksJson)
    : m_fallback(&nativeFallback),
      m_discoveryJson(std::move(discoveryJson)),
      m_jwksJson(std::move(jwksJson))
{
}

bool CoroutineOidcDiscoveryAdapter::readOnlyRoute(
    const gateway::HttpRequest& request) noexcept
{
    const bool method = request.method() == gateway::HttpMethod::Get
        || request.method() == gateway::HttpMethod::Options;
    return method && (request.path() == "/.well-known/openid-configuration"
        || request.path() == "/.well-known/jwks.json");
}

bool CoroutineOidcDiscoveryAdapter::nativeEnabledFor(
    const gateway::HttpRequest& request) const noexcept
{
    return readOnlyRoute(request) || m_fallback->nativeEnabledFor(request);
}

gateway::HttpResponse CoroutineOidcDiscoveryAdapter::denied()
{
    gateway::HttpResponse response{503, {}, {}};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    return response;
}

gateway::HttpResponse CoroutineOidcDiscoveryAdapter::handle(
    gateway::HttpRequest request)
{
    // Calling this compatibility method directly must never run a
    // synchronous OAuth handler on a native HTTP executor.
    request.wipeBody();
    request.wipeAuthorizationHeader();
    request.wipeCookieHeader();
    return denied();
}

asio::awaitable<gateway::HttpResponse>
CoroutineOidcDiscoveryAdapter::handleAsync(gateway::HttpRequest request)
{
    if (readOnlyRoute(request)) {
        // Discovery is anonymous and ignores request bodies and credentials.
        // Scrub material before returning a public response.
        request.wipeBody();
        request.wipeAuthorizationHeader();
        request.wipeCookieHeader();
        const bool options = request.method() == gateway::HttpMethod::Options;
        const bool discovery =
            request.path() == "/.well-known/openid-configuration";
        gateway::HttpResponse response{
            options ? 204 : 200,
            options ? gateway::Headers{}
                    : gateway::Headers{{"content-type", "application/json"}},
            options ? std::string{}
                    : std::string{discovery ? m_discoveryJson : m_jwksJson}};
        // Match OAuthHttpApi's discovery/CORS policy and avoid caching
        // confidential or stale key metadata across key rotations.
        response.setHeader("cache-control", "no-store");
        response.setHeader("pragma", "no-cache");
        response.setHeader("x-content-type-options", "nosniff");
        response.setHeader("referrer-policy", "no-referrer");
        response.setHeader("access-control-allow-origin", "*");
        response.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
        response.setHeader("access-control-allow-headers", "authorization, content-type");
        response.setHeader("access-control-max-age", "600");
        co_return response;
    }
    // Other native login paths still require their original credentials;
    // never scrub a delegated request before its provider processes it.
    if (!m_fallback->nativeEnabledFor(request)) {
        request.wipeBody();
        request.wipeAuthorizationHeader();
        request.wipeCookieHeader();
        co_return denied();
    }
    co_return co_await m_fallback->handleAsync(std::move(request));
}

} // namespace openproof::oauth::http

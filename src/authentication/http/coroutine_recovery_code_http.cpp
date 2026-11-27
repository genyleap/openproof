#include <boost/asio/awaitable.hpp>
#include <boost/json.hpp>

#include <string>
#include <utility>

#include "coroutine_recovery_code_http.hpp"

import openproof.identity.provider;

namespace openproof::authentication::http {
namespace asio = boost::asio;
namespace json = boost::json;
namespace idp = identity::provider;

namespace {
// Even rejected or rate-limited attempts must not retain request-owned
// session cookies or bearer headers until their normal string destruction.
class SensitiveSessionHeadersGuard final {
public:
    explicit SensitiveSessionHeadersGuard(gateway::HttpRequest& request) noexcept
        : m_request(request) {}
    SensitiveSessionHeadersGuard(const SensitiveSessionHeadersGuard&) = delete;
    SensitiveSessionHeadersGuard& operator=(const SensitiveSessionHeadersGuard&) = delete;
    ~SensitiveSessionHeadersGuard()
    {
        m_request.wipeAuthorizationHeader();
        m_request.wipeCookieHeader();
    }
private:
    gateway::HttpRequest& m_request;
};

[[nodiscard]] bool isRecoveryRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method() == gateway::HttpMethod::Post
        && request.path() == "/auth/recovery-codes";
}

[[nodiscard]] gateway::HttpResponse jsonResponse(int status, json::object body)
{
    gateway::HttpResponse response{status,
        gateway::Headers{{"content-type", "application/json"}},
        json::serialize(body)};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    return response;
}
} // namespace

CoroutineRecoveryCodeHttpAdapter::CoroutineRecoveryCodeHttpAdapter(
    gateway::http::CoroutineHttpHandler& fallback,
    gateway::TokenBucketRateLimiter& rateLimiter,
    credentials::CoroutineRecoveryCodeService& recoveryCodes,
    Authenticate authenticate)
    : m_nativeFallback(&fallback), m_rateLimiter(&rateLimiter),
      m_recoveryCodes(&recoveryCodes), m_authenticate(std::move(authenticate))
{
}

bool CoroutineRecoveryCodeHttpAdapter::nativeEnabledFor(
    const gateway::HttpRequest& request) const noexcept
{
    if (request.path() == "/auth/recovery-codes") {
        return isRecoveryRoute(request)
            && static_cast<bool>(m_authenticate);
    }
    return m_nativeFallback->nativeEnabledFor(request);
}

gateway::HttpResponse CoroutineRecoveryCodeHttpAdapter::fail(
    const foundation::Error& reason, const gateway::HttpRequest& request)
{
    gateway::HttpResponse response{
        foundation::errorHttpStatus(reason.code()),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(reason, request.correlation().value())};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    if (reason.code() == foundation::ErrorCode::AuthenticationRequired) {
        response.setHeader("www-authenticate", "Bearer");
    }
    return response;
}

gateway::HttpResponse CoroutineRecoveryCodeHttpAdapter::handle(
    gateway::HttpRequest request)
{
    SensitiveSessionHeadersGuard wipeHeadersOnExit{request};
    // Explicit fail-closed protection against a listener invoking the wrong
    // entry point. NEVER delegate to blocking session/local-account stores.
    return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
}

asio::awaitable<gateway::HttpResponse>
CoroutineRecoveryCodeHttpAdapter::handleAsync(gateway::HttpRequest request)
{
    SensitiveSessionHeadersGuard wipeHeadersOnExit{request};
    // Recheck capability after listener dispatch to defeat capability
    // revocation races and direct misuse of this async facade.
    if (!nativeEnabledFor(request)) {
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    }
    if (isRecoveryRoute(request)) {
        co_return co_await issue(std::move(request));
    }
    // Other explicitly native auth routes (session rotation, LDAP, Web3)
    // must retain their own capability checks. Never dispatch them synchronously.
    if (!m_nativeFallback->nativeEnabledFor(request)) {
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    }
    co_return co_await m_nativeFallback->handleAsync(std::move(request));
}

asio::awaitable<gateway::HttpResponse>
CoroutineRecoveryCodeHttpAdapter::issue(gateway::HttpRequest request)
{
    SensitiveSessionHeadersGuard wipeHeadersOnExit{request};
    const std::string limitKey{
        "auth-ip:" + std::string{request.remoteAddress()}};
    if (!m_rateLimiter->allow(limitKey)) {
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) co_return fail(credential.error(), request);
    if (!credential->has_value()) {
        co_return fail(foundation::Error{
            foundation::ErrorCode::AuthenticationRequired}, request);
    }
    auto authenticated = co_await m_authenticate(std::move(credential->value()));
    if (!authenticated) co_return fail(authenticated.error(), request);
    if (!idp::meetsAssurance(authenticated->assurance(),
                             idp::AssuranceLevel::Ial2)) {
        co_return fail(foundation::Error{
            foundation::ErrorCode::AssuranceInsufficient}, request);
    }
    // Eligibility and batch replacement share an exact generation fence.
    // A stale request must never revoke a newer batch as compensation.
    auto issued = co_await m_recoveryCodes->issueFenced(authenticated->identity(), 10U);
    if (!issued) co_return fail(issued.error(), request);

    json::array codes;
    codes.reserve(issued->size());
    for (const auto& code : issued.value()) {
        codes.emplace_back(code.expose());
    }
    co_return jsonResponse(201, json::object{{"codes", std::move(codes)}});
}

} // namespace openproof::authentication::http

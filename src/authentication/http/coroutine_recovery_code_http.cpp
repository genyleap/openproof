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
[[nodiscard]] bool isRecoveryRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method() == gateway::HttpMethod::Post
        && request.path() == "/auth/recovery-codes";
}
[[nodiscard]] bool authNamespace(const gateway::HttpRequest& request) noexcept
{
    return request.path() == "/auth"
        || request.path().starts_with("/auth/");
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
    Authenticate authenticate, Eligible eligible)
    : m_nativeFallback(&fallback), m_rateLimiter(&rateLimiter),
      m_recoveryCodes(&recoveryCodes), m_authenticate(std::move(authenticate)),
      m_eligible(std::move(eligible))
{
}

bool CoroutineRecoveryCodeHttpAdapter::nativeEnabledFor(
    const gateway::HttpRequest& request) const noexcept
{
    if (authNamespace(request)) {
        return isRecoveryRoute(request)
            && static_cast<bool>(m_authenticate)
            && static_cast<bool>(m_eligible);
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
    // Explicit fail-closed protection against a listener invoking the wrong
    // entry point. NEVER delegate to blocking session/local-account stores.
    return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
}

asio::awaitable<gateway::HttpResponse>
CoroutineRecoveryCodeHttpAdapter::handleAsync(gateway::HttpRequest request)
{
    // Recheck capability after listener dispatch to defeat capability
    // revocation races and direct misuse of this async facade.
    if (!nativeEnabledFor(request)) {
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    }
    if (isRecoveryRoute(request)) {
        co_return co_await issue(std::move(request));
    }
    // Only non-auth routes are delegated, and only to native fallback.
    if (!m_nativeFallback->nativeEnabledFor(request)) {
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    }
    co_return co_await m_nativeFallback->handleAsync(std::move(request));
}

asio::awaitable<gateway::HttpResponse>
CoroutineRecoveryCodeHttpAdapter::issue(gateway::HttpRequest request)
{
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
    auto eligible = co_await m_eligible(authenticated->identity());
    if (!eligible) co_return fail(eligible.error(), request);
    if (!eligible.value()) {
        co_return fail(foundation::Error{
            foundation::ErrorCode::FailedPrecondition}, request);
    }

    auto issued = co_await m_recoveryCodes->issue(authenticated->identity(), 10U);
    if (!issued) co_return fail(issued.error(), request);

    // Same final safety check as the legacy HTTP API. If TOTP eligibility
    // disappears while the code batch is persisted, invalidate all codes
    // before returning ANY plaintext to the client.
    auto stillEligible = co_await m_eligible(authenticated->identity());
    if (!stillEligible || !stillEligible.value()) {
        auto revoked = co_await m_recoveryCodes->revoke(authenticated->identity());
        if (!revoked) co_return fail(revoked.error(), request);
        if (!stillEligible) co_return fail(stillEligible.error(), request);
        co_return fail(foundation::Error{
            foundation::ErrorCode::FailedPrecondition}, request);
    }

    json::array codes;
    codes.reserve(issued->size());
    for (const auto& code : issued.value()) {
        codes.emplace_back(code.expose());
    }
    co_return jsonResponse(201, json::object{{"codes", std::move(codes)}});
}

} // namespace openproof::authentication::http

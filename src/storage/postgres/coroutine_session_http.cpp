#include <boost/asio/awaitable.hpp>
#include <algorithm>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "coroutine_session_http.hpp"

import openproof.foundation;
import openproof.gateway;

namespace openproof::storage::postgres {
namespace asio = boost::asio;
namespace {

[[nodiscard]] bool isSessionRoute(std::string_view path) noexcept
{
    return path == "/auth/session/rotate" || path == "/auth/logout"
        || path == "/auth/logout-all";
}

[[nodiscard]] gateway::HttpResponse safeResponse(int status, std::string body = {})
{
    gateway::HttpResponse response{
        status,
        body.empty() ? gateway::Headers{}
                     : gateway::Headers{{"content-type", "application/json"}},
        std::move(body)};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    return response;
}

[[nodiscard]] gateway::HttpResponse clientError(
    const foundation::Error& error, const gateway::HttpRequest& request)
{
    auto result = safeResponse(
        foundation::errorHttpStatus(error.code()),
        foundation::toClientJson(error, request.correlation().value()));
    if (error.code() == foundation::ErrorCode::AuthenticationRequired) {
        result.setHeader("www-authenticate", "Bearer");
    }
    return result;
}

[[nodiscard]] std::string sessionCookie(
    std::string_view bearer, std::string_view age)
{
    std::string cookie{"__Host-openproof-session="};
    cookie.append(bearer);
    cookie.append("; Path=/; Max-Age=");
    cookie.append(age);
    cookie.append("; Secure; HttpOnly; SameSite=Strict");
    return cookie;
}

asio::awaitable<gateway::HttpResponse> sessionMutation(
    CoroutinePostgresSessionService& service,
    gateway::TokenBucketRateLimiter& limiter,
    gateway::HttpRequest request)
{
    if (!limiter.allow(
            std::string{"auth-ip:"} + std::string{request.remoteAddress()})) {
        co_return clientError(
            foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    if (request.method() != gateway::HttpMethod::Post) {
        co_return clientError(
            foundation::Error{foundation::ErrorCode::NotFound}, request);
    }

    const bool rotate = request.path() == "/auth/session/rotate";
    const bool logoutAll = request.path() == "/auth/logout-all";
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) co_return clientError(credential.error(), request);
    if (!credential->has_value()) {
        if (rotate) {
            co_return clientError(
                foundation::Error{foundation::ErrorCode::AuthenticationRequired},
                request);
        }
        auto result = safeResponse(204);
        result.addHeader("set-cookie", sessionCookie("", "0"));
        co_return result;
    }

    if (rotate) {
        // Token secret is moved to the coroutine service; never returned in
        // JSON or logs. The freshly minted bearer is a cookie only.
        auto grant = co_await service.rotate(
            std::move(credential->value()));
        if (!grant) co_return clientError(grant.error(), request);
        const std::string id{grant->id().value()};
        // Do not interpolate storage-provided identifiers into JSON without
        // restricting the value to the session ID's base64url alphabet.
        const bool safeId = !id.empty() && id.size() <= 128U
            && std::all_of(id.begin(), id.end(), [](char c) {
                return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_';
            });
        if (!safeId) {
            co_return clientError(
                foundation::Error{foundation::ErrorCode::Internal}, request);
        }
        // IDs are generated as unpadded base64url from the project CSPRNG,
        // and the same implementation is used by the synchronous handler.
        auto result = safeResponse(
            200, "{\"session_id\":\"" + id + "\"}");
        result.addHeader("set-cookie",
                         sessionCookie(grant->token().expose(), "28800"));
        co_return result;
    }

    auto accepted = co_await service.authenticate(
        std::move(credential->value()));
    if (!accepted) {
        if (accepted.error().code() != foundation::ErrorCode::AuthenticationFailed
            && accepted.error().code() != foundation::ErrorCode::AuthenticationRequired) {
            co_return clientError(accepted.error(), request);
        }
    } else if (logoutAll) {
        auto result = co_await service.revokeAll(accepted->identity());
        if (!result) co_return clientError(result.error(), request);
    } else {
        auto result = co_await service.revoke(accepted->id());
        if (!result) co_return clientError(result.error(), request);
    }
    auto response = safeResponse(204);
    response.addHeader("set-cookie", sessionCookie("", "0"));
    co_return response;
}

} // namespace

CoroutineSessionHttpHandler::CoroutineSessionHttpHandler(
    CoroutinePostgresSessionService& sessions,
    gateway::TokenBucketRateLimiter& limiter,
    AsyncFallback fallback)
    : m_sessions(&sessions), m_limiter(&limiter), m_fallback(std::move(fallback))
{
    if (!m_fallback) {
        throw std::invalid_argument{"An async fallback is required"};
    }
}

asio::awaitable<gateway::HttpResponse>
CoroutineSessionHttpHandler::handleAsync(gateway::HttpRequest request)
{
    if (isSessionRoute(request.path())) {
        co_return co_await sessionMutation(
            *m_sessions, *m_limiter, std::move(request));
    }
    co_return co_await m_fallback(std::move(request));
}

} // namespace openproof::storage::postgres

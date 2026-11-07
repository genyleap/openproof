#include <boost/asio/awaitable.hpp>
#include <boost/json.hpp>

#include <algorithm>
#include <cstddef>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>

#include "coroutine_session_http.hpp"

import openproof.identity.provider;

namespace openproof::account::http {
namespace asio = boost::asio;
namespace json = boost::json;
namespace {

// Match the native SQL list ceiling without introducing a PostgreSQL
// dependency into the provider-neutral Account HTTP adapter.
constexpr std::size_t kMaximumSessionResponseRows = 256U;

[[nodiscard]] bool sessionListRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method() == gateway::HttpMethod::Get
        && request.path() == "/account/sessions";
}

[[nodiscard]] bool sessionRevokeRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method() == gateway::HttpMethod::Post
        && request.path() == "/account/sessions/revoke";
}

[[nodiscard]] bool accountNamespace(const gateway::HttpRequest& request) noexcept
{
    return request.path() == "/account"
        || request.path().starts_with("/account/");
}

[[nodiscard]] gateway::HttpResponse jsonResponse(int status, json::object body)
{
    gateway::HttpResponse response{
        status, gateway::Headers{{"content-type", "application/json"}},
        json::serialize(body)};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    return response;
}

[[nodiscard]] foundation::Result<session::SessionId> revokeTarget(
    const gateway::HttpRequest& request)
{
    // Retain the legacy AccountHttpApi's strict JSON-only single-field
    // request contract. Never accept extra fields or ambiguous identifiers.
    if (request.body().empty() || request.body().size() > 32U * 1024U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    const auto contentType = request.header("content-type");
    if (!contentType || !contentType->starts_with("application/json")) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    boost::system::error_code parseError;
    auto parsed = json::parse(request.body(), parseError);
    if (parseError || !parsed.is_object()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    const auto& object = parsed.as_object();
    if (object.size() != 1U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    const auto* value = object.if_contains("session_id");
    if (!value || !value->is_string()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    const std::string_view id{value->as_string().data(), value->as_string().size()};
    if (id.empty() || id.size() > 200U
        || std::ranges::any_of(id, [](char symbol) {
            const auto byte = static_cast<unsigned char>(symbol);
            return byte < 0x20U || byte == 0x7FU;
        })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    return session::SessionId{std::string{id}};
}

} // namespace

CoroutineAccountSessionAdapter::CoroutineAccountSessionAdapter(
    gateway::HttpHandler& legacyAccount,
    gateway::http::CoroutineHttpHandler& asyncFallback,
    gateway::TokenBucketRateLimiter& limiter,
    Authenticate authenticate, List list, RevokeOwned revokeOwned)
    : m_legacyAccount(&legacyAccount), m_asyncFallback(&asyncFallback),
      m_limiter(&limiter), m_authenticate(std::move(authenticate)),
      m_list(std::move(list)), m_revokeOwned(std::move(revokeOwned))
{
}

bool CoroutineAccountSessionAdapter::nativeEnabledFor(
    const gateway::HttpRequest& request) const noexcept
{
    if (!accountNamespace(request)) {
        return m_asyncFallback->nativeEnabledFor(request);
    }
    return static_cast<bool>(m_authenticate)
        && static_cast<bool>(m_list)
        && static_cast<bool>(m_revokeOwned)
        && (sessionListRoute(request) || sessionRevokeRoute(request));
}

gateway::HttpResponse CoroutineAccountSessionAdapter::handle(
    gateway::HttpRequest request)
{
    // The existing synchronous AccountHttpApi remains the default ABI for
    // every route until the listener explicitly selects this native adapter.
    return m_legacyAccount->handle(std::move(request));
}

gateway::HttpResponse CoroutineAccountSessionAdapter::fail(
    const foundation::Error& failure, const gateway::HttpRequest& request)
{
    gateway::HttpResponse response{
        foundation::errorHttpStatus(failure.code()),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(failure, request.correlation().value())};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    return response;
}

asio::awaitable<gateway::HttpResponse>
CoroutineAccountSessionAdapter::handleAsync(gateway::HttpRequest request)
{
    // Check again after dispatch: downstream capability may have been
    // withdrawn, or a caller may have invoked this entry point directly.
    if (!nativeEnabledFor(request)) {
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    }
    if (sessionListRoute(request)) {
        co_return co_await sessionList(std::move(request));
    }
    if (sessionRevokeRoute(request)) {
        co_return co_await sessionRevoke(std::move(request));
    }
    // Only non-account requests can reach the fallback's native entry.
    // No synchronous AccountHttpApi method executes on the reactor.
    co_return co_await m_asyncFallback->handleAsync(std::move(request));
}

asio::awaitable<gateway::HttpResponse>
CoroutineAccountSessionAdapter::sessionList(gateway::HttpRequest request)
{
    const std::string rateKey = "account:" + std::string{request.remoteAddress()}
        + ":" + std::string{request.path()};
    if (!m_limiter->allow(rateKey)) {
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) co_return fail(credential.error(), request);
    if (!credential->has_value()) {
        co_return fail(foundation::Error{foundation::ErrorCode::AuthenticationRequired}, request);
    }
    auto current = co_await m_authenticate(std::move(credential->value()));
    if (!current) co_return fail(current.error(), request);
    auto values = co_await m_list(current->identity());
    if (!values) co_return fail(values.error(), request);

    // Repository callbacks are replaceable by any asynchronous storage adapter.
    // Validate the entire result before serializing a single session: a faulty
    // tenant filter must never disclose another identity's session metadata.
    if (values->size() > kMaximumSessionResponseRows
        || std::ranges::any_of(values.value(), [&current](const session::Session& value) {
            return value.identity() != current->identity();
        })) {
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    }

    json::array sessions;
    for (const auto& value : values.value()) {
        json::object item;
        item["session_id"] = value.id().value();
        item["provider"] = value.provider().value();
        item["assurance"] =
            identity::provider::assuranceLevelName(value.assurance());
        item["phishing_resistant"] = value.strength().isPhishingResistant();
        item["issued_at_ms"] = value.issuedAt().time_since_epoch().count();
        item["last_seen_at_ms"] = value.lastSeenAt().time_since_epoch().count();
        item["absolute_expires_at_ms"] = value.absoluteExpiresAt().time_since_epoch().count();
        item["idle_expires_at_ms"] = value.idleExpiresAt().time_since_epoch().count();
        item["current"] = value.id() == current->id();
        if (value.userAgent()) item["user_agent"] = *value.userAgent();
        sessions.emplace_back(std::move(item));
    }
    co_return jsonResponse(200, json::object{{"sessions", std::move(sessions)}});
}

asio::awaitable<gateway::HttpResponse>
CoroutineAccountSessionAdapter::sessionRevoke(gateway::HttpRequest request)
{
    const std::string rateKey = "account:" + std::string{request.remoteAddress()}
        + ":" + std::string{request.path()};
    if (!m_limiter->allow(rateKey)) {
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) co_return fail(credential.error(), request);
    if (!credential->has_value()) {
        co_return fail(foundation::Error{foundation::ErrorCode::AuthenticationRequired}, request);
    }
    auto authenticated = co_await m_authenticate(std::move(credential->value()));
    if (!authenticated) co_return fail(authenticated.error(), request);
    auto target = revokeTarget(request);
    if (!target) co_return fail(target.error(), request);
    if (target.value() == authenticated->id()) {
        co_return fail(foundation::Error{
            foundation::ErrorCode::FailedPrecondition,
            "Use logout to end the current session."}, request);
    }
    auto revoked = co_await m_revokeOwned(
        authenticated->identity(), std::move(target).value());
    if (!revoked) co_return fail(revoked.error(), request);
    co_return jsonResponse(200, json::object{{"revoked", true}});
}

} // namespace openproof::account::http

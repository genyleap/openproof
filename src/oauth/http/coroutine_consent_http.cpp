#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "coroutine_consent_http.hpp"

import openproof.security;

namespace openproof::oauth::http {
namespace asio = boost::asio;
namespace {
constexpr std::string_view kSessionCookie = "__Host-openproof-session";
constexpr std::string_view kCsrfCookie = "__Host-openproof-consent-csrf";
constexpr std::size_t kMaximumForm = 16U * 1024U;
constexpr std::size_t kMaximumResponse = 4U * 1024U * 1024U;

bool listRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method() == gateway::HttpMethod::Get && request.path() == "/oauth/consents";
}
bool revokeRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method() == gateway::HttpMethod::Post && request.path() == "/oauth/consents/revoke";
}

void scrub(gateway::HttpRequest& request) noexcept
{
    request.wipeBody();
    request.wipeCookieHeader();
    request.wipeAuthorizationHeader();
    request.wipeTargetQuery();
}
struct RequestScrub {
    gateway::HttpRequest& request;
    ~RequestScrub() { scrub(request); }
};

void secure(gateway::HttpResponse& response)
{
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
}

gateway::HttpResponse fail(const foundation::Error& failure, const gateway::HttpRequest& request)
{
    gateway::HttpResponse response{foundation::errorHttpStatus(failure.code()),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(failure, request.correlation().value())};
    secure(response);
    // Preserve legacy OAuth error CORS policy; success responses are
    // deliberately not CORS-enabled for this cookie-authenticated surface.
    response.setHeader("access-control-allow-origin", "*");
    response.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
    response.setHeader("access-control-allow-headers", "authorization, content-type");
    response.setHeader("access-control-max-age", "600");
    return response;
}

std::optional<foundation::SecretString> cookieValue(
    const gateway::HttpRequest& request, std::string_view wanted, std::size_t maximum)
{
    const auto header = request.header("cookie");
    if (!header) return std::nullopt;
    std::optional<foundation::SecretString> result;
    std::size_t begin = 0U;
    while (begin <= header->size()) {
        const auto end = header->find(';', begin);
        auto item = header->substr(begin, end == std::string_view::npos ? end : end - begin);
        while (!item.empty() && (item.front() == ' ' || item.front() == '\t'))
            item.remove_prefix(1U);
        const auto equals = item.find('=');
        if (equals != std::string_view::npos && item.substr(0U, equals) == wanted) {
            const auto value = item.substr(equals + 1U);
            if (result || value.empty() || value.size() > maximum) return std::nullopt;
            result.emplace(std::string{value});
        }
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    return result;
}

std::string csrfCookie(std::string_view value, int age)
{
    return std::string{kCsrfCookie} + "=" + std::string{value}
        + "; Path=/; Max-Age=" + std::to_string(age) + "; Secure; HttpOnly; SameSite=Lax";
}

int hexValue(char value) noexcept
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

struct StringScrub {
    std::string& value;
    ~StringScrub() { foundation::secureWipe(value.data(), value.size()); }
};

foundation::Result<foundation::SecretString> decode(std::string_view encoded)
{
    std::string output;
    const StringScrub wipe{output};
    output.reserve(encoded.size());
    for (std::size_t i = 0U; i < encoded.size(); ++i) {
        char value = encoded[i];
        if (value == '+') value = ' ';
        else if (value == '%') {
            if (encoded.size() - i < 3U)
                return foundation::fail(foundation::ErrorCode::InvalidArgument);
            const int high = hexValue(encoded[i + 1U]), low = hexValue(encoded[i + 2U]);
            if (high < 0 || low < 0 || (high == 0 && low == 0))
                return foundation::fail(foundation::ErrorCode::InvalidArgument);
            value = static_cast<char>((high << 4U) | low);
            i += 2U;
        }
        if (value == '\0') return foundation::fail(foundation::ErrorCode::InvalidArgument);
        output.push_back(value);
    }
    return foundation::SecretString{std::move(output)};
}

foundation::Result<consent::ConsentId> revokeTarget(const gateway::HttpRequest& request)
{
    const auto mediaType = request.header("content-type");
    if (!mediaType || (*mediaType != "application/x-www-form-urlencoded"
        && !mediaType->starts_with("application/x-www-form-urlencoded;"))
        || request.body().empty() || request.body().size() > kMaximumForm)
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    std::map<std::string, foundation::SecretString, std::less<>> form;
    const auto encoded = request.body();
    std::size_t begin = 0U;
    while (begin <= encoded.size()) {
        const auto end = encoded.find('&', begin);
        const auto pair = encoded.substr(begin, end == std::string_view::npos ? end : end - begin);
        if (!pair.empty()) {
            const auto equals = pair.find('=');
            auto name = decode(pair.substr(0U, equals));
            auto value = decode(equals == std::string_view::npos ? std::string_view{} : pair.substr(equals + 1U));
            if (!name || !value || name->empty() || name->size() > 128U
                || form.contains(name->expose()))
                return foundation::fail(foundation::ErrorCode::InvalidArgument);
            form.emplace(std::string{name->expose()}, std::move(value).value());
        }
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    const auto id = form.find("consent_id");
    const auto csrf = form.find("csrf");
    const auto expected = cookieValue(request, kCsrfCookie, 128U);
    if (id == form.end() || id->second.empty() || id->second.size() > 200U
        || csrf == form.end() || csrf->second.empty() || csrf->second.size() > 128U
        || !expected || !security::constantTimeEquals(csrf->second.expose(), expected->expose()))
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    return consent::ConsentId{std::string{id->second.expose()}};
}

std::string scopeString(const std::vector<std::string>& scopes)
{
    std::string result;
    for (const auto& scope : scopes) {
        if (!result.empty()) result.push_back(' ');
        result.append(scope);
    }
    return result;
}
} // namespace

CoroutineConsentAdapter::CoroutineConsentAdapter(
    gateway::http::CoroutineHttpHandler& fallback, gateway::TokenBucketRateLimiter& limiter,
    const foundation::ClockSource& clock, Authenticate authenticate, List list, Revoke revoke)
    : m_fallback(&fallback), m_limiter(&limiter), m_clock(&clock),
      m_authenticate(std::move(authenticate)), m_list(std::move(list)), m_revoke(std::move(revoke))
{
}

bool CoroutineConsentAdapter::nativeEnabledFor(const gateway::HttpRequest& request) const noexcept
{
    if (listRoute(request) || revokeRoute(request))
        return m_authenticate && m_list && m_revoke;
    return m_fallback->nativeEnabledFor(request);
}

gateway::HttpResponse CoroutineConsentAdapter::handle(gateway::HttpRequest request)
{
    const RequestScrub guard{request};
    return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
}

asio::awaitable<gateway::HttpResponse>
CoroutineConsentAdapter::handleAsync(gateway::HttpRequest request)
{
    const bool listing = listRoute(request);
    const bool revoking = revokeRoute(request);
    if (!listing && !revoking && m_fallback->nativeEnabledFor(request))
        co_return co_await m_fallback->handleAsync(std::move(request));

    const RequestScrub guard{request};
    if (!listing && !revoking)
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    if (!m_authenticate || !m_list || !m_revoke)
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    if (!m_limiter->allow(std::string{"oauth-ip:"} + std::string{request.remoteAddress()}))
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited}, request);

    // The existing endpoint accepts only the first-party browser cookie.
    // Do not use a generic bearer-or-cookie helper here.
    auto credential = cookieValue(request, kSessionCookie, 4096U);
    if (!credential)
        co_return fail(foundation::Error{foundation::ErrorCode::AuthenticationRequired}, request);
    foundation::Result<consent::ConsentId> target =
        foundation::fail(foundation::ErrorCode::InvalidArgument);
    if (revoking) target = revokeTarget(request);
    scrub(request); // no form, cookie, authorization or query survives suspension
    try {
        auto current = co_await m_authenticate(std::move(*credential));
        if (!current) co_return fail(current.error(), request);
        if (revoking) {
            if (!target) co_return fail(target.error(), request);
            auto revoked = co_await m_revoke(std::move(target).value(), current->identity(), m_clock->now());
            if (!revoked) co_return fail(revoked.error(), request);
            gateway::HttpResponse response{204, {}, {}};
            secure(response);
            response.addHeader("set-cookie", csrfCookie("", 0));
            co_return response;
        }
        auto values = co_await m_list(current->identity());
        if (!values) co_return fail(values.error(), request);
        if (values->size() > 256U)
            co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
        auto random = security::randomTokenBase64Url(32U);
        if (!random) co_return fail(random.error(), request);
        foundation::SecretString csrf{std::move(random).value()};
        std::string body{"{\"csrf\":\"" + foundation::escapeJsonString(csrf.expose()) + "\",\"consents\":["};
        const auto now = m_clock->now();
        bool first = true;
        for (const auto& grant : values.value()) {
            if (grant.identity() != current->identity() || grant.scopes().empty()
                || grant.scopes().size() > 256U || grant.id().value().size() > 200U
                || grant.client().value().size() > 256U || grant.audience().size() > 2048U)
                co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
            if (!first) body.push_back(',');
            first = false;
            body += "{\"id\":\"" + foundation::escapeJsonString(grant.id().value())
                + "\",\"client_id\":\"" + foundation::escapeJsonString(grant.client().value())
                + "\",\"audience\":\"" + foundation::escapeJsonString(grant.audience())
                + "\",\"scope\":\"" + foundation::escapeJsonString(scopeString(grant.scopes()))
                + "\",\"active\":" + std::string{grant.activeAt(now) ? "true" : "false"} + "}";
            if (body.size() > kMaximumResponse)
                co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
        }
        body += "]}";
        gateway::HttpResponse response{200, gateway::Headers{{"content-type", "application/json"}},
            std::move(body)};
        secure(response);
        response.addHeader("set-cookie", csrfCookie(csrf.expose(), 600));
        co_return response;
    } catch (...) {
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    }
}
} // namespace openproof::oauth::http

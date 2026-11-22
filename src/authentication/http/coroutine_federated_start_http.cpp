#include <algorithm>
#include <cctype>
#include <cstddef>
#include <map>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <boost/asio/awaitable.hpp>

#include "coroutine_federated_start_http.hpp"

import openproof.foundation;
import openproof.security;

namespace openproof::authentication::http {
namespace {
namespace idp = identity::provider;
namespace asio = boost::asio;
using Parameters = std::map<std::string, std::string, std::less<>>;

constexpr std::string_view kContinuationCookie = "__Host-openproof-federation-continuation";
constexpr std::string_view kBindingCookie = "__Host-openproof-federation-binding";
constexpr std::string_view kTransactionCookie = "__Host-openproof-federation-transaction";
constexpr std::string_view kChallengeCookie = "__Host-openproof-federation-challenge";
constexpr std::string_view kReturnCookie = "__Host-openproof-federation-return";
constexpr std::string_view kModeCookie = "__Host-openproof-federation-mode";

// Cover early rate-limit, parser and provider failures as well as successful
// redirects. Request-owned bearer/cookie/query bytes must not be left in an
// ordinary string allocation after a native HTTP coroutine returns.
class SensitiveFederatedStartRequestGuard final {
public:
    explicit SensitiveFederatedStartRequestGuard(gateway::HttpRequest& request)
        : m_request(request) {}
    SensitiveFederatedStartRequestGuard(const SensitiveFederatedStartRequestGuard&) = delete;
    SensitiveFederatedStartRequestGuard& operator=(const SensitiveFederatedStartRequestGuard&) = delete;
    ~SensitiveFederatedStartRequestGuard() { wipe(); }
    void wipe() noexcept {
        m_request.wipeTargetQuery();
        m_request.wipeBody();
        m_request.wipeAuthorizationHeader();
        m_request.wipeCookieHeader();
    }
private:
    gateway::HttpRequest& m_request;
};


[[nodiscard]] bool isStart(const gateway::HttpRequest& request) noexcept
{
    return request.method() == gateway::HttpMethod::Get
        && request.path() == "/auth/federated/start";
}

[[nodiscard]] gateway::HttpResponse unavailable()
{
    gateway::HttpResponse response{503, {}, {}};
    response.setHeader("cache-control", "no-store");
    response.setHeader("x-content-type-options", "nosniff");
    return response;
}

void secure(gateway::HttpResponse& response)
{
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
}

[[nodiscard]] std::string cookie(
    std::string_view name, std::string_view value, int seconds,
    std::string_view sameSite = "None")
{
    return std::string{name} + "=" + std::string{value}
        + "; Path=/; Max-Age=" + std::to_string(seconds)
        + "; Secure; HttpOnly; SameSite=" + std::string{sameSite};
}

void clearState(gateway::HttpResponse& response)
{
    for (const auto name : {kContinuationCookie, kBindingCookie,
                            kTransactionCookie, kChallengeCookie,
                            kReturnCookie, kModeCookie}) {
        response.addHeader("set-cookie", cookie(name, "", 0));
    }
}

[[nodiscard]] gateway::HttpResponse denied(
    const foundation::Error& failure, const gateway::HttpRequest& request)
{
    gateway::HttpResponse response{
        foundation::errorHttpStatus(failure.code()),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(failure, request.correlation().value())};
    secure(response);
    clearState(response);
    return response;
}

[[nodiscard]] std::optional<unsigned int> hexDigit(char c) noexcept
{
    if (c >= '0' && c <= '9') return static_cast<unsigned int>(c - '0');
    if (c >= 'A' && c <= 'F') return 10U + static_cast<unsigned int>(c - 'A');
    if (c >= 'a' && c <= 'f') return 10U + static_cast<unsigned int>(c - 'a');
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string> decode(std::string_view value)
{
    std::string output;
    output.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '%') {
            if (i + 2U >= value.size()) return std::nullopt;
            const auto h = hexDigit(value[i + 1U]);
            const auto l = hexDigit(value[i + 2U]);
            if (!h || !l) return std::nullopt;
            output.push_back(static_cast<char>((*h << 4U) | *l));
            i += 2U;
        } else if (value[i] == '+') {
            output.push_back(' ');
        } else {
            output.push_back(value[i]);
        }
    }
    return output;
}

[[nodiscard]] std::optional<Parameters> query(const gateway::HttpRequest& request)
{
    const std::string_view target = request.target();
    const auto question = target.find('?');
    if (question == std::string_view::npos) return Parameters{};
    std::string_view input = target.substr(question + 1U);
    if (input.size() > 8192U) return std::nullopt;
    Parameters result;
    while (!input.empty()) {
        const auto amp = input.find('&');
        const auto pair = input.substr(0U, amp);
        const auto equals = pair.find('=');
        if (equals == std::string_view::npos) return std::nullopt;
        auto key = decode(pair.substr(0U, equals));
        auto value = decode(pair.substr(equals + 1U));
        if (!key || !value || key->empty() || result.contains(*key))
            return std::nullopt;
        result.emplace(std::move(*key), std::move(*value));
        if (amp == std::string_view::npos) break;
        input.remove_prefix(amp + 1U);
    }
    return result;
}

[[nodiscard]] bool validLocalReturn(std::string_view value) noexcept
{
    return !value.empty() && value.size() <= 2048U
        && value.front() == '/' && !value.starts_with("//")
        && !value.contains('\\')
        && std::ranges::none_of(value, [](char c) {
            const auto byte = static_cast<unsigned char>(c);
            return byte < 0x20U || byte == 0x7FU;
        });
}

[[nodiscard]] std::string encoded(std::string_view source)
{
    return foundation::toBase64Url(
        std::as_bytes(std::span{source.data(), source.size()}));
}

[[nodiscard]] idp::ClientContext clientContext(const gateway::HttpRequest& request)
{
    idp::ClientContext context;
    context.setRemoteAddress(std::string{request.remoteAddress()});
    if (const auto agent = request.header("user-agent"); agent.has_value()) {
        context.setUserAgent(std::string{agent->substr(
            0U, std::min<std::size_t>(agent->size(), 1024U))});
    }
    return context;
}

} // namespace

CoroutineFederatedStartAdapter::CoroutineFederatedStartAdapter(
    AuthenticationService& authentication,
    idp::ProviderRegistry& providers,
    gateway::TokenBucketRateLimiter& limiter,
    gateway::http::CoroutineHttpHandler& fallback)
    : m_authentication(&authentication), m_providers(&providers),
      m_limiter(&limiter), m_fallback(&fallback)
{
}

bool CoroutineFederatedStartAdapter::nativeEnabledFor(
    const gateway::HttpRequest& request) const noexcept
{
    return isStart(request) || m_fallback->nativeEnabledFor(request);
}

gateway::HttpResponse CoroutineFederatedStartAdapter::handle(
    gateway::HttpRequest request)
{
    // Never execute a synchronous provider or SQL operation through this
    // native adapter. Compatibility routes belong to the caller's overlay.
    request.wipeBody();
    request.wipeAuthorizationHeader();
    request.wipeCookieHeader();
    return unavailable();
}

asio::awaitable<gateway::HttpResponse>
CoroutineFederatedStartAdapter::handleAsync(gateway::HttpRequest request)
{
    if (!isStart(request)) {
        if (m_fallback->nativeEnabledFor(request))
            co_return co_await m_fallback->handleAsync(std::move(request));
        request.wipeBody();
        request.wipeAuthorizationHeader();
        request.wipeCookieHeader();
        co_return unavailable();
    }
    SensitiveFederatedStartRequestGuard wipeRequestOnExit{request};

    if (!m_limiter->allow(
            std::string{"federation-ip:"} + std::string{request.remoteAddress()})) {
        co_return denied(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    const auto params = query(request);
    if (!params) {
        co_return denied(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    const auto provider = params->find("provider");
    if (provider == params->end() || provider->second.empty()
        || provider->second.size() > 128U) {
        co_return denied(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    const auto redirect = params->find("return_to");
    const std::string returnTarget = redirect == params->end()
        ? "/" : redirect->second;
    if (!validLocalReturn(returnTarget)) {
        co_return denied(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    idp::ProviderId providerId{provider->second};
    auto* implementation = m_providers->find(providerId);
    if (implementation == nullptr
        || implementation->interactionModel() != idp::InteractionModel::Redirect) {
        co_return denied(foundation::Error{foundation::ErrorCode::NotFound}, request);
    }
    // Check the complete native provider/transaction/canonical stack before
    // doing any proof. Never fall back to legacy blocking provider methods.
    if (!m_authentication->nativeProviderAuthenticationEnabled(providerId)) {
        co_return denied(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    }

    auto bindingToken = security::randomTokenBase64Url(32U);
    if (!bindingToken) co_return denied(bindingToken.error(), request);
    auto binding = security::sha256(bindingToken.value());
    if (!binding) co_return denied(binding.error(), request);

    idp::AuthenticationRequest begin{providerId, clientContext(request)};
    begin.setRequestedAssurance(idp::AssuranceLevel::Ial1);
    // Public start has no need for client-provided cookies or body. Erase
    // them before the first suspension point.
    request.wipeTargetQuery();
    request.wipeBody();
    request.wipeAuthorizationHeader();
    request.wipeCookieHeader();

    foundation::Result<AuthenticationStart> started =
        foundation::fail(foundation::ErrorCode::Unavailable);
    try {
        started = co_await m_authentication->beginAsync(
            std::move(begin), binding.value(), request.correlation());
    } catch (...) {
        co_return denied(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    }
    if (!started) co_return denied(started.error(), request);

    const auto found = started->challenge().parameters().find("authorization_url");
    if (found == started->challenge().parameters().end()
        || !found->second.starts_with("https://")
        || found->second.size() > 8192U) {
        co_return denied(foundation::Error{foundation::ErrorCode::Internal}, request);
    }
    gateway::HttpResponse response{
        302, gateway::Headers{{"location", std::string{found->second}}}, {}};
    secure(response);
    const std::string_view sameSite = providerId.value() == "github" ? "Lax" : "None";
    response.addHeader("set-cookie", cookie(
        kContinuationCookie, started->continuationToken().expose(), 600, sameSite));
    response.addHeader("set-cookie", cookie(
        kBindingCookie, bindingToken.value(), 600, sameSite));
    response.addHeader("set-cookie", cookie(
        kTransactionCookie, encoded(started->transactionId().value()), 600, sameSite));
    response.addHeader("set-cookie", cookie(
        kChallengeCookie, encoded(started->challenge().id().value()), 600, sameSite));
    response.addHeader("set-cookie", cookie(
        kReturnCookie, encoded(returnTarget), 600, sameSite));
    co_return response;
}

} // namespace openproof::authentication::http

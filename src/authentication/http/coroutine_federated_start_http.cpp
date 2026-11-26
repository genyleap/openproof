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
#include <boost/json.hpp>

#include "coroutine_federated_start_http.hpp"

import openproof.foundation;
import openproof.security;

namespace openproof::authentication::http {
namespace {
namespace idp = identity::provider;
namespace asio = boost::asio;
namespace json = boost::json;
using Parameters = std::map<std::string, std::string, std::less<>>;
class SensitiveQueryValues final {
public:
    explicit SensitiveQueryValues(Parameters& values) noexcept : m_values(values) {}
    ~SensitiveQueryValues() {
        for (auto& entry:m_values) {
            foundation::secureWipe(entry.second.data(),entry.second.size());
        }
    }
    SensitiveQueryValues(const SensitiveQueryValues&)=delete;
    SensitiveQueryValues& operator=(const SensitiveQueryValues&)=delete;
private:
    Parameters& m_values;
};

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

[[nodiscard]] bool isConnectionStart(const gateway::HttpRequest& request) noexcept
{
    return request.method()==gateway::HttpMethod::Get && request.path()=="/account/connections/start";
}
[[nodiscard]] bool isHandoff(const gateway::HttpRequest& request) noexcept
{
    return request.path()=="/account/connections/handoff";
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
    SensitiveQueryValues wipeValues{result};
    while (!input.empty()) {
        const auto amp = input.find('&');
        const auto pair = input.substr(0U, amp);
        const auto equals = pair.find('=');
        if (equals == std::string_view::npos) return std::nullopt;
        auto key = decode(pair.substr(0U, equals));
        auto value = decode(pair.substr(equals + 1U));
        if (!key || !value || key->empty() || result.contains(*key)) {
            if (value) foundation::secureWipe(value->data(),value->size());
            return std::nullopt;
        }
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
    gateway::http::CoroutineHttpHandler& fallback, Authenticate authenticate)
    : m_authentication(&authentication), m_providers(&providers),
      m_limiter(&limiter), m_fallback(&fallback), m_authenticate(std::move(authenticate))
{
}

bool CoroutineFederatedStartAdapter::nativeEnabledFor(
    const gateway::HttpRequest& request) const noexcept
{
    if (isStart(request)) return true;
    if (isHandoff(request) && request.method()==gateway::HttpMethod::Get)
        return static_cast<bool>(m_authenticate);
    if (isConnectionStart(request) || isHandoff(request)) {
        return static_cast<bool>(m_authenticate)
            && (request.method()==gateway::HttpMethod::Get
                || (request.method()==gateway::HttpMethod::Post
                    && !request.header("authorization").has_value()))
            && !request.header("authorization").has_value();
    }
    return m_fallback->nativeEnabledFor(request);
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
    if (!isStart(request) && !isConnectionStart(request) && !isHandoff(request)) {
        if (m_fallback->nativeEnabledFor(request))
            co_return co_await m_fallback->handleAsync(std::move(request));
        request.wipeBody();
        request.wipeAuthorizationHeader();
        request.wipeCookieHeader();
        co_return unavailable();
    }
    SensitiveFederatedStartRequestGuard wipeRequestOnExit{request};

    if (!nativeEnabledFor(request)) co_return unavailable();
    if (isHandoff(request)) {
        if (!m_limiter->allow("federation-handoff-ip:"+std::string{request.remoteAddress()}))
            co_return denied(foundation::Error{foundation::ErrorCode::RateLimited},request);
        if (request.method()==gateway::HttpMethod::Post)
            co_return co_await issueHandoff(std::move(request));
        if (request.header("authorization").has_value())
            co_return denied(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        auto params=query(request);
        if (!params)
            co_return denied(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        SensitiveQueryValues wipeParams{*params};
        if (params->size()!=1U || !params->contains("ticket"))
            co_return denied(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        auto& ticket=params->at("ticket");
        if (ticket.empty() || ticket.size()>256U || !std::ranges::all_of(ticket,[](char c){
            return (c>='A' && c<='Z') || (c>='a' && c<='z') || (c>='0' && c<='9')
                || c=='-' || c=='_' || c=='.';
        })) {
            foundation::secureWipe(ticket.data(),ticket.size());
            co_return denied(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        }
        foundation::SecretString secret{std::move(ticket)};
        request.wipeTargetQuery(); request.wipeBody();
        request.wipeAuthorizationHeader(); request.wipeCookieHeader();
        try {
            auto target=co_await m_authentication->consumeBrowserConnectionHandoffAsync(std::move(secret));
            if (!target) co_return denied(target.error(),request);
            if (!validLocalReturn(target->returnTarget))
                co_return denied(foundation::Error{foundation::ErrorCode::AuthenticationFailed},request);
            co_return co_await startPrepared(std::move(request),std::move(target->providerId),
                std::move(target->returnTarget),std::move(target->identity));
        } catch (...) {
            co_return denied(foundation::Error{foundation::ErrorCode::Unavailable},request);
        }
    }

    if (!m_limiter->allow(
            std::string{"federation-ip:"} + std::string{request.remoteAddress()})) {
        co_return denied(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    const auto params = query(request);
    // Purpose comes from the route, not a caller-supplied query field.
    if (!params || params->size() > 2U
        || std::ranges::any_of(*params, [](const auto& entry) {
            return entry.first != "provider" && entry.first != "return_to";
        })) {
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
    std::optional<identity::core::IdentityId> target;
    if (isConnectionStart(request)) {
        auto credential=gateway::takeSessionCredential(request);
        if (!credential || !credential->has_value())
            co_return denied(foundation::Error{foundation::ErrorCode::AuthenticationRequired},request);
        try {
            auto actor=co_await m_authenticate(std::move(credential->value()));
            if (!actor) co_return denied(actor.error(),request);
            target.emplace(actor->identity());
        } catch (...) {
            co_return denied(foundation::Error{foundation::ErrorCode::Unavailable},request);
        }
    }
    co_return co_await startPrepared(std::move(request),idp::ProviderId{provider->second},
        returnTarget,std::move(target));
}

asio::awaitable<gateway::HttpResponse>
CoroutineFederatedStartAdapter::startPrepared(gateway::HttpRequest request,idp::ProviderId providerId,
    std::string returnTarget,std::optional<identity::core::IdentityId> connectionTarget)
{
    SensitiveFederatedStartRequestGuard wipeRequestOnExit{request};
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
        if (connectionTarget)
            started=co_await m_authentication->beginConnectionAsync(
                std::move(begin),binding.value(),request.correlation(),std::move(*connectionTarget));
        else
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
    if (connectionTarget)
        response.addHeader("set-cookie",cookie(kModeCookie,"link",600,sameSite));
    else
        response.addHeader("set-cookie",cookie(kModeCookie,"",0,sameSite));
    co_return response;
}

asio::awaitable<gateway::HttpResponse>
CoroutineFederatedStartAdapter::issueHandoff(gateway::HttpRequest request)
{
    SensitiveFederatedStartRequestGuard wipeRequestOnExit{request};
    const auto type=request.header("content-type");
    if (!type || (*type!="application/json" && !type->starts_with("application/json;"))
        || request.body().empty() || request.body().size()>8192U)
        co_return denied(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
    boost::system::error_code ec;
    auto parsed=json::parse(request.body(),ec);
    if (ec || !parsed.is_object() || parsed.as_object().size()!=2U)
        co_return denied(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
    const auto* provider=parsed.as_object().if_contains("provider");
    const auto* returning=parsed.as_object().if_contains("return_to");
    if (!provider || !provider->is_string() || !returning || !returning->is_string())
        co_return denied(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
    const std::string providerText{provider->as_string()},returnTarget{returning->as_string()};
    if (providerText.empty() || providerText.size()>128U || !validLocalReturn(returnTarget))
        co_return denied(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
    auto credential=gateway::takeSessionCredential(request);
    if (!credential || !credential->has_value())
        co_return denied(foundation::Error{foundation::ErrorCode::AuthenticationRequired},request);
    request.wipeBody(); request.wipeAuthorizationHeader(); request.wipeCookieHeader();
    try {
        auto actor=co_await m_authenticate(std::move(credential->value()));
        if (!actor) co_return denied(actor.error(),request);
        auto issued=co_await m_authentication->issueBrowserConnectionHandoffAsync(
            actor->identity(),idp::ProviderId{providerText},returnTarget,request.correlation());
        if (!issued) co_return denied(issued.error(),request);
        json::object body;
        body["handoff_url"]="/account/connections/handoff?ticket="+issued->ticket().expose();
        body["expires_at"]=foundation::toIso8601(issued->expiresAt());
        gateway::HttpResponse response{201,gateway::Headers{{"content-type","application/json"}},
            json::serialize(body)};
        secure(response);
        co_return response;
    } catch (...) {
        co_return denied(foundation::Error{foundation::ErrorCode::Unavailable},request);
    }
}

} // namespace openproof::authentication::http

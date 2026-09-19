module;

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <boost/json.hpp>

module openproof.authentication.federated.http;

import openproof.security;

namespace openproof::authentication::http {
namespace {

namespace json = boost::json;
namespace idp = identity::provider;
constexpr std::string_view kContinuationCookie = "__Host-openproof-federation-continuation";
constexpr std::string_view kBindingCookie = "__Host-openproof-federation-binding";
constexpr std::string_view kTransactionCookie = "__Host-openproof-federation-transaction";
constexpr std::string_view kChallengeCookie = "__Host-openproof-federation-challenge";
constexpr std::string_view kReturnCookie = "__Host-openproof-federation-return";
constexpr std::string_view kModeCookie = "__Host-openproof-federation-mode";
constexpr std::size_t kMaximumCallbackBody = 1024U * 1024U;
constexpr std::size_t kMaximumHandoffBody = 16U * 1024U;

[[nodiscard]] std::string cookie(std::string_view name, std::string_view value,
                                 std::int64_t maximumAge)
{
    return std::string{name} + "=" + std::string{value}
        + "; Path=/; Max-Age=" + std::to_string(maximumAge)
        + "; Secure; HttpOnly; SameSite=None";
}

[[nodiscard]] std::string sessionCookie(std::string_view value, std::int64_t maximumAge)
{
    return "__Host-openproof-session=" + std::string{value}
        + "; Path=/; Max-Age=" + std::to_string(maximumAge)
        // A federated callback is a cross-site top-level navigation. Lax keeps
        // the cookie unavailable to subresource requests while allowing the
        // immediate same-origin OAuth authorization redirect to consume it.
        + "; Secure; HttpOnly; SameSite=Lax";
}

void secure(gateway::HttpResponse& response)
{
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
}

void clearState(gateway::HttpResponse& response)
{
    response.addHeader("set-cookie", cookie(kContinuationCookie, "", 0));
    response.addHeader("set-cookie", cookie(kBindingCookie, "", 0));
    response.addHeader("set-cookie", cookie(kTransactionCookie, "", 0));
    response.addHeader("set-cookie", cookie(kChallengeCookie, "", 0));
    response.addHeader("set-cookie", cookie(kReturnCookie, "", 0));
    response.addHeader("set-cookie", cookie(kModeCookie, "", 0));
}

[[nodiscard]] bool validLocalReturn(std::string_view value) noexcept
{
    return !value.empty() && value.size() <= 2048U && value.front() == '/'
        && !value.starts_with("//") && !value.contains('\\')
        && std::ranges::none_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           });
}

[[nodiscard]] std::optional<unsigned int> hexValue(char value) noexcept
{
    if (value >= '0' && value <= '9') return static_cast<unsigned int>(value - '0');
    if (value >= 'A' && value <= 'F') return 10U + static_cast<unsigned int>(value - 'A');
    if (value >= 'a' && value <= 'f') return 10U + static_cast<unsigned int>(value - 'a');
    return std::nullopt;
}

[[nodiscard]] foundation::Result<std::string> decode(std::string_view value)
{
    std::string output;
    output.reserve(value.size());
    for (std::size_t index = 0U; index < value.size(); ++index) {
        if (value[index] == '%') {
            if (index + 2U >= value.size()) {
                return foundation::fail(foundation::ErrorCode::InvalidArgument);
            }
            auto high = hexValue(value[index + 1U]);
            auto low = hexValue(value[index + 2U]);
            if (!high || !low) return foundation::fail(foundation::ErrorCode::InvalidArgument);
            output.push_back(static_cast<char>((*high << 4U) | *low));
            index += 2U;
        } else if (value[index] == '+') {
            output.push_back(' ');
        } else {
            output.push_back(value[index]);
        }
    }
    return output;
}

using Parameters = std::map<std::string, std::string, std::less<>>;

[[nodiscard]] foundation::Result<Parameters> parseParameters(std::string_view input)
{
    Parameters output;
    while (!input.empty()) {
        const auto ampersand = input.find('&');
        const auto item = input.substr(0U, ampersand);
        const auto equals = item.find('=');
        if (equals == std::string_view::npos) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument);
        }
        auto key = decode(item.substr(0U, equals));
        auto value = decode(item.substr(equals + 1U));
        if (!key || !value || key->empty() || output.contains(key.value())) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument);
        }
        output.emplace(std::move(key).value(), std::move(value).value());
        if (ampersand == std::string_view::npos) break;
        input.remove_prefix(ampersand + 1U);
    }
    return output;
}

[[nodiscard]] foundation::Result<Parameters> query(const gateway::HttpRequest& request)
{
    const auto target = request.target();
    const auto question = target.find('?');
    if (question == std::string_view::npos) return Parameters{};
    return parseParameters(target.substr(question + 1U));
}

[[nodiscard]] foundation::Result<Parameters> callbackParameters(
    const gateway::HttpRequest& request)
{
    if (request.method() == gateway::HttpMethod::Get) return query(request);
    if (request.method() != gateway::HttpMethod::Post
        || request.body().empty() || request.body().size() > kMaximumCallbackBody) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    const auto contentType = request.header("content-type");
    if (!contentType || !contentType->starts_with("application/x-www-form-urlencoded")) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    return parseParameters(request.body());
}

[[nodiscard]] std::optional<std::string> cookieValue(
    const gateway::HttpRequest& request, std::string_view wanted, std::size_t maximum)
{
    const auto header = request.header("cookie");
    if (!header) return std::nullopt;
    std::optional<std::string> found;
    std::size_t begin = 0U;
    while (begin <= header->size()) {
        const auto end = header->find(';', begin);
        auto item = header->substr(begin,
            end == std::string_view::npos ? header->size() - begin : end - begin);
        while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) item.remove_prefix(1U);
        const auto equals = item.find('=');
        if (equals != std::string_view::npos && item.substr(0U, equals) == wanted) {
            const auto value = item.substr(equals + 1U);
            const bool safe = !value.empty() && value.size() <= maximum
                && std::ranges::all_of(value, [](char symbol) {
                       return (symbol >= 'A' && symbol <= 'Z') || (symbol >= 'a' && symbol <= 'z')
                           || (symbol >= '0' && symbol <= '9') || symbol == '-' || symbol == '_';
                   });
            if (!safe || found) return std::nullopt;
            found = std::string{value};
        }
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    return found;
}

[[nodiscard]] std::string base64UrlText(std::string_view value)
{
    return foundation::toBase64Url(std::as_bytes(std::span{value.data(), value.size()}));
}

[[nodiscard]] foundation::Result<std::string> decodeBase64UrlText(std::string_view value)
{
    auto bytes = foundation::fromBase64Url(value);
    if (!bytes || bytes->size() > 8192U) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    return std::string{reinterpret_cast<const char*>(bytes->data()), bytes->size()};
}

[[nodiscard]] idp::ClientContext clientContext(const gateway::HttpRequest& request)
{
    idp::ClientContext client;
    client.setRemoteAddress(std::string{request.remoteAddress()});
    if (const auto agent = request.header("user-agent")) {
        client.setUserAgent(std::string{agent->substr(0U, std::min<std::size_t>(agent->size(), 1024U))});
    }
    return client;
}

[[nodiscard]] std::optional<std::string_view> challengeParameter(
    const idp::AuthenticationChallenge& challenge, std::string_view name)
{
    const auto found = challenge.parameters().find(name);
    if (found == challenge.parameters().end()) return std::nullopt;
    return found->second;
}

} // namespace

FederatedAuthenticationHttpApi::FederatedAuthenticationHttpApi(
    AuthenticationService& authentication, idp::ProviderRegistry& providers,
    session::SessionService& sessions, gateway::TokenBucketRateLimiter& rateLimiter,
    gateway::HttpHandler& fallback,
    session::DelegatedAccessAuthenticator* delegated)
    : m_authentication(&authentication), m_providers(&providers), m_sessions(&sessions),
      m_delegated(delegated), m_rateLimiter(&rateLimiter), m_fallback(&fallback) {}

gateway::HttpResponse FederatedAuthenticationHttpApi::error(
    const foundation::Error& failure, const gateway::HttpRequest& request,
    bool shouldClearState) const
{
    gateway::HttpResponse response{foundation::errorHttpStatus(failure.code()),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(failure, request.correlation().value())};
    secure(response);
    if (shouldClearState) clearState(response);
    return response;
}

gateway::HttpResponse FederatedAuthenticationHttpApi::handle(gateway::HttpRequest request)
{
    if (request.path() == "/auth/providers" && request.method() == gateway::HttpMethod::Get) {
        return providers();
    }
    if (request.path() == "/auth/federated/start" && request.method() == gateway::HttpMethod::Get) {
        return start(std::move(request), false);
    }
    if (request.path() == "/account/connections/start"
        && request.method() == gateway::HttpMethod::Get) {
        return start(std::move(request), true);
    }
    if (request.path() == "/account/connections/complete"
        && request.method() == gateway::HttpMethod::Get) {
        return connectionComplete();
    }
    if (request.path() == "/account/connections/handoff"
        && request.method() == gateway::HttpMethod::Post) {
        return issueHandoff(std::move(request));
    }
    if (request.path() == "/account/connections/handoff"
        && request.method() == gateway::HttpMethod::Get) {
        return redeemHandoff(std::move(request));
    }
    if (request.path() == "/auth/federated/callback"
        && (request.method() == gateway::HttpMethod::Get
            || request.method() == gateway::HttpMethod::Post)) {
        return callback(std::move(request));
    }
    return m_fallback->handle(std::move(request));
}

gateway::HttpResponse FederatedAuthenticationHttpApi::providers()
{
    json::array values;
    for (const auto& providerId : m_providers->ids()) {
        auto* provider = m_providers->find(providerId);
        if (provider != nullptr && provider->interactionModel() == idp::InteractionModel::Redirect) {
            values.emplace_back(providerId.value());
        }
    }
    json::object body;
    body["providers"] = std::move(values);
    gateway::HttpResponse response{200, gateway::Headers{{"content-type", "application/json"}},
                                   json::serialize(body)};
    secure(response);
    return response;
}

gateway::HttpResponse FederatedAuthenticationHttpApi::connectionComplete()
{
    static constexpr std::string_view body = R"html(<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenProof — Account connected</title><style>
:root{color-scheme:light;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Tahoma,sans-serif;color:#101828;background:#f5f7fb}
*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 70% 15%,#ebe8ff 0,transparent 35%),#f5f7fb}
main{width:min(560px,100%);padding:34px;border:1px solid #e2e7ef;border-radius:20px;background:#fff;box-shadow:0 20px 55px #10182814;text-align:center}
.mark{width:64px;height:64px;margin:0 auto 18px;border-radius:20px;display:grid;place-items:center;background:#e8f8f1;color:#0e7654;font-size:30px;font-weight:800}
h1{margin:0 0 10px;font-size:25px}p{margin:0;color:#667085;line-height:1.9}.en{margin-top:18px;padding-top:18px;border-top:1px solid #e2e7ef;direction:ltr}
.brand{margin-top:24px;color:#6957e8;font-weight:800;font-size:13px;letter-spacing:.4px}</style></head>
<body><main><div class="mark">✓</div><h1>حساب با موفقیت متصل شد</h1><p>این provider به همان هویت OpenProof شما اضافه شد. می‌توانید این پنجره را ببندید و فهرست Connections را تازه کنید.</p><p class="en">The provider was added to your existing OpenProof identity. You can close this window and refresh Connections.</p><div class="brand">OPENPROOF / CANONICAL IDENTITY</div></main></body></html>)html";
    gateway::HttpResponse response{200,
        gateway::Headers{{"content-type", "text/html; charset=utf-8"}},
        std::string{body}};
    secure(response);
    response.setHeader("content-security-policy",
        "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'");
    return response;
}

gateway::HttpResponse FederatedAuthenticationHttpApi::start(
    gateway::HttpRequest request, bool connection)
{
    if (!m_rateLimiter->allow(std::string{"federation-ip:"} + std::string{request.remoteAddress()})) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    auto parameters = query(request);
    if (!parameters) return error(parameters.error(), request, true);
    const auto providerIt = parameters->find("provider");
    if (providerIt == parameters->end() || providerIt->second.empty() || providerIt->second.size() > 128U) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request, true);
    }
    const auto returnIt = parameters->find("return_to");
    const std::string returnTarget = returnIt == parameters->end() ? "/" : returnIt->second;
    if (!validLocalReturn(returnTarget)) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request, true);
    }
    std::optional<identity::core::IdentityId> connectionTarget;
    if (connection) {
        auto credential = gateway::takeSessionCredential(request);
        if (!credential || !credential->has_value()) {
            return error(foundation::Error{foundation::ErrorCode::AuthenticationRequired},
                         request, true);
        }
        auto authenticated = m_sessions->authenticate(
            credential->value(), m_delegated, "account");
        if (!authenticated) return error(authenticated.error(), request, true);
        connectionTarget.emplace(authenticated->session().identity());
    }
    return startPrepared(std::move(request), idp::ProviderId{providerIt->second},
                         returnTarget, std::move(connectionTarget));
}

gateway::HttpResponse FederatedAuthenticationHttpApi::issueHandoff(
    gateway::HttpRequest request)
{
    if (!m_rateLimiter->allow(std::string{"federation-handoff-ip:"}
                              + std::string{request.remoteAddress()})) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    const auto contentType = request.header("content-type");
    if (!contentType || !contentType->starts_with("application/json")
        || request.body().empty() || request.body().size() > kMaximumHandoffBody) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    boost::system::error_code parseError;
    json::value parsed = json::parse(request.body(), parseError);
    if (parseError || !parsed.is_object()) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    const auto& body = parsed.as_object();
    const auto providerValue = body.if_contains("provider");
    const auto returnValue = body.if_contains("return_to");
    if (providerValue == nullptr || !providerValue->is_string()
        || returnValue == nullptr || !returnValue->is_string()) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    const std::string providerText{providerValue->as_string()};
    const std::string returnTarget{returnValue->as_string()};
    if (providerText.empty() || providerText.size() > 128U
        || !validLocalReturn(returnTarget)) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    const idp::ProviderId providerId{providerText};
    auto* implementation = m_providers->find(providerId);
    if (implementation == nullptr
        || implementation->interactionModel() != idp::InteractionModel::Redirect) {
        return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
    }
    auto credential = gateway::takeSessionCredential(request);
    if (!credential || !credential->has_value()) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationRequired}, request);
    }
    auto authenticated = m_sessions->authenticate(
        credential->value(), m_delegated, "account");
    if (!authenticated) return error(authenticated.error(), request);
    auto issued = m_authentication->issueBrowserConnectionHandoff(
        authenticated->session().identity(), providerId, returnTarget,
        request.correlation());
    if (!issued) return error(issued.error(), request);
    json::object responseBody;
    responseBody["handoff_url"] = "/account/connections/handoff?ticket="
        + issued->ticket().expose();
    responseBody["expires_at"] = foundation::toIso8601(issued->expiresAt());
    gateway::HttpResponse response{
        201, gateway::Headers{{"content-type", "application/json"}},
        json::serialize(responseBody)};
    secure(response);
    return response;
}

gateway::HttpResponse FederatedAuthenticationHttpApi::redeemHandoff(
    gateway::HttpRequest request)
{
    if (!m_rateLimiter->allow(std::string{"federation-handoff-ip:"}
                              + std::string{request.remoteAddress()})) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request, true);
    }
    auto parameters = query(request);
    if (!parameters || parameters->size() != 1U) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request, true);
    }
    const auto ticket = parameters->find("ticket");
    if (ticket == parameters->end() || ticket->second.empty()
        || ticket->second.size() > 256U
        || !std::ranges::all_of(ticket->second, [](char symbol) {
               return (symbol >= 'A' && symbol <= 'Z')
                   || (symbol >= 'a' && symbol <= 'z')
                   || (symbol >= '0' && symbol <= '9')
                   || symbol == '-' || symbol == '_' || symbol == '.';
           })) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request, true);
    }
    auto target = m_authentication->consumeBrowserConnectionHandoff(
        foundation::SecretString{ticket->second});
    if (!target) return error(target.error(), request, true);
    if (!validLocalReturn(target->returnTarget)) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed},
                     request, true);
    }
    return startPrepared(std::move(request), std::move(target->providerId),
                         std::move(target->returnTarget),
                         std::optional<identity::core::IdentityId>{
                             std::move(target->identity)});
}

gateway::HttpResponse FederatedAuthenticationHttpApi::startPrepared(
    gateway::HttpRequest request, idp::ProviderId providerId,
    std::string returnTarget,
    std::optional<identity::core::IdentityId> connectionTarget)
{
    auto* implementation = m_providers->find(providerId);
    if (implementation == nullptr
        || implementation->interactionModel() != idp::InteractionModel::Redirect) {
        return error(foundation::Error{foundation::ErrorCode::NotFound}, request, true);
    }
    auto bindingToken = security::randomTokenBase64Url(32U);
    if (!bindingToken) return error(bindingToken.error(), request, true);
    auto binding = security::sha256(bindingToken.value());
    if (!binding) return error(binding.error(), request, true);
    idp::AuthenticationRequest authenticationRequest{providerId, clientContext(request)};
    authenticationRequest.setRequestedAssurance(idp::AssuranceLevel::Ial1);
    auto started = connectionTarget.has_value()
        ? m_authentication->beginConnection(authenticationRequest, binding.value(),
                                             request.correlation(), connectionTarget.value())
        : m_authentication->begin(authenticationRequest, binding.value(), request.correlation());
    if (!started) return error(started.error(), request, true);
    const auto authorizationUrl = challengeParameter(started->challenge(), "authorization_url");
    if (!authorizationUrl || !authorizationUrl->starts_with("https://")
        || authorizationUrl->size() > 8192U) {
        return error(foundation::Error{foundation::ErrorCode::Internal}, request, true);
    }
    gateway::HttpResponse response{302, gateway::Headers{{"location", std::string{*authorizationUrl}}}, {}};
    secure(response);
    response.addHeader("set-cookie", cookie(kContinuationCookie,
        started->continuationToken().expose(), 600));
    response.addHeader("set-cookie", cookie(kBindingCookie, bindingToken.value(), 600));
    response.addHeader("set-cookie", cookie(kTransactionCookie,
        base64UrlText(started->transactionId().value()), 600));
    response.addHeader("set-cookie", cookie(kChallengeCookie,
        base64UrlText(started->challenge().id().value()), 600));
    response.addHeader("set-cookie", cookie(kReturnCookie, base64UrlText(returnTarget), 600));
    if (connectionTarget.has_value()) {
        response.addHeader("set-cookie", cookie(kModeCookie, "link", 600));
    }
    return response;
}

gateway::HttpResponse FederatedAuthenticationHttpApi::callback(gateway::HttpRequest request)
{
    auto parameters = callbackParameters(request);
    const auto continuation = cookieValue(request, kContinuationCookie, 256U);
    const auto bindingToken = cookieValue(request, kBindingCookie, 256U);
    const auto transactionCookie = cookieValue(request, kTransactionCookie, 512U);
    const auto challengeCookie = cookieValue(request, kChallengeCookie, 512U);
    const auto returnCookie = cookieValue(request, kReturnCookie, 16U * 1024U);
    const auto modeCookie = cookieValue(request, kModeCookie, 16U);
    if (!parameters || !continuation || !bindingToken || !transactionCookie
        || !challengeCookie || !returnCookie || parameters->contains("error")) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed}, request, true);
    }
    const bool samlCallback = parameters->contains("SAMLResponse") || parameters->contains("RelayState");
    const auto code = parameters->find("code");
    const auto state = parameters->find("state");
    const auto samlResponse = parameters->find("SAMLResponse");
    const auto relayState = parameters->find("RelayState");
    if (samlCallback) {
        if (samlResponse == parameters->end() || relayState == parameters->end()
            || samlResponse->second.empty() || samlResponse->second.size() > 900U * 1024U
            || relayState->second.empty() || relayState->second.size() > 512U) {
            return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed}, request, true);
        }
    } else if (code == parameters->end() || state == parameters->end()
        || code->second.empty() || code->second.size() > 4096U
        || state->second.empty() || state->second.size() > 512U) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed}, request, true);
    }
    auto transactionText = decodeBase64UrlText(*transactionCookie);
    auto challengeText = decodeBase64UrlText(*challengeCookie);
    auto returnTarget = decodeBase64UrlText(*returnCookie);
    auto binding = security::sha256(*bindingToken);
    if (!transactionText || !challengeText || !returnTarget || !binding
        || !validLocalReturn(returnTarget.value())) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed}, request, true);
    }
    idp::AuthenticationResponse authenticationResponse{
        idp::ChallengeId{std::move(challengeText).value()}, clientContext(request)};
    if (samlCallback) {
        authenticationResponse.setParameter("SAMLResponse", idp::CredentialValue{samlResponse->second});
        authenticationResponse.setParameter("RelayState", idp::CredentialValue{relayState->second});
    } else {
        authenticationResponse.setParameter("code", idp::CredentialValue{code->second});
        authenticationResponse.setParameter("state", idp::CredentialValue{state->second});
    }
    const bool connection = modeCookie.has_value();
    if (connection && *modeCookie != "link") {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed}, request, true);
    }
    if (connection) {
        auto connected = m_authentication->completeConnection(
            idp::TransactionId{std::move(transactionText).value()},
            foundation::SecretString{*continuation}, binding.value(), authenticationResponse);
        if (!connected) return error(connected.error(), request, true);
        gateway::HttpResponse response{
            302, gateway::Headers{{"location", std::move(returnTarget).value()}}, {}};
        secure(response);
        clearState(response);
        return response;
    }
    auto verified = m_authentication->complete(
        idp::TransactionId{std::move(transactionText).value()},
        foundation::SecretString{*continuation}, binding.value(), authenticationResponse);
    if (!verified) return error(verified.error(), request, true);
    auto session = m_sessions->issue(verified.value(), clientContext(request));
    if (!session) return error(session.error(), request, true);
    gateway::HttpResponse response{302, gateway::Headers{{"location", std::move(returnTarget).value()}}, {}};
    secure(response);
    clearState(response);
    response.addHeader("set-cookie", sessionCookie(session->token().expose(), 8 * 60 * 60));
    return response;
}

} // namespace openproof::authentication::http

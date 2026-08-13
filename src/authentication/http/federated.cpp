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
constexpr std::size_t kMaximumCallbackBody = 1024U * 1024U;

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
        + "; Secure; HttpOnly; SameSite=Strict";
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
    gateway::HttpHandler& fallback)
    : m_authentication(&authentication), m_providers(&providers), m_sessions(&sessions),
      m_rateLimiter(&rateLimiter), m_fallback(&fallback) {}

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
        return start(std::move(request));
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

gateway::HttpResponse FederatedAuthenticationHttpApi::start(gateway::HttpRequest request)
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
    idp::ProviderId providerId{providerIt->second};
    auto* implementation = m_providers->find(providerId);
    if (implementation == nullptr || implementation->interactionModel() != idp::InteractionModel::Redirect) {
        return error(foundation::Error{foundation::ErrorCode::NotFound}, request, true);
    }
    auto bindingToken = security::randomTokenBase64Url(32U);
    if (!bindingToken) return error(bindingToken.error(), request, true);
    auto binding = security::sha256(bindingToken.value());
    if (!binding) return error(binding.error(), request, true);
    idp::AuthenticationRequest authenticationRequest{providerId, clientContext(request)};
    authenticationRequest.setRequestedAssurance(idp::AssuranceLevel::Ial1);
    auto started = m_authentication->begin(
        authenticationRequest, binding.value(), request.correlation());
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
    auto verified = m_authentication->complete(
        idp::TransactionId{std::move(transactionText).value()},
        foundation::SecretString{*continuation}, binding.value(), authenticationResponse);
    if (!verified) return error(verified.error(), request, true);
    auto session = m_sessions->issue(verified.value());
    if (!session) return error(session.error(), request, true);
    gateway::HttpResponse response{302, gateway::Headers{{"location", std::move(returnTarget).value()}}, {}};
    secure(response);
    clearState(response);
    response.addHeader("set-cookie", sessionCookie(session->token().expose(), 8 * 60 * 60));
    return response;
}

} // namespace openproof::authentication::http

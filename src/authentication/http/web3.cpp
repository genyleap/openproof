module;

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>

#include <boost/json.hpp>

module openproof.authentication.web3.http;

import openproof.foundation;
import openproof.security;

namespace openproof::authentication::http {
namespace {

namespace json = boost::json;
namespace idp = identity::provider;

constexpr std::string_view kContinuationCookie{"__Host-openproof-web3-continuation"};
constexpr std::string_view kBindingCookie{"__Host-openproof-web3-binding"};
constexpr std::string_view kTransactionCookie{"__Host-openproof-web3-transaction"};
constexpr std::string_view kChallengeCookie{"__Host-openproof-web3-challenge"};
constexpr std::size_t kMaximumBody = 16U * 1024U;

[[nodiscard]] std::string cookie(std::string_view name, std::string_view value,
                                 std::int64_t maximumAge)
{
    return std::string{name} + "=" + std::string{value}
        + "; Path=/; Max-Age=" + std::to_string(maximumAge)
        + "; Secure; HttpOnly; SameSite=Strict";
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
    response.setHeader("content-security-policy", "default-src 'none'; frame-ancestors 'none'");
}

void clearState(gateway::HttpResponse& response)
{
    response.addHeader("set-cookie", cookie(kContinuationCookie, "", 0));
    response.addHeader("set-cookie", cookie(kBindingCookie, "", 0));
    response.addHeader("set-cookie", cookie(kTransactionCookie, "", 0));
    response.addHeader("set-cookie", cookie(kChallengeCookie, "", 0));
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
                           || (symbol >= '0' && symbol <= '9') || symbol == '-' || symbol == '_' || symbol == '.';
                   });
            if (!safe || found) return std::nullopt;
            found = std::string{value};
        }
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    return found;
}

[[nodiscard]] foundation::Result<json::object> parseObject(const gateway::HttpRequest& request)
{
    if (request.body().empty() || request.body().size() > kMaximumBody) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    const auto contentType = request.header("content-type");
    if (!contentType || !contentType->starts_with("application/json")) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    boost::system::error_code parseError;
    auto value = json::parse(request.body(), parseError);
    if (parseError || !value.is_object()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    return value.as_object();
}

[[nodiscard]] bool onlyFields(const json::object& object,
                              std::initializer_list<std::string_view> allowed)
{
    return std::ranges::all_of(object, [&](const auto& item) {
        return std::ranges::find(allowed, std::string_view{item.key()}) != allowed.end();
    });
}

[[nodiscard]] std::optional<std::string> stringField(
    const json::object& object, std::string_view name, std::size_t maximum)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr || !value->is_string()) return std::nullopt;
    std::string text{value->as_string()};
    if (text.empty() || text.size() > maximum || text.contains('\0')) return std::nullopt;
    return text;
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

[[nodiscard]] bool web3Provider(std::string_view provider) noexcept
{
    return provider == "ethereum-wallet" || provider == "farcaster";
}

} // namespace

Web3AuthenticationHttpApi::Web3AuthenticationHttpApi(
    AuthenticationService& authentication, idp::ProviderRegistry& providers,
    session::SessionService& sessions, gateway::TokenBucketRateLimiter& rateLimiter,
    gateway::HttpHandler& fallback)
    : m_authentication(&authentication), m_providers(&providers), m_sessions(&sessions),
      m_rateLimiter(&rateLimiter), m_fallback(&fallback) {}

gateway::HttpResponse Web3AuthenticationHttpApi::error(
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

gateway::HttpResponse Web3AuthenticationHttpApi::handle(gateway::HttpRequest request)
{
    if (request.path() == "/auth/web3/start" && request.method() == gateway::HttpMethod::Post) {
        return start(std::move(request));
    }
    if (request.path() == "/auth/web3/complete" && request.method() == gateway::HttpMethod::Post) {
        return complete(std::move(request));
    }
    return m_fallback->handle(std::move(request));
}

gateway::HttpResponse Web3AuthenticationHttpApi::start(gateway::HttpRequest request)
{
    if (!m_rateLimiter->allow("web3-ip:" + std::string{request.remoteAddress()})) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request, true);
    }
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"provider", "address", "fid"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(),
                     request, true);
    }
    auto providerName = stringField(body.value(), "provider", 64U);
    auto address = stringField(body.value(), "address", 64U);
    if (!providerName || !address || !web3Provider(*providerName)) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request, true);
    }
    idp::ProviderId providerId{*providerName};
    auto* implementation = m_providers->find(providerId);
    if (implementation == nullptr
        || implementation->interactionModel() != idp::InteractionModel::ChallengeResponse) {
        return error(foundation::Error{foundation::ErrorCode::NotFound}, request, true);
    }
    auto bindingToken = security::randomTokenBase64Url(32U);
    if (!bindingToken) return error(bindingToken.error(), request, true);
    auto binding = security::sha256(bindingToken.value());
    if (!binding) return error(binding.error(), request, true);

    idp::AuthenticationRequest authenticationRequest{providerId, clientContext(request)};
    authenticationRequest.setRequestedAssurance(idp::AssuranceLevel::Ial1);
    authenticationRequest.setParameter("address", *address);
    if (*providerName == "farcaster") {
        auto fid = stringField(body.value(), "fid", 32U);
        if (!fid) return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request, true);
        authenticationRequest.setParameter("fid", *fid);
    }
    auto started = m_authentication->begin(authenticationRequest, binding.value(), request.correlation());
    if (!started) return error(started.error(), request, true);
    const auto message = challengeParameter(started->challenge(), "message");
    if (!message || message->empty() || message->size() > 8192U) {
        return error(foundation::Error{foundation::ErrorCode::Internal}, request, true);
    }

    json::object payload;
    payload["provider"] = *providerName;
    payload["challenge_id"] = started->challenge().id().value();
    payload["message"] = *message;
    payload["expires_at"] = foundation::toIso8601(started->challenge().expiresAt());
    if (const auto value = challengeParameter(started->challenge(), "address")) payload["address"] = *value;
    if (const auto value = challengeParameter(started->challenge(), "fid")) payload["fid"] = *value;
    if (const auto value = challengeParameter(started->challenge(), "chain_id")) payload["chain_id"] = *value;
    gateway::HttpResponse response{200, gateway::Headers{{"content-type", "application/json"}},
                                   json::serialize(payload)};
    secure(response);
    response.addHeader("set-cookie", cookie(kContinuationCookie, started->continuationToken().expose(), 600));
    response.addHeader("set-cookie", cookie(kBindingCookie, bindingToken.value(), 600));
    response.addHeader("set-cookie", cookie(kTransactionCookie, started->transactionId().value(), 600));
    response.addHeader("set-cookie", cookie(kChallengeCookie, started->challenge().id().value(), 600));
    return response;
}

gateway::HttpResponse Web3AuthenticationHttpApi::complete(gateway::HttpRequest request)
{
    if (!m_rateLimiter->allow("web3-ip:" + std::string{request.remoteAddress()})) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request, true);
    }
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"message", "signature"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(),
                     request, true);
    }
    auto message = stringField(body.value(), "message", 8192U);
    auto signature = stringField(body.value(), "signature", 8192U);
    const auto continuation = cookieValue(request, kContinuationCookie, 256U);
    const auto bindingToken = cookieValue(request, kBindingCookie, 256U);
    const auto transaction = cookieValue(request, kTransactionCookie, 256U);
    const auto challenge = cookieValue(request, kChallengeCookie, 512U);
    if (!message || !signature || !continuation || !bindingToken || !transaction || !challenge) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed}, request, true);
    }
    auto binding = security::sha256(*bindingToken);
    if (!binding) return error(binding.error(), request, true);
    idp::AuthenticationResponse authenticationResponse{idp::ChallengeId{*challenge}, clientContext(request)};
    authenticationResponse.setParameter("message", idp::CredentialValue{std::move(*message)});
    authenticationResponse.setParameter("signature", idp::CredentialValue{std::move(*signature)});
    auto verified = m_authentication->complete(
        idp::TransactionId{*transaction}, foundation::SecretString{*continuation},
        binding.value(), authenticationResponse);
    if (!verified) return error(verified.error(), request, true);
    auto issued = m_sessions->issue(verified.value());
    if (!issued) return error(issued.error(), request, true);
    json::object payload;
    payload["authenticated"] = true;
    payload["identity_id"] = verified->identity().value();
    gateway::HttpResponse response{200, gateway::Headers{{"content-type", "application/json"}},
                                   json::serialize(payload)};
    secure(response);
    clearState(response);
    response.addHeader("set-cookie", sessionCookie(issued->token().expose(), 8 * 60 * 60));
    return response;
}

} // namespace openproof::authentication::http

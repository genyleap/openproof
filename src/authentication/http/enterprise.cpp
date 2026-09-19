module;

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cctype>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>

#include <boost/json.hpp>

module openproof.authentication.enterprise.http;

import openproof.security;

namespace openproof::authentication::http {
namespace {
namespace json = boost::json;
namespace idp = identity::provider;
constexpr std::size_t kMaximumBody = 16U * 1024U;
constexpr std::string_view kContinuationCookie = "__Host-openproof-enterprise-continuation";
constexpr std::string_view kBindingCookie = "__Host-openproof-enterprise-binding";

[[nodiscard]] std::string cookie(std::string_view name, std::string_view value, std::int64_t age)
{
    return std::string{name} + "=" + std::string{value} + "; Path=/; Max-Age="
        + std::to_string(age) + "; Secure; HttpOnly; SameSite=Strict";
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
}

[[nodiscard]] foundation::Result<json::object> parseObject(const gateway::HttpRequest& request)
{
    const auto contentType = request.header("content-type");
    if (request.body().empty() || request.body().size() > kMaximumBody || !contentType
        || !contentType->starts_with("application/json")) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    boost::system::error_code ec;
    auto parsed = json::parse(request.body(), ec);
    if (ec || !parsed.is_object()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    return std::move(parsed).as_object();
}

[[nodiscard]] foundation::Result<std::string> required(const json::object& object,
                                                       std::string_view key,
                                                       std::size_t maximum)
{
    const auto* value = object.if_contains(key);
    if (value == nullptr || !value->is_string()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    const std::string_view text{value->as_string().data(), value->as_string().size()};
    if (text.empty() || text.size() > maximum || std::ranges::any_of(text, [](char symbol) {
            const auto byte = static_cast<unsigned char>(symbol);
            return byte < 0x20U || byte == 0x7FU;
        })) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    return std::string{text};
}

[[nodiscard]] bool onlyFields(const json::object& object,
                              std::initializer_list<std::string_view> allowed)
{
    return std::ranges::all_of(object, [&](const auto& item) {
        return std::ranges::find(allowed, std::string_view{item.key()}) != allowed.end();
    });
}

[[nodiscard]] std::optional<std::string> cookieValue(const gateway::HttpRequest& request,
                                                     std::string_view wanted)
{
    const auto header = request.header("cookie");
    if (!header) return std::nullopt;
    std::optional<std::string> found;
    std::size_t begin = 0U;
    while (begin <= header->size()) {
        const auto end = header->find(';', begin);
        auto item = header->substr(begin, end == std::string_view::npos ? header->size() - begin : end - begin);
        while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) item.remove_prefix(1U);
        const auto equals = item.find('=');
        if (equals != std::string_view::npos && item.substr(0U, equals) == wanted) {
            const auto value = item.substr(equals + 1U);
            if (found || value.empty() || value.size() > 512U || !std::ranges::all_of(value, [](char symbol) {
                    return std::isalnum(static_cast<unsigned char>(symbol)) != 0 || symbol == '-' || symbol == '_';
                })) return std::nullopt;
            found = std::string{value};
        }
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    return found;
}

[[nodiscard]] idp::ClientContext clientContext(const gateway::HttpRequest& request)
{
    idp::ClientContext client;
    client.setRemoteAddress(std::string{request.remoteAddress()});
    if (auto agent = request.header("user-agent")) client.setUserAgent(std::string{agent->substr(0U, 1024U)});
    return client;
}

[[nodiscard]] gateway::HttpResponse jsonResponse(int status, json::object body)
{
    gateway::HttpResponse response{status, gateway::Headers{{"content-type", "application/json"}},
                                   json::serialize(body)};
    secure(response);
    return response;
}

} // namespace

EnterpriseAuthenticationHttpApi::EnterpriseAuthenticationHttpApi(
    AuthenticationService& authentication, session::SessionService& sessions,
    gateway::TokenBucketRateLimiter& rateLimiter, gateway::HttpHandler& fallback)
    : m_authentication(&authentication), m_sessions(&sessions),
      m_rateLimiter(&rateLimiter), m_fallback(&fallback) {}

gateway::HttpResponse EnterpriseAuthenticationHttpApi::error(
    const foundation::Error& failure, const gateway::HttpRequest& request, bool clear) const
{
    gateway::HttpResponse response{foundation::errorHttpStatus(failure.code()),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(failure, request.correlation().value())};
    secure(response);
    if (clear) clearState(response);
    return response;
}

gateway::HttpResponse EnterpriseAuthenticationHttpApi::handle(gateway::HttpRequest request)
{
    if (request.path() == "/auth/ldap/start" && request.method() == gateway::HttpMethod::Post) {
        return startLdap(std::move(request));
    }
    if (request.path() == "/auth/ldap/complete" && request.method() == gateway::HttpMethod::Post) {
        return completeLdap(std::move(request));
    }
    return m_fallback->handle(std::move(request));
}

gateway::HttpResponse EnterpriseAuthenticationHttpApi::startLdap(gateway::HttpRequest request)
{
    if (!m_rateLimiter->allow(std::string{"ldap-ip:"} + std::string{request.remoteAddress()})) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"username"})) return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto username = required(body.value(), "username", 320U);
    if (!username) return error(username.error(), request);
    auto bindingToken = security::randomTokenBase64Url(32U);
    if (!bindingToken) return error(bindingToken.error(), request);
    auto binding = security::sha256(bindingToken.value());
    if (!binding) return error(binding.error(), request);
    idp::AuthenticationRequest authenticationRequest{idp::ProviderId{"ldap"}, clientContext(request)};
    authenticationRequest.setRequestedAssurance(idp::AssuranceLevel::Ial1);
    authenticationRequest.setParameter("username", username.value());
    auto started = m_authentication->begin(authenticationRequest, binding.value(), request.correlation());
    if (!started) return error(started.error(), request);
    const auto bindingParameter = started->challenge().parameters().find("username_binding");
    if (bindingParameter == started->challenge().parameters().end()) return error(foundation::Error{foundation::ErrorCode::Internal}, request);
    json::object output;
    output["transaction_id"] = started->transactionId().value();
    output["challenge_id"] = started->challenge().id().value();
    output["username"] = username.value();
    output["username_binding"] = bindingParameter->second;
    output["expires_at_ms"] = started->challenge().expiresAt().time_since_epoch().count();
    auto response = jsonResponse(202, std::move(output));
    response.addHeader("set-cookie", cookie(kContinuationCookie, started->continuationToken().expose(), 600));
    response.addHeader("set-cookie", cookie(kBindingCookie, bindingToken.value(), 600));
    return response;
}

gateway::HttpResponse EnterpriseAuthenticationHttpApi::completeLdap(gateway::HttpRequest request)
{
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"transaction_id", "challenge_id", "username", "username_binding", "password"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request, true);
    }
    auto transaction = required(body.value(), "transaction_id", 256U);
    auto challenge = required(body.value(), "challenge_id", 256U);
    auto username = required(body.value(), "username", 320U);
    auto usernameBinding = required(body.value(), "username_binding", 256U);
    auto password = required(body.value(), "password", 4096U);
    auto continuation = cookieValue(request, kContinuationCookie);
    auto bindingToken = cookieValue(request, kBindingCookie);
    if (!transaction || !challenge || !username || !usernameBinding || !password || !continuation || !bindingToken) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed}, request, true);
    }
    auto binding = security::sha256(*bindingToken);
    if (!binding) return error(binding.error(), request, true);
    idp::AuthenticationResponse authenticationResponse{idp::ChallengeId{challenge.value()}, clientContext(request)};
    authenticationResponse.setParameter("username", idp::CredentialValue{username.value()});
    authenticationResponse.setParameter("username_binding", idp::CredentialValue{usernameBinding.value()});
    authenticationResponse.setParameter("password", idp::CredentialValue{password.value()});
    auto verified = m_authentication->complete(idp::TransactionId{transaction.value()},
        foundation::SecretString{*continuation}, binding.value(), authenticationResponse);
    if (!verified) return error(verified.error(), request, true);
    auto grant = m_sessions->issue(verified.value(), clientContext(request));
    if (!grant) return error(grant.error(), request, true);
    json::object output;
    output["session_id"] = grant->id().value();
    output["assurance"] = idp::assuranceLevelName(verified->outcome().claimedAssurance());
    auto response = jsonResponse(200, std::move(output));
    clearState(response);
    response.addHeader("set-cookie", cookie("__Host-openproof-session", grant->token().expose(), 8 * 60 * 60));
    return response;
}

} // namespace openproof::authentication::http

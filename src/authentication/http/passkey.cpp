module;

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include <boost/json.hpp>

module openproof.authentication.passkey.http;

import openproof.identity.core;
import openproof.security;

namespace openproof::authentication::http {
namespace {

namespace json = boost::json;
namespace idp = identity::provider;
namespace passkey = ::openproof::provider::passkey;
using ActorIdentityId = std::remove_cvref_t<
    decltype(std::declval<const session::Session&>().identity())>;

constexpr std::size_t kMaximumBody = 128U * 1024U;
constexpr std::string_view kRegistrationCookie = "__Host-openproof-passkey-registration";
constexpr std::string_view kContinuationCookie = "__Host-openproof-passkey-continuation";
constexpr std::string_view kBindingCookie = "__Host-openproof-passkey-binding";
constexpr std::string_view kTransactionCookie = "__Host-openproof-passkey-transaction";
constexpr std::string_view kChallengeCookie = "__Host-openproof-passkey-challenge";

[[nodiscard]] gateway::HttpResponse jsonResponse(int status, json::value body)
{
    gateway::HttpResponse response{
        status,
        gateway::Headers{{"content-type", "application/json"}},
        json::serialize(body)};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    return response;
}

[[nodiscard]] gateway::HttpResponse errorResponse(
    const foundation::Error& failure, const gateway::HttpRequest& request)
{
    gateway::HttpResponse response{
        foundation::errorHttpStatus(failure.code()),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(failure, request.correlation().value())};
    response.setHeader("cache-control", "no-store");
    response.setHeader("x-content-type-options", "nosniff");
    if (failure.code() == foundation::ErrorCode::AuthenticationRequired) {
        response.setHeader("www-authenticate", "Bearer");
    }
    return response;
}

[[nodiscard]] std::string cookie(
    std::string_view name, std::string_view value, std::int64_t maximumAge)
{
    return std::string{name} + "=" + std::string{value}
        + "; Path=/; Max-Age=" + std::to_string(maximumAge)
        + "; Secure; HttpOnly; SameSite=Strict";
}

void clearAssertionCookies(gateway::HttpResponse& response)
{
    response.addHeader("set-cookie", cookie(kContinuationCookie, "", 0));
    response.addHeader("set-cookie", cookie(kBindingCookie, "", 0));
    response.addHeader("set-cookie", cookie(kTransactionCookie, "", 0));
    response.addHeader("set-cookie", cookie(kChallengeCookie, "", 0));
}

[[nodiscard]] std::optional<std::string> cookieValue(
    const gateway::HttpRequest& request,
    std::string_view wanted,
    std::size_t maximum = 512U)
{
    const auto header = request.header("cookie");
    if (!header) {
        return std::nullopt;
    }

    std::optional<std::string> found;
    std::size_t begin = 0U;
    while (begin <= header->size()) {
        const auto end = header->find(';', begin);
        auto item = header->substr(
            begin,
            end == std::string_view::npos ? header->size() - begin : end - begin);

        while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) {
            item.remove_prefix(1U);
        }

        const auto equals = item.find('=');
        if (equals != std::string_view::npos && item.substr(0U, equals) == wanted) {
            const auto value = item.substr(equals + 1U);
            const bool invalid = std::ranges::any_of(value, [](char symbol) {
                return !((symbol >= 'A' && symbol <= 'Z')
                    || (symbol >= 'a' && symbol <= 'z')
                    || (symbol >= '0' && symbol <= '9')
                    || symbol == '-' || symbol == '_');
            });
            if (value.size() > maximum || found.has_value() || invalid) {
                return std::nullopt;
            }
            found = std::string{value};
        }

        if (end == std::string_view::npos) {
            break;
        }
        begin = end + 1U;
    }

    return found;
}

[[nodiscard]] foundation::Result<json::object> bodyObject(
    const gateway::HttpRequest& request)
{
    const auto type = request.header("content-type");
    if (!type || !type->starts_with("application/json") || request.body().empty()
        || request.body().size() > kMaximumBody) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }

    boost::system::error_code error;
    auto parsed = json::parse(request.body(), error);
    if (error || !parsed.is_object()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    return std::move(parsed).as_object();
}

[[nodiscard]] foundation::Result<std::string> required(
    const json::object& object, std::string_view name, std::size_t maximum)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr || !value->is_string() || value->as_string().empty()
        || value->as_string().size() > maximum) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    return std::string{value->as_string()};
}

[[nodiscard]] foundation::Result<std::optional<std::string>> optional(
    const json::object& object, std::string_view name, std::size_t maximum)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr || value->is_null()) {
        return std::optional<std::string>{};
    }
    if (!value->is_string() || value->as_string().size() > maximum) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    return std::optional<std::string>{std::string{value->as_string()}};
}

[[nodiscard]] foundation::Result<ActorIdentityId> actor(
    gateway::HttpRequest& request, session::SessionService& sessions)
{
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) {
        return foundation::fail(credential.error());
    }
    if (!credential->has_value()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationRequired);
    }

    auto authenticated = sessions.authenticate(credential->value());
    if (!authenticated) {
        return foundation::fail(authenticated.error());
    }
    return authenticated->session().identity();
}

[[nodiscard]] idp::ClientContext clientContext(const gateway::HttpRequest& request)
{
    idp::ClientContext context;
    context.setRemoteAddress(std::string{request.remoteAddress()});
    if (const auto userAgent = request.header("user-agent")) {
        context.setUserAgent(std::string{
            userAgent->substr(0U, std::min<std::size_t>(1024U, userAgent->size()))});
    }
    return context;
}

[[nodiscard]] foundation::Result<json::value> parseOptions(std::string_view value)
{
    boost::system::error_code error;
    auto parsed = json::parse(value, error);
    if (error || !parsed.is_object()) {
        return foundation::fail(foundation::ErrorCode::Internal);
    }
    return parsed;
}

[[nodiscard]] json::object publicKeyResponse(json::value publicKey)
{
    json::object body;
    body["publicKey"] = std::move(publicKey);
    return body;
}

[[nodiscard]] json::object booleanResponse(std::string_view field, bool value)
{
    json::object body;
    body[json::string_view{field.data(), field.size()}] = value;
    return body;
}

} // namespace

PasskeyAuthenticationHttpApi::PasskeyAuthenticationHttpApi(
    passkey::PasskeyService& passkeys,
    AuthenticationService& authentication,
    session::SessionService& sessions,
    gateway::TokenBucketRateLimiter& rateLimiter,
    gateway::HttpHandler& fallback)
    : m_passkeys(&passkeys),
      m_authentication(&authentication),
      m_sessions(&sessions),
      m_rateLimiter(&rateLimiter),
      m_fallback(&fallback)
{
}

gateway::HttpResponse PasskeyAuthenticationHttpApi::handle(gateway::HttpRequest request)
{
    const auto path = request.path();
    const std::string rateKey = "passkey:" + std::string{request.remoteAddress()}
        + ":" + std::string{path};
    const bool owned = path == "/account/passkeys"
        || path == "/account/passkeys/options"
        || path.starts_with("/account/passkeys/")
        || path == "/auth/passkey/options"
        || path == "/auth/passkey/verify";

    if (!owned) {
        return m_fallback->handle(std::move(request));
    }
    if (!m_rateLimiter->allow(rateKey)) {
        return errorResponse(
            foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }

    using gateway::HttpMethod;
    if (path == "/account/passkeys/options" && request.method() == HttpMethod::Post) {
        return registrationOptions(std::move(request));
    }
    if (path == "/account/passkeys" && request.method() == HttpMethod::Post) {
        return registerCredential(std::move(request));
    }
    if (path == "/account/passkeys" && request.method() == HttpMethod::Get) {
        return listCredentials(std::move(request));
    }
    if (path.starts_with("/account/passkeys/") && request.method() == HttpMethod::Delete) {
        return removeCredential(std::move(request));
    }
    if (path == "/auth/passkey/options" && request.method() == HttpMethod::Post) {
        return assertionOptions(std::move(request));
    }
    if (path == "/auth/passkey/verify" && request.method() == HttpMethod::Post) {
        return verifyAssertion(std::move(request));
    }

    json::object body;
    body["error"] = "method_not_allowed";
    return jsonResponse(405, std::move(body));
}

gateway::HttpResponse PasskeyAuthenticationHttpApi::registrationOptions(
    gateway::HttpRequest request)
{
    auto identity = actor(request, *m_sessions);
    if (!identity) {
        return errorResponse(identity.error(), request);
    }

    auto started = m_passkeys->beginRegistration(identity.value());
    if (!started) {
        return errorResponse(started.error(), request);
    }

    auto options = parseOptions(started->publicKeyOptionsJson);
    if (!options) {
        return errorResponse(options.error(), request);
    }

    auto response = jsonResponse(
        200, publicKeyResponse(std::move(options).value()));
    response.addHeader(
        "set-cookie", cookie(kRegistrationCookie, started->ceremonyId.value(), 600));
    return response;
}

gateway::HttpResponse PasskeyAuthenticationHttpApi::registerCredential(
    gateway::HttpRequest request)
{
    auto identity = actor(request, *m_sessions);
    if (!identity) {
        return errorResponse(identity.error(), request);
    }

    const auto ceremony = cookieValue(request, kRegistrationCookie, 256U);
    auto body = bodyObject(request);
    if (!ceremony || !body) {
        return errorResponse(
            foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }

    auto credentialId = required(body.value(), "credential_id", 4096U);
    auto clientData = required(body.value(), "client_data_json", 32U * 1024U);
    auto attestation = required(body.value(), "attestation_object", 128U * 1024U);
    if (!credentialId || !clientData || !attestation) {
        return errorResponse(
            foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }

    passkey::RegistrationResponse input{
        std::move(credentialId).value(),
        std::move(clientData).value(),
        std::move(attestation).value()};
    auto status = m_passkeys->completeRegistration(
        identity.value(), idp::ChallengeId{*ceremony}, input);

    auto response = status
        ? jsonResponse(201, booleanResponse("registered", true))
        : errorResponse(status.error(), request);
    response.addHeader("set-cookie", cookie(kRegistrationCookie, "", 0));
    return response;
}

gateway::HttpResponse PasskeyAuthenticationHttpApi::listCredentials(
    gateway::HttpRequest request)
{
    auto identity = actor(request, *m_sessions);
    if (!identity) {
        return errorResponse(identity.error(), request);
    }

    auto credentials = m_passkeys->list(identity.value());
    if (!credentials) {
        return errorResponse(credentials.error(), request);
    }

    json::array values;
    for (const auto& credential : credentials.value()) {
        json::object item;
        item["credential_id"] = credential.credentialId;
        item["sign_count"] = credential.signCount;
        item["created_at_ms"] = credential.createdAt.time_since_epoch().count();
        item["last_used_at_ms"] = credential.lastUsedAt.time_since_epoch().count();
        values.emplace_back(std::move(item));
    }

    json::object body;
    body["passkeys"] = std::move(values);
    return jsonResponse(200, std::move(body));
}

gateway::HttpResponse PasskeyAuthenticationHttpApi::removeCredential(
    gateway::HttpRequest request)
{
    auto identity = actor(request, *m_sessions);
    if (!identity) {
        return errorResponse(identity.error(), request);
    }

    constexpr std::string_view prefix{"/account/passkeys/"};
    const auto credentialId = request.path().substr(prefix.size());
    if (credentialId.empty() || credentialId.size() > 4096U
        || credentialId.contains('/')) {
        return errorResponse(
            foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }

    auto status = m_passkeys->remove(identity.value(), credentialId);
    return status
        ? jsonResponse(200, booleanResponse("removed", true))
        : errorResponse(status.error(), request);
}

gateway::HttpResponse PasskeyAuthenticationHttpApi::assertionOptions(
    gateway::HttpRequest request)
{
    auto bindingToken = security::randomTokenBase64Url(32U);
    if (!bindingToken) {
        return errorResponse(bindingToken.error(), request);
    }

    auto binding = security::sha256(bindingToken.value());
    if (!binding) {
        return errorResponse(binding.error(), request);
    }

    idp::AuthenticationRequest input{
        idp::ProviderId{"passkey"}, clientContext(request)};
    input.setRequestedAssurance(idp::AssuranceLevel::Ial2);
    auto started = m_authentication->begin(
        input, binding.value(), request.correlation());
    if (!started) {
        return errorResponse(started.error(), request);
    }

    const auto found = started->challenge().parameters().find("public_key_options");
    if (found == started->challenge().parameters().end()) {
        return errorResponse(
            foundation::Error{foundation::ErrorCode::Internal}, request);
    }

    auto options = parseOptions(found->second);
    if (!options) {
        return errorResponse(options.error(), request);
    }

    auto response = jsonResponse(
        200, publicKeyResponse(std::move(options).value()));
    response.addHeader(
        "set-cookie",
        cookie(kContinuationCookie, started->continuationToken().expose(), 600));
    response.addHeader(
        "set-cookie", cookie(kBindingCookie, bindingToken.value(), 600));
    response.addHeader(
        "set-cookie", cookie(kTransactionCookie, started->transactionId().value(), 600));
    response.addHeader(
        "set-cookie", cookie(kChallengeCookie, started->challenge().id().value(), 600));
    return response;
}

gateway::HttpResponse PasskeyAuthenticationHttpApi::verifyAssertion(
    gateway::HttpRequest request)
{
    const auto continuation = cookieValue(request, kContinuationCookie);
    const auto bindingToken = cookieValue(request, kBindingCookie);
    const auto transaction = cookieValue(request, kTransactionCookie);
    const auto challenge = cookieValue(request, kChallengeCookie);
    auto body = bodyObject(request);
    if (!continuation || !bindingToken || !transaction || !challenge || !body) {
        return errorResponse(
            foundation::Error{foundation::ErrorCode::AuthenticationFailed}, request);
    }

    auto credentialId = required(body.value(), "credential_id", 4096U);
    auto clientData = required(body.value(), "client_data_json", 32U * 1024U);
    auto authenticatorData = required(
        body.value(), "authenticator_data", 128U * 1024U);
    auto signature = required(body.value(), "signature", 4096U);
    auto userHandle = optional(body.value(), "user_handle", 4096U);
    if (!credentialId || !clientData || !authenticatorData || !signature || !userHandle) {
        return errorResponse(
            foundation::Error{foundation::ErrorCode::AuthenticationFailed}, request);
    }

    auto binding = security::sha256(*bindingToken);
    if (!binding) {
        return errorResponse(binding.error(), request);
    }

    idp::AuthenticationResponse input{
        idp::ChallengeId{*challenge}, clientContext(request)};
    input.setParameter(
        "credential_id", idp::CredentialValue{std::move(credentialId).value()});
    input.setParameter(
        "client_data_json", idp::CredentialValue{std::move(clientData).value()});
    input.setParameter(
        "authenticator_data",
        idp::CredentialValue{std::move(authenticatorData).value()});
    input.setParameter(
        "signature", idp::CredentialValue{std::move(signature).value()});
    if (userHandle->has_value()) {
        input.setParameter(
            "user_handle",
            idp::CredentialValue{std::move(userHandle).value().value()});
    }

    auto verified = m_authentication->complete(
        idp::TransactionId{*transaction},
        foundation::SecretString{*continuation},
        binding.value(),
        input);
    if (!verified) {
        return errorResponse(verified.error(), request);
    }

    auto session = m_sessions->issue(verified.value(), clientContext(request));
    if (!session) {
        return errorResponse(session.error(), request);
    }

    json::object bodyResponse;
    bodyResponse["session_id"] = session->id().value();
    bodyResponse["assurance"] = "ial2";
    auto response = jsonResponse(200, std::move(bodyResponse));
    clearAssertionCookies(response);
    response.addHeader(
        "set-cookie",
        cookie("__Host-openproof-session", session->token().expose(), 8 * 60 * 60));
    return response;
}

} // namespace openproof::authentication::http

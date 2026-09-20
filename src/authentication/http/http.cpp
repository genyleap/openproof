module;

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>

#include <boost/json.hpp>

module openproof.authentication.http;

import openproof.security;

namespace openproof::authentication::http {
namespace {

namespace json = boost::json;
namespace idp = identity::provider;
constexpr std::size_t kMaximumAuthBody = 16U * 1024U;
constexpr std::string_view kPreauthCookie = "__Host-openproof-preauth";
constexpr std::string_view kBindingCookie = "__Host-openproof-preauth-binding";

[[nodiscard]] gateway::HttpResponse response(int status, json::object body)
{
    gateway::HttpResponse output{
        status, gateway::Headers{{"content-type", "application/json"}},
        json::serialize(body)};
    output.setHeader("cache-control", "no-store");
    output.setHeader("pragma", "no-cache");
    output.setHeader("x-content-type-options", "nosniff");
    output.setHeader("referrer-policy", "no-referrer");
    return output;
}

[[nodiscard]] gateway::HttpResponse emptyResponse(int status)
{
    gateway::HttpResponse output{status, {}, {}};
    output.setHeader("cache-control", "no-store");
    output.setHeader("x-content-type-options", "nosniff");
    output.setHeader("referrer-policy", "no-referrer");
    return output;
}

[[nodiscard]] std::string cookie(std::string_view name, std::string_view value,
                                 std::string_view path, std::int64_t maximumAge)
{
    return std::string{name} + "=" + std::string{value} + "; Path="
        + std::string{path} + "; Max-Age=" + std::to_string(maximumAge)
        + "; Secure; HttpOnly; SameSite=Strict";
}

void clearPreauth(gateway::HttpResponse& output)
{
    output.addHeader("set-cookie", cookie(kPreauthCookie, "", "/", 0));
    output.addHeader("set-cookie", cookie(kBindingCookie, "", "/", 0));
}

void setSessionCookie(gateway::HttpResponse& output,
                      const foundation::SecretString& token)
{
    output.addHeader("set-cookie", cookie(
        "__Host-openproof-session", token.expose(), "/", 8 * 60 * 60));
}

void clearSessionCookie(gateway::HttpResponse& output)
{
    output.addHeader("set-cookie", cookie("__Host-openproof-session", "", "/", 0));
}

[[nodiscard]] foundation::Result<json::object> parseObject(const gateway::HttpRequest& request)
{
    if (request.body().empty() || request.body().size() > kMaximumAuthBody) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request was not valid.");
    }
    const auto contentType = request.header("content-type");
    if (!contentType.has_value()
        || (*contentType != "application/json"
            && !contentType->starts_with("application/json;"))) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request was not valid.");
    }
    boost::system::error_code parseError;
    json::value parsed = json::parse(request.body(), parseError);
    if (parseError || !parsed.is_object()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request was not valid.");
    }
    return std::move(parsed).as_object();
}

[[nodiscard]] foundation::Result<std::string>
requiredString(const json::object& object, std::string_view name, std::size_t maximum)
{
    const json::value* value = object.if_contains(name);
    if (value == nullptr || !value->is_string()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request was not valid.");
    }
    const auto text = value->as_string();
    if (text.empty() || text.size() > maximum
        || std::ranges::any_of(text, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request was not valid.");
    }
    return std::string{text};
}

[[nodiscard]] foundation::Result<std::optional<std::string>>
optionalString(const json::object& object, std::string_view name, std::size_t maximum)
{
    const json::value* value = object.if_contains(name);
    if (value == nullptr) return std::optional<std::string>{};
    auto required = requiredString(object, name, maximum);
    if (!required.has_value()) return foundation::fail(required.error());
    return std::optional<std::string>{std::move(required).value()};
}

[[nodiscard]] bool onlyFields(const json::object& object,
                              std::initializer_list<std::string_view> allowed)
{
    for (const auto& item : object) {
        if (std::ranges::find(allowed, std::string_view{item.key()}) == allowed.end()) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::optional<std::string>
cookieValue(const gateway::HttpRequest& request, std::string_view wanted)
{
    const auto header = request.header("cookie");
    if (!header.has_value()) return std::nullopt;
    std::optional<std::string> found;
    std::size_t begin = 0U;
    while (begin <= header->size()) {
        const std::size_t end = header->find(';', begin);
        std::string_view item = header->substr(
            begin, end == std::string_view::npos ? header->size() - begin : end - begin);
        while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) item.remove_prefix(1U);
        while (!item.empty() && (item.back() == ' ' || item.back() == '\t')) item.remove_suffix(1U);
        const std::size_t equals = item.find('=');
        if (equals != std::string_view::npos && item.substr(0U, equals) == wanted) {
            const std::string_view value = item.substr(equals + 1U);
            if (found.has_value() || value.empty() || value.size() > 128U
                || !std::ranges::all_of(value, [](char symbol) {
                       return (symbol >= 'A' && symbol <= 'Z')
                           || (symbol >= 'a' && symbol <= 'z')
                           || (symbol >= '0' && symbol <= '9')
                           || symbol == '-' || symbol == '_';
                   })) {
                return std::nullopt;
            }
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
    if (const auto userAgent = request.header("user-agent"); userAgent.has_value()) {
        client.setUserAgent(std::string{userAgent->substr(0U, std::min<std::size_t>(
            userAgent->size(), 1024U))});
    }
    return client;
}

}

AuthenticationHttpApi::AuthenticationHttpApi(
    AuthenticationService& authentication, session::SessionService& sessions,
    credentials::RecoveryCodeService& recoveryCodes,
    ::openproof::provider::local::LocalAccountDirectory& localAccounts,
    gateway::TokenBucketRateLimiter& rateLimiter, idp::ProviderId provider,
    gateway::HttpHandler& fallback)
    : m_authentication(&authentication), m_sessions(&sessions),
      m_recoveryCodes(&recoveryCodes), m_localAccounts(&localAccounts),
      m_rateLimiter(&rateLimiter), m_provider(std::move(provider)), m_fallback(&fallback)
{
}

gateway::HttpResponse AuthenticationHttpApi::error(
    const foundation::Error& failure, const gateway::HttpRequest& request,
    bool clearPreauthentication) const
{
    gateway::HttpResponse output{
        foundation::errorHttpStatus(failure.code()),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(failure, request.correlation().value())};
    output.setHeader("cache-control", "no-store");
    output.setHeader("pragma", "no-cache");
    output.setHeader("x-content-type-options", "nosniff");
    output.setHeader("referrer-policy", "no-referrer");
    if (failure.code() == foundation::ErrorCode::AuthenticationRequired) {
        output.setHeader("www-authenticate", "Bearer");
    }
    if (clearPreauthentication) clearPreauth(output);
    return output;
}

gateway::HttpResponse AuthenticationHttpApi::handle(gateway::HttpRequest request)
{
    if (request.path() != "/auth" && !request.path().starts_with("/auth/")) {
        return m_fallback->handle(std::move(request));
    }
    if (!m_rateLimiter->allow(std::string{"auth-ip:"} + std::string{request.remoteAddress()})) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    if (request.method() != gateway::HttpMethod::Post) {
        return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
    }
    if (request.path() == "/auth/login") return login(std::move(request));
    if (request.path() == "/auth/mfa/verify") return verify(std::move(request));
    if (request.path() == "/auth/session/rotate") return rotate(std::move(request));
    if (request.path() == "/auth/logout") return logout(std::move(request), false);
    if (request.path() == "/auth/logout-all") return logout(std::move(request), true);
    if (request.path() == "/auth/recovery-codes") {
        return issueRecoveryCodes(std::move(request));
    }
    return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
}

gateway::HttpResponse AuthenticationHttpApi::login(gateway::HttpRequest request)
{
    auto body = parseObject(request);
    if (!body.has_value() || !onlyFields(body.value(), {"subject"})) {
        return error(body.has_value() ? foundation::Error{foundation::ErrorCode::InvalidArgument}
                                      : body.error(), request);
    }
    auto subject = requiredString(body.value(), "subject", 320U);
    if (!subject.has_value()) return error(subject.error(), request);
    if (!m_rateLimiter->allow(std::string{"auth-subject:"} + subject.value())) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    auto bindingToken = security::randomTokenBase64Url(32U);
    if (!bindingToken.has_value()) return error(bindingToken.error(), request);
    auto binding = security::sha256(bindingToken.value());
    if (!binding.has_value()) return error(binding.error(), request);
    idp::AuthenticationRequest authenticationRequest{m_provider, clientContext(request)};
    authenticationRequest.setParameter("subject", std::move(subject).value());
    authenticationRequest.setRequestedAssurance(idp::AssuranceLevel::Ial1);
    auto started = m_authentication->begin(
        authenticationRequest, binding.value(), request.correlation());
    if (!started.has_value()) return error(started.error(), request);

    json::object payload;
    payload["transaction_id"] = started->transactionId().value();
    payload["challenge_id"] = started->challenge().id().value();
    payload["expires_at_ms"] = started->challenge().expiresAt().time_since_epoch().count();
    auto output = response(202, std::move(payload));
    output.addHeader("set-cookie", cookie(
        kPreauthCookie, started->continuationToken().expose(), "/", 300));
    output.addHeader("set-cookie", cookie(
        kBindingCookie, bindingToken.value(), "/", 300));
    return output;
}

gateway::HttpResponse AuthenticationHttpApi::verify(gateway::HttpRequest request)
{
    auto body = parseObject(request);
    if (!body.has_value()
        || !onlyFields(body.value(),
                       {"transaction_id", "challenge_id", "password", "totp", "recovery_code"})) {
        return error(body.has_value() ? foundation::Error{foundation::ErrorCode::InvalidArgument}
                                      : body.error(), request, true);
    }
    auto transaction = requiredString(body.value(), "transaction_id", 128U);
    auto challenge = requiredString(body.value(), "challenge_id", 128U);
    auto knowledgeSecret = requiredString(body.value(), "password", 1024U);
    auto totp = optionalString(body.value(), "totp", 8U);
    auto recoveryCode = optionalString(body.value(), "recovery_code", 128U);
    const auto continuation = cookieValue(request, kPreauthCookie);
    const auto bindingToken = cookieValue(request, kBindingCookie);
    if (!transaction || !challenge || !knowledgeSecret || !totp || !recoveryCode
        || (totp->has_value() && recoveryCode->has_value())
        || !continuation.has_value() || !bindingToken.has_value()) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed},
                     request, true);
    }
    auto binding = security::sha256(bindingToken.value());
    if (!binding.has_value()) return error(binding.error(), request, true);
    idp::AuthenticationResponse authenticationResponse{
        idp::ChallengeId{std::move(challenge).value()}, clientContext(request)};
    authenticationResponse.setParameter(
        "password", idp::CredentialValue{std::move(knowledgeSecret).value()});
    if (totp->has_value()) {
        authenticationResponse.setParameter(
            "totp", idp::CredentialValue{std::move(totp).value().value()});
    }
    if (recoveryCode->has_value()) {
        authenticationResponse.setParameter(
            "recovery_code",
            idp::CredentialValue{std::move(recoveryCode).value().value()});
    }
    auto verified = m_authentication->complete(
        idp::TransactionId{std::move(transaction).value()},
        foundation::SecretString{continuation.value()}, binding.value(),
        authenticationResponse);
    if (!verified.has_value()) return error(verified.error(), request, true);
    auto grant = m_sessions->issue(verified.value(), clientContext(request));
    if (!grant.has_value()) return error(grant.error(), request, true);
    json::object payload;
    payload["session_id"] = grant->id().value();
    payload["assurance"] = idp::assuranceLevelName(
        verified->outcome().claimedAssurance());
    auto output = response(200, std::move(payload));
    clearPreauth(output);
    setSessionCookie(output, grant->token());
    return output;
}

gateway::HttpResponse AuthenticationHttpApi::rotate(gateway::HttpRequest request)
{
    auto credential = gateway::takeSessionCredential(request);
    if (!credential.has_value() || !credential->has_value()) {
        return error(credential.has_value()
                         ? foundation::Error{foundation::ErrorCode::AuthenticationRequired}
                         : credential.error(), request);
    }
    auto grant = m_sessions->rotate(credential->value());
    if (!grant.has_value()) return error(grant.error(), request);
    json::object payload;
    payload["session_id"] = grant->id().value();
    auto output = response(200, std::move(payload));
    setSessionCookie(output, grant->token());
    return output;
}

gateway::HttpResponse AuthenticationHttpApi::logout(gateway::HttpRequest request, bool all)
{
    auto credential = gateway::takeSessionCredential(request);
    if (!credential.has_value()) return error(credential.error(), request);
    if (!credential->has_value()) {
        auto output = emptyResponse(204);
        clearSessionCookie(output);
        return output;
    }
    auto authenticated = m_sessions->authenticate(credential->value());
    if (!authenticated.has_value()) {
        if (authenticated.error().code() != foundation::ErrorCode::AuthenticationFailed
            && authenticated.error().code() != foundation::ErrorCode::AuthenticationRequired) {
            return error(authenticated.error(), request);
        }
    } else if (all) {
        auto revoked = m_sessions->revokeAll(authenticated->session().identity());
        if (!revoked.has_value()) return error(revoked.error(), request);
    } else {
        auto revoked = m_sessions->revoke(authenticated->session().id());
        if (!revoked.has_value()) return error(revoked.error(), request);
    }
    auto output = emptyResponse(204);
    clearSessionCookie(output);
    return output;
}

gateway::HttpResponse AuthenticationHttpApi::issueRecoveryCodes(
    gateway::HttpRequest request)
{
    auto credential = gateway::takeSessionCredential(request);
    if (!credential.has_value() || !credential->has_value()) {
        return error(credential.has_value()
                         ? foundation::Error{foundation::ErrorCode::AuthenticationRequired}
                         : credential.error(), request);
    }
    auto authenticated = m_sessions->authenticate(credential->value());
    if (!authenticated.has_value()) return error(authenticated.error(), request);
    if (!idp::meetsAssurance(authenticated->session().assurance(),
                             idp::AssuranceLevel::Ial2)) {
        return error(foundation::Error{foundation::ErrorCode::AssuranceInsufficient}, request);
    }
    auto connections = m_authentication->connections(authenticated->session().identity());
    if (!connections.has_value()) return error(connections.error(), request);
    const auto localConnection = std::ranges::find_if(
        connections.value(), [&](const auto& external) {
            return external.providerId() == m_provider;
        });
    if (localConnection == connections->end()) {
        return error(foundation::Error{foundation::ErrorCode::FailedPrecondition}, request);
    }
    auto totpEnabled = m_localAccounts->hasTotp(localConnection->subject());
    if (!totpEnabled.has_value()) return error(totpEnabled.error(), request);
    if (!totpEnabled.value()) {
        return error(foundation::Error{foundation::ErrorCode::FailedPrecondition}, request);
    }
    auto batch = m_recoveryCodes->issue(authenticated->session().identity(), 10U);
    if (!batch.has_value()) return error(batch.error(), request);
    auto stillEnabled = m_localAccounts->hasTotp(localConnection->subject());
    if (!stillEnabled.has_value() || !stillEnabled.value()) {
        auto revoked = m_recoveryCodes->revoke(authenticated->session().identity());
        if (!revoked.has_value()) return error(revoked.error(), request);
        return error(stillEnabled.has_value()
                         ? foundation::Error{foundation::ErrorCode::FailedPrecondition}
                         : stillEnabled.error(),
                     request);
    }
    json::array codes;
    for (const auto& code : batch->codes()) codes.emplace_back(code.expose());
    json::object payload;
    payload["codes"] = std::move(codes);
    return response(201, std::move(payload));
}

}

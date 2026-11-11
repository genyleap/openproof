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

#include <boost/asio/detail/call_stack.hpp>
#include "../../gateway/asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>
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
    // Accept the JSON media type only, optionally followed by parameters.
    // Prefix matching alone would also accept application/json-malformed.
    const bool jsonContentType = contentType &&
        (*contentType == "application/json" || contentType->starts_with("application/json;"));
    if (request.body().empty() || request.body().size() > kMaximumBody || !jsonContentType) {
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
    // Keep a view into the request-owned header until the entire cookie
    // list has passed duplicate and character checks. Otherwise the first
    // credential is copied before a later duplicate makes us reject it.
    std::optional<std::string_view> found;
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
            found = value;
        }
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    if (!found) return std::nullopt;
    return std::optional<std::string>{std::in_place, *found};
}

[[nodiscard]] idp::ClientContext clientContext(const gateway::HttpRequest& request)
{
    idp::ClientContext client;
    client.setRemoteAddress(std::string{request.remoteAddress()});
    if (auto agent = request.header("user-agent")) client.setUserAgent(std::string{agent->substr(0U, 1024U)});
    return client;
}

// Ensure early-error paths do not release an un-erased LDAP password
// buffer. Native completion also wipes it explicitly before the first await.
class SensitiveRequestBodyGuard final {
public:
    explicit SensitiveRequestBodyGuard(gateway::HttpRequest& request) noexcept
        : m_request(request) {}
    SensitiveRequestBodyGuard(const SensitiveRequestBodyGuard&) = delete;
    SensitiveRequestBodyGuard& operator=(const SensitiveRequestBodyGuard&) = delete;
    ~SensitiveRequestBodyGuard() { m_request.wipeBody(); }
private:
    gateway::HttpRequest& m_request;
};

// A parsed JSON value and the separate validated std::string each hold
// independently allocated copies of a password. Wiping only HttpRequest
// does not cover errors after parsing (missing cookies, invalid fields, etc.).
class SensitiveRequestCookieGuard final {
public:
    explicit SensitiveRequestCookieGuard(gateway::HttpRequest& request) noexcept
        : m_request(request) {}
    SensitiveRequestCookieGuard(const SensitiveRequestCookieGuard&) = delete;
    SensitiveRequestCookieGuard& operator=(const SensitiveRequestCookieGuard&) = delete;
    ~SensitiveRequestCookieGuard() { m_request.wipeCookieHeader(); }
private:
    gateway::HttpRequest& m_request;
};

class SensitiveParsedPasswordGuard final {
public:
    explicit SensitiveParsedPasswordGuard(json::object* object) noexcept
        : m_object(object) {}
    SensitiveParsedPasswordGuard(const SensitiveParsedPasswordGuard&) = delete;
    SensitiveParsedPasswordGuard& operator=(const SensitiveParsedPasswordGuard&) = delete;
    ~SensitiveParsedPasswordGuard() { wipe(); }

    void wipe() noexcept
    {
        if (m_object == nullptr) return;
        if (auto* field = m_object->if_contains("password");
            field != nullptr && field->is_string()) {
            auto& value = field->as_string();
            foundation::secureWipe(value.data(), value.size());
            value.clear();
        }
    }

private:
    json::object* m_object;
};

class SensitiveCredentialCopyGuard final {
public:
    explicit SensitiveCredentialCopyGuard(std::string* value) noexcept
        : m_value(value) {}
    SensitiveCredentialCopyGuard(const SensitiveCredentialCopyGuard&) = delete;
    SensitiveCredentialCopyGuard& operator=(const SensitiveCredentialCopyGuard&) = delete;
    ~SensitiveCredentialCopyGuard()
    {
        if (m_value == nullptr) return;
        foundation::secureWipe(m_value->data(), m_value->size());
        m_value->clear();
    }
private:
    std::string* m_value;
};

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
    gateway::TokenBucketRateLimiter& rateLimiter, gateway::HttpHandler& fallback,
    session::CoroutineReplacingSessionIssuer* asyncSessions)
    : m_authentication(&authentication), m_sessions(&sessions),
      m_asyncSessions(asyncSessions),
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

gateway::HttpResponse EnterpriseAuthenticationHttpApi::startLdap(
    gateway::HttpRequest request)
{
    SensitiveRequestCookieGuard wipeCookieOnExit{request};
    // Synchronous compatibility cannot create an LDAP challenge whose
    // completion now requires native Asio. Never mint an unusable state.
    return error(foundation::Error{foundation::ErrorCode::Unavailable},
                 request, true);
}

gateway::HttpResponse EnterpriseAuthenticationHttpApi::completeLdap(
    gateway::HttpRequest request)
{
    SensitiveRequestBodyGuard wipeOnExit{request};
    SensitiveRequestCookieGuard wipeCookieOnExit{request};
    // No synchronous LDAP directory bind, transaction redemption, or
    // session repository is allowed from this compatibility handler.
    return error(foundation::Error{foundation::ErrorCode::Unavailable},
                 request, true);
}

bool EnterpriseAuthenticationHttpApi::nativeEnabledFor(
    const gateway::HttpRequest& request) const noexcept
{
    const auto path = request.path();
    if (path == "/auth/ldap/start" || path == "/auth/ldap/complete") {
        if (request.method() != gateway::HttpMethod::Post
            || m_asyncSessions == nullptr) return false;
        try {
            return m_authentication->nativeProviderAuthenticationEnabled(
                idp::ProviderId{"ldap"});
        } catch (...) {
            // Capability lookups are noexcept from the listener's point of
            // view, including OOM during provider-id construction.
            return false;
        }
    }
    if (path.starts_with("/auth/ldap/")) return false;
    try {
        auto* native = dynamic_cast<gateway::http::CoroutineHttpHandler*>(m_fallback);
        return native != nullptr && native->nativeEnabledFor(request);
    } catch (...) {
        return false;
    }
}

boost::asio::awaitable<gateway::HttpResponse>
EnterpriseAuthenticationHttpApi::handleAsync(gateway::HttpRequest request)
{
    if (!nativeEnabledFor(request)) {
        if (request.path().starts_with("/auth/ldap/")) {
            request.wipeBody();
            request.wipeCookieHeader();
        }
        co_return error(foundation::Error{foundation::ErrorCode::Unavailable},
                        request, true);
    }
    if (request.path() == "/auth/ldap/start"
        && request.method() == gateway::HttpMethod::Post)
        co_return co_await startLdapAsync(std::move(request));
    if (request.path() == "/auth/ldap/complete"
        && request.method() == gateway::HttpMethod::Post)
        co_return co_await completeLdapAsync(std::move(request));
    auto* native = dynamic_cast<gateway::http::CoroutineHttpHandler*>(m_fallback);
    if (!native || !native->nativeEnabledFor(request)) {
        co_return error(foundation::Error{foundation::ErrorCode::Unavailable},
                        request);
    }
    co_return co_await native->handleAsync(std::move(request));
}

boost::asio::awaitable<gateway::HttpResponse>
EnterpriseAuthenticationHttpApi::startLdapAsync(gateway::HttpRequest request)
{
    SensitiveRequestCookieGuard wipeCookieOnExit{request};
    if (!nativeEnabledFor(request)) {
        co_return error(foundation::Error{foundation::ErrorCode::Unavailable}, request, true);
    }
    if (!m_rateLimiter->allow(std::string{"ldap-ip:"} + std::string{request.remoteAddress()})) {
        co_return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"username"})) co_return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto username = required(body.value(), "username", 320U);
    if (!username) co_return error(username.error(), request);
    auto bindingToken = security::randomTokenBase64Url(32U);
    if (!bindingToken) co_return error(bindingToken.error(), request);
    auto binding = security::sha256(bindingToken.value());
    if (!binding) co_return error(binding.error(), request);
    idp::AuthenticationRequest authenticationRequest{idp::ProviderId{"ldap"}, clientContext(request)};
    authenticationRequest.setRequestedAssurance(idp::AssuranceLevel::Ial1);
    authenticationRequest.setParameter("username", username.value());
    request.wipeCookieHeader();
    auto started = co_await m_authentication->beginAsync(
        std::move(authenticationRequest), binding.value(), request.correlation());
    if (!started) co_return error(started.error(), request);
    const auto bindingParameter = started->challenge().parameters().find("username_binding");
    if (bindingParameter == started->challenge().parameters().end()) co_return error(foundation::Error{foundation::ErrorCode::Internal}, request);
    json::object output;
    output["transaction_id"] = started->transactionId().value();
    output["challenge_id"] = started->challenge().id().value();
    output["username"] = username.value();
    output["username_binding"] = bindingParameter->second;
    output["expires_at_ms"] = started->challenge().expiresAt().time_since_epoch().count();
    auto response = jsonResponse(202, std::move(output));
    response.addHeader("set-cookie", cookie(kContinuationCookie, started->continuationToken().expose(), 600));
    response.addHeader("set-cookie", cookie(kBindingCookie, bindingToken.value(), 600));
    co_return response;
}

boost::asio::awaitable<gateway::HttpResponse>
EnterpriseAuthenticationHttpApi::completeLdapAsync(gateway::HttpRequest request)
{
    SensitiveRequestBodyGuard wipeOnExit{request};
    SensitiveRequestCookieGuard wipeCookieOnExit{request};
    // Refuse unavailable native storage before consuming a one-time proof.
    if (!nativeEnabledFor(request) || m_asyncSessions == nullptr) {
        co_return error(foundation::Error{foundation::ErrorCode::Unavailable},
                        request, true);
    }
    // A failed/rapid password attempt must not avoid per-IP completion
    // throttling by skipping challenge creation.
    if (!m_rateLimiter->allow(
            std::string{"ldap-complete-ip:"} + std::string{request.remoteAddress()})) {
        co_return error(foundation::Error{foundation::ErrorCode::RateLimited},
                        request, true);
    }
    auto body = parseObject(request);
    SensitiveParsedPasswordGuard wipeParsedOnExit{body ? &body.value() : nullptr};
    if (!body || !onlyFields(body.value(), {"transaction_id", "challenge_id", "username", "username_binding", "password"})) {
        co_return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request, true);
    }
    auto transaction = required(body.value(), "transaction_id", 256U);
    auto challenge = required(body.value(), "challenge_id", 256U);
    auto username = required(body.value(), "username", 320U);
    auto usernameBinding = required(body.value(), "username_binding", 256U);
    // Match the native LDAPS provider's 1024-byte limit *before* consuming
    // a one-time transaction. A larger password is invalid input, not an
    // LDAP proof attempt that should burn a valid challenge.
    auto password = required(body.value(), "password", 1024U);
    SensitiveCredentialCopyGuard wipePasswordCopyOnExit{password ? &password.value() : nullptr};
    auto continuation = cookieValue(request, kContinuationCookie);
    SensitiveCredentialCopyGuard wipeContinuationOnExit{continuation ? &*continuation : nullptr};
    auto bindingToken = cookieValue(request, kBindingCookie);
    SensitiveCredentialCopyGuard wipeBindingOnExit{bindingToken ? &*bindingToken : nullptr};
    auto previousSession = cookieValue(request, "__Host-openproof-session");
    SensitiveCredentialCopyGuard wipePreviousSessionOnExit{
        previousSession ? &*previousSession : nullptr};
    if (!transaction || !challenge || !username || !usernameBinding || !password || !continuation || !bindingToken) {
        co_return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed}, request, true);
    }
    auto binding = security::sha256(*bindingToken);
    if (!binding) co_return error(binding.error(), request, true);
    idp::AuthenticationResponse authenticationResponse{idp::ChallengeId{challenge.value()}, clientContext(request)};
    authenticationResponse.setParameter("username", idp::CredentialValue{username.value()});
    authenticationResponse.setParameter("username_binding", idp::CredentialValue{usernameBinding.value()});
    authenticationResponse.setParameter(
        "password", idp::CredentialValue{std::move(password).value()});
    // The CredentialValue destructor scrubs the moved password. In addition,
    // wipe the JSON-owned copy and the request-owned bytes before suspension.
    // Guards cover all earlier returns and exception unwinding as well.
    auto& parsedPassword = body->at("password").as_string();
    foundation::secureWipe(parsedPassword.data(), parsedPassword.size());
    parsedPassword.clear();
    request.wipeBody();
    // Transfer the one-time continuation to an auto-wiping Secret. The
    // binding cookie is needed only for its digest, not across suspension.
    foundation::SecretString continuationSecret{std::move(*continuation)};
    // Preserve the first-party re-login invariant: if the browser presents
    // a previous authenticated session, its retirement and the new grant
    // must be one atomic native SQL mutation, never two separate requests.
    std::optional<foundation::SecretString> previousSessionToken;
    if (previousSession) {
        previousSessionToken.emplace(std::move(*previousSession));
    }
    foundation::secureWipe(bindingToken->data(), bindingToken->size());
    bindingToken->clear();
    request.wipeCookieHeader();
    auto verified = co_await m_authentication->completeAsync(
        idp::TransactionId{std::move(transaction).value()},
        std::move(continuationSecret), binding.value(),
        std::move(authenticationResponse));
    if (!verified) co_return error(verified.error(), request, true);
    auto grant = co_await m_asyncSessions->issueReplacingAsync(
        verified.value(), clientContext(request), std::move(previousSessionToken));
    if (!grant) co_return error(grant.error(), request, true);
    // SecretString::expose() returns a reference; copying it to plain auto
    // would allocate an unprotected bearer that is not scrubbed at destruction.
    const auto& bearer = grant->token.expose();
    if (bearer.empty() || bearer.size() > 128U
        || !std::ranges::all_of(bearer, [](char symbol) {
            return (symbol >= 'A' && symbol <= 'Z')
                || (symbol >= 'a' && symbol <= 'z')
                || (symbol >= '0' && symbol <= '9')
                || symbol == '-' || symbol == '_';
        })) {
        co_return error(foundation::Error{foundation::ErrorCode::Unavailable},
                        request, true);
    }
    json::object output;
    output["session_id"] = grant->id.value();
    output["assurance"] = idp::assuranceLevelName(verified->outcome().claimedAssurance());
    auto response = jsonResponse(200, std::move(output));
    clearState(response);
    response.addHeader("set-cookie", cookie("__Host-openproof-session", grant->token.expose(), 8 * 60 * 60));
    co_return response;
}

} // namespace openproof::authentication::http

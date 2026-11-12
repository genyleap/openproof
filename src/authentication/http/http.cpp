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
#include <utility>

#include <boost/asio/detail/call_stack.hpp>
#include "../../gateway/asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>
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
constexpr std::string_view kSubjectCookie = "__Host-openproof-preauth-subject";

// HMAC input contains a browser-bound secret. Explicit RAII wiping covers
// exceptions and any early return, not only the successful digest path.
class SensitiveBindingMaterialGuard final {
public:
    explicit SensitiveBindingMaterialGuard(std::string& value) noexcept
        : m_value(value) {}
    SensitiveBindingMaterialGuard(const SensitiveBindingMaterialGuard&) = delete;
    SensitiveBindingMaterialGuard& operator=(const SensitiveBindingMaterialGuard&) = delete;
    ~SensitiveBindingMaterialGuard()
    {
        foundation::secureWipe(m_value.data(), m_value.size());
        m_value.clear();
    }
private:
    std::string& m_value;
};

// Native authentication may deny requests before extracting their credentials
// or suspend for database/provider I/O. Neither request-owned headers nor the
// raw JSON password body should survive in an unprotected string buffer.
class SensitiveAuthRequestGuard final {
public:
    explicit SensitiveAuthRequestGuard(gateway::HttpRequest& request) noexcept
        : m_request(request) {}
    SensitiveAuthRequestGuard(const SensitiveAuthRequestGuard&) = delete;
    SensitiveAuthRequestGuard& operator=(const SensitiveAuthRequestGuard&) = delete;
    ~SensitiveAuthRequestGuard() { wipe(); }
    void wipe() noexcept
    {
        m_request.wipeBody();
        m_request.wipeAuthorizationHeader();
        m_request.wipeCookieHeader();
    }
private:
    gateway::HttpRequest& m_request;
};

// This guard MUST be constructed after the parsed JSON owner so its
// destructor wipes parsed credentials before that owner is destroyed.
class SensitiveParsedAuthSecretsGuard final {
public:
    explicit SensitiveParsedAuthSecretsGuard(json::object* object) noexcept
        : m_object(object) {}
    SensitiveParsedAuthSecretsGuard(const SensitiveParsedAuthSecretsGuard&) = delete;
    SensitiveParsedAuthSecretsGuard& operator=(const SensitiveParsedAuthSecretsGuard&) = delete;
    ~SensitiveParsedAuthSecretsGuard() { wipe(); }
    void wipe() noexcept
    {
        if (m_object == nullptr) return;
        for (std::string_view name : {"password", "totp", "recovery_code"}) {
            if (auto* field = m_object->if_contains(name);
                field != nullptr && field->is_string()) {
                auto& value = field->as_string();
                foundation::secureWipe(value.data(), value.size());
                value.clear();
            }
        }
    }
private:
    json::object* m_object;
};

// Validated std::string and optional<std::string> copies need their own
// erasure on early returns, including a missing/invalid cookie after a valid
// password has already been parsed.
class SensitiveAuthCopyGuard final {
public:
    explicit SensitiveAuthCopyGuard(std::string* value) noexcept
        : m_text(value) {}
    explicit SensitiveAuthCopyGuard(std::optional<std::string>* value) noexcept
        : m_optional(value) {}
    SensitiveAuthCopyGuard(const SensitiveAuthCopyGuard&) = delete;
    SensitiveAuthCopyGuard& operator=(const SensitiveAuthCopyGuard&) = delete;
    ~SensitiveAuthCopyGuard() { wipe(); }
    void wipe() noexcept
    {
        std::string* value = m_text;
        if (m_optional != nullptr && m_optional->has_value()) {
            value = &m_optional->value();
        }
        if (value == nullptr) return;
        foundation::secureWipe(value->data(), value->size());
        value->clear();
    }
private:
    std::string* m_text{};
    std::optional<std::string>* m_optional{};
};

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

[[nodiscard]] foundation::Result<idp::BindingDigest> preauthBinding(
    std::string_view bindingToken, std::string_view subject)
{
    if (bindingToken.empty() || subject.empty() || subject.size() > 320U) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    }
    std::string material;
    SensitiveBindingMaterialGuard wipeMaterialOnExit{material};
    material.reserve(bindingToken.size() + 1U + subject.size());
    material.append(bindingToken);
    material.push_back('\0');
    material.append(subject);
    return security::sha256(material);
}

[[nodiscard]] foundation::Result<std::string> decodePreauthSubject(
    std::string_view encoded)
{
    if (encoded.empty() || encoded.size() > 512U) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    }
    auto decoded = foundation::fromBase64Url(encoded);
    if (!decoded.has_value() || decoded->empty() || decoded->size() > 320U) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    }
    std::string subject{reinterpret_cast<const char*>(decoded->data()), decoded->size()};
    if (std::ranges::any_of(subject, [](char symbol) {
            const auto byte = static_cast<unsigned char>(symbol);
            return byte < 0x20U || byte == 0x7FU;
        })) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    }
    return subject;
}

void clearPreauth(gateway::HttpResponse& output)
{
    output.addHeader("set-cookie", cookie(kPreauthCookie, "", "/", 0));
    output.addHeader("set-cookie", cookie(kBindingCookie, "", "/", 0));
    output.addHeader("set-cookie", cookie(kSubjectCookie, "", "/", 0));
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
    // Borrow the parsed JSON string: plain auto copies passwords/TOTP into
    // an unprotected temporary before the caller can scrub it.
    const auto& text = value->as_string();
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
cookieValue(const gateway::HttpRequest& request, std::string_view wanted,
            std::size_t maximumLength = 128U)
{
    const auto header = request.header("cookie");
    if (!header.has_value()) return std::nullopt;
    // Validate the entire cookie list before allocating even one
    // credential copy; duplicates must never leave un-erased strings.
    std::optional<std::string_view> found;
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
            if (found.has_value() || value.empty() || value.size() > maximumLength
                || !std::ranges::all_of(value, [](char symbol) {
                       return (symbol >= 'A' && symbol <= 'Z')
                           || (symbol >= 'a' && symbol <= 'z')
                           || (symbol >= '0' && symbol <= '9')
                           || symbol == '-' || symbol == '_';
                   })) {
                return std::nullopt;
            }
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
    gateway::HttpHandler& fallback, session::CoroutineReplacingSessionIssuer* asyncSessions)
    : m_authentication(&authentication), m_sessions(&sessions),
      m_asyncSessions(asyncSessions),
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

// Only /auth/login and /auth/mfa/verify are ready for native dispatch.
// Other auth routes continue on the bounded compatibility worker. Native
// readiness always requires a trusted provider, native transactions, canonical
// finalizer and a replacing session issuer, not merely a coroutine-shaped API.
bool AuthenticationHttpApi::nativeEnabledFor(
    const gateway::HttpRequest& request) const noexcept
{
    const auto path = request.path();
    if (path == "/auth/login" || path == "/auth/mfa/verify") {
        return m_asyncSessions != nullptr
            && m_authentication->nativeProviderAuthenticationEnabled(m_provider);
    }
    if (path == "/auth" || path.starts_with("/auth/")) return false;
    auto* native = dynamic_cast<gateway::http::CoroutineHttpHandler*>(m_fallback);
    return native != nullptr && native->nativeEnabledFor(request);
}

boost::asio::awaitable<gateway::HttpResponse>
AuthenticationHttpApi::handleAsync(gateway::HttpRequest request)
{
    SensitiveAuthRequestGuard wipeRequestOnExit{request};
    if (request.path() != "/auth" && !request.path().starts_with("/auth/")) {
        auto* native =
            dynamic_cast<gateway::http::CoroutineHttpHandler*>(m_fallback);
        if (native != nullptr && native->nativeEnabledFor(request)) {
            co_return co_await native->handleAsync(std::move(request));
        }
        co_return error(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    }
    if (!nativeEnabledFor(request)) {
        co_return error(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    }
    if (!m_rateLimiter->allow(
            std::string{"auth-ip:"} + std::string{request.remoteAddress()})) {
        co_return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    if (request.method() != gateway::HttpMethod::Post) {
        co_return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
    }
    if (request.path() == "/auth/login") {
        co_return co_await loginAsync(std::move(request));
    }
    if (request.path() == "/auth/mfa/verify") {
        co_return co_await verifyAsync(std::move(request));
    }
    // Rotation/logout/recovery-code routes still use synchronous repository
    // contracts. Never invoke them indirectly on the native I/O executor.
    co_return error(foundation::Error{foundation::ErrorCode::Unavailable}, request);
}

boost::asio::awaitable<gateway::HttpResponse>
AuthenticationHttpApi::loginAsync(gateway::HttpRequest request)
{
    SensitiveAuthRequestGuard wipeRequestOnExit{request};
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"subject"})) {
        co_return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument}
                             : body.error(), request);
    }
    auto subject = requiredString(body.value(), "subject", 320U);
    if (!subject) co_return error(subject.error(), request);
    if (!m_rateLimiter->allow(std::string{"auth-subject:"} + subject.value())) {
        co_return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    auto bindingToken = security::randomTokenBase64Url(32U);
    if (!bindingToken) co_return error(bindingToken.error(), request);
    // Keep the browser-binding credential in an auto-wiping owner while
    // the challenge is persisted asynchronously.
    foundation::SecretString bindingSecret{std::move(bindingToken).value()};
    const std::string subjectValue = subject.value();
    auto binding = preauthBinding(bindingSecret.expose(), subjectValue);
    if (!binding) co_return error(binding.error(), request);
    const std::string encodedSubject = foundation::toBase64Url(
        std::as_bytes(std::span{subjectValue.data(), subjectValue.size()}));
    idp::AuthenticationRequest authRequest{m_provider, clientContext(request)};
    authRequest.setParameter("subject", subjectValue);
    authRequest.setRequestedAssurance(idp::AssuranceLevel::Ial1);
    // The subject and client context are already owned by the provider
    // request. A stale browser session or bearer is not needed by beginAsync.
    wipeRequestOnExit.wipe();
    auto started = co_await m_authentication->beginAsync(
        std::move(authRequest), binding.value(), request.correlation());
    if (!started) co_return error(started.error(), request);

    json::object payload;
    payload["transaction_id"] = started->transactionId().value();
    payload["challenge_id"] = started->challenge().id().value();
    payload["expires_at_ms"] = started->challenge().expiresAt().time_since_epoch().count();
    auto output = response(202, std::move(payload));
    output.addHeader("set-cookie", cookie(
        kPreauthCookie, started->continuationToken().expose(), "/", 300));
    output.addHeader("set-cookie", cookie(
        kBindingCookie, bindingSecret.expose(), "/", 300));
    output.addHeader("set-cookie", cookie(
        kSubjectCookie, encodedSubject, "/", 300));
    co_return output;
}

boost::asio::awaitable<gateway::HttpResponse>
AuthenticationHttpApi::verifyAsync(gateway::HttpRequest request)
{
    SensitiveAuthRequestGuard wipeRequestOnExit{request};
    if (!nativeEnabledFor(request)) {
        co_return error(foundation::Error{foundation::ErrorCode::Unavailable},
                        request, true);
    }
    auto body = parseObject(request);
    SensitiveParsedAuthSecretsGuard wipeParsedOnExit{
        body ? &body.value() : nullptr};
    if (!body || !onlyFields(body.value(),
                    {"transaction_id", "challenge_id", "password", "totp", "recovery_code"})) {
        co_return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument}
                             : body.error(), request, true);
    }
    auto transaction = requiredString(body.value(), "transaction_id", 128U);
    auto challenge = requiredString(body.value(), "challenge_id", 128U);
    auto knowledgeSecret = requiredString(body.value(), "password", 1024U);
    SensitiveAuthCopyGuard wipeKnowledgeOnExit{
        knowledgeSecret ? &knowledgeSecret.value() : nullptr};
    auto totp = optionalString(body.value(), "totp", 8U);
    SensitiveAuthCopyGuard wipeTotpOnExit{totp ? &totp.value() : nullptr};
    auto recoveryCode = optionalString(body.value(), "recovery_code", 128U);
    SensitiveAuthCopyGuard wipeRecoveryOnExit{
        recoveryCode ? &recoveryCode.value() : nullptr};
    auto continuation = cookieValue(request, kPreauthCookie);
    SensitiveAuthCopyGuard wipeContinuationOnExit{&continuation};
    auto bindingToken = cookieValue(request, kBindingCookie);
    SensitiveAuthCopyGuard wipeBindingOnExit{&bindingToken};
    auto encodedSubject = cookieValue(request, kSubjectCookie, 512U);
    SensitiveAuthCopyGuard wipeSubjectOnExit{&encodedSubject};
    if (!transaction || !challenge || !knowledgeSecret || !totp || !recoveryCode
        || (totp->has_value() && recoveryCode->has_value())
        || !continuation || !bindingToken || !encodedSubject) {
        co_return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed},
                        request, true);
    }
    auto subject = decodePreauthSubject(*encodedSubject);
    if (!subject) co_return error(subject.error(), request, true);
    auto binding = preauthBinding(*bindingToken, subject.value());
    if (!binding) co_return error(binding.error(), request, true);
    idp::AuthenticationResponse authResponse{
        idp::ChallengeId{std::move(challenge).value()}, clientContext(request)};
    authResponse.setParameter("subject", idp::CredentialValue{subject.value()});
    authResponse.setParameter("password",
        idp::CredentialValue{std::move(knowledgeSecret).value()});
    if (totp->has_value()) {
        authResponse.setParameter("totp",
            idp::CredentialValue{std::move(totp).value().value()});
    }
    if (recoveryCode->has_value()) {
        authResponse.setParameter("recovery_code",
            idp::CredentialValue{std::move(recoveryCode).value().value()});
    }

    // Keep the legacy browser replay invariant: the new grant and revocation
    // of an authenticated old browser session must be a single SQL mutation.
    auto previous = cookieValue(request, "__Host-openproof-session");
    SensitiveAuthCopyGuard wipePreviousOnExit{&previous};
    std::optional<foundation::SecretString> oldToken;
    if (previous) oldToken.emplace(std::move(*previous));

    // Move the one-time continuation directly into the wiping secret owner.
    // Password, TOTP and recovery-code copies are now owned by CredentialValue.
    // Clear the original JSON and request buffers *before* any suspension.
    foundation::SecretString continuationSecret{std::move(*continuation)};
    wipeParsedOnExit.wipe();
    wipeBindingOnExit.wipe();
    wipeSubjectOnExit.wipe();
    wipeRequestOnExit.wipe();
    auto verified = co_await m_authentication->completeAsync(
        idp::TransactionId{std::move(transaction).value()},
        std::move(continuationSecret), binding.value(),
        std::move(authResponse));
    if (!verified) co_return error(verified.error(), request, true);
    auto issued = co_await m_asyncSessions->issueReplacingAsync(
        verified.value(), clientContext(request), std::move(oldToken));
    if (!issued) co_return error(issued.error(), request, true);

    // SecretString::expose() returns a reference; copying it to plain auto
    // would allocate an unprotected bearer that is not scrubbed at destruction.
    const auto& bearer = issued->token.expose();
    if (bearer.empty() || bearer.size() > 128U
        || !std::ranges::all_of(bearer, [](char value) {
            return (value >= 'A' && value <= 'Z')
                || (value >= 'a' && value <= 'z')
                || (value >= '0' && value <= '9')
                || value == '-' || value == '_';
        })) {
        co_return error(foundation::Error{foundation::ErrorCode::Unavailable},
                        request, true);
    }
    json::object payload;
    payload["session_id"] = issued->id.value();
    payload["assurance"] = idp::assuranceLevelName(
        verified->outcome().claimedAssurance());
    auto output = response(200, std::move(payload));
    clearPreauth(output);
    setSessionCookie(output, issued->token);
    co_return output;
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
    const std::string subjectValue = subject.value();
    auto binding = preauthBinding(bindingToken.value(), subjectValue);
    if (!binding.has_value()) return error(binding.error(), request);
    const std::string encodedSubject = foundation::toBase64Url(
        std::as_bytes(std::span{subjectValue.data(), subjectValue.size()}));
    idp::AuthenticationRequest authenticationRequest{m_provider, clientContext(request)};
    authenticationRequest.setParameter("subject", subjectValue);
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
    output.addHeader("set-cookie", cookie(
        kSubjectCookie, encodedSubject, "/", 300));
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
    const auto encodedSubject = cookieValue(request, kSubjectCookie, 512U);
    if (!transaction || !challenge || !knowledgeSecret || !totp || !recoveryCode
        || (totp->has_value() && recoveryCode->has_value())
        || !continuation.has_value() || !bindingToken.has_value()
        || !encodedSubject.has_value()) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationFailed},
                     request, true);
    }
    auto subject = decodePreauthSubject(encodedSubject.value());
    if (!subject.has_value()) return error(subject.error(), request, true);
    auto binding = preauthBinding(bindingToken.value(), subject.value());
    if (!binding.has_value()) return error(binding.error(), request, true);
    idp::AuthenticationResponse authenticationResponse{
        idp::ChallengeId{std::move(challenge).value()}, clientContext(request)};
    authenticationResponse.setParameter(
        "subject", idp::CredentialValue{subject.value()});
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
    // A retry after a successfully verified login must not leave an additional
    // active session for the same browser. No session is touched on bad proof.
    const auto priorCookie = cookieValue(request, "__Host-openproof-session");
    const std::optional<foundation::SecretString> priorToken =
        priorCookie && !priorCookie->empty()
            ? std::optional<foundation::SecretString>{
                  std::in_place, std::string{*priorCookie}}
            : std::nullopt;
    auto grant = m_sessions->issueReplacing(
        verified.value(), clientContext(request),
        priorToken ? &*priorToken : nullptr);
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

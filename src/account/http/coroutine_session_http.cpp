#include <boost/asio/awaitable.hpp>
#include <boost/json.hpp>

#include <algorithm>
#include <cstddef>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>

#include "coroutine_session_http.hpp"

import openproof.identity.provider;

namespace openproof::account::http {
namespace asio = boost::asio;
namespace json = boost::json;
namespace {

// Match the native SQL list ceiling without introducing a PostgreSQL
// dependency into the provider-neutral Account HTTP adapter.
constexpr std::size_t kMaximumSessionResponseRows = 256U;

// Authentication may be rejected before takeSessionCredential() (routing,
// rate limiting, JSON validation). Scrub request-owned secrets even then.
// Once extracted, the SecretString itself owns its secure-wipe lifecycle.
class SensitiveSessionHeadersGuard final {
public:
    explicit SensitiveSessionHeadersGuard(gateway::HttpRequest& request) noexcept
        : m_request(request) {}
    SensitiveSessionHeadersGuard(const SensitiveSessionHeadersGuard&) = delete;
    SensitiveSessionHeadersGuard& operator=(const SensitiveSessionHeadersGuard&) = delete;
    ~SensitiveSessionHeadersGuard()
    {
        m_request.wipeAuthorizationHeader();
        m_request.wipeCookieHeader();
    }
private:
    gateway::HttpRequest& m_request;
};

[[nodiscard]] bool sessionListRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method() == gateway::HttpMethod::Get
        && request.path() == "/account/sessions";
}

[[nodiscard]] bool sessionRevokeRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method() == gateway::HttpMethod::Post
        && request.path() == "/account/sessions/revoke";
}

[[nodiscard]] bool profileReadRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method() == gateway::HttpMethod::Get
        && request.path() == "/account/profile";
}

[[nodiscard]] bool profileUpdateRoute(const gateway::HttpRequest& request) noexcept
{
    return (request.method()==gateway::HttpMethod::Patch || request.method()==gateway::HttpMethod::Put)
        && request.path()=="/account/profile";
}

[[nodiscard]] bool connectionsReadRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method() == gateway::HttpMethod::Get
        && request.path() == "/account/connections";
}

[[nodiscard]] bool totpStatusReadRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method() == gateway::HttpMethod::Get
        && request.path() == "/account/totp";
}

[[nodiscard]] bool passwordUpgradeStatusReadRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method() == gateway::HttpMethod::Get
        && request.path() == "/account/password/upgrade";
}

[[nodiscard]] bool passwordUpgradeConfirmRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method() == gateway::HttpMethod::Post
        && request.path() == "/account/password/upgrade";
}

[[nodiscard]] bool trustedPasswordUpgradeOrigin(const gateway::HttpRequest& request)
{
    const auto origin = request.header("origin");
    const auto host = request.header("host");
    if (!origin || !host || host->empty()) return false;
    if (host->find_first_of("/\\\r\n") != std::string_view::npos) return false;
    if (*origin != ("https://" + std::string{*host})) return false;
    const auto site = request.header("sec-fetch-site");
    return !site || *site == "same-origin";
}

class PasswordRequestGuard final {
public:
    explicit PasswordRequestGuard(gateway::HttpRequest& request) noexcept : m_request(request) {}
    ~PasswordRequestGuard() { m_request.wipeBody(); }
    PasswordRequestGuard(const PasswordRequestGuard&) = delete;
    PasswordRequestGuard& operator=(const PasswordRequestGuard&) = delete;
private:
    gateway::HttpRequest& m_request;
};

class ParsedPasswordGuard final {
public:
    explicit ParsedPasswordGuard(json::value& parsed) noexcept : m_parsed(parsed) {}
    ~ParsedPasswordGuard() {
        if (m_parsed.is_object()) {
            for (const auto name:{"password","secret"}) {
                if (auto* value=m_parsed.as_object().if_contains(name);value && value->is_string()) {
                    auto& text=value->as_string();
                    foundation::secureWipe(text.data(),text.size());
                    text.clear();
                }
            }
        }
    }
    ParsedPasswordGuard(const ParsedPasswordGuard&) = delete;
    ParsedPasswordGuard& operator=(const ParsedPasswordGuard&) = delete;
private:
    json::value& m_parsed;
};

[[nodiscard]] foundation::Result<foundation::SecretString> passwordUpgradeSecret(gateway::HttpRequest& request)
{
    PasswordRequestGuard wipeBody{request};
    const auto type = request.header("content-type");
    if (request.body().empty() || request.body().size()>32U*1024U || !type
        || (*type!="application/json" && !type->starts_with("application/json;")))
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    boost::system::error_code ec;
    auto parsed = json::parse(request.body(),ec);
    ParsedPasswordGuard wipeParsed{parsed};
    if (ec || !parsed.is_object() || parsed.as_object().size()!=1U)
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    auto* field = parsed.as_object().if_contains("password");
    if (!field || !field->is_string())
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    const std::string_view value{field->as_string().data(),field->as_string().size()};
    if (value.empty() || value.size()>1024U || std::ranges::any_of(value,[](char ch) {
        const auto byte = static_cast<unsigned char>(ch);
        return byte<0x20U || byte==0x7FU;
    })) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    return foundation::SecretString{std::string{value}};
}

[[nodiscard]] bool accountNamespace(const gateway::HttpRequest& request) noexcept
{
    return request.path() == "/account"
        || request.path().starts_with("/account/");
}

[[nodiscard]] gateway::HttpResponse jsonResponse(int status, json::object body)
{
    gateway::HttpResponse response{
        status, gateway::Headers{{"content-type", "application/json"}},
        json::serialize(body)};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    return response;
}

[[nodiscard]] foundation::Result<session::SessionId> revokeTarget(
    const gateway::HttpRequest& request)
{
    // Retain the legacy AccountHttpApi's strict JSON-only single-field
    // request contract. Never accept extra fields or ambiguous identifiers.
    if (request.body().empty() || request.body().size() > 32U * 1024U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    const auto contentType = request.header("content-type");
    // Require the complete JSON media-type token, optionally parameters.
    // A bare prefix also accepts application/json-invalid or jsonp.
    if (!contentType
        || (*contentType != "application/json"
            && !contentType->starts_with("application/json;"))) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    boost::system::error_code parseError;
    auto parsed = json::parse(request.body(), parseError);
    if (parseError || !parsed.is_object()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    const auto& object = parsed.as_object();
    if (object.size() != 1U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    const auto* value = object.if_contains("session_id");
    if (!value || !value->is_string()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    const std::string_view id{value->as_string().data(), value->as_string().size()};
    if (id.empty() || id.size() > 200U
        || std::ranges::any_of(id, [](char symbol) {
            const auto byte = static_cast<unsigned char>(symbol);
            return byte < 0x20U || byte == 0x7FU;
        })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    return session::SessionId{std::string{id}};
}

} // namespace

CoroutineAccountSessionAdapter::CoroutineAccountSessionAdapter(
    gateway::HttpHandler& legacyAccount,
    gateway::http::CoroutineHttpHandler& asyncFallback,
    gateway::TokenBucketRateLimiter& limiter,
    Authenticate authenticate, List list, RevokeOwned revokeOwned,
    ReadProfile readProfile, ReadConnections readConnections,
    ReadTotpStatus readTotpStatus, ReadPasswordUpgradeStatus readPasswordUpgradeStatus,
    ConfirmPasswordUpgrade confirmPasswordUpgrade, UpdateProfile updateProfile)
    : m_legacyAccount(&legacyAccount), m_asyncFallback(&asyncFallback),
      m_limiter(&limiter), m_authenticate(std::move(authenticate)),
      m_list(std::move(list)), m_revokeOwned(std::move(revokeOwned)),
      m_readProfile(std::move(readProfile)),
      m_readConnections(std::move(readConnections)),
      m_readTotpStatus(std::move(readTotpStatus)),
      m_readPasswordUpgradeStatus(std::move(readPasswordUpgradeStatus)),
      m_confirmPasswordUpgrade(std::move(confirmPasswordUpgrade)),
      m_updateProfile(std::move(updateProfile))
{
}

bool CoroutineAccountSessionAdapter::nativeEnabledFor(
    const gateway::HttpRequest& request) const noexcept
{
    // These exact connection ceremonies are owned by downstream native
    // Web3/federation handlers, not the account session/profile adapter.
    if (!accountNamespace(request)
        || request.path()=="/account/connections/web3/start"
        || request.path()=="/account/connections/web3/complete"
        || request.path()=="/account/connections/web3/handoff"
        || request.path()=="/account/connections/start"
        || request.path()=="/account/connections/handoff") {
        return m_asyncFallback->nativeEnabledFor(request);
    }
    if (profileReadRoute(request)) {
        // Legacy AccountHttpApi also accepts delegated OAuth Bearer grants.
        // Native PostgreSQL session authentication supports first-party
        // sessions only. Preserve delegated OAuth semantics on the bounded
        // compatibility worker; do not misclassify Bearer as a session.
        return !request.header("authorization").has_value()
            && static_cast<bool>(m_authenticate)
            && static_cast<bool>(m_readProfile);
    }
    if (profileUpdateRoute(request)) {
        return !request.header("authorization").has_value()
            && static_cast<bool>(m_authenticate) && static_cast<bool>(m_updateProfile);
    }
    if (connectionsReadRoute(request)) {
        // Delegated OAuth Bearer grants are still authenticated only by the
        // compatibility route; native reads accept first-party cookies.
        return !request.header("authorization").has_value()
            && static_cast<bool>(m_authenticate)
            && static_cast<bool>(m_readConnections);
    }
    if (totpStatusReadRoute(request)) {
        return !request.header("authorization").has_value()
            && static_cast<bool>(m_authenticate)
            && static_cast<bool>(m_readTotpStatus);
    }
    if (passwordUpgradeStatusReadRoute(request)) {
        return !request.header("authorization").has_value()
            && static_cast<bool>(m_authenticate)
            && static_cast<bool>(m_readPasswordUpgradeStatus);
    }
    if (passwordUpgradeConfirmRoute(request)) {
        return !request.header("authorization").has_value()
            && static_cast<bool>(m_authenticate)
            && static_cast<bool>(m_confirmPasswordUpgrade);
    }
    return static_cast<bool>(m_authenticate)
        && static_cast<bool>(m_list)
        && static_cast<bool>(m_revokeOwned)
        && (sessionListRoute(request) || sessionRevokeRoute(request));
}

gateway::HttpResponse CoroutineAccountSessionAdapter::handle(
    gateway::HttpRequest request)
{
    // The existing synchronous AccountHttpApi remains the default ABI for
    // every route until the listener explicitly selects this native adapter.
    return m_legacyAccount->handle(std::move(request));
}

gateway::HttpResponse CoroutineAccountSessionAdapter::fail(
    const foundation::Error& failure, const gateway::HttpRequest& request)
{
    gateway::HttpResponse response{
        foundation::errorHttpStatus(failure.code()),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(failure, request.correlation().value())};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    // An HTTP 401 requires a challenge. Keep native session and profile
    // endpoints interoperable with Bearer-aware clients (including the
    // synchronous Account API's missing-credential response).
    if (response.status() == 401)
        response.setHeader("www-authenticate", "Bearer");
    return response;
}

asio::awaitable<gateway::HttpResponse>
CoroutineAccountSessionAdapter::handleAsync(gateway::HttpRequest request)
{
    SensitiveSessionHeadersGuard wipeHeadersOnExit{request};
    // Check again after dispatch: downstream capability may have been
    // withdrawn, or a caller may have invoked this entry point directly.
    if (!nativeEnabledFor(request)) {
        if (passwordUpgradeConfirmRoute(request)) request.wipeBody();
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    }
    if (sessionListRoute(request)) {
        co_return co_await sessionList(std::move(request));
    }
    if (sessionRevokeRoute(request)) {
        co_return co_await sessionRevoke(std::move(request));
    }
    if (profileReadRoute(request)) {
        co_return co_await profileRead(std::move(request));
    }
    if (profileUpdateRoute(request)) {
        co_return co_await profileUpdate(std::move(request));
    }
    if (connectionsReadRoute(request)) {
        co_return co_await connectionsRead(std::move(request));
    }
    if (totpStatusReadRoute(request)) {
        co_return co_await totpStatusRead(std::move(request));
    }
    if (passwordUpgradeStatusReadRoute(request)) {
        co_return co_await passwordUpgradeStatusRead(std::move(request));
    }
    if (passwordUpgradeConfirmRoute(request)) {
        co_return co_await passwordUpgradeConfirm(std::move(request));
    }
    // Only requests explicitly admitted by the downstream native handler
    // reach this branch; never invoke synchronous AccountHttpApi here.
    co_return co_await m_asyncFallback->handleAsync(std::move(request));
}

asio::awaitable<gateway::HttpResponse>
CoroutineAccountSessionAdapter::sessionList(gateway::HttpRequest request)
{
    SensitiveSessionHeadersGuard wipeHeadersOnExit{request};
    const std::string rateKey = "account:" + std::string{request.remoteAddress()}
        + ":" + std::string{request.path()};
    if (!m_limiter->allow(rateKey)) {
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) co_return fail(credential.error(), request);
    if (!credential->has_value()) {
        co_return fail(foundation::Error{foundation::ErrorCode::AuthenticationRequired}, request);
    }
    auto current = co_await m_authenticate(std::move(credential->value()));
    if (!current) co_return fail(current.error(), request);
    auto values = co_await m_list(current->identity());
    if (!values) co_return fail(values.error(), request);

    // Repository callbacks are replaceable by any asynchronous storage adapter.
    // Validate the entire result before serializing a single session: a faulty
    // tenant filter must never disclose another identity's session metadata.
    if (values->size() > kMaximumSessionResponseRows
        || std::ranges::any_of(values.value(), [&current](const session::Session& value) {
            return value.identity() != current->identity();
        })) {
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    }

    json::array sessions;
    for (const auto& value : values.value()) {
        json::object item;
        item["session_id"] = value.id().value();
        item["provider"] = value.provider().value();
        item["assurance"] =
            identity::provider::assuranceLevelName(value.assurance());
        item["phishing_resistant"] = value.strength().isPhishingResistant();
        item["issued_at_ms"] = value.issuedAt().time_since_epoch().count();
        item["last_seen_at_ms"] = value.lastSeenAt().time_since_epoch().count();
        item["absolute_expires_at_ms"] = value.absoluteExpiresAt().time_since_epoch().count();
        item["idle_expires_at_ms"] = value.idleExpiresAt().time_since_epoch().count();
        item["current"] = value.id() == current->id();
        if (value.userAgent()) item["user_agent"] = *value.userAgent();
        sessions.emplace_back(std::move(item));
    }
    co_return jsonResponse(200, json::object{{"sessions", std::move(sessions)}});
}

asio::awaitable<gateway::HttpResponse>
CoroutineAccountSessionAdapter::sessionRevoke(gateway::HttpRequest request)
{
    SensitiveSessionHeadersGuard wipeHeadersOnExit{request};
    const std::string rateKey = "account:" + std::string{request.remoteAddress()}
        + ":" + std::string{request.path()};
    if (!m_limiter->allow(rateKey)) {
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) co_return fail(credential.error(), request);
    if (!credential->has_value()) {
        co_return fail(foundation::Error{foundation::ErrorCode::AuthenticationRequired}, request);
    }
    auto authenticated = co_await m_authenticate(std::move(credential->value()));
    if (!authenticated) co_return fail(authenticated.error(), request);
    auto target = revokeTarget(request);
    if (!target) co_return fail(target.error(), request);
    if (target.value() == authenticated->id()) {
        co_return fail(foundation::Error{
            foundation::ErrorCode::FailedPrecondition,
            "Use logout to end the current session."}, request);
    }
    auto revoked = co_await m_revokeOwned(
        authenticated->identity(), std::move(target).value());
    if (!revoked) co_return fail(revoked.error(), request);
    co_return jsonResponse(200, json::object{{"revoked", true}});
}


asio::awaitable<gateway::HttpResponse>
CoroutineAccountSessionAdapter::profileRead(gateway::HttpRequest request)
{
    SensitiveSessionHeadersGuard wipeHeadersOnExit{request};
    const std::string rateKey = "account:" + std::string{request.remoteAddress()}
        + ":" + std::string{request.path()};
    if (!m_limiter->allow(rateKey)) {
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) co_return fail(credential.error(), request);
    if (!credential->has_value()) {
        co_return fail(foundation::Error{foundation::ErrorCode::AuthenticationRequired}, request);
    }
    // Never authorize a read based only on the requested identity or a
    // caller-supplied HTTP parameter. The owner must come from the verified
    // native session and the repository must independently verify tenancy.
    auto authenticated = co_await m_authenticate(std::move(credential->value()));
    if (!authenticated) co_return fail(authenticated.error(), request);
    auto value = co_await m_readProfile(authenticated->identity());
    if (!value) co_return fail(value.error(), request);
    if (value->identity() != authenticated->identity()) {
        // Prevent a misconfigured adapter from disclosing another identity.
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    }
    json::object body;
    body["identity_id"] = value->identity().value();
    if (value->displayName()) body["display_name"] = *value->displayName();
    if (value->preferredUsername()) {
        body["preferred_username"] = *value->preferredUsername();
    }
    if (value->email()) body["email"] = *value->email();
    body["email_verified"] = value->emailVerified();
    if (value->phoneNumber()) body["phone_number"] = *value->phoneNumber();
    body["phone_number_verified"] = value->phoneNumberVerified();
    if (value->locale()) body["locale"] = *value->locale();
    if (value->pictureUrl()) body["picture"] = *value->pictureUrl();
    body["avatar_source"] = value->avatarSource();
    co_return jsonResponse(200, std::move(body));
}

asio::awaitable<gateway::HttpResponse>
CoroutineAccountSessionAdapter::connectionsRead(gateway::HttpRequest request)
{
    SensitiveSessionHeadersGuard wipeHeadersOnExit{request};
    const std::string rateKey = "account:" + std::string{request.remoteAddress()}
        + ":" + std::string{request.path()};
    if (!m_limiter->allow(rateKey))
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) co_return fail(credential.error(), request);
    if (!credential->has_value())
        co_return fail(foundation::Error{
            foundation::ErrorCode::AuthenticationRequired}, request);
    auto authenticated = co_await m_authenticate(std::move(credential->value()));
    if (!authenticated) co_return fail(authenticated.error(), request);
    auto connections = co_await m_readConnections(authenticated->identity());
    if (!connections) co_return fail(connections.error(), request);
    if (connections->first != authenticated->identity()
        || connections->second.size() > 256U) {
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    }
    // Validate the entire repository response before serializing metadata.
    // A faulty asynchronous storage adapter must never leak malformed rows.
    for (const auto& external : connections->second) {
        if (external.providerId().empty() || external.subject().empty()
            || external.providerId().value().size() > 200U
            || external.subject().value().size() > 1000U) {
            co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
        }
    }
    json::array connectionsJson;
    for (const auto& external : connections->second) {
        json::object item{
            {"provider", external.providerId().value()},
            {"subject", external.subject().value()}};
        if (external.displayName()) item["display_name"] = *external.displayName();
        if (external.preferredUsername())
            item["preferred_username"] = *external.preferredUsername();
        if (external.pictureUrl()) item["picture_url"] = *external.pictureUrl();
        // Maintain the existing provider-neutral HTTP projection, including
        // legacy Farcaster profile links for numeric FIDs only.
        if (external.providerId().value() == "farcaster") {
            const std::string fid{external.subject().value()};
            const bool numeric = !fid.empty()
                && std::ranges::all_of(fid, [](char symbol) {
                    return symbol >= '0' && symbol <= '9';
                });
            if (numeric) {
                item["fid"] = fid;
                item["profile_url"] = "https://farcaster.xyz/~/profiles/" + fid;
            }
        }
        connectionsJson.emplace_back(std::move(item));
    }
    co_return jsonResponse(200,
        json::object{{"connections", std::move(connectionsJson)}});
}

asio::awaitable<gateway::HttpResponse>
CoroutineAccountSessionAdapter::totpStatusRead(gateway::HttpRequest request)
{
    SensitiveSessionHeadersGuard wipeHeadersOnExit{request};
    const std::string rateKey = "account:" + std::string{request.remoteAddress()}
        + ":" + std::string{request.path()};
    if (!m_limiter->allow(rateKey))
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) co_return fail(credential.error(), request);
    if (!credential->has_value())
        co_return fail(foundation::Error{foundation::ErrorCode::AuthenticationRequired}, request);
    auto authenticated = co_await m_authenticate(std::move(credential->value()));
    if (!authenticated) co_return fail(authenticated.error(), request);
    auto status = co_await m_readTotpStatus(authenticated->identity());
    if (!status) co_return fail(status.error(), request);
    if (status->first != authenticated->identity())
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    co_return jsonResponse(200, json::object{
        {"available", status->second.has_value()},
        {"enabled", status->second.value_or(false)},
        {"assurance", identity::provider::assuranceLevelName(authenticated->assurance())}});
}

asio::awaitable<gateway::HttpResponse>
CoroutineAccountSessionAdapter::passwordUpgradeStatusRead(gateway::HttpRequest request)
{
    SensitiveSessionHeadersGuard wipeHeadersOnExit{request};
    const std::string rateKey = "account:" + std::string{request.remoteAddress()}
        + ":" + std::string{request.path()};
    if (!m_limiter->allow(rateKey))
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) co_return fail(credential.error(), request);
    if (!credential->has_value())
        co_return fail(foundation::Error{foundation::ErrorCode::AuthenticationRequired}, request);
    auto authenticated = co_await m_authenticate(std::move(credential->value()));
    if (!authenticated) co_return fail(authenticated.error(), request);
    auto status = co_await m_readPasswordUpgradeStatus(authenticated->identity());
    if (!status) co_return fail(status.error(), request);
    if (status->first != authenticated->identity())
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    co_return jsonResponse(200, json::object{
        {"available", status->second.has_value()},
        {"needs_upgrade", status->second.value_or(false)},
        {"target_algorithm", "argon2id"}});
}

asio::awaitable<gateway::HttpResponse>
CoroutineAccountSessionAdapter::passwordUpgradeConfirm(gateway::HttpRequest request)
{
    SensitiveSessionHeadersGuard wipeHeaders{request};
    PasswordRequestGuard wipeBody{request};
    const std::string rateKey = "account:" + std::string{request.remoteAddress()}
        + ":" + std::string{request.path()};
    if (!m_limiter->allow(rateKey))
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited},request);
    if (!trustedPasswordUpgradeOrigin(request))
        co_return fail(foundation::Error{foundation::ErrorCode::PermissionDenied},request);
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) co_return fail(credential.error(),request);
    if (!credential->has_value())
        co_return fail(foundation::Error{foundation::ErrorCode::AuthenticationRequired},request);
    // Parse/wipe raw password before any asynchronous database work.
    auto secret = passwordUpgradeSecret(request);
    auto authenticated = co_await m_authenticate(std::move(credential->value()));
    if (!authenticated) co_return fail(authenticated.error(),request);
    if (!m_limiter->allow("account:password-upgrade:identity:"
            + std::string{authenticated->identity().value()}))
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited},request);
    if (!secret) co_return fail(secret.error(),request);
    auto result = co_await m_confirmPasswordUpgrade(authenticated->identity(),
                                                   std::move(secret).value());
    if (!result) co_return fail(result.error(),request);
    if (result->first!=authenticated->identity())
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable},request);
    co_return jsonResponse(200,json::object{{"upgraded",result->second},{"needs_upgrade",false}});
}

asio::awaitable<gateway::HttpResponse>
CoroutineAccountSessionAdapter::profileUpdate(gateway::HttpRequest request)
{
    SensitiveSessionHeadersGuard wipeHeaders{request};
    const std::string rateKey="account:"+std::string{request.remoteAddress()}
        +":"+std::string{request.path()};
    if (!m_limiter->allow(rateKey))
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited},request);
    auto credential=gateway::takeSessionCredential(request);
    if (!credential) co_return fail(credential.error(),request);
    if (!credential->has_value())
        co_return fail(foundation::Error{foundation::ErrorCode::AuthenticationRequired},request);
    auto authenticated=co_await m_authenticate(std::move(credential->value()));
    if (!authenticated) co_return fail(authenticated.error(),request);
    const auto type=request.header("content-type");
    if (request.body().empty() || request.body().size()>32U*1024U || !type
        || (*type!="application/json" && !type->starts_with("application/json;")))
        co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
    boost::system::error_code ec;
    const auto parsed=json::parse(request.body(),ec);
    if (ec || !parsed.is_object())
        co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
    ProfileUpdate change;
    // Match legacy replacement semantics: omitted/null/empty fields clear
    // presentation data; omitted avatar source preserves its existing value.
    for (const auto& entry:parsed.as_object()) {
        std::optional<std::string>* target=nullptr;
        std::size_t maximum=0U;
        const std::string_view name{entry.key().data(),entry.key().size()};
        if (name=="display_name") {target=&change.displayName;maximum=256U;}
        else if (name=="preferred_username") {target=&change.username;maximum=128U;}
        else if (name=="locale") {target=&change.locale;maximum=64U;}
        else if (name=="picture") {target=&change.picture;maximum=2048U;}
        else if (name=="avatar_source") {target=&change.avatarSource;maximum=128U;}
        else co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        const auto& field=entry.value();
        if (field.is_null()) continue;
        if (!field.is_string())
            co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        const std::string_view text{field.as_string().data(),field.as_string().size()};
        if (text.empty()) continue;
        if (text.size()>maximum || std::ranges::any_of(text,[](char ch){
            const auto byte=static_cast<unsigned char>(ch);
            return byte<0x20U || byte==0x7FU;
        })) co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        *target=std::string{text};
    }
    auto result=co_await m_updateProfile(authenticated->identity(),std::move(change));
    if (!result) co_return fail(result.error(),request);
    if (result->identity()!=authenticated->identity())
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable},request);
    const auto& value=result.value();
    json::object body;
    body["identity_id"] = value.identity().value();
    if (value.displayName()) body["display_name"] = *value.displayName();
    if (value.preferredUsername()) {
        body["preferred_username"] = *value.preferredUsername();
    }
    if (value.email()) body["email"] = *value.email();
    body["email_verified"] = value.emailVerified();
    if (value.phoneNumber()) body["phone_number"] = *value.phoneNumber();
    body["phone_number_verified"] = value.phoneNumberVerified();
    if (value.locale()) body["locale"] = *value.locale();
    if (value.pictureUrl()) body["picture"] = *value.pictureUrl();
    body["avatar_source"] = value.avatarSource();
    co_return jsonResponse(200, std::move(body));
}

namespace {
[[nodiscard]] bool signupRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method()==gateway::HttpMethod::Post
        && (request.path()=="/account/signup" || request.path()=="/account/email/verify");
}
[[nodiscard]] bool contactIssueRoute(const gateway::HttpRequest& request) noexcept
{
    return request.method()==gateway::HttpMethod::Post
        && (request.path()=="/account/email/change" || request.path()=="/account/phone"
            || request.path()=="/account/email/resend" || request.path()=="/account/password/forgot");
}
[[nodiscard]] bool publicEmailIssue(const gateway::HttpRequest& request) noexcept
{
    return request.path()=="/account/email/resend" || request.path()=="/account/password/forgot";
}
}

CoroutineContactVerificationAdapter::CoroutineContactVerificationAdapter(
    gateway::http::CoroutineHttpHandler& fallback,gateway::TokenBucketRateLimiter& limiter,
    Authenticate authenticate,Issue issue,PublicIssue publicIssue,Signup signup,VerifySignup verifySignup)
    : m_fallback(&fallback),m_limiter(&limiter),m_authenticate(std::move(authenticate)),
      m_issue(std::move(issue)),m_publicIssue(std::move(publicIssue)),
      m_signup(std::move(signup)),m_verifySignup(std::move(verifySignup)) {}

bool CoroutineContactVerificationAdapter::nativeEnabledFor(const gateway::HttpRequest& request) const noexcept
{
    if (signupRoute(request) && (m_signup || m_verifySignup)) return m_signup && m_verifySignup;
    if (contactIssueRoute(request)) return publicEmailIssue(request) ? static_cast<bool>(m_publicIssue)
        : static_cast<bool>(m_authenticate) && static_cast<bool>(m_issue);
    return m_fallback->nativeEnabledFor(request);
}

gateway::HttpResponse CoroutineContactVerificationAdapter::fail(
    const foundation::Error& failure,const gateway::HttpRequest& request)
{
    gateway::HttpResponse response{foundation::errorHttpStatus(failure.code()),
        gateway::Headers{{"content-type","application/json"}},
        foundation::toClientJson(failure,request.correlation().value())};
    response.setHeader("cache-control","no-store");
    response.setHeader("pragma","no-cache");
    response.setHeader("x-content-type-options","nosniff");
    response.setHeader("referrer-policy","no-referrer");
    if (response.status()==401) response.setHeader("www-authenticate","Bearer");
    return response;
}

gateway::HttpResponse CoroutineContactVerificationAdapter::handle(gateway::HttpRequest request)
{
    if (!contactIssueRoute(request) && !(signupRoute(request) && (m_signup || m_verifySignup)))
        return m_fallback->handle(std::move(request));
    SensitiveSessionHeadersGuard wipeHeaders{request};
    PasswordRequestGuard wipeBody{request};
    return fail(foundation::Error{foundation::ErrorCode::Unavailable},request);
}

asio::awaitable<gateway::HttpResponse>
CoroutineContactVerificationAdapter::handleAsync(gateway::HttpRequest request)
{
    if (signupRoute(request) && (m_signup || m_verifySignup))
        co_return co_await signupOrVerify(std::move(request));
    if (!contactIssueRoute(request)) {
        if (m_fallback->nativeEnabledFor(request))
            co_return co_await m_fallback->handleAsync(std::move(request));
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable},request);
    }
    SensitiveSessionHeadersGuard wipeHeaders{request};
    PasswordRequestGuard wipeBody{request};
    const bool publicRequest=publicEmailIssue(request);
    if (publicRequest ? !m_publicIssue : (!m_authenticate || !m_issue))
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable},request);
    if (!m_limiter->allow("account:"+std::string{request.remoteAddress()}+":"+std::string{request.path()}))
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited},request);
    std::optional<session::Session> actor;
    if (!publicRequest) {
        auto credential=gateway::takeSessionCredential(request);
        if (!credential) co_return fail(credential.error(),request);
        if (!credential->has_value())
            co_return fail(foundation::Error{foundation::ErrorCode::AuthenticationRequired},request);
        auto authenticated=co_await m_authenticate(std::move(credential->value()));
        if (!authenticated) co_return fail(authenticated.error(),request);
        actor.emplace(std::move(authenticated).value());
    } else {
        request.wipeAuthorizationHeader();
        request.wipeCookieHeader();
    }
    const bool email=request.path()!="/account/phone";
    const auto type=request.header("content-type");
    if (request.body().empty() || request.body().size()>32U*1024U || !type
        || (*type!="application/json" && !type->starts_with("application/json;")))
        co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
    std::string destination;
    {
        boost::system::error_code ec;
        auto parsed=json::parse(request.body(),ec);
        if (ec || !parsed.is_object() || parsed.as_object().size()!=1U)
            co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        const auto* field=parsed.as_object().if_contains(email?"email":"phone_number");
        if (!field || !field->is_string())
            co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        const std::string_view value{field->as_string().data(),field->as_string().size()};
        if (value.empty() || value.size()>(email?320U:32U)
            || std::ranges::any_of(value,[](char ch){
                const auto byte=static_cast<unsigned char>(ch);
                return byte<0x20U || byte==0x7FU;
            })) co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        destination.assign(value);
    }
    request.wipeBody();
    if (publicRequest) {
        auto status=co_await m_publicIssue(request.path()=="/account/email/resend"
            ? VerificationPurpose::SignupEmail:VerificationPurpose::PasswordReset,std::move(destination));
        if (!status) co_return fail(status.error(),request);
        co_return jsonResponse(202,json::object{{"accepted",true}});
    }
    auto status=co_await m_issue(actor->identity(),
        email?VerificationPurpose::ChangeEmail:VerificationPurpose::VerifyPhone,
        std::move(destination));
    if (!status) co_return fail(status.error(),request);
    co_return jsonResponse(202,json::object{{"accepted",true}});
}

asio::awaitable<gateway::HttpResponse>
CoroutineContactVerificationAdapter::signupOrVerify(gateway::HttpRequest request)
{
    SensitiveSessionHeadersGuard wipeHeaders{request};
    PasswordRequestGuard wipeBody{request};
    request.wipeAuthorizationHeader();
    request.wipeCookieHeader();
    if (!m_signup || !m_verifySignup)
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable},request);
    if (!m_limiter->allow("account:"+std::string{request.remoteAddress()}+":"+std::string{request.path()}))
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited},request);
    const auto type=request.header("content-type");
    if (request.body().empty() || request.body().size()>32U*1024U || !type
        || (*type!="application/json" && !type->starts_with("application/json;")))
        co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
    const bool signup=request.path()=="/account/signup";
    std::string identifier;
    std::optional<std::string> displayName;
    foundation::SecretString proof;
    {
        boost::system::error_code ec;
        auto parsed=json::parse(request.body(),ec);
        ParsedPasswordGuard wipeParsed{parsed};
        if (ec || !parsed.is_object())
            co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        auto& object=parsed.as_object();
        for (const auto& entry:object) {
            if (signup ? (entry.key()!="email" && entry.key()!="password" && entry.key()!="display_name")
                       : (entry.key()!="verification_id" && entry.key()!="secret"))
                co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        }
        const auto bounded=[&](const char* name,std::size_t maximum)->std::optional<std::string_view>{
            const auto* field=object.if_contains(name);
            if (!field || !field->is_string()) return std::nullopt;
            const std::string_view value{field->as_string().data(),field->as_string().size()};
            if (value.empty() || value.size()>maximum || std::ranges::any_of(value,[](char ch){
                const auto byte=static_cast<unsigned char>(ch);
                return byte<0x20U || byte==0x7fU;
            })) return std::nullopt;
            return value;
        };
        const auto name=bounded(signup?"email":"verification_id",signup?320U:200U);
        const auto secret=bounded(signup?"password":"secret",signup?1024U:512U);
        if (!name || !secret)
            co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        if (signup && object.contains("display_name") && !object.at("display_name").is_null()) {
            const auto label=bounded("display_name",256U);
            if (!label) co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
            displayName=std::string{*label};
        }
        identifier.assign(*name);
        proof=foundation::SecretString{std::string{*secret}};
    }
    request.wipeBody();
    if (signup) {
        auto owner=co_await m_signup(std::move(identifier),std::move(proof),std::move(displayName));
        if (!owner) co_return fail(owner.error(),request);
        if (owner->empty()) co_return fail(foundation::Error{foundation::ErrorCode::Internal},request);
        co_return jsonResponse(201,json::object{{"identity_id",owner->value()},{"verification_required",true}});
    }
    identity::provider::ClientContext client;
    client.setRemoteAddress(std::string{request.remoteAddress()});
    if (const auto agent=request.header("user-agent"))
        client.setUserAgent(std::string{agent->substr(0U,1024U)});
    auto issued=co_await m_verifySignup(VerificationId{std::move(identifier)},std::move(proof),std::move(client));
    if (!issued) co_return fail(issued.error(),request);
    const auto safe=[](std::string_view value){
        return !value.empty() && value.size()<=128U && std::ranges::all_of(value,[](char ch){
            return (ch>='a' && ch<='z') || (ch>='A' && ch<='Z')
                || (ch>='0' && ch<='9') || ch=='-' || ch=='_';
        });
    };
    if (!safe(issued->id.value()) || !safe(issued->token.expose()))
        co_return fail(foundation::Error{foundation::ErrorCode::Internal},request);
    auto response=jsonResponse(200,json::object{{"verified",true},{"session_id",issued->id.value()},
        {"assurance",identity::provider::assuranceLevelName(identity::provider::AssuranceLevel::Ial1)}});
    response.addHeader("set-cookie","__Host-openproof-session="+std::string{issued->token.expose()}
        +"; Path=/; Max-Age=28800; Secure; HttpOnly; SameSite=Strict");
    co_return response;
}

} // namespace openproof::account::http

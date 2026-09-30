module;

#include <algorithm>
#include <cstddef>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>

#include <boost/json.hpp>

module openproof.account.http;

import openproof.security;

namespace openproof::account::http {
namespace {

namespace json = boost::json;
constexpr std::size_t kMaximumBody = 32U * 1024U;

[[nodiscard]] gateway::HttpResponse jsonResponse(int status, json::value body)
{
    gateway::HttpResponse response{
        status, gateway::Headers{{"content-type", "application/json"}}, json::serialize(body)};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    return response;
}

[[nodiscard]] gateway::HttpResponse accepted()
{
    return jsonResponse(202, json::object{{"accepted", true}});
}

[[nodiscard]] std::string sessionCookie(std::string_view value)
{
    return "__Host-openproof-session=" + std::string{value}
        + "; Path=/; Max-Age=28800; Secure; HttpOnly; SameSite=Strict";
}

[[nodiscard]] identity::provider::ClientContext clientContext(
    const gateway::HttpRequest& request)
{
    identity::provider::ClientContext client;
    client.setRemoteAddress(std::string{request.remoteAddress()});
    if (const auto userAgent = request.header("user-agent"); userAgent.has_value()) {
        client.setUserAgent(std::string{userAgent->substr(
            0U, std::min<std::size_t>(userAgent->size(), 1024U))});
    }
    return client;
}

[[nodiscard]] foundation::Result<json::object> objectBody(const gateway::HttpRequest& request)
{
    if (request.body().empty() || request.body().size() > kMaximumBody) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request was not valid.");
    }
    const auto contentType = request.header("content-type");
    if (!contentType.has_value() || (!contentType->starts_with("application/json"))) {
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

[[nodiscard]] bool safeText(std::string_view text, std::size_t maximum) noexcept
{
    return !text.empty() && text.size() <= maximum
        && std::ranges::none_of(text, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           });
}

[[nodiscard]] foundation::Result<std::string> requiredString(
    const json::object& object, std::string_view name, std::size_t maximum)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr || !value->is_string()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request was not valid.");
    }
    std::string text{value->as_string()};
    if (!safeText(text, maximum)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request was not valid.");
    }
    return text;
}

[[nodiscard]] foundation::Result<std::optional<std::string>> optionalString(
    const json::object& object, std::string_view name, std::size_t maximum)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr || value->is_null()) return std::optional<std::string>{};
    auto text = requiredString(object, name, maximum);
    if (!text) return foundation::fail(text.error());
    return std::optional<std::string>{std::move(text).value()};
}

[[nodiscard]] foundation::Result<std::optional<std::string>> optionalProfileString(
    const json::object& object, std::string_view name, std::size_t maximum)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr || value->is_null()) return std::optional<std::string>{};
    if (!value->is_string()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request was not valid.");
    }
    std::string text{value->as_string()};
    if (text.empty()) return std::optional<std::string>{};
    if (!safeText(text, maximum)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request was not valid.");
    }
    return std::optional<std::string>{std::move(text)};
}

[[nodiscard]] bool onlyFields(const json::object& object,
                              std::initializer_list<std::string_view> allowed)
{
    return std::ranges::all_of(object, [&](const auto& member) {
        return std::ranges::find(allowed, std::string_view{member.key()}) != allowed.end();
    });
}

[[nodiscard]] json::object profileJson(const identity::profile::IdentityProfile& profile)
{
    json::object body;
    body["identity_id"] = profile.identity().value();
    if (profile.displayName()) body["display_name"] = *profile.displayName();
    if (profile.preferredUsername()) body["preferred_username"] = *profile.preferredUsername();
    if (profile.email()) body["email"] = *profile.email();
    body["email_verified"] = profile.emailVerified();
    if (profile.phoneNumber()) body["phone_number"] = *profile.phoneNumber();
    body["phone_number_verified"] = profile.phoneNumberVerified();
    if (profile.locale()) body["locale"] = *profile.locale();
    if (profile.pictureUrl()) body["picture"] = *profile.pictureUrl();
    body["avatar_source"] = profile.avatarSource();
    return body;
}

}

AccountHttpApi::AccountHttpApi(AccountService& accounts,
                               authentication::AuthenticationService& authentication,
                               session::SessionService& sessions,
                               gateway::TokenBucketRateLimiter& limiter,
                               gateway::HttpHandler& fallback,
                               session::DelegatedAccessAuthenticator* delegated)
    : m_accounts(&accounts), m_authentication(&authentication), m_sessions(&sessions),
      m_delegated(delegated), m_limiter(&limiter), m_fallback(&fallback)
{
}

gateway::HttpResponse AccountHttpApi::error(
    const foundation::Error& failure, const gateway::HttpRequest& request) const
{
    gateway::HttpResponse response{
        foundation::errorHttpStatus(failure.code()),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(failure, request.correlation().value())};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    if (failure.code() == foundation::ErrorCode::AuthenticationRequired) {
        response.setHeader("www-authenticate", "Bearer");
    }
    return response;
}

foundation::Result<session::AuthenticatedSession>
AccountHttpApi::authenticate(gateway::HttpRequest& request) const
{
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) return foundation::fail(credential.error());
    if (!credential->has_value()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationRequired,
                                "Authentication is required.");
    }
    return m_sessions->authenticate(credential->value(), m_delegated, "account");
}

foundation::Result<identity::core::IdentityId>
AccountHttpApi::authorize(gateway::HttpRequest& request) const
{
    auto authenticated = authenticate(request);
    if (!authenticated) return foundation::fail(authenticated.error());
    return authenticated->session().identity();
}

gateway::HttpResponse AccountHttpApi::handle(gateway::HttpRequest request)
{
    if (request.path() != "/account" && !request.path().starts_with("/account/")) {
        return m_fallback->handle(std::move(request));
    }
    const std::string rateKey = "account:" + std::string{request.remoteAddress()} + ":"
        + std::string{request.path()};
    if (!m_limiter->allow(rateKey)) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }

    using gateway::HttpMethod;
    if (request.method() == HttpMethod::Post && request.path() == "/account/signup") return signup(std::move(request));
    if (request.method() == HttpMethod::Post && request.path() == "/account/email/verify") return verifyEmail(std::move(request));
    if (request.method() == HttpMethod::Post && request.path() == "/account/email/resend") return resendEmail(std::move(request));
    if (request.method() == HttpMethod::Post && request.path() == "/account/email/change") return beginEmailChange(std::move(request));
    if (request.method() == HttpMethod::Post && request.path() == "/account/email/change/verify") return completeEmailChange(std::move(request));
    if (request.method() == HttpMethod::Post && request.path() == "/account/phone") return beginPhone(std::move(request));
    if (request.method() == HttpMethod::Post && request.path() == "/account/phone/verify") return completePhone(std::move(request));
    if (request.method() == HttpMethod::Post && request.path() == "/account/password/forgot") return forgotPassword(std::move(request));
    if (request.method() == HttpMethod::Post && request.path() == "/account/password/reset") return resetPassword(std::move(request));
    if (request.method() == HttpMethod::Get && request.path() == "/account/security") return securityPage(std::move(request));
    if (request.method() == HttpMethod::Get && request.path() == "/account/totp") return totpStatus(std::move(request));
    if (request.method() == HttpMethod::Post && request.path() == "/account/totp/start") return beginTotpEnrollment(std::move(request));
    if (request.method() == HttpMethod::Post && request.path() == "/account/totp/complete") return completeTotpEnrollment(std::move(request));
    if (request.method() == HttpMethod::Post && request.path() == "/account/totp/disable") return disableTotp(std::move(request));
    if (request.method() == HttpMethod::Get && request.path() == "/account/profile") return getProfile(std::move(request));
    if ((request.method() == HttpMethod::Patch || request.method() == HttpMethod::Put)
        && request.path() == "/account/profile") return updateProfile(std::move(request));
    if (request.method() == HttpMethod::Get && request.path() == "/account/sessions") {
        return sessions(std::move(request));
    }
    if (request.method() == HttpMethod::Post
        && request.path() == "/account/sessions/revoke") {
        return revokeSession(std::move(request));
    }
    if (request.method() == HttpMethod::Get && request.path() == "/account/connections") {
        return connections(std::move(request));
    }
    if (request.method() == HttpMethod::Post
        && request.path() == "/account/connections/disconnect") {
        return disconnect(std::move(request));
    }
    if (request.method() == HttpMethod::Get
        && request.path() == "/account/connections/start") {
        return m_fallback->handle(std::move(request));
    }
    if (request.method() == HttpMethod::Get
        && request.path() == "/account/connections/complete") {
        return m_fallback->handle(std::move(request));
    }
    if ((request.method() == HttpMethod::Get || request.method() == HttpMethod::Post)
        && request.path() == "/account/connections/handoff") {
        return m_fallback->handle(std::move(request));
    }
    if (request.method() == HttpMethod::Post
        && (request.path() == "/account/connections/web3/handoff"
            || request.path() == "/account/connections/web3/start"
            || request.path() == "/account/connections/web3/complete")) {
        return m_fallback->handle(std::move(request));
    }
    return jsonResponse(404, json::object{{"error", "not_found"}});
}

gateway::HttpResponse AccountHttpApi::signup(gateway::HttpRequest request)
{
    auto body = objectBody(request);
    if (!body || !onlyFields(body.value(), {"email", "password", "display_name"}))
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto email = requiredString(body.value(), "email", 320U);
    auto password = requiredString(body.value(), "password", 1024U);
    auto displayName = optionalString(body.value(), "display_name", 256U);
    if (!email || !password || !displayName) return error(!email ? email.error() : (!password ? password.error() : displayName.error()), request);
    foundation::SecretString passwordSecret{std::move(password).value()};
    auto identity = m_accounts->signup(std::move(email).value(), passwordSecret,
                                       std::move(displayName).value());
    if (!identity) return error(identity.error(), request);
    return jsonResponse(201, json::object{{"identity_id", identity->value()}, {"verification_required", true}});
}

gateway::HttpResponse AccountHttpApi::verifyEmail(gateway::HttpRequest request)
{
    auto body = objectBody(request);
    if (!body || !onlyFields(body.value(), {"verification_id", "secret"}))
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto id = requiredString(body.value(), "verification_id", 200U);
    auto secret = requiredString(body.value(), "secret", 512U);
    if (!id || !secret) return error(id ? secret.error() : id.error(), request);
    foundation::SecretString proof{std::move(secret).value()};
    auto external = m_accounts->verifyEmailAndGetExternal(
        VerificationId{std::move(id).value()}, proof);
    if (!external) return error(external.error(), request);

    auto verified = m_authentication->acceptVerifiedEmail(external.value());
    if (!verified) return error(verified.error(), request);
    auto grant = m_sessions->issue(verified.value(), clientContext(request));
    if (!grant) return error(grant.error(), request);

    json::object payload{
        {"verified", true},
        {"session_id", grant->id().value()},
        {"assurance", identity::provider::assuranceLevelName(
            verified->outcome().claimedAssurance())}};
    auto response = jsonResponse(200, std::move(payload));
    response.addHeader("set-cookie", sessionCookie(grant->token().expose()));
    return response;
}

gateway::HttpResponse AccountHttpApi::resendEmail(gateway::HttpRequest request)
{
    auto body = objectBody(request);
    if (!body || !onlyFields(body.value(), {"email"})) return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto email = requiredString(body.value(), "email", 320U);
    if (!email) return error(email.error(), request);
    auto status = m_accounts->resendSignupVerification(std::move(email).value());
    if (!status && status.error().code() != foundation::ErrorCode::NotFound) return error(status.error(), request);
    return accepted();
}

gateway::HttpResponse AccountHttpApi::beginEmailChange(gateway::HttpRequest request)
{
    auto actor = authorize(request); if (!actor) return error(actor.error(), request);
    auto body = objectBody(request); if (!body || !onlyFields(body.value(), {"email"})) return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto email = requiredString(body.value(), "email", 320U); if (!email) return error(email.error(), request);
    auto status = m_accounts->beginEmailChange(actor.value(), std::move(email).value());
    return status ? accepted() : error(status.error(), request);
}

gateway::HttpResponse AccountHttpApi::completeEmailChange(gateway::HttpRequest request)
{
    auto actor = authorize(request); if (!actor) return error(actor.error(), request);
    auto body = objectBody(request);
    if (!body || !onlyFields(body.value(), {"verification_id", "secret", "password"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    }
    auto id = requiredString(body.value(), "verification_id", 200U);
    auto secret = requiredString(body.value(), "secret", 512U);
    auto password = optionalString(body.value(), "password", 1024U);
    if (!id || !secret || !password) {
        return error(!id ? id.error() : (!secret ? secret.error() : password.error()), request);
    }
    foundation::SecretString proof{std::move(secret).value()};
    std::optional<foundation::SecretString> newPassword;
    if (password->has_value()) newPassword.emplace(std::move(password).value().value());
    auto status = m_accounts->completeEmailChange(
        actor.value(), VerificationId{std::move(id).value()}, proof,
        newPassword.has_value() ? &newPassword.value() : nullptr);
    if (!status) return error(status.error(), request);
    auto profile = m_accounts->profile(actor.value());
    return profile ? jsonResponse(200, profileJson(profile.value())) : error(profile.error(), request);
}

gateway::HttpResponse AccountHttpApi::beginPhone(gateway::HttpRequest request)
{
    auto actor = authorize(request); if (!actor) return error(actor.error(), request);
    auto body = objectBody(request); if (!body || !onlyFields(body.value(), {"phone_number"})) return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto phone = requiredString(body.value(), "phone_number", 32U); if (!phone) return error(phone.error(), request);
    auto status = m_accounts->beginPhoneVerification(actor.value(), std::move(phone).value());
    return status ? accepted() : error(status.error(), request);
}

gateway::HttpResponse AccountHttpApi::completePhone(gateway::HttpRequest request)
{
    auto actor = authorize(request); if (!actor) return error(actor.error(), request);
    auto body = objectBody(request); if (!body || !onlyFields(body.value(), {"verification_id", "secret"})) return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto id = requiredString(body.value(), "verification_id", 200U); auto secret = requiredString(body.value(), "secret", 64U);
    if (!id || !secret) return error(id ? secret.error() : id.error(), request);
    foundation::SecretString proof{std::move(secret).value()};
    auto status = m_accounts->completePhoneVerification(
        actor.value(), VerificationId{std::move(id).value()}, proof);
    if (!status) return error(status.error(), request);
    auto profile = m_accounts->profile(actor.value());
    return profile ? jsonResponse(200, profileJson(profile.value())) : error(profile.error(), request);
}

gateway::HttpResponse AccountHttpApi::forgotPassword(gateway::HttpRequest request)
{
    auto body = objectBody(request); if (!body || !onlyFields(body.value(), {"email"})) return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto email = requiredString(body.value(), "email", 320U); if (!email) return error(email.error(), request);
    auto status = m_accounts->beginPasswordReset(std::move(email).value());
    return status ? accepted() : error(status.error(), request);
}

gateway::HttpResponse AccountHttpApi::resetPassword(gateway::HttpRequest request)
{
    auto body = objectBody(request); if (!body || !onlyFields(body.value(), {"verification_id", "secret", "new_password"})) return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto id = requiredString(body.value(), "verification_id", 200U); auto secret = requiredString(body.value(), "secret", 512U); auto password = requiredString(body.value(), "new_password", 1024U);
    if (!id || !secret || !password) return error(!id ? id.error() : (!secret ? secret.error() : password.error()), request);
    foundation::SecretString proof{std::move(secret).value()}; foundation::SecretString newPassword{std::move(password).value()};
    auto status = m_accounts->completePasswordReset(VerificationId{std::move(id).value()}, proof, newPassword);
    return status ? jsonResponse(200, json::object{{"password_reset", true}}) : error(status.error(), request);
}

gateway::HttpResponse AccountHttpApi::securityPage(gateway::HttpRequest request)
{
    auto authenticated = authenticate(request);
    if (!authenticated) {
        gateway::HttpResponse response{
            303,
            gateway::Headers{{"location", "/login?return_to=%2Faccount%2Fsecurity"}},
            {}};
        response.setHeader("cache-control", "no-store");
        response.setHeader("pragma", "no-cache");
        response.setHeader("x-content-type-options", "nosniff");
        response.setHeader("referrer-policy", "no-referrer");
        return response;
    }

    auto enabled = m_accounts->totpEnabled(authenticated->session().identity());
    if (!enabled) return error(enabled.error(), request);

    auto nonce = security::randomTokenBase64Url(24U);
    if (!nonce) return error(nonce.error(), request);
    const std::string pageNonce = nonce.value();
    const bool available = enabled->has_value();
    const bool totpEnabled = enabled->value_or(false);
    const bool ial2 = identity::provider::meetsAssurance(
        authenticated->session().assurance(),
        identity::provider::AssuranceLevel::Ial2);

    std::string body = R"HTML(<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark"><title>Account Security · OpenProof</title>
<style nonce=")HTML" + pageNonce + R"HTML(">
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#090b10;color:#f6f7fb}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 15% 0%,rgba(105,92,255,.22),transparent 34rem),linear-gradient(180deg,#10131b,#080a0f);padding:24px}
.shell{width:min(100%,760px);margin:0 auto}.brand{display:flex;align-items:center;gap:13px;margin:12px 4px 24px;color:#e5e6ff;font-weight:800;font-size:21px}.brand-mark{width:44px;height:44px;border-radius:14px;display:grid;place-items:center;background:linear-gradient(135deg,#7478ff,#9c68ff);box-shadow:0 16px 38px rgba(102,92,255,.28)}.brand small{display:block;margin-top:2px;color:#8c91a4;font-size:11px;letter-spacing:.11em;text-transform:uppercase}
.card{background:rgba(23,26,35,.96);border:1px solid rgba(255,255,255,.09);border-radius:30px;padding:clamp(24px,5vw,40px);box-shadow:0 30px 100px rgba(0,0,0,.4)}.kicker{display:inline-flex;padding:8px 12px;border-radius:999px;background:rgba(111,107,255,.15);color:#c9c9ff;font-size:12px;font-weight:800;letter-spacing:.07em;text-transform:uppercase}
h1{font-size:clamp(34px,7vw,52px);line-height:1.02;letter-spacing:-.05em;margin:18px 0 12px}h2{font-size:19px;margin:0 0 9px}.lead,.muted{color:#aeb3c4;line-height:1.65}.lead{font-size:16px;margin:0 0 26px}.muted{margin:0 0 17px}
.status{display:flex;align-items:center;gap:13px;padding:16px 17px;border:1px solid rgba(255,255,255,.09);border-radius:18px;background:#11141b}.status strong{font-size:15px}.status span{color:#9298ac;font-size:13px}.dot{width:11px;height:11px;border-radius:50%;background:#f59e0b;box-shadow:0 0 0 5px rgba(245,158,11,.09)}.dot.on{background:#4ade80;box-shadow:0 0 0 5px rgba(74,222,128,.09)}
.panel{border-top:1px solid rgba(255,255,255,.08);padding-top:26px;margin-top:26px}.field{display:grid;gap:8px;margin:15px 0}.field>span{font-size:12px;color:#a8adbf;font-weight:750;text-transform:uppercase;letter-spacing:.06em}
input{width:100%;border:1px solid rgba(255,255,255,.13);border-radius:15px;background:#0d1016;color:#fff;padding:14px 15px;font:inherit;outline:none}input:focus{border-color:#7d82ff;box-shadow:0 0 0 3px rgba(125,130,255,.15)}
button,.button{appearance:none;border:0;border-radius:14px;background:linear-gradient(135deg,#7076ff,#9568ff);color:#fff;padding:13px 17px;font:750 14px inherit;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center}.secondary{background:#171a23!important;border:1px solid rgba(255,255,255,.11)!important}.actions{display:flex;gap:10px;flex-wrap:wrap}
.setup{display:none;margin-top:18px;padding:19px;border-radius:19px;background:#0f1218;border:1px solid rgba(255,255,255,.08)}.setup.show{display:block}.key{display:flex;gap:10px;align-items:center;padding:13px;border-radius:14px;background:#090b10;border:1px solid rgba(255,255,255,.08)}.key code{flex:1;word-break:break-all;font:650 14px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.04em}
.notice{display:none;margin:18px 0 0;padding:13px 15px;border-radius:14px;font-size:13px;line-height:1.55}.notice.show{display:block}.notice.error{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.28);color:#fecaca}.notice.ok{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.25);color:#bbf7d0}
.code{font-size:25px;letter-spacing:.22em;text-align:center;font-variant-numeric:tabular-nums}.foot{color:#747b8f;font-size:12px;line-height:1.55;margin:15px 0 0}.codes{white-space:pre-wrap;font:650 14px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace;color:#e7e8f2}.spaced{margin-top:12px}.stage2{margin-top:25px}.center{text-align:center}
@media(max-width:560px){body{padding:16px}.card{border-radius:23px}.actions>*{width:100%}.key{align-items:stretch;flex-direction:column}.key button{width:100%}}
</style></head><body><main class="shell"><div class="brand"><span class="brand-mark">G</span><span>Genyleap<small>Secured by OpenProof</small></span></div>
<section class="card"><span class="kicker">Account security</span><h1>Protect your OpenProof account</h1>
<p class="lead">Set up an authenticator for IAL2 access. The setup key stays in this browser and is shown only for the active enrollment.</p>
<div class="status"><span class="dot )HTML";
    body += totpEnabled ? "on" : "";
    body += R"HTML("></span><div><strong>)HTML";
    body += totpEnabled ? "Authenticator enabled" : "Authenticator not set up";
    body += R"HTML(</strong><br><span>Current session: )HTML";
    body += std::string{identity::provider::assuranceLevelName(
        authenticated->session().assurance())};
    body += R"HTML(</span></div></div><div id="notice" class="notice" role="status" aria-live="polite"></div>)HTML";

    if (!available) {
        body += R"HTML(<div class="panel"><h2>Authenticator unavailable</h2>
<p class="muted">This identity does not have a local password sign-in method, so a TOTP authenticator cannot be enrolled here.</p></div>)HTML";
    } else if (!totpEnabled) {
        body += R"HTML(<div class="panel"><h2>Set up an authenticator</h2>
<p class="muted">Confirm your OpenProof password. Then add the generated setup key to Google Authenticator, Microsoft Authenticator, 1Password, Authy, or another TOTP app.</p>
<form id="startForm"><label class="field"><span>OpenProof password</span>
<input name="password" type="password" autocomplete="current-password" maxlength="1024" required></label>
<button type="submit">Create setup key</button></form>
<div id="setup" class="setup"><h2>1. Add this setup key</h2>
<p class="muted">In your authenticator choose “Enter setup key” (time based). This long key is not the 6-digit login code.</p>
<div class="key"><code id="secret"></code><button class="secondary" type="button" id="copy">Copy key</button></div>
<div class="actions spaced"><a id="openAuthenticator" class="button secondary" href="#">Open authenticator app</a></div>
<h2 class="stage2">2. Verify the 6-digit code</h2>
<p class="muted">Your authenticator will now show a new 6-digit code about every 30 seconds.</p>
<form id="verifyForm"><label class="field"><span>Authenticator code</span>
<input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" minlength="6" maxlength="6" placeholder="000000" required></label>
<button type="submit">Enable authenticator</button></form>
<p class="foot">Enrollment expires after 10 minutes. If it expires, create a new setup key and replace the unfinished entry in your authenticator.</p></div></div>)HTML";
    } else if (!ial2) {
        body += R"HTML(<div class="panel"><h2>Authenticator is ready</h2>
<p class="muted">This browser session was created with password only. Sign in once more and enter the current 6-digit authenticator code to activate an IAL2 session.</p>
<a class="button" href="/login?return_to=%2Fadmin%2Fconsole">Sign in with authenticator</a></div>)HTML";
    } else {
        body += R"HTML(<div class="panel"><h2>IAL2 session active</h2>
<p class="muted">This browser session satisfies the assurance required for owner administration.</p>
<div class="actions"><a class="button" href="/admin/console">Open Admin Console</a>
<button id="recovery" class="secondary" type="button">Generate recovery codes</button></div>
<div id="recoveryBox" class="setup"><h2>Recovery codes</h2><p class="muted">Store these somewhere safe. A new batch replaces the previous batch and the codes are shown only once.</p>
<pre id="recoveryCodes" class="codes"></pre><button id="copyRecovery" class="secondary" type="button">Copy recovery codes</button></div></div>)HTML";
    }

    body += R"HTML(</section><p class="foot center">OpenProof keeps application sessions separate from your Genyleap credentials.</p></main>
<script nonce=")HTML" + pageNonce + R"HTML(">
const notice=document.querySelector('#notice');
const show=(message,type='error')=>{notice.textContent=message;notice.className='notice show '+type};
async function api(url,method='GET',body){
  const response=await fetch(url,{method,credentials:'same-origin',headers:body?{'content-type':'application/json'}:{},body:body?JSON.stringify(body):undefined});
  const text=await response.text();let data={};
  try{data=text?JSON.parse(text):{}}catch{data={error:{message:text||'Unexpected response'}}}
  if(!response.ok)throw new Error(data?.error?.message||'The request could not be completed.');
  return data;
}
let enrollmentId=null;
const startForm=document.querySelector('#startForm');
if(startForm)startForm.addEventListener('submit',async event=>{
  event.preventDefault();notice.className='notice';
  const password=String(new FormData(startForm).get('password')||'');
  if(!password){show('Enter your OpenProof password.');return}
  try{
    const enrollment=await api('/account/totp/start','POST',{password});
    enrollmentId=enrollment.enrollment_id;
    const secret=String(enrollment.secret_base32||'');
    document.querySelector('#secret').textContent=secret;
    document.querySelector('#openAuthenticator').href='otpauth://totp/Genyleap%20OpenProof?secret='+encodeURIComponent(secret)+'&issuer=OpenProof&algorithm=SHA1&digits=6&period=30';
    document.querySelector('#setup').classList.add('show');
    startForm.reset();
    show('Setup key created. Add it to your authenticator, then enter the 6-digit code.','ok');
    document.querySelector('#verifyForm input[name="code"]').focus();
  }catch(error){show(error.message)}
});
const copy=document.querySelector('#copy');
if(copy)copy.addEventListener('click',async()=>{
  try{await navigator.clipboard.writeText(document.querySelector('#secret').textContent);show('Setup key copied. Keep it private.','ok')}
  catch{show('Copy was blocked. Select the setup key manually.')}
});
const verifyForm=document.querySelector('#verifyForm');
if(verifyForm)verifyForm.addEventListener('submit',async event=>{
  event.preventDefault();
  if(!enrollmentId){show('Create a setup key first.');return}
  const code=String(new FormData(verifyForm).get('code')||'').replace(/\s+/g,'');
  if(!/^\d{6}$/.test(code)){show('Enter exactly the 6 digits shown by your authenticator.');return}
  try{
    await api('/account/totp/complete','POST',{enrollment_id:enrollmentId,code});
    show('Authenticator enabled. Sign in again with the current 6-digit code to activate IAL2.','ok');
    setTimeout(()=>location.assign('/login?return_to=%2Fadmin%2Fconsole'),1000);
  }catch(error){show(error.message)}
});
const recovery=document.querySelector('#recovery');
if(recovery)recovery.addEventListener('click',async()=>{
  try{
    const data=await api('/auth/recovery-codes','POST');
    const codes=Array.isArray(data.codes)?data.codes.map(String):[];
    if(!codes.length)throw new Error('OpenProof did not return recovery codes.');
    document.querySelector('#recoveryCodes').textContent=codes.join('\n');
    document.querySelector('#recoveryBox').classList.add('show');
    show('Recovery codes generated. Store them securely; this batch is shown only once.','ok');
  }catch(error){show(error.message)}
});
const copyRecovery=document.querySelector('#copyRecovery');
if(copyRecovery)copyRecovery.addEventListener('click',async()=>{
  try{await navigator.clipboard.writeText(document.querySelector('#recoveryCodes').textContent);show('Recovery codes copied. Store them securely.','ok')}
  catch{show('Copy was blocked. Select the recovery codes manually.')}
});
</script></body></html>)HTML";

    gateway::HttpResponse response{
        200,
        gateway::Headers{{"content-type", "text/html; charset=utf-8"}},
        std::move(body)};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    response.setHeader(
        "content-security-policy",
        "default-src 'none'; style-src 'nonce-" + pageNonce
            + "'; script-src 'nonce-" + pageNonce
            + "'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    return response;
}

gateway::HttpResponse AccountHttpApi::totpStatus(gateway::HttpRequest request)
{
    auto authenticated = authenticate(request);
    if (!authenticated) return error(authenticated.error(), request);
    auto enabled = m_accounts->totpEnabled(authenticated->session().identity());
    if (!enabled) return error(enabled.error(), request);
    json::object body;
    body["available"] = enabled->has_value();
    body["enabled"] = enabled->value_or(false);
    body["assurance"] = identity::provider::assuranceLevelName(
        authenticated->session().assurance());
    return jsonResponse(200, std::move(body));
}

gateway::HttpResponse AccountHttpApi::beginTotpEnrollment(gateway::HttpRequest request)
{
    auto authenticated = authenticate(request);
    if (!authenticated) return error(authenticated.error(), request);
    auto body = objectBody(request);
    if (!body || !onlyFields(body.value(), {"password"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument}
                          : body.error(), request);
    }
    auto password = requiredString(body.value(), "password", 1024U);
    if (!password) return error(password.error(), request);
    foundation::SecretString secret{std::move(password).value()};
    auto started = m_accounts->beginTotpEnrollment(
        authenticated->session().identity(), secret,
        authenticated->session().assurance());
    if (!started) return error(started.error(), request);

    json::object responseBody;
    responseBody["enrollment_id"] = started->id().value();
    responseBody["secret_base32"] = started->secretBase32().expose();
    responseBody["expires_at_ms"] = started->expiresAt().time_since_epoch().count();
    responseBody["replacing"] = started->replacing();
    return jsonResponse(201, std::move(responseBody));
}

gateway::HttpResponse AccountHttpApi::completeTotpEnrollment(gateway::HttpRequest request)
{
    auto authenticated = authenticate(request);
    if (!authenticated) return error(authenticated.error(), request);
    auto body = objectBody(request);
    if (!body || !onlyFields(body.value(), {"enrollment_id", "code"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument}
                          : body.error(), request);
    }
    auto id = requiredString(body.value(), "enrollment_id", 200U);
    auto code = requiredString(body.value(), "code", 8U);
    if (!id || !code) return error(!id ? id.error() : code.error(), request);
    auto status = m_accounts->completeTotpEnrollment(
        authenticated->session().identity(),
        TotpEnrollmentId{std::move(id).value()}, code.value(),
        authenticated->session().assurance());
    return status
        ? jsonResponse(200, json::object{{"enabled", true}})
        : error(status.error(), request);
}

gateway::HttpResponse AccountHttpApi::disableTotp(gateway::HttpRequest request)
{
    auto authenticated = authenticate(request);
    if (!authenticated) return error(authenticated.error(), request);
    auto body = objectBody(request);
    if (!body || !onlyFields(body.value(), {"password"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument}
                          : body.error(), request);
    }
    auto password = requiredString(body.value(), "password", 1024U);
    if (!password) return error(password.error(), request);
    foundation::SecretString secret{std::move(password).value()};
    auto status = m_accounts->disableTotp(
        authenticated->session().identity(), secret,
        authenticated->session().assurance());
    return status
        ? jsonResponse(200, json::object{
              {"enabled", false}, {"recovery_codes_revoked", true}})
        : error(status.error(), request);
}

gateway::HttpResponse AccountHttpApi::getProfile(gateway::HttpRequest request)
{
    auto actor = authorize(request); if (!actor) return error(actor.error(), request);
    auto profile = m_accounts->profile(actor.value());
    return profile ? jsonResponse(200, profileJson(profile.value())) : error(profile.error(), request);
}

gateway::HttpResponse AccountHttpApi::updateProfile(gateway::HttpRequest request)
{
    auto actor = authorize(request); if (!actor) return error(actor.error(), request);
    auto body = objectBody(request);
    if (!body || !onlyFields(body.value(), {"display_name", "preferred_username", "locale", "picture", "avatar_source"})) return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto display = optionalProfileString(body.value(), "display_name", 256U);
    auto username = optionalProfileString(body.value(), "preferred_username", 128U);
    auto locale = optionalProfileString(body.value(), "locale", 64U);
    auto picture = optionalProfileString(body.value(), "picture", 2048U);
    auto avatarSource = optionalProfileString(body.value(), "avatar_source", 128U);
    if (!display || !username || !locale || !picture || !avatarSource) return error(!display ? display.error() : (!username ? username.error() : (!locale ? locale.error() : (!picture ? picture.error() : avatarSource.error()))), request);
    auto status = m_accounts->updateProfile(actor.value(), std::move(display).value(),
                                            std::move(username).value(), std::move(locale).value(),
                                            std::move(picture).value(), std::move(avatarSource).value());
    if (!status) return error(status.error(), request);
    auto profile = m_accounts->profile(actor.value());
    return profile ? jsonResponse(200, profileJson(profile.value())) : error(profile.error(), request);
}

gateway::HttpResponse AccountHttpApi::sessions(gateway::HttpRequest request)
{
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) return error(credential.error(), request);
    if (!credential->has_value()) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationRequired}, request);
    }
    auto authenticated = m_sessions->authenticate(credential->value());
    if (!authenticated) return error(authenticated.error(), request);
    const auto& current = authenticated->session();
    auto values = m_sessions->list(current.identity());
    if (!values) return error(values.error(), request);

    json::array sessions;
    for (const auto& value : values.value()) {
        json::object item;
        item["session_id"] = value.id().value();
        item["provider"] = value.provider().value();
        item["assurance"] = identity::provider::assuranceLevelName(value.assurance());
        item["phishing_resistant"] = value.strength().isPhishingResistant();
        item["issued_at_ms"] = value.issuedAt().time_since_epoch().count();
        item["last_seen_at_ms"] = value.lastSeenAt().time_since_epoch().count();
        item["absolute_expires_at_ms"] = value.absoluteExpiresAt().time_since_epoch().count();
        item["idle_expires_at_ms"] = value.idleExpiresAt().time_since_epoch().count();
        item["current"] = value.id() == current.id();
        if (value.userAgent()) item["user_agent"] = *value.userAgent();
        sessions.emplace_back(std::move(item));
    }
    return jsonResponse(200, json::object{{"sessions", std::move(sessions)}});
}

gateway::HttpResponse AccountHttpApi::revokeSession(gateway::HttpRequest request)
{
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) return error(credential.error(), request);
    if (!credential->has_value()) {
        return error(foundation::Error{foundation::ErrorCode::AuthenticationRequired}, request);
    }
    auto authenticated = m_sessions->authenticate(credential->value());
    if (!authenticated) return error(authenticated.error(), request);

    auto body = objectBody(request);
    if (!body || !onlyFields(body.value(), {"session_id"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    }
    auto idText = requiredString(body.value(), "session_id", 200U);
    if (!idText) return error(idText.error(), request);
    const session::SessionId target{std::move(idText).value()};
    if (target == authenticated->session().id()) {
        return error(foundation::Error{
            foundation::ErrorCode::FailedPrecondition,
            "Use logout to end the current session."}, request);
    }
    auto revoked = m_sessions->revokeOwned(authenticated->session().identity(), target);
    return revoked
        ? jsonResponse(200, json::object{{"revoked", true}})
        : error(revoked.error(), request);
}

gateway::HttpResponse AccountHttpApi::connections(gateway::HttpRequest request)
{
    auto actor = authorize(request);
    if (!actor) return error(actor.error(), request);
    auto values = m_authentication->connections(actor.value());
    if (!values) return error(values.error(), request);
    json::array connectionsJson;
    for (const auto& external : values.value()) {
        json::object item{
            {"provider", external.providerId().value()},
            {"subject", external.subject().value()}};
        if (external.displayName()) item["display_name"] = *external.displayName();
        if (external.preferredUsername()) item["preferred_username"] = *external.preferredUsername();
        if (external.pictureUrl()) item["picture_url"] = *external.pictureUrl();
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
    return jsonResponse(200, json::object{{"connections", std::move(connectionsJson)}});
}

gateway::HttpResponse AccountHttpApi::disconnect(gateway::HttpRequest request)
{
    auto actor = authorize(request);
    if (!actor) return error(actor.error(), request);
    auto body = objectBody(request);
    if (!body || !onlyFields(body.value(), {"provider", "subject"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument}
                          : body.error(), request);
    }
    auto provider = requiredString(body.value(), "provider", 128U);
    auto subject = requiredString(body.value(), "subject", 512U);
    if (!provider || !subject) return error(provider ? subject.error() : provider.error(), request);
    const identity::core::ExternalIdentityRef external{
        identity::provider::ProviderId{std::move(provider).value()},
        identity::provider::ExternalSubject{std::move(subject).value()}};
    auto status = m_authentication->disconnect(actor.value(), external);
    if (!status) return error(status.error(), request);
    return jsonResponse(200, json::object{{"disconnected", true}});
}

}

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

[[nodiscard]] bool trustedPasswordUpgradeOrigin(const gateway::HttpRequest& request)
{
    // Cookie-authenticated POSTs must be initiated by the same HTTPS origin.
    // JSON-only input plus SameSite=Strict cookies are defense in depth.
    const auto origin = request.header("origin");
    const auto host = request.header("host");
    if (!origin || !host || host->empty()) return false;
    if (host->find_first_of("/\\\r\n") != std::string_view::npos) return false;
    if (*origin != ("https://" + std::string{*host})) return false;
    const auto site = request.header("sec-fetch-site");
    return !site || *site == "same-origin";
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
    if (request.method() == HttpMethod::Get && request.path() == "/account/recover") return recoveryPage(std::move(request));
    if (request.method() == HttpMethod::Get && request.path() == "/account/security") return securityPage(std::move(request));
    if (request.method() == HttpMethod::Get && request.path() == "/account/password/upgrade") return passwordUpgradeStatus(std::move(request));
    if (request.method() == HttpMethod::Post && request.path() == "/account/password/upgrade") return confirmPasswordUpgrade(std::move(request));
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

gateway::HttpResponse AccountHttpApi::recoveryPage(gateway::HttpRequest request)
{
    static_cast<void>(request);
    auto nonce = security::randomTokenBase64Url(24U);
    if (!nonce) {
        return jsonResponse(500, json::object{{"error", "Unable to render recovery page."}});
    }
    const std::string pageNonce = nonce.value();

    std::string body = R"HTML(<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark"><title>Recover account · OpenProof</title>
<style nonce=")HTML" + pageNonce + R"HTML(">
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#090b10;color:#f7f7fb}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 15% 0%,rgba(105,92,255,.22),transparent 34rem),linear-gradient(180deg,#10131b,#080a0f);padding:24px}
.shell{width:min(100%,620px)}.brand{display:flex;align-items:center;gap:13px;margin:0 4px 24px;color:#e5e6ff;font-weight:800;font-size:21px}.brand-mark{width:44px;height:44px;border-radius:14px;display:grid;place-items:center;background:linear-gradient(135deg,#7478ff,#9c68ff);box-shadow:0 16px 38px rgba(102,92,255,.28)}.brand small{display:block;margin-top:2px;color:#8c91a4;font-size:11px;letter-spacing:.11em;text-transform:uppercase}
.card{background:rgba(23,26,35,.96);border:1px solid rgba(255,255,255,.09);border-radius:30px;padding:clamp(26px,6vw,40px);box-shadow:0 30px 100px rgba(0,0,0,.4)}.kicker{display:inline-flex;padding:8px 12px;border-radius:999px;background:rgba(111,107,255,.15);color:#c9c9ff;font-size:12px;font-weight:800;letter-spacing:.07em;text-transform:uppercase}
h1{font-size:clamp(34px,8vw,50px);line-height:1.02;letter-spacing:-.05em;margin:18px 0 12px}h2{font-size:21px;margin:0 0 9px}.lead,.muted{color:#aeb3c4;line-height:1.65}.lead{margin:0 0 25px}.muted{margin:0 0 17px}.field{display:grid;gap:8px;margin:15px 0}.field>span{font-size:12px;color:#a8adbf;font-weight:750;text-transform:uppercase;letter-spacing:.06em}
input{width:100%;border:1px solid rgba(255,255,255,.13);border-radius:15px;background:#0d1016;color:#fff;padding:14px 15px;font:inherit;outline:none}input:focus{border-color:#7d82ff;box-shadow:0 0 0 3px rgba(125,130,255,.15)}
button,.button{appearance:none;border:0;border-radius:14px;background:linear-gradient(135deg,#7076ff,#9568ff);color:#fff;padding:14px 17px;font:750 15px inherit;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center}.button.secondary{background:#171a23;border:1px solid rgba(255,255,255,.11)}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}
.notice{display:none;margin:18px 0 0;padding:13px 15px;border-radius:14px;font-size:13px;line-height:1.55}.notice.show{display:block}.notice.error{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.28);color:#fecaca}.notice.ok{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.25);color:#bbf7d0}.panel{display:none}.panel.show{display:block}.foot{color:#747b8f;font-size:12px;line-height:1.55;margin:16px 0 0}.text-link{color:#b8bbff;text-decoration:none;font-weight:700}.text-link:hover{text-decoration:underline}.footer{text-align:center;color:#666d80;font-size:12px;line-height:1.55;margin:18px 12px 0}
@media(max-width:560px){body{padding:16px}.card{border-radius:23px}.actions>*{width:100%}}
</style></head><body><main class="shell"><div class="brand"><span class="brand-mark">G</span><span>Genyleap<small>Secured by OpenProof</small></span></div>
<section class="card"><span class="kicker">Account recovery</span><h1>Reset your OpenProof password</h1>
<p class="lead">OpenProof never reveals your existing password. Recovery verifies control of your email, then lets you choose a new password.</p>
<div id="requestPanel" class="panel"><h2>Send a reset link</h2><p class="muted">Enter the email address used by your OpenProof account.</p>
<form id="requestForm"><label class="field"><span>Email address</span><input name="email" type="email" autocomplete="email" maxlength="320" required></label><button type="submit">Send reset link</button></form>
<p class="foot">For privacy, OpenProof gives the same response whether or not an account exists for that address.</p></div>
<div id="resetPanel" class="panel"><h2>Choose a new password</h2><p class="muted">Use at least 8 characters. Completing the reset revokes existing OpenProof sessions for this identity.</p>
<form id="resetForm"><label class="field"><span>New password</span><input name="password" type="password" autocomplete="new-password" minlength="8" maxlength="1024" required></label>
<label class="field"><span>Confirm new password</span><input name="confirm" type="password" autocomplete="new-password" minlength="8" maxlength="1024" required></label>
<button type="submit">Reset password</button></form></div>
<div id="notice" class="notice" role="status" aria-live="polite"></div>
<div class="actions"><a class="button secondary" href="/login?return_to=%2Faccount%2Fsecurity">Back to sign in</a></div>
</section><p class="footer">Recovery links are single-use and time-limited.</p></main>
<script nonce=")HTML" + pageNonce + R"HTML(">
const notice=document.querySelector('#notice');
const show=(message,type='error')=>{notice.textContent=message;notice.className='notice show '+type};
async function api(url,body){
  const response=await fetch(url,{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  const text=await response.text();let data={};
  try{data=text?JSON.parse(text):{}}catch{data={error:{message:text||'Unexpected response'}}}
  if(!response.ok)throw new Error(data?.error?.message||'The request could not be completed.');
  return data;
}
const params=new URLSearchParams(location.search);
const queryId=params.get('id');
const querySecret=params.get('secret');
if(queryId&&querySecret){
  sessionStorage.setItem('openproof_reset_id',queryId);
  sessionStorage.setItem('openproof_reset_secret',querySecret);
  history.replaceState(null,'','/account/recover');
}
const resetId=sessionStorage.getItem('openproof_reset_id');
const resetSecret=sessionStorage.getItem('openproof_reset_secret');
const hasProof=Boolean(resetId&&resetSecret);
document.querySelector(hasProof?'#resetPanel':'#requestPanel').classList.add('show');
const requestForm=document.querySelector('#requestForm');
requestForm.addEventListener('submit',async event=>{
  event.preventDefault();notice.className='notice';
  const email=String(new FormData(requestForm).get('email')||'').trim();
  try{
    await api('/account/password/forgot',{email});
    requestForm.reset();
    show('If that email belongs to an OpenProof account, a single-use reset link has been sent.','ok');
  }catch(error){show(error.message)}
});
const resetForm=document.querySelector('#resetForm');
resetForm.addEventListener('submit',async event=>{
  event.preventDefault();notice.className='notice';
  if(!resetId||!resetSecret){show('This reset link is missing or no longer available. Request a new one.');return}
  const data=new FormData(resetForm);
  const password=String(data.get('password')||'');
  const confirm=String(data.get('confirm')||'');
  if(password.length<8){show('Use a password with at least 8 characters.');return}
  if(password!==confirm){show('The two password fields do not match.');return}
  try{
    await api('/account/password/reset',{verification_id:resetId,secret:resetSecret,new_password:password});
    sessionStorage.removeItem('openproof_reset_id');
    sessionStorage.removeItem('openproof_reset_secret');
    resetForm.reset();
    show('Password reset complete. Sign in with your new password.','ok');
    setTimeout(()=>location.assign('/login?return_to=%2Faccount%2Fsecurity'),1200);
  }catch(error){show(error.message)}
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
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 15% 0%,rgba(105,92,255,.22),transparent 34rem),linear-gradient(180deg,#10131b,#080a0f);padding:clamp(14px,2.2vw,24px)}
.shell{width:min(100%,720px);margin:0 auto}.brand{display:flex;align-items:center;gap:12px;margin:8px 4px 18px;color:#e5e6ff;font-weight:800;font-size:20px}.brand-mark{width:42px;height:42px;border-radius:13px;display:grid;place-items:center;background:linear-gradient(135deg,#7478ff,#9c68ff);box-shadow:0 14px 34px rgba(102,92,255,.26)}.brand small{display:block;margin-top:2px;color:#8c91a4;font-size:10px;letter-spacing:.11em;text-transform:uppercase}
.card{background:rgba(23,26,35,.96);border:1px solid rgba(255,255,255,.09);border-radius:26px;padding:clamp(22px,3vw,32px);box-shadow:0 26px 80px rgba(0,0,0,.36)}.kicker{display:inline-flex;padding:7px 11px;border-radius:999px;background:rgba(111,107,255,.15);color:#c9c9ff;font-size:11px;font-weight:800;letter-spacing:.07em;text-transform:uppercase}
h1{font-size:clamp(32px,5vw,44px);line-height:1.04;letter-spacing:-.045em;margin:15px 0 10px}h2{font-size:18px;margin:0 0 8px}.lead,.muted{color:#aeb3c4;line-height:1.58}.lead{font-size:15px;margin:0 0 22px}.muted{font-size:14px;margin:0 0 14px}
.upgrade-banner{display:none;margin:18px 0;padding:16px;border-radius:17px;border:1px solid rgba(127,152,255,.42);background:rgba(90,105,220,.12)}
.upgrade-banner.show{display:block}.upgrade-overlay{position:fixed;inset:0;z-index:30;background:rgba(0,0,0,.78);display:grid;place-items:center;padding:20px}
.upgrade-overlay[hidden]{display:none}.upgrade-dialog{width:min(100%,490px);border-radius:24px;background:#191e2b;border:1px solid #444c64;padding:26px;box-shadow:0 32px 110px #000b}
.upgrade-dialog p{line-height:1.65;color:#bdc5d4}.upgrade-dialog h2{font-size:25px}.upgrade-dialog .actions{margin-top:18px}
.upgrade-message{color:#fca5a5;min-height:18px;font-size:13px}.upgrade-dialog button:disabled{opacity:.6;cursor:wait}
.status{display:flex;align-items:center;gap:13px;padding:16px 17px;border:1px solid rgba(255,255,255,.09);border-radius:18px;background:#11141b}.status strong{font-size:15px}.status span{color:#9298ac;font-size:13px}.dot{width:11px;height:11px;border-radius:50%;background:#f59e0b;box-shadow:0 0 0 5px rgba(245,158,11,.09)}.dot.on{background:#4ade80;box-shadow:0 0 0 5px rgba(74,222,128,.09)}
.panel{border-top:1px solid rgba(255,255,255,.08);padding-top:22px;margin-top:22px}.field{display:grid;gap:7px;margin:12px 0}.field>span{font-size:11px;color:#a8adbf;font-weight:750;text-transform:uppercase;letter-spacing:.06em}
input{width:100%;border:1px solid rgba(255,255,255,.13);border-radius:13px;background:#0d1016;color:#fff;padding:12px 14px;font:inherit;outline:none}input:focus{border-color:#7d82ff;box-shadow:0 0 0 3px rgba(125,130,255,.15)}
button,.button{appearance:none;border:0;border-radius:12px;background:linear-gradient(135deg,#7076ff,#9568ff);color:#fff;padding:11px 15px;font:750 13px inherit;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center}.secondary{background:#171a23!important;border:1px solid rgba(255,255,255,.11)!important}.actions{display:flex;gap:9px;flex-wrap:wrap}
.setup{display:none;margin-top:16px;padding:16px;border-radius:17px;background:#0f1218;border:1px solid rgba(255,255,255,.08)}.setup.show{display:block}.setup-grid{display:grid;grid-template-columns:minmax(0,1.08fr) minmax(0,.92fr);gap:14px}.setup-step{min-width:0;padding:15px;border-radius:15px;background:#0b0e14;border:1px solid rgba(255,255,255,.07)}.key{display:flex;gap:8px;align-items:center;padding:10px;border-radius:12px;background:#080a0f;border:1px solid rgba(255,255,255,.08)}.key code{flex:1;min-width:0;word-break:break-all;font:650 12px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.035em}
.notice{display:none;margin:15px 0 0;padding:12px 14px;border-radius:13px;font-size:12px;line-height:1.5}.notice.show{display:block}.notice.error{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.28);color:#fecaca}.notice.ok{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.25);color:#bbf7d0}
.code{font-size:22px;letter-spacing:.18em;text-align:center;font-variant-numeric:tabular-nums}.foot{color:#747b8f;font-size:11px;line-height:1.5;margin:12px 0 0}.codes{white-space:pre-wrap;font:650 13px/1.65 ui-monospace,SFMono-Regular,Menlo,monospace;color:#e7e8f2}.spaced{margin-top:10px}.center{text-align:center}.text-link{color:#b8bbff;text-decoration:none;font-weight:700}.text-link:hover{text-decoration:underline}
@media(max-width:720px){.setup-grid{grid-template-columns:1fr}.shell{width:min(100%,620px)}}
@media(max-width:560px){body{padding:12px}.brand{margin:6px 2px 14px}.card{border-radius:20px;padding:20px}.status{padding:13px 14px;border-radius:15px}.actions>*{width:100%}.key{align-items:stretch;flex-direction:column}.key button{width:100%}.setup{padding:12px}.setup-step{padding:13px}.code{font-size:20px}}
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
<p class="foot">Forgot your password? <a class="text-link" href="/account/recover">Reset it securely</a>.</p>
<div id="setup" class="setup"><div class="setup-grid">
<section class="setup-step"><h2>1. Add this setup key</h2>
<p class="muted">In your authenticator choose “Enter setup key” (time based). This long key is not the 6-digit login code.</p>
<div class="key"><code id="secret"></code><button class="secondary" type="button" id="copy">Copy key</button></div>
<div class="actions spaced"><a id="openAuthenticator" class="button secondary" href="#">Open authenticator app</a></div></section>
<section class="setup-step"><h2>2. Verify the 6-digit code</h2>
<p class="muted">Your authenticator will now show a new 6-digit code about every 30 seconds.</p>
<form id="verifyForm"><label class="field"><span>Authenticator code</span>
<input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" minlength="6" maxlength="6" placeholder="000000" required></label>
<button type="submit">Enable authenticator</button></form></section></div>
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

    body += R"HTML(<div id="upgradeBanner" class="upgrade-banner" role="status">
<h2>Password protection upgrade available</h2>
<p class="muted">Your existing password still works. Confirm it once to protect its stored hash with Argon2id; you do not need to change your password.</p>
<button type="button" id="upgradeOpen">Confirm current password</button></div>
</section><p class="foot center">OpenProof keeps application sessions separate from your Genyleap credentials.</p></main>
<div id="upgradeOverlay" class="upgrade-overlay" hidden>
<section class="upgrade-dialog" role="dialog" aria-modal="true" aria-labelledby="upgradeTitle" aria-describedby="upgradeDescription">
<h2 id="upgradeTitle">Upgrade password protection</h2>
<p id="upgradeDescription">OpenProof can now protect your stored password hash using Argon2id. Confirm your current OpenProof password to finish this optional upgrade. Your password and active sessions stay the same.</p>
<form id="upgradeForm">
<label class="field"><span>Current OpenProof password</span>
<input id="upgradePassword" name="password" type="password" autocomplete="current-password" minlength="8" maxlength="1024" required></label>
<div id="upgradeMessage" class="upgrade-message" role="alert" aria-live="polite"></div>
<div class="actions">
<button type="submit" id="upgradeSubmit">Confirm &amp; upgrade</button>
<button type="button" class="secondary" id="upgradeLater">Not now</button></div></form>
<p class="foot">Only confirm your password on the official OpenProof website. This does not add a new login factor.</p>
</section></div>
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
const upgradeBanner=document.querySelector('#upgradeBanner');
const upgradeOverlay=document.querySelector('#upgradeOverlay');
const upgradeForm=document.querySelector('#upgradeForm');
const upgradeMessage=document.querySelector('#upgradeMessage');
const upgradePassword=document.querySelector('#upgradePassword');
const upgradeOpen=document.querySelector('#upgradeOpen');
const upgradeLater=document.querySelector('#upgradeLater');
const upgradeSubmit=document.querySelector('#upgradeSubmit');
const upgradeDismissKey='openproof-password-upgrade-dismissed';
function openUpgrade(){upgradeOverlay.hidden=false;upgradePassword.focus()}
function closeUpgrade(snooze){
  upgradeOverlay.hidden=true;upgradeForm.reset();upgradeMessage.textContent='';
  if(snooze)sessionStorage.setItem(upgradeDismissKey,'1');
  upgradeOpen.focus();
}
upgradeOpen.addEventListener('click',openUpgrade);
upgradeLater.addEventListener('click',()=>closeUpgrade(true));
upgradeOverlay.addEventListener('keydown',e=>{
  if(e.key==='Escape'){e.preventDefault();closeUpgrade(true)}
  if(e.key==='Tab'){
    const items=[upgradePassword,upgradeSubmit,upgradeLater].filter(x=>!x.disabled);
    const first=items[0],last=items[items.length-1];
    if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus()}
    else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus()}
  }
});
upgradeForm.addEventListener('submit',async event=>{
  event.preventDefault();
  const password=String(new FormData(upgradeForm).get('password')||'');
  upgradeMessage.textContent='';upgradeSubmit.disabled=true;
  try{
    const result=await api('/account/password/upgrade','POST',{password});
    upgradeOverlay.hidden=true;upgradeForm.reset();
    upgradeBanner.classList.remove('show');sessionStorage.removeItem(upgradeDismissKey);
    show(result.upgraded?'Your password hash is now protected with Argon2id.':'Your password protection is already up to date.','ok');
  }catch(error){
    upgradeForm.reset();upgradePassword.focus();
    upgradeMessage.textContent=error.message||'Unable to confirm this password.';
  }finally{upgradeSubmit.disabled=false}
});
api('/account/password/upgrade').then(status=>{
  if(!status.available||!status.needs_upgrade)return;
  upgradeBanner.classList.add('show');
  if(sessionStorage.getItem(upgradeDismissKey)!=='1')openUpgrade();
}).catch(()=>{}); // Never interrupt existing security flows.

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
    show('Authenticator enabled. The code you just used is consumed. Wait for your authenticator to show a NEW 6-digit code, then sign in with that new code.','ok');
    setTimeout(()=>location.assign('/login?return_to=%2Fadmin%2Fconsole&notice=totp-enrolled'),1400);
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

gateway::HttpResponse AccountHttpApi::passwordUpgradeStatus(gateway::HttpRequest request)
{
    auto actor = authorize(request);
    if (!actor) return error(actor.error(), request);
    auto needed = m_accounts->passwordUpgradeNeeded(actor.value());
    if (!needed) return error(needed.error(), request);
    const bool available = needed->has_value();
    return jsonResponse(200, json::object{
        {"available", available},
        {"needs_upgrade", needed->value_or(false)},
        {"target_algorithm", "argon2id"}
    });
}

gateway::HttpResponse AccountHttpApi::confirmPasswordUpgrade(gateway::HttpRequest request)
{
    if (!trustedPasswordUpgradeOrigin(request)) {
        return error(foundation::Error{foundation::ErrorCode::PermissionDenied}, request);
    }
    auto actor = authorize(request);
    if (!actor) return error(actor.error(), request);
    auto body = objectBody(request);
    if (!body || !onlyFields(body.value(), {"password"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument}
                          : body.error(), request);
    }
    auto password = requiredString(body.value(), "password", 1024U);
    if (!password) return error(password.error(), request);
    foundation::SecretString secret{std::move(password).value()};
    auto upgraded = m_accounts->confirmPasswordUpgrade(actor.value(), secret);
    if (!upgraded) return error(upgraded.error(), request);
    return jsonResponse(200, json::object{{"upgraded", upgraded.value()},
                                          {"needs_upgrade", false}});
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

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

foundation::Result<identity::core::IdentityId>
AccountHttpApi::authorize(gateway::HttpRequest& request) const
{
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) return foundation::fail(credential.error());
    if (!credential->has_value()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationRequired,
                                "Authentication is required.");
    }
    auto authenticated = m_sessions->authenticate(
        credential->value(), m_delegated, "account");
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
    if (request.method() == HttpMethod::Get && request.path() == "/account/profile") return getProfile(std::move(request));
    if ((request.method() == HttpMethod::Patch || request.method() == HttpMethod::Put)
        && request.path() == "/account/profile") return updateProfile(std::move(request));
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
        && (request.path() == "/account/connections/web3/start"
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
    auto status = m_accounts->verifyEmail(VerificationId{std::move(id).value()}, proof);
    return status ? jsonResponse(200, json::object{{"verified", true}}) : error(status.error(), request);
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
    auto body = objectBody(request); if (!body || !onlyFields(body.value(), {"verification_id", "secret"})) return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto id = requiredString(body.value(), "verification_id", 200U); auto secret = requiredString(body.value(), "secret", 512U);
    if (!id || !secret) return error(id ? secret.error() : id.error(), request);
    foundation::SecretString proof{std::move(secret).value()};
    auto status = m_accounts->completeEmailChange(
        actor.value(), VerificationId{std::move(id).value()}, proof);
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
    if (!body || !onlyFields(body.value(), {"display_name", "preferred_username", "locale", "picture"})) return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto display = optionalString(body.value(), "display_name", 256U);
    auto username = optionalString(body.value(), "preferred_username", 128U);
    auto locale = optionalString(body.value(), "locale", 64U);
    auto picture = optionalString(body.value(), "picture", 2048U);
    if (!display || !username || !locale || !picture) return error(!display ? display.error() : (!username ? username.error() : (!locale ? locale.error() : picture.error())), request);
    auto status = m_accounts->updateProfile(actor.value(), std::move(display).value(),
                                            std::move(username).value(), std::move(locale).value(),
                                            std::move(picture).value());
    if (!status) return error(status.error(), request);
    auto profile = m_accounts->profile(actor.value());
    return profile ? jsonResponse(200, profileJson(profile.value())) : error(profile.error(), request);
}

gateway::HttpResponse AccountHttpApi::connections(gateway::HttpRequest request)
{
    auto actor = authorize(request);
    if (!actor) return error(actor.error(), request);
    auto values = m_authentication->connections(actor.value());
    if (!values) return error(values.error(), request);
    json::array connectionsJson;
    for (const auto& external : values.value()) {
        connectionsJson.emplace_back(json::object{
            {"provider", external.providerId().value()},
            {"subject", external.subject().value()}});
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

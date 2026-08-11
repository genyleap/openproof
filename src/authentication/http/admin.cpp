module;

#include <algorithm>
#include <cstddef>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/json.hpp>

module openproof.administration.http;

import openproof.credentials;
import openproof.organization;
import openproof.security;

namespace openproof::administration::http {
namespace {

namespace json = boost::json;
namespace idp = identity::provider;
constexpr std::size_t kMaximumAdminBody = 16U * 1024U;

[[nodiscard]] gateway::HttpResponse jsonResponse(int status, json::object body)
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

[[nodiscard]] foundation::Result<json::object>
parseObject(const gateway::HttpRequest& request)
{
    if (request.body().empty() || request.body().size() > kMaximumAdminBody) {
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

[[nodiscard]] bool validText(std::string_view value, std::size_t maximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::none_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           });
}

[[nodiscard]] foundation::Result<std::string>
requiredString(const json::object& object, std::string_view name,
               std::size_t maximum)
{
    const json::value* value = object.if_contains(name);
    if (value == nullptr || !value->is_string()
        || !validText(value->as_string(), maximum)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request was not valid.");
    }
    return std::string{value->as_string()};
}

[[nodiscard]] foundation::Result<std::vector<organization::Role>>
requiredRoles(const json::object& object)
{
    const json::value* value = object.if_contains("roles");
    if (value == nullptr || !value->is_array() || value->as_array().empty()
        || value->as_array().size() > 16U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request was not valid.");
    }
    std::vector<organization::Role> roles;
    roles.reserve(value->as_array().size());
    for (const json::value& item : value->as_array()) {
        if (!item.is_string() || !validText(item.as_string(), 200U)) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The request was not valid.");
        }
        roles.emplace_back(std::string{item.as_string()});
    }
    return roles;
}

[[nodiscard]] bool onlyFields(
    const json::object& object,
    std::initializer_list<std::string_view> allowed)
{
    return std::ranges::all_of(object, [&](const auto& item) {
        return std::ranges::find(allowed, std::string_view{item.key()})
            != allowed.end();
    });
}

}

AdministrationHttpApi::AdministrationHttpApi(
    session::SessionService& sessions, LocalMemberProvisioner& members,
    gateway::TokenBucketRateLimiter& rateLimiter,
    identity::core::OrganizationId organization,
    idp::ProviderId provider, const foundation::ClockSource& clock,
    gateway::HttpHandler& fallback)
    : m_sessions(&sessions), m_members(&members), m_rateLimiter(&rateLimiter),
      m_organization(std::move(organization)), m_provider(std::move(provider)),
      m_clock(&clock), m_fallback(&fallback)
{
}

gateway::HttpResponse AdministrationHttpApi::error(
    const foundation::Error& failure,
    const gateway::HttpRequest& request) const
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
    return output;
}

gateway::HttpResponse AdministrationHttpApi::handle(gateway::HttpRequest request)
{
    if (request.path() != "/admin" && !request.path().starts_with("/admin/")) {
        return m_fallback->handle(std::move(request));
    }
    if (!m_rateLimiter->allow(
            "admin-ip:" + std::string{request.remoteAddress()})) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    if (request.method() != gateway::HttpMethod::Post
        || request.path() != "/admin/local-members") {
        return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
    }
    auto credential = gateway::takeSessionCredential(request);
    if (!credential || !credential->has_value()) {
        return error(credential
                         ? foundation::Error{foundation::ErrorCode::AuthenticationRequired}
                         : credential.error(), request);
    }
    auto authenticated = m_sessions->authenticate(credential->value());
    if (!authenticated) return error(authenticated.error(), request);
    if (!idp::meetsAssurance(authenticated->session().assurance(),
                             idp::AssuranceLevel::Ial2)) {
        return error(foundation::Error{foundation::ErrorCode::AssuranceInsufficient},
                     request);
    }
    const identity::core::IdentityId& actor =
        authenticated->session().identity();
    if (!m_rateLimiter->allow("admin-identity:" + std::string{actor.value()})) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    return createLocalMember(std::move(request), actor);
}

gateway::HttpResponse AdministrationHttpApi::createLocalMember(
    gateway::HttpRequest request,
    const identity::core::IdentityId& actor)
{
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"identity_id", "subject", "roles"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument}
                          : body.error(), request);
    }
    auto identityId = requiredString(body.value(), "identity_id", 200U);
    auto subject = requiredString(body.value(), "subject", 320U);
    auto roles = requiredRoles(body.value());
    if (!identityId || !subject || !roles) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    auto password = security::randomTokenBase64Url(32U);
    auto totp = credentials::TotpSecret::generate();
    if (!password || !totp) {
        return error(foundation::Error{foundation::ErrorCode::Internal}, request);
    }
    auto enrollment = LocalMemberEnrollment::create(
        m_organization,
        identity::core::IdentityId{std::move(identityId).value()}, m_provider,
        idp::ExternalSubject{std::move(subject).value()},
        std::move(roles).value(),
        foundation::SecretString{std::move(password).value()},
        std::move(totp).value(), m_clock->now());
    if (!enrollment) return error(enrollment.error(), request);
    const foundation::Status provisioned = m_members->provision(actor, enrollment.value());
    if (!provisioned) return error(provisioned.error(), request);

    const foundation::SecretString base32 =
        enrollment->generatedTotp().enrollmentBase32();
    json::object payload;
    payload["identity_id"] = enrollment->identity().id().value();
    payload["initial_password"] = enrollment->generatedPassword().expose();
    payload["totp_secret_base32"] = base32.expose();
    return jsonResponse(201, std::move(payload));
}

}

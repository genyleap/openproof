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

[[nodiscard]] gateway::HttpResponse emptyResponse(int status)
{
    gateway::HttpResponse output{status, {}, {}};
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
    session::SessionService& sessions, LocalMemberAdministrator& members,
    identity::core::IdentityRepository& identities,
    organization::MembershipRepository& memberships,
    gateway::TokenBucketRateLimiter& rateLimiter,
    identity::core::OrganizationId organization,
    idp::ProviderId provider, const foundation::ClockSource& clock,
    gateway::HttpHandler& fallback)
    : m_sessions(&sessions), m_members(&members), m_identities(&identities),
      m_memberships(&memberships), m_rateLimiter(&rateLimiter),
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
    const bool list = request.method() == gateway::HttpMethod::Get
        && request.path() == "/admin/local-members";
    const bool create = request.method() == gateway::HttpMethod::Post
        && request.path() == "/admin/local-members";
    const bool roles = request.method() == gateway::HttpMethod::Put
        && request.path() == "/admin/local-members/roles";
    const bool suspend = request.method() == gateway::HttpMethod::Post
        && request.path() == "/admin/local-members/suspend";
    const bool reinstate = request.method() == gateway::HttpMethod::Post
        && request.path() == "/admin/local-members/reinstate";
    const bool remove = request.method() == gateway::HttpMethod::Post
        && request.path() == "/admin/local-members/remove";
    const bool reset = request.method() == gateway::HttpMethod::Post
        && request.path() == "/admin/local-members/credentials/reset";
    if (!list && !create && !roles && !suspend && !reinstate && !remove && !reset) {
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
    if (list) return listLocalMembers(std::move(request));
    if (create) return createLocalMember(std::move(request), actor);
    if (roles) return replaceRoles(std::move(request), actor);
    if (suspend) {
        return changeLifecycle(std::move(request), actor,
                               MemberLifecycleAction::Suspend);
    }
    if (reinstate) {
        return changeLifecycle(std::move(request), actor,
                               MemberLifecycleAction::Reinstate);
    }
    if (remove) {
        return changeLifecycle(std::move(request), actor,
                               MemberLifecycleAction::Remove);
    }
    return resetCredentials(std::move(request), actor);
}

gateway::HttpResponse AdministrationHttpApi::listLocalMembers(gateway::HttpRequest request)
{
    auto ids = m_memberships->membersOf(m_organization);
    if (!ids) return error(ids.error(), request);
    json::array items;
    for (const auto& id : ids.value()) {
        auto membership = m_memberships->find(m_organization, id);
        auto identity = m_identities->findById(m_organization, id);
        if (!membership) return error(membership.error(), request);
        if (!identity) return error(identity.error(), request);
        if (!membership->has_value() || !identity->has_value()) continue;
        json::object item;
        item["identity_id"] = std::string{id.value()};
        item["identity_status"] = std::string{identity::core::identityStatusName(identity->value().status())};
        item["membership_state"] = std::string{organization::membershipStateName(membership->value().state())};
        json::array roles;
        for (const auto& role : membership->value().roles()) {
            roles.emplace_back(std::string{role.value()});
        }
        item["roles"] = std::move(roles);
        items.emplace_back(std::move(item));
    }
    json::object body;
    body["members"] = std::move(items);
    return jsonResponse(200, std::move(body));
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

gateway::HttpResponse AdministrationHttpApi::replaceRoles(
    gateway::HttpRequest request, const identity::core::IdentityId& actor)
{
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"identity_id", "roles"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument}
                          : body.error(), request);
    }
    auto identityId = requiredString(body.value(), "identity_id", 200U);
    auto roles = requiredRoles(body.value());
    if (!identityId || !roles) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    auto replacement = MemberRoleReplacement::create(
        m_organization,
        identity::core::IdentityId{std::move(identityId).value()},
        std::move(roles).value(), m_clock->now());
    if (!replacement) return error(replacement.error(), request);
    const foundation::Status replaced =
        m_members->replaceRoles(actor, replacement.value());
    return replaced ? emptyResponse(204) : error(replaced.error(), request);
}

gateway::HttpResponse AdministrationHttpApi::changeLifecycle(
    gateway::HttpRequest request, const identity::core::IdentityId& actor,
    MemberLifecycleAction action)
{
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"identity_id"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument}
                          : body.error(), request);
    }
    auto identityId = requiredString(body.value(), "identity_id", 200U);
    if (!identityId) return error(identityId.error(), request);
    auto change = MemberLifecycleChange::create(
        m_organization,
        identity::core::IdentityId{std::move(identityId).value()},
        action, m_clock->now());
    if (!change) return error(change.error(), request);
    const foundation::Status changed =
        m_members->changeLifecycle(actor, change.value());
    return changed ? emptyResponse(204) : error(changed.error(), request);
}

gateway::HttpResponse AdministrationHttpApi::resetCredentials(
    gateway::HttpRequest request, const identity::core::IdentityId& actor)
{
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"identity_id"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument}
                          : body.error(), request);
    }
    auto identityId = requiredString(body.value(), "identity_id", 200U);
    if (!identityId) return error(identityId.error(), request);
    auto password = security::randomTokenBase64Url(32U);
    auto totp = credentials::TotpSecret::generate();
    if (!password || !totp) {
        return error(foundation::Error{foundation::ErrorCode::Internal}, request);
    }
    auto reset = LocalCredentialReset::create(
        m_organization,
        identity::core::IdentityId{std::move(identityId).value()},
        foundation::SecretString{std::move(password).value()},
        std::move(totp).value(), m_clock->now());
    if (!reset) return error(reset.error(), request);
    const foundation::Status resetStatus =
        m_members->resetCredentials(actor, reset.value());
    if (!resetStatus) return error(resetStatus.error(), request);

    const foundation::SecretString base32 =
        reset->generatedTotp().enrollmentBase32();
    json::object payload;
    payload["identity_id"] = reset->identityId().value();
    payload["initial_password"] = reset->generatedPassword().expose();
    payload["totp_secret_base32"] = base32.expose();
    return jsonResponse(200, std::move(payload));
}

}

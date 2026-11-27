#include <boost/asio/awaitable.hpp>
#include <boost/json.hpp>

#include <algorithm>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "coroutine_admin_read_http.hpp"

import openproof.identity.provider;
import openproof.organization;
import openproof.credentials;
import openproof.security;

namespace openproof::administration::http {
namespace asio = boost::asio;
namespace json = boost::json;
namespace idp = identity::provider;
namespace {
struct Scrub final {
    gateway::HttpRequest& request;
    ~Scrub() {
        request.wipeAuthorizationHeader();
        request.wipeCookieHeader();
        request.wipeBody();
        request.wipeTargetQuery();
    }
};

void secureHeaders(gateway::HttpResponse& response) {
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
}

bool isList(const gateway::HttpRequest& request) noexcept {
    return request.path() == "/admin/local-members"
        && request.method() == gateway::HttpMethod::Get;
}
bool isMutation(const gateway::HttpRequest& request) noexcept {
    const auto path = request.path();
    using gateway::HttpMethod;
    return (request.method()==HttpMethod::Put && path=="/admin/local-members/roles")
        || (request.method()==HttpMethod::Post && (path=="/admin/local-members"
            || path=="/admin/local-members/suspend" || path=="/admin/local-members/reinstate"
            || path=="/admin/local-members/remove" || path=="/admin/local-members/credentials/reset"));
}
bool memberPath(std::string_view path) noexcept {
    return path=="/admin/local-members" || path.starts_with("/admin/local-members/");
}
bool validText(std::string_view value, std::size_t maximum) {
    return !value.empty() && value.size()<=maximum
        && std::none_of(value.begin(),value.end(),[](char c) {
            const auto byte=static_cast<unsigned char>(c);
            return byte<0x20U || byte==0x7fU;
        });
}
foundation::Result<std::string> requiredString(const json::object& body,
    std::string_view name,std::size_t max) {
    const auto* item=body.if_contains(name);
    if (!item || !item->is_string() || !validText(item->as_string(),max))
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    return std::string{item->as_string()};
}
foundation::Result<std::vector<organization::Role>> rolesFrom(const json::object& body) {
    const auto* value=body.if_contains("roles");
    if (!value || !value->is_array() || value->as_array().empty() || value->as_array().size()>16U)
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    std::vector<organization::Role> roles;
    for (const auto& role:value->as_array()) {
        if (!role.is_string() || !validText(role.as_string(),200U))
            return foundation::fail(foundation::ErrorCode::InvalidArgument);
        roles.emplace_back(std::string{role.as_string()});
    }
    return roles;
}
bool onlyFields(const json::object& body,std::initializer_list<std::string_view> names) {
    return std::all_of(body.begin(),body.end(),[&](const auto& entry) {
        return std::find(names.begin(),names.end(),std::string_view{entry.key()})!=names.end();
    });
}
gateway::HttpResponse credentialResponse(int status,std::string_view owner,
    const foundation::SecretString& password,const credentials::TotpSecret& seed) {
    auto base32=seed.enrollmentBase32();
    json::object body{{"identity_id",std::string{owner}}};
    struct Wipe final {
        json::object& body;
        ~Wipe() {
            for (const auto* key:{"initial_password","totp_secret_base32"}) {
                if (auto* value=body.if_contains(key); value && value->is_string()) {
                    auto& text=value->as_string();
                    foundation::secureWipe(text.data(),text.size());
                }
            }
        }
    } wipe{body};
    // Install the wiping guard before the first credential copy, so a
    // failed allocation while inserting the second field also scrubs the first.
    body["initial_password"] = password.expose();
    body["totp_secret_base32"] = base32.expose();
    gateway::HttpResponse response{status, gateway::Headers{{"content-type","application/json"}},
        json::serialize(body)};
    secureHeaders(response);
    return response;
}
}

CoroutineAdministrationReadAdapter::CoroutineAdministrationReadAdapter(
    gateway::http::CoroutineHttpHandler& fallback, gateway::TokenBucketRateLimiter& limiter,
    Authenticate authenticate, Read read, std::optional<MutationContext> mutation)
    : m_fallback(&fallback), m_limiter(&limiter),
      m_authenticate(std::move(authenticate)), m_read(std::move(read)),
      m_mutation(std::move(mutation)) {}

bool CoroutineAdministrationReadAdapter::nativeEnabledFor(
    const gateway::HttpRequest& request) const noexcept {
    if (memberPath(request.path())) {
        if (!m_authenticate) return false;
        if (isList(request)) return static_cast<bool>(m_read);
        return isMutation(request) && m_mutation && m_mutation->clock && m_mutation->mutate;
    }
    return m_fallback->nativeEnabledFor(request);
}

gateway::HttpResponse CoroutineAdministrationReadAdapter::fail(
    const foundation::Error& failure, const gateway::HttpRequest& request) {
    gateway::HttpResponse response{foundation::errorHttpStatus(failure.code()),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(failure, request.correlation().value())};
    secureHeaders(response);
    if (failure.code() == foundation::ErrorCode::AuthenticationRequired)
        response.setHeader("www-authenticate", "Bearer");
    return response;
}

gateway::HttpResponse CoroutineAdministrationReadAdapter::handle(gateway::HttpRequest request) {
    Scrub wipe{request};
    return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
}

asio::awaitable<gateway::HttpResponse>
CoroutineAdministrationReadAdapter::handleAsync(gateway::HttpRequest request) {
    Scrub wipe{request};
    if (!nativeEnabledFor(request))
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    if (isList(request) || isMutation(request)) co_return co_await list(std::move(request));
    if (!m_fallback->nativeEnabledFor(request))
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    co_return co_await m_fallback->handleAsync(std::move(request));
}

asio::awaitable<gateway::HttpResponse>
CoroutineAdministrationReadAdapter::list(gateway::HttpRequest request) {
    Scrub wipe{request};
    if (!m_limiter->allow("admin-ip:" + std::string{request.remoteAddress()}))
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    if (request.header("authorization").value_or("").starts_with("DPoP "))
        co_return fail(foundation::Error{foundation::ErrorCode::AuthenticationFailed},request);
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) co_return fail(credential.error(), request);
    if (!credential->has_value())
        co_return fail(foundation::Error{foundation::ErrorCode::AuthenticationRequired}, request);
    auto session = co_await m_authenticate(std::move(credential->value()));
    if (!session) co_return fail(session.error(), request);
    if (!idp::meetsAssurance(session->assurance(), idp::AssuranceLevel::Ial2))
        co_return fail(foundation::Error{foundation::ErrorCode::AssuranceInsufficient}, request);
    const auto actor = session->identity();
    if (!m_limiter->allow("admin-identity:" + std::string{actor.value()}))
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    if (!isList(request)) co_return co_await mutate(std::move(request), actor);
    auto listing = co_await m_read(actor);
    if (!listing) co_return fail(listing.error(), request);
    // Independent checks before serialization. The actor must match the
    // authenticated session and be present with an effective owner role.
    if (listing->actor != actor || listing->members.empty() || listing->members.size() > 256U)
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    const auto owner = std::find_if(listing->members.begin(), listing->members.end(),
        [&actor](const auto& member) {
            return member.identity == actor
                && member.identityStatus == identity::core::IdentityStatus::Active
                && member.membershipState == organization::MembershipState::Active
                && std::any_of(member.roles.begin(), member.roles.end(),
                    [](const auto& role) { return role.value() == "owner"; });
        });
    if (owner == listing->members.end())
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    json::array members;
    for (const auto& member : listing->members) {
        if (member.identity.empty() || member.roles.size() > 16U
            || (member.membershipState == organization::MembershipState::Removed && !member.roles.empty()))
            co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
        json::array roles;
        for (const auto& role : member.roles) roles.emplace_back(std::string{role.value()});
        members.emplace_back(json::object{
            {"identity_id", std::string{member.identity.value()}},
            {"identity_status", std::string{identity::core::identityStatusName(member.identityStatus)}},
            {"membership_state", std::string{organization::membershipStateName(member.membershipState)}},
            {"roles", std::move(roles)}});
    }
    gateway::HttpResponse response{200, gateway::Headers{{"content-type", "application/json"}},
        json::serialize(json::object{{"members", std::move(members)}})};
    secureHeaders(response);
    co_return response;
}

asio::awaitable<gateway::HttpResponse>
CoroutineAdministrationReadAdapter::mutate(gateway::HttpRequest request,identity::core::IdentityId actor)
{
    Scrub wipe{request};
    const auto mime=request.header("content-type");
    if (!m_mutation || !m_mutation->mutate || !m_mutation->clock || !isMutation(request)
        || request.body().empty() || request.body().size()>16U*1024U || !mime
        || (*mime!="application/json" && !mime->starts_with("application/json;")))
        co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
    boost::system::error_code parseError;
    auto parsed=json::parse(request.body(),parseError);
    request.wipeBody();
    if (parseError || !parsed.is_object())
        co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
    const auto& body=parsed.as_object();
    auto target=requiredString(body,"identity_id",200U);
    if (!target) co_return fail(target.error(),request);
    auto targetId=identity::core::IdentityId{std::move(target).value()};
    const auto now=m_mutation->clock->now();
    const auto path=request.path();
    std::optional<Command> command;
    if (path=="/admin/local-members/roles") {
        auto roles=rolesFrom(body);
        if (!roles || !onlyFields(body,{"identity_id","roles"}))
            co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        auto replacement=MemberRoleReplacement::create(m_mutation->organization,
            std::move(targetId),std::move(roles).value(),now);
        if (!replacement) co_return fail(replacement.error(),request);
        command.emplace(std::in_place_type<MemberRoleReplacement>,std::move(replacement).value());
    } else if (path=="/admin/local-members") {
        auto roles=rolesFrom(body);
        auto subject=requiredString(body,"subject",320U);
        if (!roles || !subject || !onlyFields(body,{"identity_id","subject","roles"}))
            co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        auto generated=security::randomTokenBase64Url(32U);
        if (!generated)
            co_return fail(foundation::Error{foundation::ErrorCode::Internal},request);
        // Take wiping ownership before another operation can fail or throw.
        foundation::SecretString password{std::move(generated).value()};
        auto totp=credentials::TotpSecret::generate();
        if (!totp)
            co_return fail(foundation::Error{foundation::ErrorCode::Internal},request);
        auto enrollment=LocalMemberEnrollment::create(m_mutation->organization,std::move(targetId),
            m_mutation->provider,idp::ExternalSubject{std::move(subject).value()},
            std::move(roles).value(),std::move(password),
            std::move(totp).value(),now);
        if (!enrollment) co_return fail(enrollment.error(),request);
        command.emplace(std::in_place_type<LocalMemberEnrollment>,std::move(enrollment).value());
    } else if (path=="/admin/local-members/credentials/reset") {
        if (!onlyFields(body,{"identity_id"}))
            co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        auto generated=security::randomTokenBase64Url(32U);
        if (!generated)
            co_return fail(foundation::Error{foundation::ErrorCode::Internal},request);
        // Take wiping ownership before another operation can fail or throw.
        foundation::SecretString password{std::move(generated).value()};
        auto totp=credentials::TotpSecret::generate();
        if (!totp)
            co_return fail(foundation::Error{foundation::ErrorCode::Internal},request);
        auto reset=LocalCredentialReset::create(m_mutation->organization,std::move(targetId),
            std::move(password),std::move(totp).value(),now);
        if (!reset) co_return fail(reset.error(),request);
        command.emplace(std::in_place_type<LocalCredentialReset>,std::move(reset).value());
    } else {
        if (!onlyFields(body,{"identity_id"}))
            co_return fail(foundation::Error{foundation::ErrorCode::InvalidArgument},request);
        const auto action=path=="/admin/local-members/suspend" ? MemberLifecycleAction::Suspend
            : path=="/admin/local-members/reinstate" ? MemberLifecycleAction::Reinstate
            : MemberLifecycleAction::Remove;
        auto change=MemberLifecycleChange::create(m_mutation->organization,std::move(targetId),action,now);
        if (!change) co_return fail(change.error(),request);
        command.emplace(std::in_place_type<MemberLifecycleChange>,std::move(change).value());
    }
    // Do not release a generated credential before the owner-authorized
    // transaction, audit chain and outbox have all committed successfully.
    auto result=co_await m_mutation->mutate(std::move(actor),*command);
    if (!result) co_return fail(result.error(),request);
    if (const auto* enrollment=std::get_if<LocalMemberEnrollment>(&*command))
        co_return credentialResponse(201,enrollment->identity().id().value(),
            enrollment->generatedPassword(),enrollment->generatedTotp());
    if (const auto* reset=std::get_if<LocalCredentialReset>(&*command))
        co_return credentialResponse(200,reset->identityId().value(),
            reset->generatedPassword(),reset->generatedTotp());
    gateway::HttpResponse response{204,{},{}};
    secureHeaders(response);
    co_return response;
}

} // namespace openproof::administration::http

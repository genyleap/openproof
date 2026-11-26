#include <boost/asio/awaitable.hpp>
#include <boost/json.hpp>

#include <algorithm>
#include <string>
#include <utility>

#include "coroutine_admin_read_http.hpp"

import openproof.identity.provider;
import openproof.organization;

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
}

CoroutineAdministrationReadAdapter::CoroutineAdministrationReadAdapter(
    gateway::http::CoroutineHttpHandler& fallback, gateway::TokenBucketRateLimiter& limiter,
    Authenticate authenticate, Read read)
    : m_fallback(&fallback), m_limiter(&limiter),
      m_authenticate(std::move(authenticate)), m_read(std::move(read)) {}

bool CoroutineAdministrationReadAdapter::nativeEnabledFor(
    const gateway::HttpRequest& request) const noexcept {
    if (request.path() == "/admin/local-members")
        return isList(request) && static_cast<bool>(m_authenticate) && static_cast<bool>(m_read);
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
    if (isList(request)) co_return co_await list(std::move(request));
    if (!m_fallback->nativeEnabledFor(request))
        co_return fail(foundation::Error{foundation::ErrorCode::Unavailable}, request);
    co_return co_await m_fallback->handleAsync(std::move(request));
}

asio::awaitable<gateway::HttpResponse>
CoroutineAdministrationReadAdapter::list(gateway::HttpRequest request) {
    Scrub wipe{request};
    if (!m_limiter->allow("admin-ip:" + std::string{request.remoteAddress()}))
        co_return fail(foundation::Error{foundation::ErrorCode::RateLimited}, request);
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

} // namespace openproof::administration::http

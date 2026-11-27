module;
#include <string>
#include <utility>

module openproof.administration.http;

namespace openproof::administration::http {
// Legacy constructor retained as a fail-closed ABI; no synchronous
// administrator, session service or membership repository is retained.
AdministrationHttpApi::AdministrationHttpApi(
    session::SessionService&, LocalMemberAdministrator&,
    identity::core::IdentityRepository&, organization::MembershipRepository&,
    gateway::TokenBucketRateLimiter& rateLimiter, identity::core::OrganizationId,
    identity::provider::ProviderId, const foundation::ClockSource&,
    gateway::HttpHandler& fallback)
    : m_rateLimiter(&rateLimiter), m_fallback(&fallback) {}

gateway::HttpResponse AdministrationHttpApi::handle(gateway::HttpRequest request)
{
    if (request.path()!="/admin" && !request.path().starts_with("/admin/"))
        return m_fallback->handle(std::move(request));
    request.wipeBody();
    request.wipeAuthorizationHeader();
    request.wipeCookieHeader();
    request.wipeTargetQuery();
    const auto error=m_rateLimiter->allow("admin-ip:"+std::string{request.remoteAddress()})
        ? foundation::ErrorCode::Unavailable : foundation::ErrorCode::RateLimited;
    return gateway::HttpResponse{foundation::errorHttpStatus(error),
        gateway::Headers{{"content-type","application/json"},{"cache-control","no-store"},
            {"pragma","no-cache"},{"x-content-type-options","nosniff"},{"referrer-policy","no-referrer"}},
        foundation::toClientJson(foundation::Error{error},request.correlation().value())};
}
}

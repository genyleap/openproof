module;
#include <string>
#include <string_view>
#include <utility>

module openproof.account.http;

namespace openproof::account::http {
AccountHttpApi::AccountHttpApi(gateway::TokenBucketRateLimiter& limiter,gateway::HttpHandler& fallback)
    : m_limiter(&limiter),m_fallback(&fallback) {}
AccountHttpApi::AccountHttpApi(AccountService&,authentication::AuthenticationService&,
    session::SessionService&,gateway::TokenBucketRateLimiter& limiter,
    gateway::HttpHandler& fallback,session::DelegatedAccessAuthenticator*)
    : AccountHttpApi(limiter,fallback) {}

gateway::HttpResponse AccountHttpApi::handle(gateway::HttpRequest request)
{
    if (request.path()!="/account" && !request.path().starts_with("/account/"))
        return m_fallback->handle(std::move(request));
    // Never perform or forward an account operation from the legacy ABI.
    // Exact native overlays own all registered account routes.
    const bool allowed=m_limiter->allow("account:"+std::string{request.remoteAddress()}+
        ":"+std::string{request.path()});
    request.wipeBody();
    request.wipeAuthorizationHeader();
    request.wipeCookieHeader();
    request.wipeTargetQuery();
    using E=foundation::ErrorCode;
    const auto error=allowed ? E::Unavailable : E::RateLimited;
    gateway::HttpResponse response{foundation::errorHttpStatus(error),
        gateway::Headers{{"content-type","application/json"},{"cache-control","no-store"},
            {"pragma","no-cache"},{"x-content-type-options","nosniff"},{"referrer-policy","no-referrer"}},
        foundation::toClientJson(foundation::Error{error},request.correlation().value())};
    return response;
}
}

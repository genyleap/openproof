module;

export module openproof.account.http;

import openproof.account;
import openproof.authentication;
import openproof.foundation;
import openproof.gateway;
import openproof.session;

export namespace openproof::account::http {

/** Retired synchronous account HTTP ABI. Only namespace ownership remains.
 * All account operations must enter through the native coroutine dispatcher.
 */
class AccountHttpApi final : public gateway::HttpHandler {
public:
    AccountHttpApi(gateway::TokenBucketRateLimiter& limiter,gateway::HttpHandler& fallback);
    AccountHttpApi(AccountService&,authentication::AuthenticationService&,
                   session::SessionService&,gateway::TokenBucketRateLimiter& limiter,
                   gateway::HttpHandler& fallback,
                   session::DelegatedAccessAuthenticator* = nullptr);
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;
private:
    gateway::TokenBucketRateLimiter* m_limiter;
    gateway::HttpHandler* m_fallback;
};

}

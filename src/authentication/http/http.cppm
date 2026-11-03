module;

#include <string>
#include <boost/asio/detail/call_stack.hpp>
#include "../../gateway/asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>

export module openproof.authentication.http;

import openproof.authentication;
import openproof.credentials;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.provider;
import openproof.provider.local;
import openproof.session;

export namespace openproof::authentication::http {

/** HTTP auth plane mounted under /auth with a gateway fallback. */
class AuthenticationHttpApi final : public gateway::http::CoroutineHttpHandler {
public:
    AuthenticationHttpApi(AuthenticationService& authentication,
                          session::SessionService& sessions,
                          credentials::RecoveryCodeService& recoveryCodes,
                          ::openproof::provider::local::LocalAccountDirectory& localAccounts,
                          gateway::TokenBucketRateLimiter& rateLimiter,
                          identity::provider::ProviderId provider,
                          gateway::HttpHandler& fallback,
                          session::CoroutineReplacingSessionIssuer* asyncSessions = nullptr);

    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;
    [[nodiscard]] bool nativeEnabled() const noexcept override {
        // Native capability is per handler, not per endpoint. Until rotation,
        // logout and recovery-code APIs also have async persistence, enabling
        // only login/verify would break existing production routes.
        return kAllAuthRoutesNative && m_asyncSessions != nullptr
            && m_authentication->nativeProviderAuthenticationEnabled(m_provider);
    }
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request) override;

private:
    // Must remain false until every exposed /auth endpoint can run natively.
    // The opt-in flag is intentionally not runtime-configurable.
    static constexpr bool kAllAuthRoutesNative = false;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    loginAsync(gateway::HttpRequest request);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    verifyAsync(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse login(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse verify(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse rotate(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse logout(gateway::HttpRequest request, bool all);
    [[nodiscard]] gateway::HttpResponse issueRecoveryCodes(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse error(const foundation::Error& failure,
                                              const gateway::HttpRequest& request,
                                              bool clearPreauth = false) const;

    AuthenticationService* m_authentication;
    session::SessionService* m_sessions;
    session::CoroutineReplacingSessionIssuer* m_asyncSessions;
    credentials::RecoveryCodeService* m_recoveryCodes;
    ::openproof::provider::local::LocalAccountDirectory* m_localAccounts;
    gateway::TokenBucketRateLimiter* m_rateLimiter;
    identity::provider::ProviderId m_provider;
    gateway::HttpHandler* m_fallback;
};

}


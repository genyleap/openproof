#pragma once
#include <functional>
#include <optional>
#include <string>
#include <boost/asio/awaitable.hpp>

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.profile;
import openproof.session;

namespace openproof::oauth::http {
// Native OAuth token reads and revocation. All persistence callbacks must use
// native I/O. Client and token secrets are converted to keyed fingerprints.
class CoroutineTokenReadAdapter final : public gateway::http::CoroutineHttpHandler {
public:
    using ReadAccess=std::function<boost::asio::awaitable<foundation::Result<session::DelegatedAccess>>(
        std::string,foundation::Instant*)>;
    using AuthenticateClient=std::function<boost::asio::awaitable<foundation::Status>(std::string,std::string)>;
    using ReadProfile=std::function<boost::asio::awaitable<foundation::Result<identity::profile::IdentityProfile>>(
        identity::core::IdentityId)>;
    using VerifySender=std::function<boost::asio::awaitable<foundation::Status>(
        gateway::HttpRequest&,session::DelegatedSenderConstraint,foundation::SecretString,bool)>;

    using Revoke=std::function<boost::asio::awaitable<foundation::Status>(
        std::string,std::optional<std::string>,std::string)>;
    CoroutineTokenReadAdapter(gateway::http::CoroutineHttpHandler& fallback,
        gateway::TokenBucketRateLimiter& limiter,foundation::SecretString tokenKey,
        foundation::SecretString clientKey,ReadAccess access,AuthenticateClient client,
        ReadProfile profile,VerifySender sender,Revoke revoke={});
    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }
    [[nodiscard]] bool nativeEnabledFor(const gateway::HttpRequest&) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> handleAsync(gateway::HttpRequest) override;
private:
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> userInfo(gateway::HttpRequest);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> introspect(gateway::HttpRequest);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> revoke(gateway::HttpRequest);
    gateway::http::CoroutineHttpHandler* m_fallback;
    gateway::TokenBucketRateLimiter* m_limiter;
    foundation::SecretString m_tokenKey,m_clientKey;
    ReadAccess m_access;
    AuthenticateClient m_client;
    ReadProfile m_profile;
    VerifySender m_sender;
    Revoke m_revoke;
};
}

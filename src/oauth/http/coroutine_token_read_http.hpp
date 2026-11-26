#pragma once
#include <functional>
#include <optional>
#include <string>
#include <vector>
#include <boost/asio/awaitable.hpp>

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.profile;
import openproof.identity.provider;
import openproof.session;
import openproof.token;
import openproof.oauth;

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
    using Rotate=std::function<boost::asio::awaitable<foundation::Result<std::vector<std::string>>>(
        std::string,std::optional<std::string>,std::string,std::string,std::string,
        std::optional<session::DelegatedSenderConstraint>)>;
    using PrepareSender=std::function<boost::asio::awaitable<foundation::Result<
        std::optional<token::SenderConstraint>>>(gateway::HttpRequest&)>;
    using ExchangeCode=std::function<boost::asio::awaitable<foundation::Result<NativeCodeExchangeResult>>(
        std::string,std::optional<std::string>,std::string,std::string,std::string,
        std::string,std::string,std::string,std::optional<session::DelegatedSenderConstraint>)>;
    using IssueMachine=std::function<boost::asio::awaitable<foundation::Result<NativeMachineGrantResult>>(
        std::string,std::optional<std::string>,std::optional<std::string>,std::string,
        std::vector<std::string>,std::string,std::string,std::optional<session::DelegatedSenderConstraint>)>;
    using PollDevice=std::function<boost::asio::awaitable<foundation::Result<NativeDevicePollResult>>(
        std::string,std::optional<std::string>,std::string,std::string,std::string,std::string,
        std::optional<session::DelegatedSenderConstraint>)>;
    using BeginDevice=std::function<boost::asio::awaitable<foundation::Status>(
        std::string,std::optional<std::string>,std::string,std::string,
        std::vector<std::string>,std::optional<std::string>)>;
    using AuthenticateBrowser=std::function<boost::asio::awaitable<foundation::Result<session::Session>>(foundation::SecretString)>;
    using ReadDeviceApproval=std::function<boost::asio::awaitable<foundation::Result<NativeDeviceApproval>>(
        std::string,identity::core::IdentityId)>;
    using DecideDevice=std::function<boost::asio::awaitable<foundation::Status>(
        std::string,identity::core::IdentityId,session::SessionId,bool,std::string)>;
    struct DevicePollContext final {
        foundation::SecretString deviceKey;
        PollDevice poll;
        BeginDevice begin{};
        std::string verificationUri{};
        AuthenticateBrowser authenticate{};
        ReadDeviceApproval readApproval{};
        DecideDevice decide{};
    };
    using VerifyJar=std::function<foundation::Result<NativeJarAuthorization>(
        std::string_view,std::string_view,foundation::Instant)>;
    using PushAuthorization=std::function<boost::asio::awaitable<foundation::Status>(
        std::string,std::optional<std::string>,std::string,std::optional<AuthorizationRequest>,VerifyJar,bool)>;
    using SignResponse=std::function<foundation::Result<std::string>(const AuthorizationRequest&,bool,std::string_view)>;
    using CompleteAuthorization=std::function<boost::asio::awaitable<foundation::Result<NativeAuthorizationResult>>(
        std::string,std::optional<std::string>,std::optional<AuthorizationRequest>,identity::core::IdentityId,
        session::SessionId,NativeAuthorizationDecision,std::string,std::string,
        std::function<foundation::Result<std::string>(const AuthorizationRequest&,bool)>)>;
    struct ParContext final {
        std::string issuer;
        PushAuthorization push;
        CompleteAuthorization complete{};
        SignResponse sign{};
    };
    using Login=std::function<boost::asio::awaitable<foundation::Result<session::CoroutineIssuedSession>>(
        std::string,foundation::SecretString,std::optional<foundation::SecretString>,
        std::optional<foundation::SecretString>,identity::provider::ClientContext,foundation::CorrelationId)>;
    struct CodeExchangeContext final {
        foundation::SecretString codeKey;
        ExchangeCode exchange;
    };
    CoroutineTokenReadAdapter(gateway::http::CoroutineHttpHandler& fallback,
        gateway::TokenBucketRateLimiter& limiter,foundation::SecretString tokenKey,
        foundation::SecretString clientKey,ReadAccess access,AuthenticateClient client,
        ReadProfile profile,VerifySender sender,Revoke revoke={},
        Rotate rotate={},PrepareSender prepareSender={},
        foundation::Duration accessLifetime=foundation::Duration{900000},
        std::optional<CodeExchangeContext> codeExchange=std::nullopt,IssueMachine issueMachine={},
        std::optional<DevicePollContext> devicePoll=std::nullopt,
        std::optional<ParContext> par=std::nullopt,Login login={});
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
    Rotate m_rotate;
    PrepareSender m_prepareSender;
    foundation::Duration m_accessLifetime;
    std::optional<CodeExchangeContext> m_codeExchange;
    IssueMachine m_issueMachine;
    std::optional<DevicePollContext> m_devicePoll;
    std::optional<ParContext> m_par;
    Login m_login;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> loginBrowser(gateway::HttpRequest);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> authorizeBrowser(gateway::HttpRequest);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> pushAuthorization(gateway::HttpRequest);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> deviceBrowser(gateway::HttpRequest);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> beginDevice(gateway::HttpRequest);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> pollDevice(gateway::HttpRequest);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> issueMachine(gateway::HttpRequest);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> exchangeCode(gateway::HttpRequest);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> refresh(gateway::HttpRequest);
};
}

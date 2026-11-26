#pragma once
#include <functional>
#include <optional>
#include <vector>
#include <boost/asio/detail/call_stack.hpp>
#include "../../gateway/asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.provider.passkey;
import openproof.session;
import openproof.authentication;

namespace openproof::authentication::http {
class CoroutinePasskeyProvider final : public identity::provider::AuthenticationProvider,
    public identity::provider::CoroutineAuthenticationProvider {
public:
    using Verify=std::function<boost::asio::awaitable<foundation::Result<identity::core::IdentityId>>(
        identity::provider::ChallengeId,::openproof::provider::passkey::AssertionResponse,foundation::Instant)>;
    CoroutinePasskeyProvider(const ::openproof::provider::passkey::PasskeyConfig& config,const foundation::ClockSource& clock,Verify verify);
    [[nodiscard]] identity::provider::ProviderId id() const override;
    [[nodiscard]] identity::provider::InteractionModel interactionModel() const noexcept override;
    [[nodiscard]] identity::provider::AssuranceLevel maximumClaimableAssurance() const noexcept override;
    [[nodiscard]] foundation::Result<identity::provider::AuthenticationChallenge> beginAuthentication(const identity::provider::AuthenticationRequest&) override;
    [[nodiscard]] foundation::Result<identity::provider::AuthenticationOutcome> completeAuthentication(const identity::provider::AuthenticationResponse&) override;
    [[nodiscard]] boost::asio::awaitable<foundation::Result<identity::provider::AuthenticationChallenge>> beginAuthenticationAsync(identity::provider::AuthenticationRequest) override;
    [[nodiscard]] boost::asio::awaitable<foundation::Result<identity::provider::AuthenticationOutcome>> completeAuthenticationAsync(identity::provider::AuthenticationResponse) override;
private:
    const ::openproof::provider::passkey::PasskeyConfig* m_config;
    const foundation::ClockSource* m_clock;
    Verify m_verify;
};

class CoroutinePasskeyAccountAdapter final : public gateway::http::CoroutineHttpHandler {
public:
    using Authenticate=std::function<boost::asio::awaitable<foundation::Result<session::Session>>(foundation::SecretString)>;
    using Read=std::function<boost::asio::awaitable<foundation::Result<std::vector<::openproof::provider::passkey::CredentialSummary>>>(
        identity::core::IdentityId,session::SessionId,foundation::Instant,
        std::optional<::openproof::provider::passkey::RegistrationCeremony>)>;
    using Mutate=std::function<boost::asio::awaitable<foundation::Status>(
        identity::core::IdentityId,session::SessionId,foundation::Instant,std::string,
        std::optional<identity::provider::ChallengeId>,std::optional<::openproof::provider::passkey::PasskeyCredential>)>;
    CoroutinePasskeyAccountAdapter(gateway::http::CoroutineHttpHandler& fallback,
        gateway::TokenBucketRateLimiter& limiter,const foundation::ClockSource& clock,
        const ::openproof::provider::passkey::PasskeyConfig& config,Authenticate authenticate,Read read,Mutate mutate={},
        AuthenticationService* authentication=nullptr,session::CoroutineReplacingSessionIssuer* issuer=nullptr);
    [[nodiscard]] bool nativeEnabledFor(const gateway::HttpRequest&) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> handleAsync(gateway::HttpRequest) override;
private:
    gateway::http::CoroutineHttpHandler* m_fallback;
    gateway::TokenBucketRateLimiter* m_limiter;
    const foundation::ClockSource* m_clock;
    const ::openproof::provider::passkey::PasskeyConfig* m_config;
    Authenticate m_authenticate;
    Read m_read;
    Mutate m_mutate;
    AuthenticationService* m_authentication;
    session::CoroutineReplacingSessionIssuer* m_issuer;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> assertion(gateway::HttpRequest);
};
}

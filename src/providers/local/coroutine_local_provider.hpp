#pragma once
#include <boost/asio/awaitable.hpp>
#include <optional>
import openproof.foundation;
import openproof.identity.provider;
import openproof.provider.local;

namespace openproof::provider::local {

// Implementations must verify the full proof against a current credential
// generation. The trusted coordinator owns single-use challenge redemption.
class CoroutineLocalProofVerifier {
public:
    virtual ~CoroutineLocalProofVerifier() = default;
    [[nodiscard]] virtual boost::asio::awaitable<foundation::Result<LocalVerification>>
    verifyAsync(idp::ExternalSubject subject, foundation::SecretString password,
        std::optional<foundation::SecretString> totp,
        std::optional<foundation::SecretString> recovery, foundation::Instant now) = 0;
};

class CoroutineLocalAuthenticationProvider final : public idp::AuthenticationProvider,
    public idp::CoroutineAuthenticationProvider {
public:
    CoroutineLocalAuthenticationProvider(idp::ProviderId id, CoroutineLocalProofVerifier& verifier,
        const foundation::ClockSource& clock, foundation::Duration lifetime);
    [[nodiscard]] idp::ProviderId id() const override;
    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override;
    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override;
    [[nodiscard]] foundation::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest& request) override;
    [[nodiscard]] foundation::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse&) override;
    [[nodiscard]] boost::asio::awaitable<foundation::Result<idp::AuthenticationChallenge>>
    beginAuthenticationAsync(idp::AuthenticationRequest request) override;
    [[nodiscard]] boost::asio::awaitable<foundation::Result<idp::AuthenticationOutcome>>
    completeAuthenticationAsync(idp::AuthenticationResponse response) override;
private:
    idp::ProviderId m_id;
    CoroutineLocalProofVerifier& m_verifier;
    const foundation::ClockSource& m_clock;
    foundation::Duration m_lifetime;
};
}

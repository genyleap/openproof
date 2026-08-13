module;

#include <optional>
#include <string>

export module openproof.oauth.http.sender;

import openproof.foundation;
import openproof.gateway;
import openproof.oauth;
import openproof.session;
import openproof.token;

export namespace openproof::oauth::http {

/**
 * @brief Verifies RFC 9449 DPoP proofs and authenticated mTLS certificate forwarding.
 *
 * mTLS forwarding is accepted only when an ingress assertion is HMAC-authenticated,
 * request-bound, time-bounded, and replay-protected. A raw client-certificate header
 * is never trusted.
 */
class SenderProofVerifier final : public gateway::SenderConstraintVerifier {
public:
    SenderProofVerifier(DpopService& dpop, MtlsForwardingReplayStore& mtlsReplays,
                        const foundation::ClockSource& clock,
                        std::string publicOrigin,
                        std::optional<foundation::SecretString> mtlsForwardingKey);

    /** @brief Returns a sender binding presented at an OAuth token endpoint, if any. */
    [[nodiscard]] foundation::Result<std::optional<token::SenderConstraint>>
    tokenEndpointConstraint(gateway::HttpRequest& request);

    /** @brief Verifies the sender binding carried by an OAuth token at a protocol endpoint. */
    [[nodiscard]] foundation::Status verifyTokenConstraint(
        gateway::HttpRequest& request,
        const token::SenderConstraint& constraint,
        const foundation::SecretString& accessToken,
        bool dpopAuthorizationScheme);

    [[nodiscard]] foundation::Status verify(
        gateway::HttpRequest& request,
        const session::DelegatedSenderConstraint& constraint,
        const foundation::SecretString& accessToken,
        bool dpopAuthorizationScheme) override;

private:
    [[nodiscard]] foundation::Result<token::SenderConstraint> verifyDpop(
        gateway::HttpRequest& request,
        const foundation::SecretString* accessToken = nullptr);
    [[nodiscard]] foundation::Result<token::SenderConstraint> verifyMtlsForwarding(
        gateway::HttpRequest& request);
    [[nodiscard]] std::string expectedHtu(const gateway::HttpRequest& request) const;

    DpopService* m_dpop;
    MtlsForwardingReplayStore* m_mtlsReplays;
    const foundation::ClockSource* m_clock;
    std::string m_publicOrigin;
    std::optional<foundation::SecretString> m_mtlsForwardingKey;
};

}

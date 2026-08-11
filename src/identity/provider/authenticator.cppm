module;

#include <optional>
#include <memory>
#include <string>
#include <string_view>

export module openproof.identity.provider:authenticator;

import openproof.foundation;

import :assurance;
import :outcome;

export namespace openproof::identity::provider {

/**
 * @brief How a provider interacts with the subject, independent of protocol.
 *
 * This enumeration deliberately names *interaction shapes*, not protocols. An
 * earlier revision enumerated `Oidc`, `Wallet`, `Farcaster`, `Ens`, `Telecom`
 * and so on, which meant adding a provider required editing this file -- the
 * exact coupling the SPI exists to prevent. Protocol identity belongs to
 * @ref ProviderId, which is an opaque string and needs no change here.
 *
 * The set is closed because it describes the orchestration the caller must
 * perform, and a caller can only implement the shapes it knows about. Each
 * value tells the caller what to do next and nothing about which protocol is
 * behind it:
 *
 *  - @c Redirect          send the subject elsewhere and await a callback
 *                         (OIDC, OAuth 2.0, enterprise SAML)
 *  - @c ChallengeResponse issue a challenge, receive a signed or computed answer
 *                         (WebAuthn, wallet signatures, TOTP)
 *  - @c OutOfBand         deliver over a separate channel and await confirmation
 *                         (email link, SMS code, USSD session, push approval)
 *  - @c Assertion         accept and verify an assertion minted elsewhere
 *                         (service tokens, mTLS, pre-issued proofs)
 *  - @c Delegated         an operator or external authority vouches after an
 *                         offline process (in-person verification, KYC)
 */
enum class InteractionModel {
    Redirect,
    ChallengeResponse,
    OutOfBand,
    Assertion,
    Delegated,
};

/** @brief Returns the stable wire name of @p model, for example "redirect". */
[[nodiscard]] std::string_view interactionModelName(InteractionModel model) noexcept;

/** @brief Tag for the identifier of an in-flight authentication challenge. */
struct ChallengeIdTag {};

/** @brief Identifies one in-flight challenge. Single-use and server-issued. */
using ChallengeId = foundation::StrongId<ChallengeIdTag>;

/**
 * @brief Context describing the caller, used for risk evaluation and audit.
 *
 * Every field is attacker-controlled and must be treated as untrusted input. It
 * informs risk scoring; it never authenticates anyone.
 */
class ClientContext final {
public:
    ClientContext() = default;

    void setRemoteAddress(std::string value);
    void setUserAgent(std::string value);

    [[nodiscard]] std::string_view remoteAddress() const noexcept;
    [[nodiscard]] std::string_view userAgent() const noexcept;

private:
    std::string m_remoteAddress;
    std::string m_userAgent;
};

/**
 * @brief A request to begin authentication with a provider.
 */
class AuthenticationRequest final {
public:
    AuthenticationRequest(ProviderId provider, ClientContext client);

    [[nodiscard]] const ProviderId& provider() const noexcept;
    [[nodiscard]] const ClientContext& client() const noexcept;

    /** @brief The minimum assurance the caller needs, when it has a requirement. */
    [[nodiscard]] const std::optional<AssuranceLevel>& requestedAssurance() const noexcept;
    void setRequestedAssurance(AssuranceLevel level);

    /**
     * @brief Provider-specific inputs, such as a redirect URI or a wallet address.
     *
     * Untrusted. A provider must validate every parameter it consumes; in
     * particular a redirect target must be checked against a registered
     * allow-list, never merely reflected.
     */
    [[nodiscard]] const AttributeMap& parameters() const noexcept;
    void setParameter(std::string key, std::string value);

private:
    ProviderId m_provider;
    ClientContext m_client;
    std::optional<AssuranceLevel> m_requestedAssurance;
    AttributeMap m_parameters;
};

/**
 * @brief A challenge issued to the client, to be answered to complete authentication.
 *
 * One shape covers every protocol the platform must support: an OIDC
 * authorization URL with state and nonce, a WebAuthn challenge, a wallet nonce
 * bound to a domain and chain, a magic-link token, a USSD session reference.
 *
 * Two properties are mandatory for every provider and are represented here
 * rather than left to each implementation: a challenge expires, and it is
 * identified by a server-issued single-use identifier. Together they close the
 * replay and stale-challenge paths that this class of protocol is prone to.
 */
class AuthenticationChallenge final {
public:
    AuthenticationChallenge(ChallengeId id, foundation::Instant expiresAt);

    [[nodiscard]] const ChallengeId& id() const noexcept;
    [[nodiscard]] foundation::Instant expiresAt() const noexcept;

    /** @brief Returns whether the challenge is expired at @p now. */
    [[nodiscard]] bool isExpiredAt(foundation::Instant now) const noexcept;

    /** @brief Provider-specific data the client needs, such as a URL or a nonce. */
    [[nodiscard]] const AttributeMap& parameters() const noexcept;
    void setParameter(std::string key, std::string value);

private:
    ChallengeId m_id;
    foundation::Instant m_expiresAt;
    AttributeMap m_parameters;
};

/**
 * @brief The client's answer to a challenge.
 */
class AuthenticationResponse final {
public:
    AuthenticationResponse(ChallengeId challengeId, ClientContext client);

    AuthenticationResponse(const AuthenticationResponse&) = delete;
    AuthenticationResponse& operator=(const AuthenticationResponse&) = delete;
    AuthenticationResponse(AuthenticationResponse&&) noexcept;
    AuthenticationResponse& operator=(AuthenticationResponse&&) noexcept;
    ~AuthenticationResponse();

    [[nodiscard]] const ChallengeId& challengeId() const noexcept;
    [[nodiscard]] const ClientContext& client() const noexcept;

    /**
     * @brief Provider-specific response data: an authorization code, a signature,
     *        an assertion, a one-time code.
     *
     * Entirely untrusted until the provider has verified it.
     */
    [[nodiscard]] const SecretAttributeMap& parameters() const noexcept;
    void setParameter(std::string key, CredentialValue value);

private:
    class Storage;

    ChallengeId m_challengeId;
    ClientContext m_client;
    std::unique_ptr<Storage> m_storage;
};

/**
 * @brief The extension point every authentication method implements.
 *
 * This is the architectural boundary of the platform. The identity core depends
 * on this interface and on nothing below it, so Google, Apple, GitHub, a
 * passkey, an Ethereum wallet, ENS, Farcaster, LDAP, SAML, a telecom operator,
 * a smart card, an in-person verification desk and a protocol invented after
 * this code was written are all additions rather than modifications.
 *
 * Implementations must uphold these obligations, none of which the core can
 * check on their behalf:
 *
 *  - Prove, do not assume. A client-supplied identifier -- a wallet address, an
 *    email, a username -- is an assertion until cryptographically or
 *    protocol-verified.
 *  - Bind every challenge to a single-use, server-issued nonce, and reject a
 *    reused or expired one.
 *  - Validate issuer, audience, signature and expiry where the protocol has
 *    them, and bind to the origin or domain where the protocol allows it.
 *  - Populate VerifiedClaims only with claims actually verified.
 *  - Record audit-grade, credential-free evidence.
 *  - Never accept, store, log or transmit a private key.
 *
 * @note Implementations must be safe to call concurrently: the registry hands
 *       the same instance to every request thread.
 */
class AuthenticationProvider {
public:
    AuthenticationProvider(const AuthenticationProvider&) = delete;
    AuthenticationProvider& operator=(const AuthenticationProvider&) = delete;
    AuthenticationProvider(AuthenticationProvider&&) = delete;
    AuthenticationProvider& operator=(AuthenticationProvider&&) = delete;

    virtual ~AuthenticationProvider() = default;

    /** @brief The provider's stable identifier, unique within the registry. */
    [[nodiscard]] virtual ProviderId id() const = 0;

    /**
     * @brief How this provider interacts with the subject.
     *
     * Tells the caller what orchestration to perform. It deliberately does not
     * identify the protocol; @ref id() does that, and the identity core never
     * branches on either.
     */
    [[nodiscard]] virtual InteractionModel interactionModel() const noexcept = 0;

    /**
     * @brief The highest assurance this provider may ever claim.
     *
     * Declared by the provider and constrained by policy. It exists so that a
     * misconfigured or compromised provider cannot assert an arbitrarily high
     * level for an exchange that did not justify it.
     */
    [[nodiscard]] virtual AssuranceLevel maximumClaimableAssurance() const noexcept = 0;

    /** @brief Issues a challenge for @p request. */
    [[nodiscard]] virtual foundation::Result<AuthenticationChallenge>
    beginAuthentication(const AuthenticationRequest& request) = 0;

    /**
     * @brief Verifies @p response and produces a normalized outcome.
     *
     * Must fail rather than return a partially verified outcome. A failure here
     * is a denied authentication, never a downgraded one.
     */
    [[nodiscard]] virtual foundation::Result<AuthenticationOutcome>
    completeAuthentication(const AuthenticationResponse& response) = 0;

protected:
    AuthenticationProvider() = default;
};

}

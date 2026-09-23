module;

#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.authentication:service;

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.profile;
import openproof.identity.provider;

export namespace openproof::authentication {

namespace provider = identity::provider;

/**
 * @brief Operator-owned upper bounds for provider assurance claims.
 *
 * A provider's own maximum is not a trust boundary: compromised provider code
 * can lie about both its outcome and its declared maximum. The effective cap is
 * therefore the lower of the provider declaration and this independently
 * supplied policy. An unlisted provider is not trusted to authenticate.
 */
class ProviderTrustPolicy final {
public:
    ProviderTrustPolicy() = default;

    /** @brief Adds a provider cap. Duplicate or empty identifiers are rejected. */
    [[nodiscard]] foundation::Status trust(provider::ProviderId providerId,
                                           provider::AssuranceLevel maximum,
                                           bool allowSelfProvisioning = false);

    /** @brief Returns the configured cap, or no value when the provider is untrusted. */
    [[nodiscard]] std::optional<provider::AssuranceLevel>
    maximumFor(const provider::ProviderId& providerId) const noexcept;

    /** @brief Whether a verified, previously unseen subject may create a new canonical identity. */
    [[nodiscard]] bool maySelfProvision(const provider::ProviderId& providerId) const noexcept;

private:
    std::map<provider::ProviderId, provider::AssuranceLevel> m_maximums;
    std::map<provider::ProviderId, bool> m_selfProvisioning;
};

/**
 * @brief The server-generated state returned when authentication starts.
 *
 * The continuation token is credential material. A transport should normally
 * place it in a Secure, HttpOnly, SameSite pre-authentication cookie and expose
 * only the transaction identifier through the callback state.
 */
class AuthenticationStart final {
public:
    AuthenticationStart(const AuthenticationStart&) = delete;
    AuthenticationStart& operator=(const AuthenticationStart&) = delete;
    AuthenticationStart(AuthenticationStart&&) noexcept = default;
    AuthenticationStart& operator=(AuthenticationStart&&) noexcept = default;
    ~AuthenticationStart() = default;

    [[nodiscard]] const provider::TransactionId& transactionId() const noexcept;
    [[nodiscard]] const provider::AuthenticationChallenge& challenge() const noexcept;
    [[nodiscard]] const foundation::SecretString& continuationToken() const noexcept;

private:
    friend class AuthenticationService;

    AuthenticationStart(provider::TransactionId transactionId,
                        provider::AuthenticationChallenge challenge,
                        foundation::SecretString continuationToken);

    provider::TransactionId m_transactionId;
    provider::AuthenticationChallenge m_challenge;
    foundation::SecretString m_continuationToken;
};

/**
 * @brief An authentication outcome accepted by the trusted coordinator.
 *
 * AuthenticationOutcome is intentionally constructible by provider code because
 * it is the SPI result. This wrapper is different: only AuthenticationService
 * can mint it, after transaction, binding, provider identity, time and assurance
 * checks have all succeeded and the external subject has been resolved through
 * an explicit canonical identity link. Authorization consumes this type rather
 * than a raw provider assertion.
 */
class VerifiedAuthentication final {
public:
    [[nodiscard]] const provider::AuthenticationOutcome& outcome() const noexcept;
    [[nodiscard]] const identity::core::IdentityId& identity() const noexcept;

private:
    friend class AuthenticationService;

    VerifiedAuthentication(provider::AuthenticationOutcome outcome,
                           identity::core::IdentityId identity);

    provider::AuthenticationOutcome m_outcome;
    identity::core::IdentityId m_identity;
};

/** @brief Short-lived, one-time bridge from an authenticated native client to a browser. */
class BrowserConnectionHandoff final {
public:
    BrowserConnectionHandoff(const BrowserConnectionHandoff&) = delete;
    BrowserConnectionHandoff& operator=(const BrowserConnectionHandoff&) = delete;
    BrowserConnectionHandoff(BrowserConnectionHandoff&&) noexcept = default;
    BrowserConnectionHandoff& operator=(BrowserConnectionHandoff&&) noexcept = default;

    [[nodiscard]] const foundation::SecretString& ticket() const noexcept;
    [[nodiscard]] foundation::Instant expiresAt() const noexcept;

private:
    friend class AuthenticationService;
    BrowserConnectionHandoff(foundation::SecretString ticket,
                             foundation::Instant expiresAt);
    foundation::SecretString m_ticket;
    foundation::Instant m_expiresAt{};
};

/** @brief Server-bound values recovered after a browser handoff is consumed. */
struct BrowserConnectionTarget final {
    identity::core::IdentityId identity;
    provider::ProviderId providerId;
    std::string returnTarget;
};

/**
 * @brief Two-secret bridge for wallet authentication across mobile browsers.
 *
 * The publisher ticket may be exposed to the wallet app. The redeem ticket stays
 * in the originating browser and is the only credential that can mint its session.
 */
class BrowserAuthenticationHandoff final {
public:
    BrowserAuthenticationHandoff(const BrowserAuthenticationHandoff&) = delete;
    BrowserAuthenticationHandoff& operator=(const BrowserAuthenticationHandoff&) = delete;
    BrowserAuthenticationHandoff(BrowserAuthenticationHandoff&&) noexcept = default;
    BrowserAuthenticationHandoff& operator=(BrowserAuthenticationHandoff&&) noexcept = default;

    [[nodiscard]] const foundation::SecretString& publisherTicket() const noexcept;
    [[nodiscard]] const foundation::SecretString& redeemTicket() const noexcept;
    [[nodiscard]] foundation::Instant expiresAt() const noexcept;

private:
    friend class AuthenticationService;
    BrowserAuthenticationHandoff(foundation::SecretString publisherTicket,
                                 foundation::SecretString redeemTicket,
                                 foundation::Instant expiresAt);

    foundation::SecretString m_publisherTicket;
    foundation::SecretString m_redeemTicket;
    foundation::Instant m_expiresAt{};
};

/**
 * @brief Trusted coordinator for every authentication exchange.
 *
 * The service enforces transaction redemption, cross-session binding, challenge
 * identity, provider identity, requested assurance, independently configured
 * assurance caps, and the external-to-canonical identity link. Transport code
 * must not call AuthenticationProvider directly. Provider failures are
 * normalized and provider exceptions are contained at this boundary.
 *
 * @note Thread-safe when the supplied registry, store, providers and clock honour
 *       their documented thread-safety contracts.
 */
class AuthenticationService final {
public:
    AuthenticationService(provider::ProviderRegistry& providers,
                          provider::AuthenticationTransactionStore& transactions,
                          identity::core::ExternalIdentityDirectory& identities,
                          const foundation::ClockSource& clock, ProviderTrustPolicy trustPolicy,
                          foundation::Duration maximumTransactionLifetime,
                          identity::core::IdentityRepository* lifecycleRepository = nullptr,
                          identity::core::OrganizationId organization = {},
                          identity::profile::IdentityProfileRepository* profileRepository = nullptr);

    AuthenticationService(const AuthenticationService&) = delete;
    AuthenticationService& operator=(const AuthenticationService&) = delete;
    AuthenticationService(AuthenticationService&&) = delete;
    AuthenticationService& operator=(AuthenticationService&&) = delete;
    ~AuthenticationService() = default;

    /** @brief Starts an exchange and atomically records its server-owned state. */
    [[nodiscard]] foundation::Result<AuthenticationStart>
    begin(const provider::AuthenticationRequest& request,
          const provider::BindingDigest& binding,
          foundation::CorrelationId correlation);

    /** @brief Starts a provider proof that may only attach to @p identity. */
    [[nodiscard]] foundation::Result<AuthenticationStart>
    beginConnection(const provider::AuthenticationRequest& request,
                    const provider::BindingDigest& binding,
                    foundation::CorrelationId correlation,
                    const identity::core::IdentityId& identity);

    /**
     * @brief Redeems an exchange exactly once and validates the provider outcome.
     *
     * The transaction is consumed before provider verification. A malformed or
     * forged callback therefore burns the exchange instead of leaving a reusable
     * oracle. Authentication check failures use a generic client message, with
     * the specific cause confined to operator detail. A requested-assurance
     * shortfall remains separately classifiable as AssuranceInsufficient.
     */
    [[nodiscard]] foundation::Result<VerifiedAuthentication>
    complete(const provider::TransactionId& transactionId,
             const foundation::SecretString& continuationToken,
             const provider::BindingDigest& binding,
             const provider::AuthenticationResponse& response);

    /**
     * @brief Converts a completed first-party email-verification ceremony into
     *        an IAL1 authentication after re-checking the canonical identity link.
     */
    [[nodiscard]] foundation::Result<VerifiedAuthentication>
    acceptVerifiedEmail(const identity::core::ExternalIdentityRef& external);

    /**
     * @brief Completes a server-bound connection ceremony without creating a session.
     *
     * The target identity is recovered exclusively from the consumed server-side
     * transaction created by @c beginConnection. A normal login transaction cannot
     * be upgraded into a connection, and a connection transaction cannot mint a
     * login session.
     */
    [[nodiscard]] foundation::Result<identity::core::ExternalIdentityRef>
    completeConnection(const provider::TransactionId& transactionId,
                       const foundation::SecretString& continuationToken,
                       const provider::BindingDigest& binding,
                       const provider::AuthenticationResponse& response);

    /**
     * @brief Refreshes display-only metadata for an already verified connection.
     *
     * These values never participate in authentication, identity ownership or
     * authorization decisions.
     */
    [[nodiscard]] foundation::Status updateConnectionPresentation(
        const identity::core::ExternalIdentityRef& external,
        std::optional<std::string> displayName,
        std::optional<std::string> preferredUsername,
        std::optional<std::string> pictureUrl);

    /** @brief Lists the authentication-capable external accounts attached to an identity. */
    [[nodiscard]] foundation::Result<std::vector<identity::core::ExternalIdentityRef>>
    connections(const identity::core::IdentityId& identity) const;

    /** @brief Disconnects one login method while refusing to remove the last one. */
    [[nodiscard]] foundation::Status disconnect(
        const identity::core::IdentityId& identity,
        const identity::core::ExternalIdentityRef& external);

    /**
     * @brief Issues a one-time native-to-browser connection ticket.
     *
     * The canonical identity, redirect provider and local return path are kept in
     * the atomic transaction store. The browser receives no session or bearer token.
     */
    [[nodiscard]] foundation::Result<BrowserConnectionHandoff>
    issueBrowserConnectionHandoff(
        const identity::core::IdentityId& identity,
        const provider::ProviderId& providerId,
        std::string returnTarget,
        foundation::CorrelationId correlation);

    /** @brief Atomically consumes a native-to-browser connection ticket. */
    [[nodiscard]] foundation::Result<BrowserConnectionTarget>
    consumeBrowserConnectionHandoff(const foundation::SecretString& ticket);

    /**
     * @brief Issues separated publisher/redeemer credentials for mobile wallet login.
     *
     * Only the publisher ticket is sent through a wallet deep link. The redeem
     * ticket remains in the original browser.
     */
    [[nodiscard]] foundation::Result<BrowserAuthenticationHandoff>
    issueBrowserAuthenticationHandoff(
        const provider::ProviderId& providerId,
        foundation::CorrelationId correlation);

    /** @brief Publishes a verified wallet result to the originating browser ticket. */
    [[nodiscard]] foundation::Status publishBrowserAuthenticationHandoff(
        const foundation::SecretString& publisherTicket,
        const VerifiedAuthentication& authentication);

    /** @brief Redeems a completed mobile-wallet authentication exactly once. */
    [[nodiscard]] foundation::Result<VerifiedAuthentication>
    redeemBrowserAuthenticationHandoff(
        const foundation::SecretString& redeemTicket);

private:
    struct CompletedExchange final {
        provider::AuthenticationOutcome outcome;
        std::optional<identity::core::IdentityId> connectionTarget;
        foundation::Instant completedAt{};
    };

    [[nodiscard]] foundation::Result<AuthenticationStart>
    beginInternal(const provider::AuthenticationRequest& request,
                  const provider::BindingDigest& binding,
                  foundation::CorrelationId correlation,
                  const identity::core::IdentityId* connectionTarget);

    [[nodiscard]] foundation::Result<CompletedExchange>
    completeExchange(const provider::TransactionId& transactionId,
                     const foundation::SecretString& continuationToken,
                     const provider::BindingDigest& binding,
                     const provider::AuthenticationResponse& response,
                     bool requireConnection);

    [[nodiscard]] foundation::Status requireActiveIdentity(
        const identity::core::IdentityId& identity) const;

    [[nodiscard]] foundation::Status attachVerified(
        const identity::core::IdentityId& identity,
        const identity::core::ExternalIdentityRef& external,
        foundation::Instant verifiedAt);

    [[nodiscard]] std::optional<provider::AssuranceLevel>
    effectiveMaximum(provider::AuthenticationProvider& implementation,
                     const provider::ProviderId& providerId) const noexcept;

    provider::ProviderRegistry& m_providers;
    provider::AuthenticationTransactionStore& m_transactions;
    identity::core::ExternalIdentityDirectory& m_identities;
    const foundation::ClockSource& m_clock;
    const ProviderTrustPolicy m_trustPolicy;
    foundation::Duration m_maximumTransactionLifetime;
    identity::core::IdentityRepository* m_lifecycleRepository{};
    identity::core::OrganizationId m_organization;
    identity::profile::IdentityProfileRepository* m_profileRepository{};
    mutable std::mutex m_connectionMutex;
};

}

module;

#include <map>
#include <optional>
#include <string_view>

export module openproof.authentication:service;

import openproof.foundation;
import openproof.identity.core;
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
                                           provider::AssuranceLevel maximum);

    /** @brief Returns the configured cap, or no value when the provider is untrusted. */
    [[nodiscard]] std::optional<provider::AssuranceLevel>
    maximumFor(const provider::ProviderId& providerId) const noexcept;

private:
    std::map<provider::ProviderId, provider::AssuranceLevel> m_maximums;
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
                          foundation::Duration maximumTransactionLifetime);

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

private:
    [[nodiscard]] std::optional<provider::AssuranceLevel>
    effectiveMaximum(provider::AuthenticationProvider& implementation,
                     const provider::ProviderId& providerId) const noexcept;

    provider::ProviderRegistry& m_providers;
    provider::AuthenticationTransactionStore& m_transactions;
    identity::core::ExternalIdentityDirectory& m_identities;
    const foundation::ClockSource& m_clock;
    const ProviderTrustPolicy m_trustPolicy;
    foundation::Duration m_maximumTransactionLifetime;
};

}

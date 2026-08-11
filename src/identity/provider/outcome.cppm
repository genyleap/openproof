module;

#include <cstddef>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>

export module openproof.identity.provider:outcome;

import openproof.foundation;

import :assurance;

export namespace openproof::identity::provider {

/** @brief Tag for the stable identifier of a registered provider. */
struct ProviderIdTag {};

/** @brief Identifies a registered authentication provider, for example "google". */
using ProviderId = foundation::StrongId<ProviderIdTag>;

/** @brief Tag for a subject identifier scoped to one provider. */
struct ExternalSubjectTag {};

/**
 * @brief A subject identifier as the provider knows it.
 *
 * Scoped to its issuing provider and never globally unique: a Google `sub`, a
 * wallet address and a Farcaster id may all be present for one person. This is
 * emphatically not a OpenProof identity key. External subjects are *linked* to a
 * canonical OpenProof Identity; they never become one, because a provider that is
 * compromised, retired, or that recycles identifiers would otherwise take the
 * account with it.
 */
using ExternalSubject = foundation::StrongId<ExternalSubjectTag>;

/** @brief Generic string attributes exchanged with a provider. */
using AttributeMap = std::map<std::string, std::string, std::less<>>;

/**
 * @brief One credential-bearing value received from an untrusted client.
 *
 * This purpose-specific wrapper is deliberately not convertible, formattable,
 * comparable or copyable. Its buffer is wiped on destruction. It mirrors the
 * platform Secret contract while keeping a concrete, non-template type at the
 * provider ABI boundary.
 */
class CredentialValue final {
public:
    explicit CredentialValue(std::string value);

    CredentialValue(const CredentialValue&) = delete;
    CredentialValue& operator=(const CredentialValue&) = delete;
    CredentialValue(CredentialValue&& other) noexcept;
    CredentialValue& operator=(CredentialValue&& other) noexcept;
    ~CredentialValue();

    [[nodiscard]] const std::string& expose() const noexcept;
    [[nodiscard]] bool empty() const noexcept;

private:
    void wipe() noexcept;

    std::string m_value;
};

/** @brief Move-only credential parameters keyed by protocol field name. */
using SecretAttributeMap = std::map<std::string, CredentialValue, std::less<>>;

/**
 * @brief Claims that mean the same thing regardless of which provider asserted them.
 *
 * The enumeration is intentionally small and cross-protocol: every entry means
 * the same thing no matter which provider asserted it. Anything specific to one
 * provider or one ecosystem goes in an extension entry instead.
 *
 * A wallet address and a chain id were briefly members of this list. They were
 * removed: they are Web3 vocabulary, meaningless to an OIDC or telecom provider,
 * and their presence here made the "provider-neutral" claim set a place where
 * one ecosystem's concepts accumulate. A wallet provider records them with
 * @ref VerifiedClaims::setExtension, which is exactly what extensions are for.
 */
enum class ClaimName {
    Email,
    EmailVerified,
    PhoneNumber,
    PhoneNumberVerified,
    DisplayName,
    PreferredUsername,
    Locale,
    PictureUrl,
};

/** @brief Returns the stable wire key of @p name, for example "email_verified". */
[[nodiscard]] std::string_view claimNameKey(ClaimName name) noexcept;

/**
 * @brief Normalized claims a provider has actually verified.
 *
 * "Verified" is a load-bearing word. A provider must place a claim here only if
 * it checked the claim, not merely if it received it. An unverified email
 * address that is treated as verified is a direct account-takeover path when
 * account linking later matches on it.
 */
class VerifiedClaims final {
public:
    VerifiedClaims() = default;

    /** @brief Sets a normalized claim. */
    void set(ClaimName name, std::string value);

    /** @brief Sets a provider-specific claim that has no normalized equivalent. */
    void setExtension(std::string key, std::string value);

    [[nodiscard]] std::optional<std::string_view> get(ClaimName name) const;
    [[nodiscard]] std::optional<std::string_view> getExtension(std::string_view key) const;

    /** @brief Convenience accessor for a boolean-valued claim such as EmailVerified. */
    [[nodiscard]] bool isTrue(ClaimName name) const;

    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] const AttributeMap& all() const noexcept;

private:
    AttributeMap m_claims;
};

/**
 * @brief Audit-grade description of how an authentication was verified.
 *
 * Recorded so that an incident can be investigated afterwards: which issuer was
 * validated, which key identifier signed the assertion, which chain a signature
 * was bound to, which authenticator was used.
 *
 * It must never contain credential material. The entry points accept only
 * strings, and openproof::foundation::Secret has no conversion to a string and no
 * formatter, so a credential cannot be placed here without an explicit and
 * conspicuous call to expose().
 */
class ProviderEvidence final {
public:
    ProviderEvidence() = default;

    /** @brief Records one audit attribute. Must not carry credential material. */
    void add(std::string key, std::string value);

    [[nodiscard]] std::optional<std::string_view> get(std::string_view key) const;
    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] const AttributeMap& all() const noexcept;

private:
    AttributeMap m_attributes;
};

/**
 * @brief The single normalized result every authentication provider produces.
 *
 * This type is the reason the identity core has no provider-specific code. OIDC,
 * WebAuthn, a wallet signature, a Farcaster proof, an enterprise SAML assertion,
 * a USSD exchange and a protocol that does not exist yet all reduce to this
 * value. Adding a provider therefore adds a module; it does not change the
 * domain model.
 *
 * @note The assurance recorded here is what the provider *claims*. It is not the
 *       platform's conclusion. openproof.policy adjudicates whether a given provider
 *       is trusted to claim a given level, which is why the accessor is named
 *       @ref claimedAssurance() rather than `assurance()`.
 */
class AuthenticationOutcome final {
public:
    /**
     * @brief Validates and constructs an outcome.
     * @return ErrorCode::InvalidArgument when the provider or subject is empty.
     *         An outcome without a subject would authenticate nobody, and
     *         accepting one would let a misbehaving provider produce a session
     *         bound to an empty identifier.
     */
    [[nodiscard]] static foundation::Result<AuthenticationOutcome>
    create(ProviderId provider, ExternalSubject subject, VerifiedClaims claims,
           AssuranceLevel claimedAssurance, AuthenticationStrength strength,
           ProviderEvidence evidence, foundation::Instant verifiedAt);

    [[nodiscard]] const ProviderId& provider() const noexcept;
    [[nodiscard]] const ExternalSubject& subject() const noexcept;
    [[nodiscard]] const VerifiedClaims& claims() const noexcept;

    /** @brief The assurance level the provider asserts. Adjudicated by policy. */
    [[nodiscard]] AssuranceLevel claimedAssurance() const noexcept;

    [[nodiscard]] const AuthenticationStrength& strength() const noexcept;
    [[nodiscard]] const ProviderEvidence& evidence() const noexcept;
    [[nodiscard]] foundation::Instant verifiedAt() const noexcept;

private:
    AuthenticationOutcome(ProviderId provider, ExternalSubject subject, VerifiedClaims claims,
                          AssuranceLevel claimedAssurance, AuthenticationStrength strength,
                          ProviderEvidence evidence, foundation::Instant verifiedAt);

    ProviderId m_provider;
    ExternalSubject m_subject;
    VerifiedClaims m_claims;
    AssuranceLevel m_claimedAssurance{AssuranceLevel::Ial0};
    AuthenticationStrength m_strength;
    ProviderEvidence m_evidence;
    foundation::Instant m_verifiedAt{};
};

}

module;

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.evidence.verifiers;

import openproof.evidence;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

export namespace openproof::evidence::verification {

struct ChallengeDigestTag {};
using ChallengeDigest = foundation::StrongId<ChallengeDigestTag>;

class Challenge final {
public:
    [[nodiscard]] static foundation::Result<Challenge> create(
        ChallengeDigest digest, identity::core::IdentityId identity,
        identity::provider::ProviderId provider, foundation::Instant issuedAt,
        foundation::Instant expiresAt);
    [[nodiscard]] const ChallengeDigest& digest() const noexcept;
    [[nodiscard]] const identity::core::IdentityId& identity() const noexcept;
    [[nodiscard]] const identity::provider::ProviderId& provider() const noexcept;
    [[nodiscard]] foundation::Instant issuedAt() const noexcept;
    [[nodiscard]] foundation::Instant expiresAt() const noexcept;
private:
    Challenge(ChallengeDigest digest, identity::core::IdentityId identity,
              identity::provider::ProviderId provider, foundation::Instant issuedAt,
              foundation::Instant expiresAt);
    ChallengeDigest m_digest;
    identity::core::IdentityId m_identity;
    identity::provider::ProviderId m_provider;
    foundation::Instant m_issuedAt{};
    foundation::Instant m_expiresAt{};
};

class ChallengeStore {
public:
    ChallengeStore(const ChallengeStore&) = delete;
    ChallengeStore& operator=(const ChallengeStore&) = delete;
    virtual ~ChallengeStore() = default;
    [[nodiscard]] virtual foundation::Status add(Challenge challenge) = 0;
    [[nodiscard]] virtual foundation::Status consume(
        const ChallengeDigest& digest, const identity::core::IdentityId& identity,
        const identity::provider::ProviderId& provider, foundation::Instant now) = 0;
protected:
    ChallengeStore() = default;
};

struct IssuedChallenge final {
    foundation::SecretString token;
    foundation::Instant expiresAt{};
};

/** @brief Durable one-time proof challenge service for evidence verification ceremonies. */
class ChallengeService final {
public:
    ChallengeService(ChallengeStore& store, const foundation::ClockSource& clock,
                     foundation::Duration lifetime);
    [[nodiscard]] foundation::Result<IssuedChallenge> issue(
        const identity::core::IdentityId& identity,
        const identity::provider::ProviderId& provider);
    [[nodiscard]] foundation::Status consume(
        const identity::core::IdentityId& identity,
        const identity::provider::ProviderId& provider,
        const foundation::SecretString& token);
private:
    ChallengeStore* m_store;
    const foundation::ClockSource* m_clock;
    foundation::Duration m_lifetime{};
};

/** @brief Pinned-key RS256 external attestation verifier. */
class SignedJwtVerifier final : public evidence::EvidenceVerifier {
public:
    [[nodiscard]] static foundation::Result<std::unique_ptr<SignedJwtVerifier>> create(
        identity::provider::ProviderId provider, std::string issuer,
        std::string audience, std::string publicKeyPem,
        foundation::Duration maximumAge);

    [[nodiscard]] identity::provider::ProviderId provider() const override;
    [[nodiscard]] foundation::Result<std::vector<evidence::Evidence>> verify(
        const identity::core::IdentityId& identity,
        const identity::provider::AttributeMap& publicInputs,
        const identity::provider::SecretAttributeMap& secretInputs,
        foundation::Instant now) override;
private:
    SignedJwtVerifier(identity::provider::ProviderId provider, std::string issuer,
                      std::string audience, std::string publicKeyPem,
                      foundation::Duration maximumAge);
    identity::provider::ProviderId m_provider;
    std::string m_issuer;
    std::string m_audience;
    std::string m_publicKeyPem;
    foundation::Duration m_maximumAge{};
};

/** @brief CA-validated X.509 identity evidence with detached proof-of-possession. */
class X509Verifier final : public evidence::EvidenceVerifier {
public:
    [[nodiscard]] static foundation::Result<std::unique_ptr<X509Verifier>> create(
        identity::provider::ProviderId provider, std::string caFile,
        std::string crlFile = {});

    [[nodiscard]] identity::provider::ProviderId provider() const override;
    [[nodiscard]] foundation::Result<std::vector<evidence::Evidence>> verify(
        const identity::core::IdentityId& identity,
        const identity::provider::AttributeMap& publicInputs,
        const identity::provider::SecretAttributeMap& secretInputs,
        foundation::Instant now) override;
private:
    X509Verifier(identity::provider::ProviderId provider, std::string caFile,
                 std::string crlFile);
    identity::provider::ProviderId m_provider;
    std::string m_caFile;
    std::string m_crlFile;
};

} // namespace openproof::evidence::verification

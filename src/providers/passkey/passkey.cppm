module;

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.provider.passkey;

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

export namespace openproof::provider::passkey {

/** @brief A durable WebAuthn credential owned by one canonical identity. */
struct PasskeyCredential final {
    std::string credentialId;
    identity::core::IdentityId identity;
    std::string publicKeyX;
    std::string publicKeyY;
    std::uint32_t signCount{};
    foundation::Instant createdAt{};
    foundation::Instant lastUsedAt{};
};

/** @brief One-time registration ceremony state. */
struct RegistrationCeremony final {
    identity::provider::ChallengeId id;
    identity::core::IdentityId identity;
    foundation::Instant expiresAt{};
};

/** @brief Persistence port for WebAuthn registration state and credentials. */
class PasskeyRepository {
public:
    PasskeyRepository(const PasskeyRepository&) = delete;
    PasskeyRepository& operator=(const PasskeyRepository&) = delete;
    virtual ~PasskeyRepository() = default;

    [[nodiscard]] virtual foundation::Status addCeremony(RegistrationCeremony ceremony) = 0;
    [[nodiscard]] virtual foundation::Status consumeCeremony(
        const identity::provider::ChallengeId& id,
        const identity::core::IdentityId& identity,
        foundation::Instant now) = 0;
    [[nodiscard]] virtual foundation::Status addCredential(PasskeyCredential credential) = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<PasskeyCredential>> findCredential(
        std::string_view credentialId) const = 0;
    [[nodiscard]] virtual foundation::Result<std::vector<PasskeyCredential>> listCredentials(
        const identity::core::IdentityId& identity) const = 0;
    /**
     * @brief Atomically records a successful credential use and advances a supported signature counter.
     *
     * Authenticators that do not implement a signature counter report zero on every use. For those
     * credentials, a 0 -> 0 update is valid and still persists @p usedAt. Non-zero counters must
     * advance strictly.
     */
    [[nodiscard]] virtual foundation::Status advanceCounter(
        std::string_view credentialId, std::uint32_t expected,
        std::uint32_t replacement, foundation::Instant usedAt) = 0;
    /**
     * @brief Removes @p credentialId only when another passkey credential remains.
     *
     * Implementations must make the count-and-delete decision atomically per
     * identity. This prevents concurrent removals from deleting every passkey
     * while the passkey authentication connection is still attached.
     */
    [[nodiscard]] virtual foundation::Status removeCredentialIfAnotherExists(
        const identity::core::IdentityId& identity, std::string_view credentialId) = 0;
    [[nodiscard]] virtual foundation::Status removeCredential(
        const identity::core::IdentityId& identity, std::string_view credentialId) = 0;

protected:
    PasskeyRepository() = default;
};

/** @brief Thread-safe volatile WebAuthn repository intended for tests. */
class InMemoryPasskeyRepository final : public PasskeyRepository {
public:
    [[nodiscard]] foundation::Status addCeremony(RegistrationCeremony ceremony) override;
    [[nodiscard]] foundation::Status consumeCeremony(
        const identity::provider::ChallengeId& id,
        const identity::core::IdentityId& identity,
        foundation::Instant now) override;
    [[nodiscard]] foundation::Status addCredential(PasskeyCredential credential) override;
    [[nodiscard]] foundation::Result<std::optional<PasskeyCredential>> findCredential(
        std::string_view credentialId) const override;
    [[nodiscard]] foundation::Result<std::vector<PasskeyCredential>> listCredentials(
        const identity::core::IdentityId& identity) const override;
    [[nodiscard]] foundation::Status advanceCounter(
        std::string_view credentialId, std::uint32_t expected,
        std::uint32_t replacement, foundation::Instant usedAt) override;
    [[nodiscard]] foundation::Status removeCredentialIfAnotherExists(
        const identity::core::IdentityId& identity, std::string_view credentialId) override;
    [[nodiscard]] foundation::Status removeCredential(
        const identity::core::IdentityId& identity, std::string_view credentialId) override;

private:
    mutable std::mutex m_mutex;
    std::map<identity::provider::ChallengeId, RegistrationCeremony> m_ceremonies;
    std::map<std::string, PasskeyCredential, std::less<>> m_credentials;
};

/** @brief Validated WebAuthn relying-party configuration. */
class PasskeyConfig final {
public:
    [[nodiscard]] static foundation::Result<PasskeyConfig> create(
        std::string relyingPartyId, std::string relyingPartyName,
        std::string origin, foundation::SecretString derivationKey,
        foundation::Duration ceremonyLifetime);

    PasskeyConfig(const PasskeyConfig&) = delete;
    PasskeyConfig& operator=(const PasskeyConfig&) = delete;
    PasskeyConfig(PasskeyConfig&&) noexcept = default;
    PasskeyConfig& operator=(PasskeyConfig&&) noexcept = default;

    [[nodiscard]] std::string_view relyingPartyId() const noexcept;
    [[nodiscard]] std::string_view relyingPartyName() const noexcept;
    [[nodiscard]] std::string_view origin() const noexcept;
    [[nodiscard]] const foundation::SecretString& derivationKey() const noexcept;
    [[nodiscard]] foundation::Duration ceremonyLifetime() const noexcept;

private:
    PasskeyConfig(std::string relyingPartyId, std::string relyingPartyName,
                  std::string origin, foundation::SecretString derivationKey,
                  foundation::Duration ceremonyLifetime);
    std::string m_relyingPartyId;
    std::string m_relyingPartyName;
    std::string m_origin;
    foundation::SecretString m_derivationKey;
    foundation::Duration m_ceremonyLifetime{};
};

/** @brief Browser registration response after base64url serialization. */
struct RegistrationResponse final {
    std::string credentialId;
    std::string clientDataJson;
    std::string attestationObject;
};

/** @brief Browser assertion response after base64url serialization. */
struct AssertionResponse final {
    std::string credentialId;
    std::string clientDataJson;
    std::string authenticatorData;
    std::string signature;
    std::optional<std::string> userHandle;
};

/** @brief Result returned when an authenticated user starts passkey registration. */
struct RegistrationStart final {
    identity::provider::ChallengeId ceremonyId;
    std::string publicKeyOptionsJson;
};

/** @brief Authenticated self-service WebAuthn registration/removal service. */
class PasskeyService final {
public:
    PasskeyService(PasskeyRepository& repository,
                   identity::core::ExternalIdentityDirectory& externalIdentities,
                   const foundation::ClockSource& clock, const PasskeyConfig& config);

    [[nodiscard]] foundation::Result<RegistrationStart> beginRegistration(
        const identity::core::IdentityId& identity);
    [[nodiscard]] foundation::Status completeRegistration(
        const identity::core::IdentityId& identity,
        const identity::provider::ChallengeId& ceremonyId,
        const RegistrationResponse& response);
    [[nodiscard]] foundation::Result<std::vector<PasskeyCredential>> list(
        const identity::core::IdentityId& identity) const;
    [[nodiscard]] foundation::Status remove(
        const identity::core::IdentityId& identity, std::string_view credentialId);

private:
    PasskeyRepository* m_repository;
    identity::core::ExternalIdentityDirectory* m_externalIdentities;
    const foundation::ClockSource* m_clock;
    const PasskeyConfig* m_config;
};

/** @brief WebAuthn assertion provider used by the authentication broker. */
class PasskeyAuthenticationProvider final : public identity::provider::AuthenticationProvider {
public:
    PasskeyAuthenticationProvider(PasskeyRepository& repository,
                                  const foundation::ClockSource& clock,
                                  const PasskeyConfig& config);

    [[nodiscard]] identity::provider::ProviderId id() const override;
    [[nodiscard]] identity::provider::InteractionModel interactionModel() const noexcept override;
    [[nodiscard]] identity::provider::AssuranceLevel maximumClaimableAssurance() const noexcept override;
    [[nodiscard]] foundation::Result<identity::provider::AuthenticationChallenge>
    beginAuthentication(const identity::provider::AuthenticationRequest& request) override;
    [[nodiscard]] foundation::Result<identity::provider::AuthenticationOutcome>
    completeAuthentication(const identity::provider::AuthenticationResponse& response) override;

private:
    PasskeyRepository* m_repository;
    const foundation::ClockSource* m_clock;
    const PasskeyConfig* m_config;
    std::mutex m_authenticationMutex;
    std::map<identity::provider::ChallengeId, foundation::Instant> m_pendingAuthentication;
};

} // namespace openproof::provider::passkey

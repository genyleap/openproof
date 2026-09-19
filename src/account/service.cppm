module;

#include <cstdint>
#include <optional>
#include <string>

export module openproof.account:service;

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.profile;
import openproof.identity.provider;
import openproof.provider.local;
import openproof.session;
import :model;
import :repository;

export namespace openproof::account {

/** @brief Key used only to fingerprint verification secrets at rest. */
class VerificationKey final {
public:
    [[nodiscard]] static foundation::Result<VerificationKey>
    create(foundation::SecretString key);
    VerificationKey(const VerificationKey&) = delete;
    VerificationKey& operator=(const VerificationKey&) = delete;
    VerificationKey(VerificationKey&&) noexcept = default;
    VerificationKey& operator=(VerificationKey&&) noexcept = default;
    ~VerificationKey() = default;

private:
    friend class AccountService;
    explicit VerificationKey(foundation::SecretString key);
    foundation::SecretString m_key;
};

class AccountPolicy final {
public:
    [[nodiscard]] static foundation::Result<AccountPolicy> create(
        foundation::Duration emailVerificationLifetime,
        foundation::Duration phoneVerificationLifetime,
        foundation::Duration passwordResetLifetime,
        std::uint32_t maximumAttempts);

    [[nodiscard]] foundation::Duration emailVerificationLifetime() const noexcept;
    [[nodiscard]] foundation::Duration phoneVerificationLifetime() const noexcept;
    [[nodiscard]] foundation::Duration passwordResetLifetime() const noexcept;
    [[nodiscard]] std::uint32_t maximumAttempts() const noexcept;

private:
    AccountPolicy(foundation::Duration emailVerificationLifetime,
                  foundation::Duration phoneVerificationLifetime,
                  foundation::Duration passwordResetLifetime,
                  std::uint32_t maximumAttempts);
    foundation::Duration m_emailLifetime{};
    foundation::Duration m_phoneLifetime{};
    foundation::Duration m_resetLifetime{};
    std::uint32_t m_maximumAttempts{};
};

/** @brief Delivery boundary. Implementations send secrets without logging them. */
class VerificationDelivery {
public:
    VerificationDelivery(const VerificationDelivery&) = delete;
    VerificationDelivery& operator=(const VerificationDelivery&) = delete;
    virtual ~VerificationDelivery() = default;

    [[nodiscard]] virtual foundation::Status deliver(
        const VerificationDispatch& dispatch) = 0;

protected:
    VerificationDelivery() = default;
};

/** @brief Public account lifecycle and self-service coordinator. */
class AccountService final {
public:
    AccountService(identity::core::OrganizationId organization,
                   identity::provider::ProviderId localProvider,
                   identity::provider::ProviderId phoneProvider,
                   identity::core::IdentityRepository& identities,
                   identity::core::ExternalIdentityDirectory& externalIdentities,
                   identity::profile::IdentityProfileRepository& profiles,
                   provider::local::LocalAccountDirectory& localAccounts,
                   AccountRepository& repository,
                   session::SessionService& sessions,
                   const foundation::ClockSource& clock,
                   VerificationKey key, AccountPolicy policy,
                   VerificationDelivery& delivery);

    [[nodiscard]] foundation::Result<identity::core::IdentityId> signup(
        std::string email, const foundation::SecretString& password,
        std::optional<std::string> displayName = std::nullopt);

    [[nodiscard]] foundation::Status resendSignupVerification(std::string email);

    [[nodiscard]] foundation::Status verifyEmail(
        const VerificationId& id, const foundation::SecretString& secret);

    [[nodiscard]] foundation::Status beginEmailChange(
        const identity::core::IdentityId& identity, std::string replacementEmail);

    [[nodiscard]] foundation::Status completeEmailChange(
        const identity::core::IdentityId& expectedIdentity,
        const VerificationId& id, const foundation::SecretString& secret,
        const foundation::SecretString* newPassword = nullptr);

    [[nodiscard]] foundation::Status beginPhoneVerification(
        const identity::core::IdentityId& identity, std::string phoneNumber);

    [[nodiscard]] foundation::Status completePhoneVerification(
        const identity::core::IdentityId& expectedIdentity,
        const VerificationId& id, const foundation::SecretString& secret);

    /** Returns success even when the email is unknown, preventing account enumeration. */
    [[nodiscard]] foundation::Status beginPasswordReset(std::string email);

    [[nodiscard]] foundation::Status completePasswordReset(
        const VerificationId& id, const foundation::SecretString& secret,
        const foundation::SecretString& newPassword);

    [[nodiscard]] foundation::Status updateProfile(
        const identity::core::IdentityId& identity,
        std::optional<std::string> displayName,
        std::optional<std::string> preferredUsername,
        std::optional<std::string> locale,
        std::optional<std::string> pictureUrl,
        std::optional<std::string> avatarSource = std::nullopt);

    /** Returns the current self-service identity profile. */
    [[nodiscard]] foundation::Result<identity::profile::IdentityProfile> profile(
        const identity::core::IdentityId& identity) const;

private:
    [[nodiscard]] foundation::Result<VerificationDispatch> issue(
        const identity::core::IdentityId& identity,
        VerificationPurpose purpose, VerificationChannel channel,
        std::string destination, foundation::Duration lifetime);
    [[nodiscard]] foundation::Result<VerificationChallenge> consume(
        const VerificationId& id, const foundation::SecretString& secret,
        VerificationPurpose purpose,
        const identity::core::IdentityId* expectedIdentity = nullptr);
    [[nodiscard]] foundation::Result<VerificationDigest> digest(
        const VerificationId& id, const foundation::SecretString& secret) const;
    [[nodiscard]] foundation::Result<identity::profile::IdentityProfile>
    requireProfile(const identity::core::IdentityId& identity) const;
    [[nodiscard]] foundation::Status attachVerified(
        const identity::core::IdentityId& identity,
        const identity::core::ExternalIdentityRef& external);

    identity::core::OrganizationId m_organization;
    identity::provider::ProviderId m_localProvider;
    identity::provider::ProviderId m_phoneProvider;
    identity::core::IdentityRepository* m_identities;
    identity::core::ExternalIdentityDirectory* m_externalIdentities;
    identity::profile::IdentityProfileRepository* m_profiles;
    provider::local::LocalAccountDirectory* m_localAccounts;
    AccountRepository* m_repository;
    session::SessionService* m_sessions;
    const foundation::ClockSource* m_clock;
    VerificationKey m_key;
    AccountPolicy m_policy;
    VerificationDelivery* m_delivery;
};

}

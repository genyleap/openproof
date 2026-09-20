module;

#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

export module openproof.provider.local;

import openproof.credentials;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

export namespace openproof::provider::local {

namespace idp = identity::provider;

enum class LocalVerification {
    Password,
    PasswordAndTotp,
    PasswordAndRecoveryCode,
};

/** Credential-specific domain boundary used by the local provider. */
class LocalAccountDirectory {
public:
    LocalAccountDirectory(const LocalAccountDirectory&) = delete;
    LocalAccountDirectory& operator=(const LocalAccountDirectory&) = delete;
    LocalAccountDirectory(LocalAccountDirectory&&) = delete;
    LocalAccountDirectory& operator=(LocalAccountDirectory&&) = delete;
    virtual ~LocalAccountDirectory() = default;

    [[nodiscard]] virtual foundation::Status enroll(
        idp::ExternalSubject subject, const foundation::SecretString& password,
        std::optional<credentials::TotpSecret> totp) = 0;

    /**
     * @brief Stores a credential before an external identity link is verified.
     *
     * Used by public signup. The canonical identity must already exist but may
     * remain non-authenticating until the verification ceremony completes.
     */
    [[nodiscard]] virtual foundation::Status enrollPending(
        identity::core::IdentityId canonicalIdentity, idp::ExternalSubject subject,
        const foundation::SecretString& password,
        std::optional<credentials::TotpSecret> totp) = 0;

    /** @brief Rebinds an in-memory/login alias after a verified email change. */
    [[nodiscard]] virtual foundation::Status rebindSubject(
        const identity::core::IdentityId& identity,
        const idp::ExternalSubject& previous,
        idp::ExternalSubject replacement) = 0;

    /** @brief Removes a pending credential during failed signup compensation. */
    [[nodiscard]] virtual foundation::Status removePending(
        const identity::core::IdentityId& identity,
        const idp::ExternalSubject& subject) = 0;
    [[nodiscard]] virtual foundation::Status changePassword(
        const idp::ExternalSubject& subject,
        const foundation::SecretString& password) = 0;
    /** @brief Verifies only the knowledge factor without enforcing an enrolled second factor. */
    [[nodiscard]] virtual foundation::Status verifyPassword(
        const idp::ExternalSubject& subject,
        const foundation::SecretString& password) = 0;
    [[nodiscard]] virtual foundation::Result<bool> hasTotp(
        const idp::ExternalSubject& subject) = 0;
    /** Verifies the enrollment code, then installs/replaces the TOTP seed atomically. */
    [[nodiscard]] virtual foundation::Status replaceTotp(
        const idp::ExternalSubject& subject, credentials::TotpSecret& secret,
        std::string_view verificationCode, foundation::Instant now) = 0;
    [[nodiscard]] virtual foundation::Status removeTotp(
        const idp::ExternalSubject& subject) = 0;
    [[nodiscard]] virtual foundation::Result<LocalVerification> verify(
        const idp::ExternalSubject& subject,
        const foundation::SecretString& password,
        std::optional<std::string_view> totp,
        foundation::Instant now) = 0;

protected:
    LocalAccountDirectory() = default;
};

/** Thread-safe single-process adapter. Persistent adapters must encrypt TOTP seeds. */
class InMemoryLocalAccountDirectory final : public LocalAccountDirectory {
public:
    [[nodiscard]] static foundation::Result<std::unique_ptr<InMemoryLocalAccountDirectory>>
    create(credentials::PasswordHasher passwordHasher,
           credentials::TotpPolicy totpPolicy);
    ~InMemoryLocalAccountDirectory() override;

    [[nodiscard]] foundation::Status enroll(
        idp::ExternalSubject subject, const foundation::SecretString& password,
        std::optional<credentials::TotpSecret> totp) override;
    [[nodiscard]] foundation::Status enrollPending(
        identity::core::IdentityId canonicalIdentity, idp::ExternalSubject subject,
        const foundation::SecretString& password,
        std::optional<credentials::TotpSecret> totp) override;
    [[nodiscard]] foundation::Status rebindSubject(
        const identity::core::IdentityId& identity,
        const idp::ExternalSubject& previous,
        idp::ExternalSubject replacement) override;
    [[nodiscard]] foundation::Status removePending(
        const identity::core::IdentityId& identity,
        const idp::ExternalSubject& subject) override;
    [[nodiscard]] foundation::Status changePassword(
        const idp::ExternalSubject& subject,
        const foundation::SecretString& password) override;
    [[nodiscard]] foundation::Status verifyPassword(
        const idp::ExternalSubject& subject,
        const foundation::SecretString& password) override;
    [[nodiscard]] foundation::Result<bool> hasTotp(
        const idp::ExternalSubject& subject) override;
    [[nodiscard]] foundation::Status replaceTotp(
        const idp::ExternalSubject& subject, credentials::TotpSecret& secret,
        std::string_view verificationCode, foundation::Instant now) override;
    [[nodiscard]] foundation::Status removeTotp(
        const idp::ExternalSubject& subject) override;
    [[nodiscard]] foundation::Result<LocalVerification> verify(
        const idp::ExternalSubject& subject,
        const foundation::SecretString& password,
        std::optional<std::string_view> totp,
        foundation::Instant now) override;

private:
    struct Account;
    InMemoryLocalAccountDirectory(credentials::PasswordHasher passwordHasher,
                                  credentials::TotpPolicy totpPolicy,
                                  credentials::PasswordHash dummyHash);
    credentials::PasswordHasher m_passwordHasher;
    credentials::TotpPolicy m_totpPolicy;
    credentials::PasswordHash m_dummyHash;
    mutable std::mutex m_mutex;
    std::map<idp::ExternalSubject, std::unique_ptr<Account>> m_accounts;
};

/**
 * Concrete challenge-response provider for locally managed passwords and TOTP.
 * It intentionally has no registration API; credential administration goes
 * through LocalAccountDirectory and cannot be reached through authentication.
 */
class LocalAuthenticationProvider final : public idp::AuthenticationProvider {
public:
    LocalAuthenticationProvider(
        idp::ProviderId id, LocalAccountDirectory& accounts,
        const foundation::ClockSource& clock, foundation::Duration challengeLifetime,
        identity::core::ExternalIdentityDirectory* identities = nullptr,
        credentials::RecoveryCodeService* recoveryCodes = nullptr);

    [[nodiscard]] idp::ProviderId id() const override;
    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override;
    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override;
    [[nodiscard]] foundation::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest& request) override;
    [[nodiscard]] foundation::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse& response) override;

private:
    struct Pending final {
        idp::ExternalSubject subject;
        foundation::Instant expiresAt;
    };
    idp::ProviderId m_id;
    LocalAccountDirectory* m_accounts;
    identity::core::ExternalIdentityDirectory* m_identities;
    credentials::RecoveryCodeService* m_recoveryCodes;
    const foundation::ClockSource* m_clock;
    foundation::Duration m_challengeLifetime;
    std::mutex m_mutex;
    std::map<idp::ChallengeId, Pending> m_pending;
};

}

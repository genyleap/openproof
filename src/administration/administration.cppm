module;

#include <string>
#include <string_view>
#include <vector>

export module openproof.administration;

import openproof.credentials;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.organization;

export namespace openproof::administration {

/**
 * Validated, one-time ceremony for creating the first tenant owner.
 *
 * This is intentionally not a registration request. The external identity link
 * passes through the explicit verification state machine under operator
 * authority, and the resulting membership always receives the fixed `owner`
 * role. Password and TOTP material remain non-copyable secret types.
 */
class InitialAdministrator final {
public:
    [[nodiscard]] static foundation::Result<InitialAdministrator> create(
        identity::core::OrganizationId organizationId,
        std::string organizationName,
        identity::core::IdentityId identityId,
        identity::provider::ProviderId providerId,
        identity::provider::ExternalSubject externalSubject,
        foundation::SecretString password,
        credentials::TotpSecret totp,
        foundation::Instant now);

    InitialAdministrator(const InitialAdministrator&) = delete;
    InitialAdministrator& operator=(const InitialAdministrator&) = delete;
    InitialAdministrator(InitialAdministrator&&) noexcept = default;
    InitialAdministrator& operator=(InitialAdministrator&&) noexcept = default;
    ~InitialAdministrator() = default;

    [[nodiscard]] const organization::Organization& organization() const noexcept;
    [[nodiscard]] const identity::core::Identity& identity() const noexcept;
    [[nodiscard]] const identity::core::IdentityLink& link() const noexcept;
    [[nodiscard]] const organization::Membership& membership() const noexcept;
    [[nodiscard]] const foundation::SecretString& password() const noexcept;
    [[nodiscard]] const credentials::TotpSecret& totp() const noexcept;

private:
    InitialAdministrator(organization::Organization organization,
                         identity::core::Identity identity,
                         identity::core::IdentityLink link,
                         organization::Membership membership,
                         foundation::SecretString password,
                         credentials::TotpSecret totp);

    organization::Organization m_organization;
    identity::core::Identity m_identity;
    identity::core::IdentityLink m_link;
    organization::Membership m_membership;
    foundation::SecretString m_password;
    credentials::TotpSecret m_totp;
};

/** Atomic persistence boundary for the first-administrator ceremony. */
class BootstrapRepository {
public:
    BootstrapRepository(const BootstrapRepository&) = delete;
    BootstrapRepository& operator=(const BootstrapRepository&) = delete;
    BootstrapRepository(BootstrapRepository&&) = delete;
    BootstrapRepository& operator=(BootstrapRepository&&) = delete;
    virtual ~BootstrapRepository() = default;

    /**
     * Creates every bootstrap aggregate atomically.
     * Implementations must refuse when any organization already exists.
     */
    [[nodiscard]] virtual foundation::Status
    initialize(const InitialAdministrator& administrator) = 0;

protected:
    BootstrapRepository() = default;
};

/** Validated secret-bearing command for adding one local organization member. */
class LocalMemberEnrollment final {
public:
    [[nodiscard]] static foundation::Result<LocalMemberEnrollment> create(
        identity::core::OrganizationId organizationId,
        identity::core::IdentityId identityId,
        identity::provider::ProviderId providerId,
        identity::provider::ExternalSubject externalSubject,
        std::vector<organization::Role> roles,
        foundation::SecretString generatedPassword,
        credentials::TotpSecret generatedTotp,
        foundation::Instant now);

    LocalMemberEnrollment(const LocalMemberEnrollment&) = delete;
    LocalMemberEnrollment& operator=(const LocalMemberEnrollment&) = delete;
    LocalMemberEnrollment(LocalMemberEnrollment&&) noexcept = default;
    LocalMemberEnrollment& operator=(LocalMemberEnrollment&&) noexcept = default;
    ~LocalMemberEnrollment() = default;

    [[nodiscard]] const identity::core::OrganizationId& organizationId() const noexcept;
    [[nodiscard]] const identity::core::Identity& identity() const noexcept;
    [[nodiscard]] const identity::core::IdentityLink& link() const noexcept;
    [[nodiscard]] const organization::Membership& membership() const noexcept;
    [[nodiscard]] const foundation::SecretString& generatedPassword() const noexcept;
    [[nodiscard]] const credentials::TotpSecret& generatedTotp() const noexcept;

private:
    LocalMemberEnrollment(
        identity::core::OrganizationId organizationId,
        identity::core::Identity identity,
        identity::core::IdentityLink link,
        organization::Membership membership,
        foundation::SecretString generatedPassword,
        credentials::TotpSecret generatedTotp);

    identity::core::OrganizationId m_organizationId;
    identity::core::Identity m_identity;
    identity::core::IdentityLink m_link;
    organization::Membership m_membership;
    foundation::SecretString m_generatedPassword;
    credentials::TotpSecret m_generatedTotp;
};

/** Atomic, owner-authorized persistence boundary for local member creation. */
class LocalMemberProvisioner {
public:
    LocalMemberProvisioner(const LocalMemberProvisioner&) = delete;
    LocalMemberProvisioner& operator=(const LocalMemberProvisioner&) = delete;
    LocalMemberProvisioner(LocalMemberProvisioner&&) = delete;
    LocalMemberProvisioner& operator=(LocalMemberProvisioner&&) = delete;
    virtual ~LocalMemberProvisioner() = default;

    /**
     * Persists @p enrollment only when @p actor is an active owner of its
     * active organization. Authorization and mutation must share a transaction.
     */
    [[nodiscard]] virtual foundation::Status provision(
        const identity::core::IdentityId& actor,
        const LocalMemberEnrollment& enrollment) = 0;

protected:
    LocalMemberProvisioner() = default;
};

}

module;

#include <algorithm>
#include <chrono>
#include <string>
#include <string_view>
#include <utility>

module openproof.administration;

namespace openproof::administration {
namespace {

[[nodiscard]] bool validText(std::string_view value, std::size_t maximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::none_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           });
}

}

InitialAdministrator::InitialAdministrator(
    organization::Organization organizationValue,
    identity::core::Identity identityValue,
    identity::core::IdentityLink linkValue,
    organization::Membership membershipValue,
    foundation::SecretString passwordValue,
    credentials::TotpSecret totpValue)
    : m_organization(std::move(organizationValue)),
      m_identity(std::move(identityValue)), m_link(std::move(linkValue)),
      m_membership(std::move(membershipValue)),
      m_password(std::move(passwordValue)), m_totp(std::move(totpValue))
{
}

foundation::Result<InitialAdministrator> InitialAdministrator::create(
    identity::core::OrganizationId organizationId,
    std::string organizationName,
    identity::core::IdentityId identityId,
    identity::provider::ProviderId providerId,
    identity::provider::ExternalSubject externalSubject,
    foundation::SecretString password,
    credentials::TotpSecret totp,
    foundation::Instant now)
{
    if (!validText(organizationId.value(), 200U)
        || !validText(organizationName, 500U)
        || !validText(identityId.value(), 200U)
        || !validText(providerId.value(), 200U)
        || !validText(externalSubject.value(), 1000U)
        || password.expose().size() < 16U || password.expose().size() > 1024U
        || identityId.value() == externalSubject.value()) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "The initial-administrator request is invalid.");
    }

    auto tenant = organization::Organization::create(
        organizationId, std::move(organizationName), now);
    auto subject = identity::core::Identity::create(
        identityId, identity::core::SubjectKind::Human, now);
    if (!tenant) return foundation::fail(tenant.error());
    if (!subject) return foundation::fail(subject.error());

    auto link = identity::core::IdentityLink::request(
        identityId,
        identity::core::ExternalIdentityRef{providerId, externalSubject},
        now, std::chrono::minutes{5});
    if (!link) return foundation::fail(link.error());
    auto required = link->requireVerification(now);
    if (!required) return foundation::fail(required.error());
    auto verified = link->markVerified(now);
    if (!verified) return foundation::fail(verified.error());
    auto completed = link->complete(now);
    if (!completed) return foundation::fail(completed.error());

    auto membership = organization::Membership::invite(
        organizationId, identityId, now);
    if (!membership) return foundation::fail(membership.error());
    auto role = membership->grantRole(organization::Role{"owner"});
    if (!role) return foundation::fail(role.error());
    auto accepted = membership->accept();
    if (!accepted) return foundation::fail(accepted.error());

    return InitialAdministrator{
        std::move(tenant).value(), std::move(subject).value(),
        std::move(link).value(), std::move(membership).value(),
        std::move(password), std::move(totp)};
}

const organization::Organization&
InitialAdministrator::organization() const noexcept { return m_organization; }
const identity::core::Identity&
InitialAdministrator::identity() const noexcept { return m_identity; }
const identity::core::IdentityLink&
InitialAdministrator::link() const noexcept { return m_link; }
const organization::Membership&
InitialAdministrator::membership() const noexcept { return m_membership; }
const foundation::SecretString&
InitialAdministrator::password() const noexcept { return m_password; }
const credentials::TotpSecret&
InitialAdministrator::totp() const noexcept { return m_totp; }

LocalMemberEnrollment::LocalMemberEnrollment(
    identity::core::OrganizationId organizationId,
    identity::core::Identity identityValue,
    identity::core::IdentityLink linkValue,
    organization::Membership membershipValue,
    foundation::SecretString password,
    credentials::TotpSecret totp)
    : m_organizationId(std::move(organizationId)),
      m_identity(std::move(identityValue)), m_link(std::move(linkValue)),
      m_membership(std::move(membershipValue)),
      m_generatedPassword(std::move(password)),
      m_generatedTotp(std::move(totp))
{
}

foundation::Result<LocalMemberEnrollment> LocalMemberEnrollment::create(
    identity::core::OrganizationId organizationId,
    identity::core::IdentityId identityId,
    identity::provider::ProviderId providerId,
    identity::provider::ExternalSubject externalSubject,
    std::vector<organization::Role> roles,
    foundation::SecretString generatedPassword,
    credentials::TotpSecret generatedTotp,
    foundation::Instant now)
{
    if (!validText(organizationId.value(), 200U)
        || !validText(identityId.value(), 200U)
        || !validText(providerId.value(), 200U)
        || !validText(externalSubject.value(), 1000U)
        || identityId.value() == externalSubject.value()
        || roles.empty() || roles.size() > 16U
        || generatedPassword.expose().size() < 32U
        || generatedPassword.expose().size() > 1024U
        || std::ranges::any_of(roles, [](const organization::Role& role) {
               return !validText(role.value(), 200U);
           })) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "The local-member enrollment request is invalid.");
    }
    std::ranges::sort(roles);
    if (std::ranges::adjacent_find(roles) != roles.end()) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "Local-member roles must be unique.");
    }

    auto identityValue = identity::core::Identity::create(
        identityId, identity::core::SubjectKind::Human, now);
    auto link = identity::core::IdentityLink::request(
        identityId,
        identity::core::ExternalIdentityRef{providerId, externalSubject},
        now, std::chrono::minutes{5});
    auto membership = organization::Membership::invite(
        organizationId, identityId, now);
    if (!identityValue) return foundation::fail(identityValue.error());
    if (!link) return foundation::fail(link.error());
    if (!membership) return foundation::fail(membership.error());
    auto required = link->requireVerification(now);
    if (!required) return foundation::fail(required.error());
    auto verified = link->markVerified(now);
    if (!verified) return foundation::fail(verified.error());
    auto completed = link->complete(now);
    if (!completed) return foundation::fail(completed.error());
    for (organization::Role& role : roles) {
        auto granted = membership->grantRole(std::move(role));
        if (!granted) return foundation::fail(granted.error());
    }
    auto accepted = membership->accept();
    if (!accepted) return foundation::fail(accepted.error());

    return LocalMemberEnrollment{
        std::move(organizationId), std::move(identityValue).value(),
        std::move(link).value(), std::move(membership).value(),
        std::move(generatedPassword), std::move(generatedTotp)};
}

const identity::core::OrganizationId&
LocalMemberEnrollment::organizationId() const noexcept { return m_organizationId; }
const identity::core::Identity&
LocalMemberEnrollment::identity() const noexcept { return m_identity; }
const identity::core::IdentityLink&
LocalMemberEnrollment::link() const noexcept { return m_link; }
const organization::Membership&
LocalMemberEnrollment::membership() const noexcept { return m_membership; }
const foundation::SecretString&
LocalMemberEnrollment::generatedPassword() const noexcept
{ return m_generatedPassword; }
const credentials::TotpSecret&
LocalMemberEnrollment::generatedTotp() const noexcept { return m_generatedTotp; }

}

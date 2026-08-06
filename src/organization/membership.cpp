module;

#include <algorithm>
#include <chrono>
#include <string_view>
#include <utility>
#include <vector>

module openproof.organization;

namespace openproof::organization {

std::string_view membershipStateName(MembershipState state) noexcept
{
    switch (state) {
    case MembershipState::Invited:
        return "invited";
    case MembershipState::Active:
        return "active";
    case MembershipState::Suspended:
        return "suspended";
    case MembershipState::Removed:
        return "removed";
    }
    return "removed";
}

bool permitsAccess(MembershipState state) noexcept
{
    switch (state) {
    case MembershipState::Active:
        return true;
    case MembershipState::Invited:
    case MembershipState::Suspended:
    case MembershipState::Removed:
        return false;
    }
    return false;
}

Membership::Membership(OrganizationId organization, IdentityId identity,
                       foundation::Instant invitedAt)
    : m_organization(std::move(organization))
    , m_identity(std::move(identity))
    , m_invitedAt(invitedAt)
{
}

foundation::Result<Membership> Membership::invite(OrganizationId organization,
                                                  IdentityId identity,
                                                  foundation::Instant invitedAt)
{
    if (organization.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A membership must name an organization.");
    }
    if (identity.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A membership must name an identity.");
    }
    return Membership{std::move(organization), std::move(identity), invitedAt};
}

const OrganizationId& Membership::organization() const noexcept
{
    return m_organization;
}

const IdentityId& Membership::identity() const noexcept
{
    return m_identity;
}

MembershipState Membership::state() const noexcept
{
    return m_state;
}

foundation::Instant Membership::invitedAt() const noexcept
{
    return m_invitedAt;
}

const std::vector<Role>& Membership::roles() const noexcept
{
    return m_roles;
}

bool Membership::hasRole(const Role& role) const noexcept
{
    // The state check comes first deliberately. A suspended member keeps their
    // roles so reinstatement does not require re-granting, but those roles must
    // grant nothing while suspended.
    if (!permitsAccess(m_state)) {
        return false;
    }
    return std::ranges::find(m_roles, role) != m_roles.end();
}

foundation::Status Membership::accept()
{
    if (m_state != MembershipState::Invited) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "This invitation is no longer open.");
    }
    m_state = MembershipState::Active;
    return foundation::ok();
}

foundation::Status Membership::suspend()
{
    if (m_state != MembershipState::Active) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "Only an active membership can be suspended.");
    }
    m_state = MembershipState::Suspended;
    return foundation::ok();
}

foundation::Status Membership::reinstate()
{
    if (m_state != MembershipState::Suspended) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "Only a suspended membership can be reinstated.");
    }
    m_state = MembershipState::Active;
    return foundation::ok();
}

foundation::Status Membership::remove()
{
    if (m_state == MembershipState::Removed) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "This membership has already been removed.");
    }

    m_state = MembershipState::Removed;

    // Roles are dropped, not retained. If they survived removal, a re-invited
    // member would silently regain whatever authority they held before.
    m_roles.clear();

    contract_assert(m_roles.empty());
    return foundation::ok();
}

foundation::Status Membership::grantRole(Role role)
{
    if (role.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A role must have a name.");
    }
    if (m_state == MembershipState::Removed) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "This membership has been removed.",
            "Refused to grant a role to a removed membership; the authority would be "
            "attached to a relationship that no longer exists.");
    }

    if (std::ranges::find(m_roles, role) != m_roles.end()) {
        return foundation::ok();
    }

    m_roles.push_back(std::move(role));

    // Kept sorted so that listings are stable and comparisons are order
    // independent; a role set that varies by insertion order makes audit
    // records of the same grant look different.
    std::ranges::sort(m_roles);
    return foundation::ok();
}

foundation::Status Membership::revokeRole(const Role& role)
{
    const auto position = std::ranges::find(m_roles, role);
    if (position == m_roles.end()) {
        return foundation::fail(
            foundation::ErrorCode::NotFound,
            "That role is not held by this member.",
            "Revocation reported honestly rather than as idempotent success, so a caller "
            "cannot believe it removed authority that was never there.");
    }

    m_roles.erase(position);
    return foundation::ok();
}

}

module;

#include <chrono>
#include <string_view>
#include <vector>

export module openproof.organization.membership;

import openproof.foundation;
import openproof.identity.core;

export namespace openproof::organization {

/** @brief The canonical identity key, owned by the identity domain. */
using IdentityId = identity::core::IdentityId;

/** @brief The tenant key, owned by the identity vocabulary. */
using OrganizationId = identity::core::OrganizationId;

/** @brief Tag for a role name, always interpreted within an organization. */
struct RoleTag {};

/**
 * @brief A role assigned through an organization membership.
 *
 * Organization owns assignment and lifecycle; policy only interprets this
 * vocabulary. Keeping the type here avoids a dependency from organization up
 * into the authorization layer.
 */
using Role = foundation::StrongId<RoleTag>;

/**
 * @brief Lifecycle of one identity's membership in one organization.
 *
 * An invitation is not a membership. Modelling them as separate states stops
 * "was invited" from being mistaken for "is a member", which is the difference
 * between an offer and an access grant.
 */
enum class MembershipState {
    Invited,   ///< Offered, not accepted. Grants nothing.
    Active,    ///< Accepted and in force.
    Suspended, ///< Temporarily barred; roles are retained but grant nothing.
    Removed,   ///< Terminal. Roles are dropped.
};

/** @brief Returns the stable wire name of @p state, for example "suspended". */
[[nodiscard]] std::string_view membershipStateName(MembershipState state) noexcept;

/**
 * @brief Returns whether @p state lets the member act in the organization.
 *
 * Only @c Active does. Written as an allow-list so a state added later grants
 * nothing until someone deliberately permits it.
 */
[[nodiscard]] bool permitsAccess(MembershipState state) noexcept;

/**
 * @brief An identity's membership of an organization, with its roles.
 *
 * Roles are held here rather than on the identity, because §23 makes them
 * organization-scoped: the same person may be an owner of one tenant and a
 * viewer of another, and a role stored on the identity would leak across both.
 *
 * This aggregate assigns roles; it never interprets them. Deciding what a role
 * permits is the policy engine's job, and keeping that separation is what stops
 * authorization logic from accumulating here.
 */
class Membership final {
public:
    /**
     * @brief Creates a membership in state @c Invited, holding no roles.
     * @return ErrorCode::InvalidArgument when either key is empty.
     */
    [[nodiscard]] static foundation::Result<Membership>
    invite(OrganizationId organization, IdentityId identity, foundation::Instant invitedAt);

    [[nodiscard]] const OrganizationId& organization() const noexcept;
    [[nodiscard]] const IdentityId& identity() const noexcept;
    [[nodiscard]] MembershipState state() const noexcept;
    [[nodiscard]] foundation::Instant invitedAt() const noexcept;

    /** @brief Roles granted in this organization, in stable order. */
    [[nodiscard]] const std::vector<Role>& roles() const noexcept;

    /**
     * @brief Returns whether the member effectively holds @p role.
     *
     * False whenever the membership does not permit access, regardless of what
     * is stored. A suspended member keeps their roles so that reinstating them
     * does not require re-granting, but those roles grant nothing meanwhile --
     * and a caller that inspected @ref roles() directly could miss that.
     */
    [[nodiscard]] bool hasRole(const Role& role) const noexcept;

    /** @brief @c Invited -> @c Active. */
    [[nodiscard]] foundation::Status accept();

    /** @brief @c Active -> @c Suspended. Roles are retained but inert. */
    [[nodiscard]] foundation::Status suspend();

    /** @brief @c Suspended -> @c Active. */
    [[nodiscard]] foundation::Status reinstate();

    /**
     * @brief Ends the membership. Terminal, and drops every role.
     *
     * Roles are dropped rather than retained so that a removed member who is
     * later re-invited starts with none. Silently restoring an owner role on
     * re-invitation is exactly the kind of privilege resurrection §52 warns
     * about.
     */
    [[nodiscard]] foundation::Status remove();

    /**
     * @brief Grants @p role.
     * @return ErrorCode::FailedPrecondition when the membership is terminal.
     *         Granting a role to a removed member would leave authority
     *         attached to a relationship that no longer exists.
     */
    [[nodiscard]] foundation::Status grantRole(Role role);

    /**
     * @brief Revokes @p role.
     * @return ErrorCode::NotFound when the role was not held. Revocation is
     *         reported honestly rather than treated as idempotent success, so a
     *         caller cannot believe it removed authority it never found.
     */
    [[nodiscard]] foundation::Status revokeRole(const Role& role);

private:
    Membership(OrganizationId organization, IdentityId identity, foundation::Instant invitedAt);

    OrganizationId m_organization;
    IdentityId m_identity;
    MembershipState m_state{MembershipState::Invited};
    foundation::Instant m_invitedAt{};
    std::vector<Role> m_roles;
};

}

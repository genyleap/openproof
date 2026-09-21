module;

#include <chrono>
#include <string_view>
#include <vector>

export module openproof.identity.core:merge;

import openproof.foundation;

import :identity;
import :link;
import :repository;

export namespace openproof::identity::core {

/**
 * @brief States of an identity merge.
 *
 * Merging is the most destructive operation the identity domain offers: it
 * disables one canonical identity and moves its associations to another. It is
 * therefore an explicit, auditable state machine rather than a function call,
 * for the same reason linking is -- an attacker who can merge their identity
 * into a victim's, or a victim's into theirs, owns the account without ever
 * touching a credential.
 *
 * There is no path from @c Requested to @c Applied. Verification is mandatory.
 */
enum class MergeState {
    Requested,            ///< A merge has been proposed. Proves nothing.
    VerificationRequired, ///< The platform demanded proof of control of both identities.
    Verified,             ///< Control of both was proven. Still not merged.
    Applied,              ///< The merge was executed. Terminal.
    Rejected,             ///< Refused. Terminal.
    Expired,              ///< Not completed in time. Terminal.
};

/** @brief Returns the stable wire name of @p state, for example "verified". */
[[nodiscard]] std::string_view mergeStateName(MergeState state) noexcept;

/** @brief Returns whether @p state admits no further transition. */
[[nodiscard]] bool isTerminalMergeState(MergeState state) noexcept;

/**
 * @brief An explicit, expiring request to absorb one identity into another.
 *
 * Both identities are named at request time and neither may change afterwards,
 * so a verified merge cannot be redirected at a different target between
 * verification and application.
 *
 * The organization is part of the request and is checked when the merge is
 * applied. A merge therefore cannot cross tenants: both identities are resolved
 * through an organization-scoped repository, and an identity in another
 * organization simply does not resolve.
 */
class IdentityMerge final {
public:
    /**
     * @brief Opens a merge request in state @c Requested.
     *
     * @param organization The tenant both identities must belong to.
     * @param source       The identity to be absorbed. It ends as @c Merged.
     * @param target       The identity that survives.
     * @param validFor     How long verification may take before the request expires.
     *
     * @return ErrorCode::InvalidArgument when either key is empty, when source
     *         and target are the same identity, or when @p validFor is not
     *         positive. Merging an identity into itself is always a caller
     *         defect, and accepting it would disable the identity it was meant
     *         to preserve.
     */
    [[nodiscard]] static foundation::Result<IdentityMerge>
    request(OrganizationId organization, IdentityId source, IdentityId target,
            foundation::Instant now, foundation::Duration validFor);

    [[nodiscard]] const OrganizationId& organization() const noexcept;
    [[nodiscard]] const IdentityId& source() const noexcept;
    [[nodiscard]] const IdentityId& target() const noexcept;
    [[nodiscard]] MergeState state() const noexcept;
    [[nodiscard]] foundation::Instant requestedAt() const noexcept;
    [[nodiscard]] foundation::Instant expiresAt() const noexcept;

    /** @brief Returns whether the request has expired at @p now. Inclusive. */
    [[nodiscard]] bool isExpiredAt(foundation::Instant now) const noexcept;

    /** @brief @c Requested -> @c VerificationRequired. */
    [[nodiscard]] foundation::Status requireVerification(foundation::Instant now);

    /**
     * @brief @c VerificationRequired -> @c Verified.
     *
     * The caller asserts that control of **both** identities has been proven to
     * the assurance its policy requires. This type does not and cannot check
     * that; it records the claim and refuses every path that would reach
     * @c Applied without it.
     */
    [[nodiscard]] foundation::Status markVerified(foundation::Instant now);

    /**
     * @brief @c Verified -> @c Applied.
     *
     * Normally called by @ref applyMerge rather than directly, so that the
     * state transition and the data movement stay together.
     */
    [[nodiscard]] foundation::Status markApplied(foundation::Instant now);

    /** @brief Refuses the merge from any non-terminal state. Terminal. */
    [[nodiscard]] foundation::Status reject(foundation::Instant now);

    /** @brief Expires the merge from any non-terminal state. Terminal. */
    [[nodiscard]] foundation::Status expire(foundation::Instant now);

private:
    IdentityMerge(OrganizationId organization, IdentityId source, IdentityId target,
                  foundation::Instant requestedAt, foundation::Instant expiresAt);

    [[nodiscard]] foundation::Status transitionTo(MergeState next, foundation::Instant now,
                                                  bool honourExpiry);

    OrganizationId m_organization;
    IdentityId m_source;
    IdentityId m_target;
    MergeState m_state{MergeState::Requested};
    foundation::Instant m_requestedAt{};
    foundation::Instant m_expiresAt{};
};

/**
 * @brief Immutable provenance of a merge that actually happened.
 *
 * Brief §52 requires that a merge never destroys evidence of the previous
 * relationship. The absorbed identity survives as a tombstone in state
 * @c Merged, and this record says what it became and what moved with it.
 *
 * Without it, an association that used to belong to the source would appear to
 * have always belonged to the target, which is exactly the history an incident
 * investigation needs.
 */
class MergeRecord final {
public:
    MergeRecord(OrganizationId organization, IdentityId source, IdentityId target,
                foundation::Instant appliedAt, std::vector<ExternalIdentityRef> movedAssociations);

    [[nodiscard]] const OrganizationId& organization() const noexcept;
    [[nodiscard]] const IdentityId& source() const noexcept;
    [[nodiscard]] const IdentityId& target() const noexcept;
    [[nodiscard]] foundation::Instant appliedAt() const noexcept;

    /** @brief The associations transferred from source to target, in stable order. */
    [[nodiscard]] const std::vector<ExternalIdentityRef>& movedAssociations() const noexcept;

private:
    OrganizationId m_organization;
    IdentityId m_source;
    IdentityId m_target;
    foundation::Instant m_appliedAt{};
    std::vector<ExternalIdentityRef> m_movedAssociations;
};

/**
 * @brief Executes a verified merge.
 *
 * What it does, in order:
 *   1. refuses unless @p merge is @c Verified and unexpired;
 *   2. resolves both identities through @p identities **scoped to the merge's
 *      organization**, so a cross-tenant merge cannot resolve;
 *   3. refuses if either identity is already terminal;
 *   4. moves the source's external associations to the target;
 *   5. marks the source @c Merged;
 *   6. marks the request @c Applied and returns the provenance record.
 *
 * ### What it deliberately does not do
 *
 * **It transfers no authority.** Organization memberships, roles and
 * entitlements are untouched. This is the mechanism that satisfies §52's
 * "prevent privilege escalation": if merge moved memberships, then merging a
 * low-privilege identity into a high-privilege one -- or persuading an
 * administrator to merge theirs into yours -- would be a privilege-escalation
 * primitive. Associations are evidence of *who you are*; memberships are
 * *what you may do*. Only the former moves, and the latter must be re-granted
 * deliberately.
 *
 * @note Not atomic. Between step 4 and step 5 a crash leaves associations moved
 *       and the source still active. The order is chosen so that the unsafe
 *       direction is impossible: the source is disabled before nothing, and a
 *       partial run can only ever leave the source with fewer associations than
 *       it began with, never the target with authority it was not granted.
 *       Deployments that require atomic merge persistence must use a
 *       transactional repository implementation.
 */
[[nodiscard]] foundation::Result<MergeRecord> applyMerge(IdentityMerge& merge,
                                                         IdentityRepository& identities,
                                                         ExternalIdentityDirectory& directory,
                                                         foundation::Instant now);

}

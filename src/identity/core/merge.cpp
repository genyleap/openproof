module;

#include <chrono>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

module openproof.identity.core;

namespace openproof::identity::core {

std::string_view mergeStateName(MergeState state) noexcept
{
    switch (state) {
    case MergeState::Requested:
        return "requested";
    case MergeState::VerificationRequired:
        return "verification_required";
    case MergeState::Verified:
        return "verified";
    case MergeState::Applied:
        return "applied";
    case MergeState::Rejected:
        return "rejected";
    case MergeState::Expired:
        return "expired";
    }
    return "rejected";
}

bool isTerminalMergeState(MergeState state) noexcept
{
    // Allow-list of non-terminal states, so a state added later is terminal
    // until someone deliberately says otherwise. The opposite spelling would
    // silently make a new state transitionable.
    switch (state) {
    case MergeState::Requested:
    case MergeState::VerificationRequired:
    case MergeState::Verified:
        return false;
    case MergeState::Applied:
    case MergeState::Rejected:
    case MergeState::Expired:
        return true;
    }
    return true;
}

IdentityMerge::IdentityMerge(OrganizationId organization, IdentityId source, IdentityId target,
                             foundation::Instant requestedAt, foundation::Instant expiresAt)
    : m_organization(std::move(organization))
    , m_source(std::move(source))
    , m_target(std::move(target))
    , m_requestedAt(requestedAt)
    , m_expiresAt(expiresAt)
{
}

foundation::Result<IdentityMerge> IdentityMerge::request(OrganizationId organization,
                                                         IdentityId source, IdentityId target,
                                                         foundation::Instant now,
                                                         foundation::Duration validFor)
{
    if (organization.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A merge must name an organization.");
    }
    if (source.empty() || target.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A merge must name both identities.");
    }
    if (source == target) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "An identity cannot be merged into itself.",
            "Source and target were the same key. Applying it would mark the surviving "
            "identity as merged and disable the account the operation was meant to keep.");
    }
    if (validFor <= foundation::Duration::zero()) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "A merge request must have a positive lifetime.",
            "A non-positive lifetime yields a request that is already expired, which would "
            "either be unusable or, if expiry were ignored, never expire at all.");
    }

    return IdentityMerge{std::move(organization), std::move(source), std::move(target), now,
                         now + validFor};
}

const OrganizationId& IdentityMerge::organization() const noexcept
{
    return m_organization;
}

const IdentityId& IdentityMerge::source() const noexcept
{
    return m_source;
}

const IdentityId& IdentityMerge::target() const noexcept
{
    return m_target;
}

MergeState IdentityMerge::state() const noexcept
{
    return m_state;
}

foundation::Instant IdentityMerge::requestedAt() const noexcept
{
    return m_requestedAt;
}

foundation::Instant IdentityMerge::expiresAt() const noexcept
{
    return m_expiresAt;
}

bool IdentityMerge::isExpiredAt(foundation::Instant now) const noexcept
{
    // Inclusive: a request presented exactly at its deadline is expired. The
    // boundary resolves in the safe direction.
    return now >= m_expiresAt;
}

foundation::Status IdentityMerge::transitionTo(MergeState next, foundation::Instant now,
                                               bool honourExpiry)
{
    if (isTerminalMergeState(m_state)) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "This merge request can no longer be changed.",
            "Refused to transition out of a terminal merge state.");
    }

    // Expiry is checked before every progressing transition, so a request that
    // sat unverified past its deadline cannot be walked forward afterwards.
    // reject() and expire() pass honourExpiry = false: closing a stale request
    // must always remain possible.
    if (honourExpiry && isExpiredAt(now)) {
        m_state = MergeState::Expired;
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "This merge request has expired.");
    }

    m_state = next;
    return foundation::ok();
}

foundation::Status IdentityMerge::requireVerification(foundation::Instant now)
{
    if (m_state != MergeState::Requested) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "This merge request is not awaiting verification.");
    }
    return transitionTo(MergeState::VerificationRequired, now, true);
}

foundation::Status IdentityMerge::markVerified(foundation::Instant now)
{
    if (m_state != MergeState::VerificationRequired) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "This merge request cannot be marked verified.",
            "Verification may only follow an explicit verification requirement. Allowing it "
            "from any other state would make the requirement optional.");
    }
    return transitionTo(MergeState::Verified, now, true);
}

foundation::Status IdentityMerge::markApplied(foundation::Instant now)
{
    if (m_state != MergeState::Verified) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "This merge request has not been verified.",
            "Refused to apply a merge that did not pass through the Verified state.");
    }
    return transitionTo(MergeState::Applied, now, true);
}

foundation::Status IdentityMerge::reject(foundation::Instant now)
{
    return transitionTo(MergeState::Rejected, now, false);
}

foundation::Status IdentityMerge::expire(foundation::Instant now)
{
    return transitionTo(MergeState::Expired, now, false);
}

MergeRecord::MergeRecord(OrganizationId organization, IdentityId source, IdentityId target,
                         foundation::Instant appliedAt,
                         std::vector<ExternalIdentityRef> movedAssociations)
    : m_organization(std::move(organization))
    , m_source(std::move(source))
    , m_target(std::move(target))
    , m_appliedAt(appliedAt)
    , m_movedAssociations(std::move(movedAssociations))
{
}

const OrganizationId& MergeRecord::organization() const noexcept
{
    return m_organization;
}

const IdentityId& MergeRecord::source() const noexcept
{
    return m_source;
}

const IdentityId& MergeRecord::target() const noexcept
{
    return m_target;
}

foundation::Instant MergeRecord::appliedAt() const noexcept
{
    return m_appliedAt;
}

const std::vector<ExternalIdentityRef>& MergeRecord::movedAssociations() const noexcept
{
    return m_movedAssociations;
}

namespace {

/** A status that no longer admits participation in a merge. */
[[nodiscard]] bool isTerminalIdentityStatus(IdentityStatus status) noexcept
{
    return status == IdentityStatus::Deleted || status == IdentityStatus::Merged;
}

}

foundation::Result<MergeRecord> applyMerge(IdentityMerge& merge, IdentityRepository& identities,
                                           ExternalIdentityDirectory& directory,
                                           foundation::Instant now)
{
    if (merge.state() != MergeState::Verified) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "This merge request has not been verified.",
            "applyMerge refused a request that had not passed through the Verified state.");
    }
    if (merge.isExpiredAt(now)) {
        static_cast<void>(merge.expire(now));
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "This merge request has expired.");
    }

    // Both lookups are scoped to the request's organization. An identity in
    // another tenant does not resolve here, which is what makes a cross-tenant
    // merge impossible rather than merely forbidden.
    const foundation::Result<std::optional<Identity>> sourceLookup =
        identities.findById(merge.organization(), merge.source());
    if (!sourceLookup.has_value()) {
        return foundation::fail(sourceLookup.error());
    }
    const foundation::Result<std::optional<Identity>> targetLookup =
        identities.findById(merge.organization(), merge.target());
    if (!targetLookup.has_value()) {
        return foundation::fail(targetLookup.error());
    }

    if (!sourceLookup.value().has_value() || !targetLookup.value().has_value()) {
        return foundation::fail(
            foundation::ErrorCode::NotFound,
            "One of the identities in this merge was not found.",
            "Either a key does not exist or it belongs to another organization; the two are "
            "deliberately indistinguishable here.");
    }

    if (isTerminalIdentityStatus(sourceLookup.value()->status())
        || isTerminalIdentityStatus(targetLookup.value()->status())) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "One of the identities in this merge can no longer be modified.",
            "Refused to merge into or out of a deleted or already-merged identity. Doing so "
            "would either resurrect a retired key or produce a chain of merges whose final "
            "owner is ambiguous.");
    }

    const foundation::Result<std::vector<ExternalIdentityRef>> owned =
        directory.externalIdentitiesOf(merge.source());
    if (!owned.has_value()) {
        return foundation::fail(owned.error());
    }

    // Associations move first, then the source is disabled. See the note on
    // atomicity in the declaration: a partial run leaves the source with fewer
    // associations, never the target with authority it was not granted.
    std::vector<ExternalIdentityRef> moved;
    moved.reserve(owned.value().size());
    for (const ExternalIdentityRef& external : owned.value()) {
        const foundation::Status reassigned =
            directory.reassign(external, merge.source(), merge.target());
        if (!reassigned.has_value()) {
            return foundation::fail(reassigned.error());
        }
        moved.push_back(external);
    }

    const foundation::Status retired =
        identities.changeStatus(merge.organization(), merge.source(), IdentityStatus::Merged);
    if (!retired.has_value()) {
        return foundation::fail(retired.error());
    }

    const foundation::Status applied = merge.markApplied(now);
    if (!applied.has_value()) {
        return foundation::fail(applied.error());
    }

    foundation::requireInvariant(merge.state() == MergeState::Applied, "identity merge did not reach applied state");
    foundation::requireInvariant(moved.size() == owned.value().size(), "identity merge moved an unexpected number of external identities");

    return MergeRecord{merge.organization(), merge.source(), merge.target(), now,
                       std::move(moved)};
}

}

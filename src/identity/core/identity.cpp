module;

#include <string>
#include <string_view>
#include <utility>

module openproof.identity.core;

namespace openproof::identity::core {

std::string_view subjectKindName(SubjectKind kind) noexcept
{
    switch (kind) {
    case SubjectKind::Human:
        return "human";
    case SubjectKind::Service:
        return "service";
    case SubjectKind::Workload:
        return "workload";
    case SubjectKind::Organization:
        return "organization";
    }
    return "human";
}

std::string_view identityStatusName(IdentityStatus status) noexcept
{
    switch (status) {
    case IdentityStatus::Active:
        return "active";
    case IdentityStatus::Suspended:
        return "suspended";
    case IdentityStatus::Locked:
        return "locked";
    case IdentityStatus::Deactivated:
        return "deactivated";
    case IdentityStatus::Deleted:
        return "deleted";
    case IdentityStatus::Merged:
        return "merged";
    }
    return "deactivated";
}

bool permitsAuthentication(IdentityStatus status) noexcept
{
    // Written as an allow-list rather than a deny-list on purpose: a status added
    // later is denied until someone deliberately permits it. The reverse spelling
    // would silently admit every new status.
    switch (status) {
    case IdentityStatus::Active:
        return true;
    case IdentityStatus::Suspended:
    case IdentityStatus::Locked:
    case IdentityStatus::Deactivated:
    case IdentityStatus::Deleted:
    // A merged identity must never authenticate. Its credentials and
    // associations now belong to the successor, and letting the absorbed key
    // still log in would reopen the account the merge was meant to close.
    case IdentityStatus::Merged:
        return false;
    }
    return false;
}

Identity::Identity(IdentityId id, SubjectKind kind, foundation::Instant createdAt)
    : m_id(std::move(id))
    , m_kind(kind)
    , m_createdAt(createdAt)
{
}

foundation::Result<Identity> Identity::create(IdentityId id, SubjectKind kind,
                                              foundation::Instant createdAt)
{
    if (id.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An identity must have an identifier.");
    }
    return Identity{std::move(id), kind, createdAt};
}

const IdentityId& Identity::id() const noexcept
{
    return m_id;
}

SubjectKind Identity::kind() const noexcept
{
    return m_kind;
}

IdentityStatus Identity::status() const noexcept
{
    return m_status;
}

foundation::Instant Identity::createdAt() const noexcept
{
    return m_createdAt;
}

bool Identity::canAuthenticate() const noexcept
{
    return permitsAuthentication(m_status);
}

foundation::Status Identity::changeStatus(IdentityStatus status)
{
    if (m_status == IdentityStatus::Deleted) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "This identity cannot be modified.",
            "A deleted identity cannot change status. Its key may still be referenced by "
            "audit records and external associations, so resurrecting it would silently "
            "reattach them.");
    }

    if (m_status == IdentityStatus::Merged) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "This identity cannot be modified.",
            "A merged identity cannot change status. Its associations were transferred to a "
            "successor, so reactivating it would produce two live identities claiming the "
            "same external accounts.");
    }

    m_status = status;
    return foundation::ok();
}

}

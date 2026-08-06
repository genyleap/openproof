module;

#include <chrono>
#include <string>
#include <string_view>
#include <utility>

module openproof.organization;

namespace openproof::organization {

std::string_view organizationStatusName(OrganizationStatus status) noexcept
{
    switch (status) {
    case OrganizationStatus::Active:
        return "active";
    case OrganizationStatus::Suspended:
        return "suspended";
    case OrganizationStatus::Archived:
        return "archived";
    }
    return "suspended";
}

bool permitsUse(OrganizationStatus status) noexcept
{
    switch (status) {
    case OrganizationStatus::Active:
        return true;
    case OrganizationStatus::Suspended:
    case OrganizationStatus::Archived:
        return false;
    }
    return false;
}

Organization::Organization(OrganizationId id, std::string displayName,
                           foundation::Instant createdAt)
    : m_id(std::move(id))
    , m_displayName(std::move(displayName))
    , m_createdAt(createdAt)
{
}

foundation::Result<Organization> Organization::create(OrganizationId id, std::string displayName,
                                                      foundation::Instant createdAt)
{
    if (id.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An organization must have an identifier.");
    }
    if (displayName.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An organization must have a display name.");
    }
    return Organization{std::move(id), std::move(displayName), createdAt};
}

const OrganizationId& Organization::id() const noexcept
{
    return m_id;
}

std::string_view Organization::displayName() const noexcept
{
    return m_displayName;
}

OrganizationStatus Organization::status() const noexcept
{
    return m_status;
}

foundation::Instant Organization::createdAt() const noexcept
{
    return m_createdAt;
}

bool Organization::isUsable() const noexcept
{
    return permitsUse(m_status);
}

foundation::Status Organization::changeStatus(OrganizationStatus status)
{
    if (m_status == OrganizationStatus::Archived) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "This organization cannot be modified.",
            "An archived organization cannot change status. Memberships and audit records "
            "still reference its key, so reviving it would silently reactivate them.");
    }

    m_status = status;
    return foundation::ok();
}

foundation::Status Organization::rename(std::string displayName)
{
    if (displayName.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An organization must have a display name.");
    }
    if (m_status == OrganizationStatus::Archived) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "This organization cannot be modified.");
    }

    m_displayName = std::move(displayName);
    return foundation::ok();
}

}

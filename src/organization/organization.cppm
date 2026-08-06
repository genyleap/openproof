module;

#include <chrono>
#include <string>
#include <string_view>

export module openproof.organization:organization;

import openproof.foundation;
import openproof.identity.core;

export namespace openproof::organization {

/** @brief The tenant key, owned by the identity domain and reused here. */
using OrganizationId = identity::core::OrganizationId;

/**
 * @brief Lifecycle status of a tenant.
 *
 * Separate from the status of any identity inside it. Suspending an
 * organization must not require walking its members, and reactivating one must
 * not silently reactivate a member an administrator suspended individually.
 */
enum class OrganizationStatus {
    Active,    ///< Normal operation.
    Suspended, ///< Temporarily barred; reversible.
    Archived,  ///< Retired. Terminal, and retained for audit integrity.
};

/** @brief Returns the stable wire name of @p status, for example "archived". */
[[nodiscard]] std::string_view organizationStatusName(OrganizationStatus status) noexcept;

/**
 * @brief Returns whether @p status permits the tenant to be used at all.
 *
 * Centralised so no call site writes its own list. Written as an allow-list, so
 * a status added later is refused until someone deliberately permits it.
 */
[[nodiscard]] bool permitsUse(OrganizationStatus status) noexcept;

/**
 * @brief A tenant.
 *
 * Deliberately small: it owns identity, display name, status and creation time.
 * Members, roles and policies are separate aggregates that reference it, so
 * loading an organization does not load its entire membership.
 */
class Organization final {
public:
    /**
     * @brief Validates and creates an active organization.
     * @return ErrorCode::InvalidArgument when the key or display name is empty.
     */
    [[nodiscard]] static foundation::Result<Organization>
    create(OrganizationId id, std::string displayName, foundation::Instant createdAt);

    [[nodiscard]] const OrganizationId& id() const noexcept;
    [[nodiscard]] std::string_view displayName() const noexcept;
    [[nodiscard]] OrganizationStatus status() const noexcept;
    [[nodiscard]] foundation::Instant createdAt() const noexcept;

    /** @brief Returns whether this tenant may currently be used. */
    [[nodiscard]] bool isUsable() const noexcept;

    /**
     * @brief Moves the organization to @p status.
     * @return ErrorCode::FailedPrecondition when it is Archived, which is
     *         terminal: reviving an archived tenant would reactivate every
     *         membership that still references it.
     */
    [[nodiscard]] foundation::Status changeStatus(OrganizationStatus status);

    /** @brief Renames the organization. The key never changes. */
    [[nodiscard]] foundation::Status rename(std::string displayName);

private:
    Organization(OrganizationId id, std::string displayName, foundation::Instant createdAt);

    OrganizationId m_id;
    std::string m_displayName;
    OrganizationStatus m_status{OrganizationStatus::Active};
    foundation::Instant m_createdAt{};
};

}

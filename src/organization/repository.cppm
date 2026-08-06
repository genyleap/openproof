module;

#include <cstddef>
#include <map>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

export module openproof.organization:repository;

import openproof.foundation;

import :organization;
import :membership;

export namespace openproof::organization {

/**
 * @brief Persistence contract for the organization aggregate.
 *
 * Domain operations, not table operations. There is no `remove`: a tenant is
 * retired by moving it to @c Archived, which keeps the key resolvable for the
 * audit records and memberships that still reference it.
 *
 * @note Implementations must be safe to call concurrently.
 */
class OrganizationRepository {
public:
    OrganizationRepository(const OrganizationRepository&) = delete;
    OrganizationRepository& operator=(const OrganizationRepository&) = delete;
    OrganizationRepository(OrganizationRepository&&) = delete;
    OrganizationRepository& operator=(OrganizationRepository&&) = delete;

    virtual ~OrganizationRepository() = default;

    /** @brief Records a new organization. ErrorCode::AlreadyExists on a duplicate key. */
    [[nodiscard]] virtual foundation::Status add(Organization organization) = 0;

    /** @brief Returns the organization, or an empty optional. */
    [[nodiscard]] virtual foundation::Result<std::optional<Organization>>
    findById(const OrganizationId& id) const = 0;

    /** @brief Moves an organization to @p status. ErrorCode::NotFound when absent. */
    [[nodiscard]] virtual foundation::Status changeStatus(const OrganizationId& id,
                                                          OrganizationStatus status) = 0;

    [[nodiscard]] virtual foundation::Result<std::size_t> count() const = 0;

protected:
    OrganizationRepository() = default;
};

/**
 * @brief Persistence contract for memberships.
 *
 * The organization is part of the key of every operation, exactly as it is for
 * IdentityRepository, so a membership in another tenant is not addressable.
 *
 * @ref organizationsOf is the one query keyed by identity rather than tenant.
 * It exists because "which organizations may I act in?" is a question only the
 * subject can ask about themselves, and answering it is what lets a caller pick
 * a tenant before any tenant-scoped call is possible.
 *
 * @note Implementations must be safe to call concurrently.
 */
class MembershipRepository {
public:
    MembershipRepository(const MembershipRepository&) = delete;
    MembershipRepository& operator=(const MembershipRepository&) = delete;
    MembershipRepository(MembershipRepository&&) = delete;
    MembershipRepository& operator=(MembershipRepository&&) = delete;

    virtual ~MembershipRepository() = default;

    /**
     * @brief Records a membership.
     * @return ErrorCode::AlreadyExists when this identity already has a
     *         membership in this organization. A second membership row would
     *         make "which roles does this member hold?" ambiguous.
     */
    [[nodiscard]] virtual foundation::Status add(Membership membership) = 0;

    /** @brief Returns the membership of @p identity in @p organization. */
    [[nodiscard]] virtual foundation::Result<std::optional<Membership>>
    find(const OrganizationId& organization, const IdentityId& identity) const = 0;

    /**
     * @brief Replaces a stored membership with an updated copy.
     * @return ErrorCode::NotFound when absent.
     */
    [[nodiscard]] virtual foundation::Status save(const Membership& membership) = 0;

    /** @brief Returns the members of @p organization, in key order. */
    [[nodiscard]] virtual foundation::Result<std::vector<IdentityId>>
    membersOf(const OrganizationId& organization) const = 0;

    /** @brief Returns the organizations @p identity belongs to, in key order. */
    [[nodiscard]] virtual foundation::Result<std::vector<OrganizationId>>
    organizationsOf(const IdentityId& identity) const = 0;

    [[nodiscard]] virtual foundation::Result<std::size_t>
    countIn(const OrganizationId& organization) const = 0;

protected:
    MembershipRepository() = default;
};

/**
 * @brief In-memory organization repository, for tests and pre-PostgreSQL phases.
 * @note Thread-safe.
 */
class InMemoryOrganizationRepository final : public OrganizationRepository {
public:
    InMemoryOrganizationRepository() = default;

    [[nodiscard]] foundation::Status add(Organization organization) override;
    [[nodiscard]] foundation::Result<std::optional<Organization>>
    findById(const OrganizationId& id) const override;
    [[nodiscard]] foundation::Status changeStatus(const OrganizationId& id,
                                                  OrganizationStatus status) override;
    [[nodiscard]] foundation::Result<std::size_t> count() const override;

private:
    mutable std::mutex m_mutex;
    std::map<OrganizationId, Organization> m_entries;
};

/**
 * @brief In-memory membership repository, for tests and pre-PostgreSQL phases.
 * @note Thread-safe.
 */
class InMemoryMembershipRepository final : public MembershipRepository {
public:
    InMemoryMembershipRepository() = default;

    [[nodiscard]] foundation::Status add(Membership membership) override;
    [[nodiscard]] foundation::Result<std::optional<Membership>>
    find(const OrganizationId& organization, const IdentityId& identity) const override;
    [[nodiscard]] foundation::Status save(const Membership& membership) override;
    [[nodiscard]] foundation::Result<std::vector<IdentityId>>
    membersOf(const OrganizationId& organization) const override;
    [[nodiscard]] foundation::Result<std::vector<OrganizationId>>
    organizationsOf(const IdentityId& identity) const override;
    [[nodiscard]] foundation::Result<std::size_t>
    countIn(const OrganizationId& organization) const override;

    /** @brief Total across all organizations. Intended for tests. */
    [[nodiscard]] std::size_t size() const;

private:
    /** Composite key: a membership is identified by tenant *and* subject. */
    using Key = std::pair<OrganizationId, IdentityId>;

    mutable std::mutex m_mutex;
    std::map<Key, Membership> m_entries;
};

}

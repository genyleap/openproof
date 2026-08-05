module;

#include <cstddef>
#include <map>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

export module openproof.identity.core:repository;

import openproof.foundation;

import :identity;

export namespace openproof::identity::core {

/**
 * @brief Persistence contract for the canonical identity aggregate.
 *
 * This is a *domain* repository, not a generic CRUD store, and the distinction
 * is deliberate. A generic `Repository<Entity, Id>` keyed only by an identifier
 * has nowhere to put the organization, so multi-tenant isolation would depend on
 * every call site remembering to add a predicate -- and one forgotten predicate
 * in one handler is a cross-tenant read.
 *
 * Here the tenant is a parameter of **every** operation. A caller cannot express
 * "find this identity" without also saying which organization is asking, so
 * cross-tenant access is not something the interface can describe. A lookup with
 * the wrong organization reports absence; it never reports the identity.
 *
 * The operations are domain operations rather than table operations. There is no
 * `remove`: an identity is retired by moving it to IdentityStatus::Deleted, which
 * preserves the tombstone that audit integrity and association cleanup depend on.
 * A repository that could delete the row would quietly break both.
 *
 * @note Implementations must be safe to call concurrently.
 */
class IdentityRepository {
public:
    IdentityRepository(const IdentityRepository&) = delete;
    IdentityRepository& operator=(const IdentityRepository&) = delete;
    IdentityRepository(IdentityRepository&&) = delete;
    IdentityRepository& operator=(IdentityRepository&&) = delete;

    virtual ~IdentityRepository() = default;

    /**
     * @brief Records a newly created identity within @p organization.
     * @return ErrorCode::AlreadyExists when the key is already present in any
     *         organization. Identity keys are globally unique: allowing the same
     *         key in two tenants would make a key ambiguous the moment anything
     *         references it without its tenant.
     */
    [[nodiscard]] virtual foundation::Status add(const OrganizationId& organization, Identity identity) = 0;

    /**
     * @brief Returns the identity @p id within @p organization.
     * @return An empty optional when the key is absent **or** belongs to another
     *         organization. The two cases are deliberately indistinguishable to
     *         the caller, so a tenant cannot probe for the existence of keys it
     *         does not own.
     */
    [[nodiscard]] virtual foundation::Result<std::optional<Identity>>
    findById(const OrganizationId& organization, const IdentityId& id) const = 0;

    /**
     * @brief Moves an identity to @p status.
     * @return ErrorCode::NotFound when the identity is absent from @p organization;
     *         ErrorCode::FailedPrecondition when the transition is not permitted.
     */
    [[nodiscard]] virtual foundation::Status changeStatus(const OrganizationId& organization, const IdentityId& id, IdentityStatus status) = 0;

    /** @brief Returns the identities of @p kind in @p organization, in key order. */
    [[nodiscard]] virtual foundation::Result<std::vector<IdentityId>>
    idsOfKind(const OrganizationId& organization, SubjectKind kind) const = 0;

    /** @brief Returns how many identities @p organization holds. */
    [[nodiscard]] virtual foundation::Result<std::size_t>
    countIn(const OrganizationId& organization) const = 0;

protected:
    IdentityRepository() = default;
};

/**
 * @brief In-memory identity repository for tests and the pre-PostgreSQL phases.
 *
 * Not a production store: contents are lost when the process exits and are not
 * shared between instances. It exists so the domain layers can be built and
 * tested against the real contract before an adapter exists, and so unit tests
 * never require a database.
 *
 * @note Thread-safe. Every operation takes an internal mutex.
 */
class InMemoryIdentityRepository final : public IdentityRepository {
public:
    InMemoryIdentityRepository() = default;

    [[nodiscard]] foundation::Status add(const OrganizationId& organization,Identity identity) override;
    [[nodiscard]] foundation::Result<std::optional<Identity>>findById(const OrganizationId& organization, const IdentityId& id) const override;
    [[nodiscard]] foundation::Status changeStatus(const OrganizationId& organization, const IdentityId& id, IdentityStatus status) override;
    [[nodiscard]] foundation::Result<std::vector<IdentityId>> idsOfKind(const OrganizationId& organization, SubjectKind kind) const override;
    [[nodiscard]] foundation::Result<std::size_t> countIn(const OrganizationId& organization) const override;

    /** @brief Total across all organizations. Intended for tests. */
    [[nodiscard]] std::size_t size() const;

private:
    /** An identity together with the tenant that owns it. */
    struct Owned {
        OrganizationId organization;
        Identity identity;
    };

    mutable std::mutex m_mutex;
    std::map<IdentityId, Owned> m_entries;
};

}

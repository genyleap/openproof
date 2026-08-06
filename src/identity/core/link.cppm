module;

#include <cstddef>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module openproof.identity.core:link;

import openproof.foundation;
import openproof.identity.provider;

import :identity;

export namespace openproof::identity::core {

/**
 * @brief A provider-scoped subject, paired with the provider that asserted it.
 *
 * The pair is the unit of association, because an external subject is only
 * meaningful together with its issuer: `12345` from one provider and `12345`
 * from another are unrelated, and treating them as equal would merge strangers.
 */
class ExternalIdentityRef final {
public:
    ExternalIdentityRef(provider::ProviderId providerId, provider::ExternalSubject subject);

    [[nodiscard]] const provider::ProviderId& providerId() const noexcept;
    [[nodiscard]] const provider::ExternalSubject& subject() const noexcept;

    [[nodiscard]] friend bool operator==(const ExternalIdentityRef& left, const ExternalIdentityRef& right) = default;
    [[nodiscard]] friend std::strong_ordering operator<=>(const ExternalIdentityRef& left, const ExternalIdentityRef& right) = default;

private:
    provider::ProviderId m_providerId;
    provider::ExternalSubject m_subject;
};

/**
 * @brief States of an identity-linking operation.
 *
 * Linking is modelled as an explicit state machine rather than a boolean because
 * it is one of the highest-value attack surfaces in an identity platform: an
 * attacker who can attach an external identity they control to a victim's OpenProof
 * Identity owns that account, without ever touching the victim's credentials.
 *
 * Every transition is deliberate and auditable, and there is no path that
 * reaches @c Linked without passing through @c Verified.
 */
enum class LinkState {
    LinkRequested,        ///< A link has been proposed. Proves nothing yet.
    VerificationRequired, ///< The platform demanded proof of control.
    Verified,             ///< Control was proven. Still not linked.
    Linked,               ///< The association is active.
    Rejected,             ///< Refused. Terminal.
    Expired,              ///< Not completed in time. Terminal.
    Revoked,              ///< Previously linked, now withdrawn. Terminal.
};

/** @brief Returns the stable wire name of @p state, for example "verification_required". */
[[nodiscard]] std::string_view linkStateName(LinkState state) noexcept;

/** @brief Returns whether @p state admits no further transitions. */
[[nodiscard]] bool isTerminalLinkState(LinkState state) noexcept;

/**
 * @brief An explicit, auditable request to associate an external identity with a
 *        canonical OpenProof Identity.
 *
 * The transitions permitted are exactly:
 *
 * @verbatim
 *   LinkRequested ──> VerificationRequired ──> Verified ──> Linked ──> Revoked
 *         │                    │                  │
 *         └────────────────────┴──────────────────┴──> Rejected
 *         └────────────────────┴─────────────────────> Expired
 * @endverbatim
 *
 * There is deliberately no transition into @c Linked from anywhere except
 * @c Verified. That single restriction is what makes "identity linking never
 * occurs implicitly" a property of the code rather than a rule in a document:
 * no amount of matching email addresses can move a link forward, because
 * matching attributes are not a transition.
 */
class IdentityLink final {
public:
    /**
     * @brief Opens a link request.
     * @param owner    The canonical identity the external identity would attach to.
     * @param lifetime How long the request may remain open. Must be positive.
     * @return ErrorCode::InvalidArgument when the owner or external reference is
     *         empty, or the lifetime is not positive.
     */
    [[nodiscard]] static foundation::Result<IdentityLink>
    request(IdentityId owner, ExternalIdentityRef external, foundation::Instant requestedAt,
            foundation::Duration lifetime);

    [[nodiscard]] const IdentityId& owner() const noexcept;
    [[nodiscard]] const ExternalIdentityRef& external() const noexcept;
    [[nodiscard]] LinkState state() const noexcept;
    [[nodiscard]] foundation::Instant requestedAt() const noexcept;
    [[nodiscard]] foundation::Instant expiresAt() const noexcept;
    [[nodiscard]] bool isExpiredAt(foundation::Instant now) const noexcept;

    /** @brief Demands proof of control. Valid only from @c LinkRequested. */
    [[nodiscard]] foundation::Status requireVerification(foundation::Instant now);

    /**
     * @brief Records that control was proven. Valid only from @c VerificationRequired.
     *
     * The caller must have verified control through a provider, not inferred it
     * from an attribute. This function records a conclusion; it does not reach it.
     */
    [[nodiscard]] foundation::Status markVerified(foundation::Instant now);

    /** @brief Activates the association. Valid only from @c Verified. */
    [[nodiscard]] foundation::Status complete(foundation::Instant now);

    /** @brief Refuses the request. Valid from any non-terminal state. */
    [[nodiscard]] foundation::Status reject(foundation::Instant now);

    /** @brief Withdraws an active association. Valid only from @c Linked. */
    [[nodiscard]] foundation::Status revoke(foundation::Instant now);

    /** @brief Marks an unfinished request expired. */
    [[nodiscard]] foundation::Status expire(foundation::Instant now);

private:
    IdentityLink(IdentityId owner, ExternalIdentityRef external, foundation::Instant requestedAt, foundation::Instant expiresAt);
    [[nodiscard]] foundation::Status transitionTo(LinkState next, foundation::Instant now, bool honourExpiry);

    IdentityId m_owner;
    ExternalIdentityRef m_external;
    LinkState m_state{LinkState::LinkRequested};
    foundation::Instant m_requestedAt{};
    foundation::Instant m_expiresAt{};
};

/**
 * @brief Authoritative record of which canonical identity owns which external identity.
 *
 * Enforces the invariant that an external identity belongs to at most one OpenProof
 * Identity. @ref attach refuses rather than transfers when the association is
 * already claimed, because silent transfer is account takeover with extra steps.
 * Reassignment is a separate, explicitly authorised operation, not a side effect
 * of signing in.
 *
 * @note Implementations must be safe to call concurrently.
 */
class ExternalIdentityDirectory {
public:
    ExternalIdentityDirectory(const ExternalIdentityDirectory&) = delete;
    ExternalIdentityDirectory& operator=(const ExternalIdentityDirectory&) = delete;
    ExternalIdentityDirectory(ExternalIdentityDirectory&&) = delete;
    ExternalIdentityDirectory& operator=(ExternalIdentityDirectory&&) = delete;

    virtual ~ExternalIdentityDirectory() = default;

    /**
     * @brief Records an association from a completed link.
     * @return ErrorCode::FailedPrecondition when @p link is not @c Linked;
     *         ErrorCode::Conflict when the external identity already belongs to a
     *         different canonical identity.
     */
    [[nodiscard]] virtual foundation::Status attach(const IdentityLink& link) = 0;

    /** @brief Returns the owner of @p external, or an empty optional. */
    [[nodiscard]] virtual foundation::Result<std::optional<IdentityId>>
    ownerOf(const ExternalIdentityRef& external) const = 0;

    /**
     * @brief Removes an association.
     * @return ErrorCode::NotFound when absent; ErrorCode::PermissionDenied when
     *         @p expectedOwner does not currently own it, so that a caller cannot
     *         detach an association belonging to someone else.
     */
    [[nodiscard]] virtual foundation::Status detach(const ExternalIdentityRef& external, const IdentityId& expectedOwner) = 0;

    /**
     * @brief Moves an association from one canonical identity to another.
     *
     * Exists for identity merge, which must move associations without
     * destroying and recreating them: a detach-then-attach pair leaves a window
     * in which the association belongs to nobody, and loses the fact that it was
     * moved rather than re-proven.
     *
     * @p expectedCurrentOwner is mandatory and checked. Without it this would be
     * a primitive for taking over any association by naming it, which is exactly
     * the account-takeover path the linking state machine exists to close.
     *
     * @return ErrorCode::NotFound when the association is absent;
     *         ErrorCode::PermissionDenied when @p expectedCurrentOwner does not
     *         currently own it.
     */
    [[nodiscard]] virtual foundation::Status reassign(const ExternalIdentityRef& external,
                                                      const IdentityId& expectedCurrentOwner,
                                                      const IdentityId& newOwner) = 0;

    /** @brief Returns every external identity owned by @p owner, in stable order. */
    [[nodiscard]] virtual foundation::Result<std::vector<ExternalIdentityRef>>
    externalIdentitiesOf(const IdentityId& owner) const = 0;

    [[nodiscard]] virtual std::size_t size() const = 0;

protected:
    ExternalIdentityDirectory() = default;
};

/**
 * @brief In-memory directory, for tests and for the pre-PostgreSQL phases.
 * @note Thread-safe.
 */
class InMemoryExternalIdentityDirectory final : public ExternalIdentityDirectory {
public:
    InMemoryExternalIdentityDirectory() = default;

    [[nodiscard]] foundation::Status attach(const IdentityLink& link) override;

    [[nodiscard]] foundation::Result<std::optional<IdentityId>>
    ownerOf(const ExternalIdentityRef& external) const override;

    [[nodiscard]] foundation::Status detach(const ExternalIdentityRef& external, const IdentityId& expectedOwner) override;

    [[nodiscard]] foundation::Status reassign(const ExternalIdentityRef& external,
                                              const IdentityId& expectedCurrentOwner,
                                              const IdentityId& newOwner) override;

    [[nodiscard]] foundation::Result<std::vector<ExternalIdentityRef>>
    externalIdentitiesOf(const IdentityId& owner) const override;

    [[nodiscard]] std::size_t size() const override;

private:
    mutable std::mutex m_mutex;
    std::map<ExternalIdentityRef, IdentityId> m_owners;
};

}

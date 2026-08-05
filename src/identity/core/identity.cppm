module;

#include <string>
#include <string_view>

export module openproof.identity.core:identity;

import openproof.foundation;

export namespace openproof::identity::core {

/** @brief Tag for the canonical OpenProof Identity key. */
struct IdentityIdTag {};

/**
 * @brief The canonical OpenProof Identity key.
 *
 * Internal, stable and opaque. It is the *only* primary key for a subject in
 * this platform.
 *
 * This type is distinct from openproof::identity::provider::ExternalSubject, and that
 * distinction is enforced by the type system rather than by convention: a Google
 * `sub`, a wallet address, an ENS name, a Farcaster id, an email address and a
 * phone number are all *associations*, and none of them may become an
 * IdentityId. A provider that is compromised, retired, or that recycles its
 * identifiers would otherwise take the account with it.
 */
using IdentityId = foundation::StrongId<IdentityIdTag>;

/** @brief Tag for an organization key. */
struct OrganizationIdTag {};

/** @brief Identifies an organization (tenant). */
using OrganizationId = foundation::StrongId<OrganizationIdTag>;

/**
 * @brief What kind of subject an identity represents.
 *
 * Not every subject is a person. Modelling this explicitly keeps
 * service-to-service authentication from being expressed as a human user with a
 * long-lived session, which is how service credentials end up with a person's
 * privileges and lifetime.
 */
enum class SubjectKind {
    Human,        ///< A person.
    Service,      ///< A named service account, owned by an organization.
    Workload,     ///< A running instance, typically with short-lived credentials.
    Organization, ///< An organization acting as a subject in its own right.
};

/** @brief Returns the stable wire name of @p kind, for example "workload". */
[[nodiscard]] std::string_view subjectKindName(SubjectKind kind) noexcept;

/**
 * @brief Lifecycle status of a canonical identity.
 *
 * Distinct from any session or credential state: revoking every session does not
 * suspend an identity, and suspending an identity must not depend on someone
 * remembering to revoke its sessions.
 */
enum class IdentityStatus {
    Active,      ///< Normal operation.
    Suspended,   ///< Temporarily barred; reversible by an administrator.
    Locked,      ///< Barred by an automated security control.
    Deactivated, ///< Retired by the subject or the organization.
    Deleted,     ///< Erased; retained only as a tombstone for audit integrity.
};

/** @brief Returns the stable wire name of @p status. */
[[nodiscard]] std::string_view identityStatusName(IdentityStatus status) noexcept;

/**
 * @brief Returns whether @p status permits authentication to proceed.
 *
 * Centralised so that no call site writes its own list of acceptable statuses;
 * a forgotten case in one handler is a bypass.
 */
[[nodiscard]] bool permitsAuthentication(IdentityStatus status) noexcept;

/**
 * @brief The canonical OpenProof Identity.
 *
 * Deliberately small. It owns identity, kind, status and creation time, and
 * nothing else: credentials, external associations, sessions, roles and
 * entitlements are separate aggregates that reference this one. Putting them
 * here would make every authentication load a subject's entire history.
 *
 * The identity core knows nothing about Google, GitHub, Apple, Farcaster,
 * Ethereum, ENS, USSD, OAuth, HTTP or PostgreSQL. If a change to this file
 * requires naming any of them, the change belongs elsewhere.
 */
class Identity final {
public:
    /**
     * @brief Validates and creates an active identity.
     * @return ErrorCode::InvalidArgument when @p id is empty.
     */
    [[nodiscard]] static foundation::Result<Identity> create(IdentityId id, SubjectKind kind, foundation::Instant createdAt);
    [[nodiscard]] const IdentityId& id() const noexcept;
    [[nodiscard]] SubjectKind kind() const noexcept;
    [[nodiscard]] IdentityStatus status() const noexcept;
    [[nodiscard]] foundation::Instant createdAt() const noexcept;

    /** @brief Returns whether this identity may currently authenticate. */
    [[nodiscard]] bool canAuthenticate() const noexcept;

    /**
     * @brief Moves the identity to @p status.
     * @return ErrorCode::FailedPrecondition when the identity is Deleted, which
     *         is terminal: resurrecting a deleted identity would reattach any
     *         associations that still reference its key.
     */
    [[nodiscard]] foundation::Status changeStatus(IdentityStatus status);

private:
    Identity(IdentityId id, SubjectKind kind, foundation::Instant createdAt);

    IdentityId m_id;
    SubjectKind m_kind{SubjectKind::Human};
    IdentityStatus m_status{IdentityStatus::Active};
    foundation::Instant m_createdAt{};
};

}

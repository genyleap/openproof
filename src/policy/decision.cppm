module;

#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.policy:decision;

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

export namespace openproof::policy {

/** @brief Tag for an action name such as "session.revoke". */
struct ActionTag {};

/** @brief What the subject is attempting, for example "agent.execute". */
using Action = foundation::StrongId<ActionTag>;

/** @brief Tag for a resource identifier. */
struct ResourceTag {};

/** @brief What is being acted upon, for example "billing:invoice/42". */
using Resource = foundation::StrongId<ResourceTag>;

/** @brief Tag for an entitlement key such as "analytics.pro". */
struct EntitlementTag {};

/**
 * @brief A capability granted to a subject by a system outside this platform.
 *
 * Entitlements enter from a billing or subscription system through an adapter.
 * This platform consumes them and never computes them: no pricing, plan or
 * payment logic belongs on this side of the boundary.
 */
using Entitlement = foundation::StrongId<EntitlementTag>;

/** @brief Tag for a role name, always interpreted within an organization. */
struct RoleTag {};

/** @brief A role held by a subject *within a specific organization*. */
using Role = foundation::StrongId<RoleTag>;

/** @brief Tag for a permission name. */
struct PermissionTag {};

/** @brief A discrete permission, for example "session.revoke". */
using Permission = foundation::StrongId<PermissionTag>;

/**
 * @brief What the platform knows about how the subject authenticated.
 *
 * Separate from the subject's identity on purpose. "Who are you" and "how
 * strongly did you prove it" are different questions, and collapsing them is how
 * a long-lived low-assurance session ends up authorising a high-risk operation.
 */
class AuthenticationContext final {
public:
    AuthenticationContext() = default;

    /** @brief Records that a subject authenticated, and how. */
    AuthenticationContext(identity::provider::ProviderId providerId,
                          identity::provider::AssuranceLevel claimedAssurance,
                          identity::provider::AuthenticationStrength strength,
                          foundation::Instant authenticatedAt);

    /** @brief Whether any authentication happened at all. */
    [[nodiscard]] bool isAuthenticated() const noexcept;

    [[nodiscard]] const identity::provider::ProviderId& providerId() const noexcept;

    /**
     * @brief The assurance the provider claimed.
     *
     * Named "claimed" throughout: it is an assertion by the provider, and the
     * policy engine decides whether that provider is trusted to make it.
     */
    [[nodiscard]] identity::provider::AssuranceLevel claimedAssurance() const noexcept;

    [[nodiscard]] const identity::provider::AuthenticationStrength& strength() const noexcept;
    [[nodiscard]] foundation::Instant authenticatedAt() const noexcept;

private:
    bool m_authenticated{false};
    identity::provider::ProviderId m_providerId;
    identity::provider::AssuranceLevel m_claimedAssurance{identity::provider::AssuranceLevel::Ial0};
    identity::provider::AuthenticationStrength m_strength;
    foundation::Instant m_authenticatedAt{};
};

/**
 * @brief Everything a policy may consider when deciding one request.
 *
 * Assembled by the caller and passed whole, so that a policy never reaches back
 * into a database mid-decision and so that the same inputs always produce the
 * same decision -- which is what makes decisions reproducible during an incident.
 *
 * Organization context is a first-class field rather than an optional extra:
 * roles in this platform are organization-scoped, and a decision made without
 * knowing the organization is a decision made without knowing the roles.
 */
class AuthorizationRequest final {
public:
    AuthorizationRequest(identity::core::IdentityId subject, Action action, Resource resource);

    [[nodiscard]] const identity::core::IdentityId& subject() const noexcept;
    [[nodiscard]] const Action& action() const noexcept;
    [[nodiscard]] const Resource& resource() const noexcept;

    /** @brief The organization the request is made within, when there is one. */
    [[nodiscard]] const std::optional<identity::core::OrganizationId>&
    organization() const noexcept;
    AuthorizationRequest& withOrganization(identity::core::OrganizationId organization);

    [[nodiscard]] const AuthenticationContext& authentication() const noexcept;
    AuthorizationRequest& withAuthentication(AuthenticationContext context);

    /** @brief Roles held by the subject *in this organization*. */
    [[nodiscard]] const std::vector<Role>& roles() const noexcept;
    AuthorizationRequest& withRole(Role role);

    [[nodiscard]] const std::vector<Permission>& permissions() const noexcept;
    AuthorizationRequest& withPermission(Permission permission);

    [[nodiscard]] const std::vector<Entitlement>& entitlements() const noexcept;
    AuthorizationRequest& withEntitlement(Entitlement entitlement);

    /** @brief Whether the subject holds @p entitlement. */
    [[nodiscard]] bool hasEntitlement(const Entitlement& entitlement) const;

    /** @brief Whether the subject holds @p role in this organization. */
    [[nodiscard]] bool hasRole(const Role& role) const;

private:
    identity::core::IdentityId m_subject;
    Action m_action;
    Resource m_resource;
    std::optional<identity::core::OrganizationId> m_organization;
    AuthenticationContext m_authentication;
    std::vector<Role> m_roles;
    std::vector<Permission> m_permissions;
    std::vector<Entitlement> m_entitlements;
};

/**
 * @brief The four outcomes a policy evaluation can have.
 *
 * Collapsing these into a boolean is the defect this enumeration exists to
 * prevent. "No policy matched" and "the policy engine could not run" are not the
 * same as "denied", and an operator debugging a production incident needs to
 * tell them apart. They are all *resolved* to deny for protected operations --
 * see @ref isPermitted -- but they are recorded distinctly.
 */
enum class DecisionKind {
    Allow,         ///< A policy explicitly permitted the request.
    Deny,          ///< A policy explicitly refused the request.
    NotApplicable, ///< No policy matched. Not a permission.
    Indeterminate, ///< Evaluation could not complete. Not a permission.
};

/** @brief Returns the stable wire name of @p kind, for example "not_applicable". */
[[nodiscard]] std::string_view decisionKindName(DecisionKind kind) noexcept;

/**
 * @brief The result of evaluating one authorization request.
 *
 * Carries the reason as well as the outcome, because "denied" without a reason
 * is unactionable for an operator and indistinguishable from a bug.
 */
class AuthorizationDecision final {
public:
    /** @brief An explicit permit. */
    [[nodiscard]] static AuthorizationDecision allow(std::string reason);

    /** @brief An explicit refusal. */
    [[nodiscard]] static AuthorizationDecision deny(std::string reason);

    /** @brief No policy matched the request. */
    [[nodiscard]] static AuthorizationDecision notApplicable(std::string reason);

    /**
     * @brief Evaluation could not complete.
     *
     * Used when a dependency the policy needed was unavailable. It must never be
     * produced to mean "nothing was wrong".
     */
    [[nodiscard]] static AuthorizationDecision indeterminate(std::string reason);

    [[nodiscard]] DecisionKind kind() const noexcept;
    [[nodiscard]] std::string_view reason() const noexcept;

    /**
     * @brief Whether this decision permits the operation.
     *
     * True only for @c Allow. This is the single place the four-valued outcome
     * collapses to a boolean, so that no call site invents its own rule and
     * accidentally treats @c NotApplicable or @c Indeterminate as permission.
     *
     * Infrastructure failure never becomes authorization success.
     */
    [[nodiscard]] bool isPermitted() const noexcept;

private:
    AuthorizationDecision(DecisionKind kind, std::string reason);

    DecisionKind m_kind{DecisionKind::Indeterminate};
    std::string m_reason;
};

/**
 * @brief The contract every policy implementation satisfies.
 *
 * Route handlers, and later the OpenProof gateway, ask this interface. They never inspect a
 * role, a subscription or an "isAdmin" flag themselves: a rule expressed at a
 * call site is a rule that cannot be reviewed, tested or changed centrally.
 *
 * @note Implementations must be safe to call concurrently and should not perform
 *       I/O: the request carries everything the decision needs.
 */
class PolicyEngine {
public:
    PolicyEngine(const PolicyEngine&) = delete;
    PolicyEngine& operator=(const PolicyEngine&) = delete;
    PolicyEngine(PolicyEngine&&) = delete;
    PolicyEngine& operator=(PolicyEngine&&) = delete;

    virtual ~PolicyEngine() = default;

    /**
     * @brief Evaluates @p request.
     *
     * An implementation that cannot reach a conclusion returns
     * @c Indeterminate. It must not throw, and it must not return @c Allow to
     * express uncertainty.
     */
    [[nodiscard]] virtual AuthorizationDecision evaluate(const AuthorizationRequest& request) = 0;

protected:
    PolicyEngine() = default;
};

/**
 * @brief Evaluates a protected operation, failing closed on every non-Allow outcome.
 *
 * The single entry point protected operations should use. It exists so that
 * "protected operations default to deny when authorization cannot be
 * established" is implemented once rather than restated at every call site.
 *
 * A null engine is treated as @c Indeterminate rather than dereferenced: a
 * misconfigured composition root must deny, not crash and not permit.
 */
[[nodiscard]] AuthorizationDecision evaluateProtected(PolicyEngine* engine,
                                                      const AuthorizationRequest& request);

}

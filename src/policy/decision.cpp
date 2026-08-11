module;

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.policy;

namespace openproof::policy {

AuthenticationContext::AuthenticationContext(
    const authentication::VerifiedAuthentication& authentication)
    : m_providerId(authentication.outcome().provider())
    , m_claimedAssurance(authentication.outcome().claimedAssurance())
    , m_strength(authentication.outcome().strength())
    , m_authenticatedAt(authentication.outcome().verifiedAt())
{
}

bool AuthenticationContext::isAuthenticated() const noexcept
{
    return true;
}

const identity::provider::ProviderId& AuthenticationContext::providerId() const noexcept
{
    return m_providerId;
}

identity::provider::AssuranceLevel AuthenticationContext::claimedAssurance() const noexcept
{
    return m_claimedAssurance;
}

const identity::provider::AuthenticationStrength& AuthenticationContext::strength() const noexcept
{
    return m_strength;
}

foundation::Instant AuthenticationContext::authenticatedAt() const noexcept
{
    return m_authenticatedAt;
}

AuthorizationRequest::AuthorizationRequest(identity::core::IdentityId subject,
                                           identity::core::OrganizationId organization,
                                           AuthenticationContext authentication,
                                           std::vector<Role> roles, Action action,
                                           Resource resource)
    : m_subject(std::move(subject))
    , m_action(std::move(action))
    , m_resource(std::move(resource))
    , m_organization(std::move(organization))
    , m_authentication(std::move(authentication))
    , m_roles(std::move(roles))
{
}

foundation::Result<AuthorizationRequest> AuthorizationRequest::create(
    const authentication::VerifiedAuthentication& authentication,
    const identity::core::OrganizationId& organizationId,
    const organization::OrganizationRepository& organizations,
    const identity::core::IdentityRepository& identities,
    const organization::MembershipRepository& memberships,
    Action action, Resource resource)
{
    if (action.empty() || resource.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An authorization request must name an action and resource.");
    }

    foundation::Result<std::optional<organization::Organization>> organization =
        organizations.findById(organizationId);
    if (!organization.has_value()) {
        return foundation::fail(organization.error());
    }
    if (!organization->has_value() || !organization->value().isUsable()) {
        return foundation::fail(
            foundation::ErrorCode::PermissionDenied,
            std::string{foundation::defaultErrorMessage(foundation::ErrorCode::PermissionDenied)},
            "Authorization context creation refused: organization is absent or inactive.");
    }
    if (organization->value().id() != organizationId) {
        return foundation::fail(
            foundation::ErrorCode::PermissionDenied,
            std::string{foundation::defaultErrorMessage(foundation::ErrorCode::PermissionDenied)},
            "Authorization context creation refused: repository returned an organization "
            "under the wrong key.");
    }

    foundation::Result<std::optional<identity::core::Identity>> identity =
        identities.findById(organizationId, authentication.identity());
    if (!identity.has_value()) {
        return foundation::fail(identity.error());
    }
    if (!identity->has_value()) {
        return foundation::fail(
            foundation::ErrorCode::PermissionDenied,
            std::string{foundation::defaultErrorMessage(foundation::ErrorCode::PermissionDenied)},
            "Authorization context creation refused: authenticated identity is absent from "
            "the requested organization.");
    }
    if (identity->value().id() != authentication.identity()) {
        return foundation::fail(
            foundation::ErrorCode::PermissionDenied,
            std::string{foundation::defaultErrorMessage(foundation::ErrorCode::PermissionDenied)},
            "Authorization context creation refused: repository returned an identity under "
            "the wrong key.");
    }
    if (!identity->value().canAuthenticate()) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "The subject cannot perform protected operations.",
            "Authorization context creation refused because the canonical identity is not active.");
    }

    foundation::Result<std::optional<organization::Membership>> membership =
        memberships.find(organizationId, authentication.identity());
    if (!membership.has_value()) {
        return foundation::fail(membership.error());
    }
    if (!membership->has_value() || !organization::permitsAccess(membership->value().state())) {
        return foundation::fail(
            foundation::ErrorCode::PermissionDenied,
            std::string{foundation::defaultErrorMessage(foundation::ErrorCode::PermissionDenied)},
            "Authorization context creation refused: membership is absent or inactive.");
    }
    if (membership->value().identity() != identity->value().id()
        || membership->value().organization() != organizationId) {
        return foundation::fail(
            foundation::ErrorCode::PermissionDenied,
            std::string{foundation::defaultErrorMessage(foundation::ErrorCode::PermissionDenied)},
            "Authorization context creation refused: repository returned a membership under "
            "the wrong key.");
    }

    return AuthorizationRequest{identity->value().id(), organizationId,
                                AuthenticationContext{authentication},
                                membership->value().roles(), std::move(action),
                                std::move(resource)};
}

const identity::core::IdentityId& AuthorizationRequest::subject() const noexcept
{
    return m_subject;
}

const Action& AuthorizationRequest::action() const noexcept
{
    return m_action;
}

const Resource& AuthorizationRequest::resource() const noexcept
{
    return m_resource;
}

const identity::core::OrganizationId& AuthorizationRequest::organization() const noexcept
{
    return m_organization;
}

const AuthenticationContext& AuthorizationRequest::authentication() const noexcept
{
    return m_authentication;
}

const std::vector<Role>& AuthorizationRequest::roles() const noexcept
{
    return m_roles;
}

const std::vector<Permission>& AuthorizationRequest::permissions() const noexcept
{
    return m_permissions;
}

const std::vector<Entitlement>& AuthorizationRequest::entitlements() const noexcept
{
    return m_entitlements;
}

bool AuthorizationRequest::hasEntitlement(const Entitlement& entitlement) const
{
    return std::ranges::find(m_entitlements, entitlement) != m_entitlements.end();
}

bool AuthorizationRequest::hasRole(const Role& role) const
{
    return std::ranges::find(m_roles, role) != m_roles.end();
}

std::string_view decisionKindName(DecisionKind kind) noexcept
{
    switch (kind) {
    case DecisionKind::Allow:
        return "allow";
    case DecisionKind::Deny:
        return "deny";
    case DecisionKind::NotApplicable:
        return "not_applicable";
    case DecisionKind::Indeterminate:
        return "indeterminate";
    }
    return "indeterminate";
}

AuthorizationDecision::AuthorizationDecision(DecisionKind kind, std::string reason)
    : m_kind(kind)
    , m_reason(std::move(reason))
{
}

AuthorizationDecision AuthorizationDecision::allow(std::string reason)
{
    return AuthorizationDecision{DecisionKind::Allow, std::move(reason)};
}

AuthorizationDecision AuthorizationDecision::deny(std::string reason)
{
    return AuthorizationDecision{DecisionKind::Deny, std::move(reason)};
}

AuthorizationDecision AuthorizationDecision::notApplicable(std::string reason)
{
    return AuthorizationDecision{DecisionKind::NotApplicable, std::move(reason)};
}

AuthorizationDecision AuthorizationDecision::indeterminate(std::string reason)
{
    return AuthorizationDecision{DecisionKind::Indeterminate, std::move(reason)};
}

DecisionKind AuthorizationDecision::kind() const noexcept
{
    return m_kind;
}

std::string_view AuthorizationDecision::reason() const noexcept
{
    return m_reason;
}

bool AuthorizationDecision::isPermitted() const noexcept
{
    // Written as an allow-list of exactly one value. A deny-list spelling would
    // silently permit any decision kind added later.
    return m_kind == DecisionKind::Allow;
}

AuthorizationDecision evaluateProtected(PolicyEngine* engine,
                                        const AuthorizationRequest& request)
{
    if (engine == nullptr) {
        // A composition root that failed to install a policy engine must deny.
        // Dereferencing would crash the process and permitting would be worse.
        return AuthorizationDecision::indeterminate(
            "No policy engine is installed; the protected operation was denied.");
    }

    const AuthorizationDecision decision = engine->evaluate(request);
    if (decision.isPermitted()) {
        return decision;
    }

    // Every non-Allow outcome is returned unchanged rather than rewritten to
    // Deny: the caller is denied either way through isPermitted(), and an
    // operator still needs to see whether the cause was an explicit refusal, an
    // unmatched policy, or an engine that could not run.
    return decision;
}

}

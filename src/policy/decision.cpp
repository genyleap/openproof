module;

#include <algorithm>
#include <memory>
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

AuthenticationContext::AuthenticationContext(
    const session::AuthenticatedSession& authenticatedSession)
    : m_providerId(authenticatedSession.session().provider())
    , m_claimedAssurance(authenticatedSession.session().assurance())
    , m_strength(authenticatedSession.session().strength())
    , m_authenticatedAt(authenticatedSession.session().authenticatedAt())
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
    return createResolved(authentication.identity(), AuthenticationContext{authentication},
                          organizationId, organizations, identities, memberships,
                          std::move(action), std::move(resource));
}

foundation::Result<AuthorizationRequest> AuthorizationRequest::create(
    const session::AuthenticatedSession& authenticatedSession,
    const identity::core::OrganizationId& organizationId,
    const organization::OrganizationRepository& organizations,
    const identity::core::IdentityRepository& identities,
    const organization::MembershipRepository& memberships,
    Action action, Resource resource)
{
    return createResolved(authenticatedSession.session().identity(),
                          AuthenticationContext{authenticatedSession},
                          organizationId, organizations, identities, memberships,
                          std::move(action), std::move(resource));
}

foundation::Result<AuthorizationRequest> AuthorizationRequest::createResolved(
    identity::core::IdentityId authenticatedIdentity,
    AuthenticationContext authenticationContext,
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
        identities.findById(organizationId, authenticatedIdentity);
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
    if (identity->value().id() != authenticatedIdentity) {
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
        memberships.find(organizationId, authenticatedIdentity);
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
                                std::move(authenticationContext),
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

std::string_view roleMatchModeName(RoleMatchMode mode) noexcept
{
    switch (mode) {
    case RoleMatchMode::Any: return "any";
    case RoleMatchMode::All: return "all";
    }
    return "all";
}

RolePolicyRule::RolePolicyRule(
    Action actionValue, Resource resourceValue,
    std::vector<Role> requiredRolesValue, RoleMatchMode roleMatchValue,
    identity::provider::AssuranceLevel minimumAssuranceValue)
    : m_action(std::move(actionValue)), m_resource(std::move(resourceValue)),
      m_requiredRoles(std::move(requiredRolesValue)),
      m_roleMatch(roleMatchValue), m_minimumAssurance(minimumAssuranceValue)
{
}

foundation::Result<RolePolicyRule> RolePolicyRule::create(
    Action action, Resource resource, std::vector<Role> requiredRoles,
    RoleMatchMode roleMatch,
    identity::provider::AssuranceLevel minimumAssurance)
{
    const bool recognizedMode = roleMatch == RoleMatchMode::Any
        || roleMatch == RoleMatchMode::All;
    const bool recognizedAssurance =
        minimumAssurance >= identity::provider::AssuranceLevel::Ial1
        && minimumAssurance <= identity::provider::AssuranceLevel::Ial4;
    if (action.empty() || resource.empty() || requiredRoles.empty()
        || requiredRoles.size() > 16U || !recognizedMode
        || !recognizedAssurance
        || std::ranges::any_of(requiredRoles, [](const Role& role) {
               return role.empty() || role.value().size() > 200U
                   || std::ranges::any_of(role.value(), [](char symbol) {
                          const auto byte = static_cast<unsigned char>(symbol);
                          return byte < 0x21U || byte == 0x7FU;
                      });
           })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The route authorization rule is invalid.");
    }
    std::ranges::sort(requiredRoles);
    if (std::ranges::adjacent_find(requiredRoles) != requiredRoles.end()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Required route roles must be unique.");
    }
    return RolePolicyRule{std::move(action), std::move(resource),
                          std::move(requiredRoles), roleMatch,
                          minimumAssurance};
}

const Action& RolePolicyRule::action() const noexcept { return m_action; }
const Resource& RolePolicyRule::resource() const noexcept { return m_resource; }
const std::vector<Role>& RolePolicyRule::requiredRoles() const noexcept
{ return m_requiredRoles; }
RoleMatchMode RolePolicyRule::roleMatch() const noexcept { return m_roleMatch; }
identity::provider::AssuranceLevel
RolePolicyRule::minimumAssurance() const noexcept { return m_minimumAssurance; }

RolePolicyEngine::RolePolicyEngine(std::vector<RolePolicyRule> rules)
    : m_rules(std::move(rules))
{
}

foundation::Result<std::unique_ptr<RolePolicyEngine>>
RolePolicyEngine::create(std::vector<RolePolicyRule> rules)
{
    if (rules.empty() || rules.size() > 256U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "At least one bounded route policy is required.");
    }
    std::ranges::sort(rules, {}, [](const RolePolicyRule& rule) {
        return std::pair{rule.action(), rule.resource()};
    });
    if (std::ranges::adjacent_find(
            rules, {}, [](const RolePolicyRule& rule) {
                return std::pair{rule.action(), rule.resource()};
            }) != rules.end()) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "A route policy is duplicated.");
    }
    return std::unique_ptr<RolePolicyEngine>{
        new RolePolicyEngine{std::move(rules)}};
}

AuthorizationDecision RolePolicyEngine::evaluate(
    const AuthorizationRequest& request)
{
    const auto rule = std::ranges::find_if(m_rules, [&](const RolePolicyRule& item) {
        return item.action() == request.action()
            && item.resource() == request.resource();
    });
    if (rule == m_rules.end()) {
        return AuthorizationDecision::notApplicable(
            "No exact route authorization rule matched.");
    }
    if (!identity::provider::meetsAssurance(
            request.authentication().claimedAssurance(),
            rule->minimumAssurance())) {
        return AuthorizationDecision::deny(
            "The authenticated session does not meet the route assurance requirement.");
    }
    const auto holds = [&](const Role& role) { return request.hasRole(role); };
    const bool permitted = rule->roleMatch() == RoleMatchMode::All
        ? std::ranges::all_of(rule->requiredRoles(), holds)
        : std::ranges::any_of(rule->requiredRoles(), holds);
    return permitted
        ? AuthorizationDecision::allow(
              "The trusted membership satisfies the route role policy.")
        : AuthorizationDecision::deny(
              "The trusted membership does not satisfy the route role policy.");
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

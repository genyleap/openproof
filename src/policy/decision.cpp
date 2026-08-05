module;

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.policy;

namespace openproof::policy {

AuthenticationContext::AuthenticationContext(identity::provider::ProviderId providerId,
                                             identity::provider::AssuranceLevel claimedAssurance,
                                             identity::provider::AuthenticationStrength strength,
                                             foundation::Instant authenticatedAt)
    : m_authenticated(true)
    , m_providerId(std::move(providerId))
    , m_claimedAssurance(claimedAssurance)
    , m_strength(strength)
    , m_authenticatedAt(authenticatedAt)
{
}

bool AuthenticationContext::isAuthenticated() const noexcept
{
    return m_authenticated;
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

AuthorizationRequest::AuthorizationRequest(identity::core::IdentityId subject, Action action,
                                           Resource resource)
    : m_subject(std::move(subject))
    , m_action(std::move(action))
    , m_resource(std::move(resource))
{
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

const std::optional<identity::core::OrganizationId>&
AuthorizationRequest::organization() const noexcept
{
    return m_organization;
}

AuthorizationRequest&
AuthorizationRequest::withOrganization(identity::core::OrganizationId organization)
{
    m_organization = std::move(organization);
    return *this;
}

const AuthenticationContext& AuthorizationRequest::authentication() const noexcept
{
    return m_authentication;
}

AuthorizationRequest& AuthorizationRequest::withAuthentication(AuthenticationContext context)
{
    m_authentication = std::move(context);
    return *this;
}

const std::vector<Role>& AuthorizationRequest::roles() const noexcept
{
    return m_roles;
}

AuthorizationRequest& AuthorizationRequest::withRole(Role role)
{
    m_roles.push_back(std::move(role));
    return *this;
}

const std::vector<Permission>& AuthorizationRequest::permissions() const noexcept
{
    return m_permissions;
}

AuthorizationRequest& AuthorizationRequest::withPermission(Permission permission)
{
    m_permissions.push_back(std::move(permission));
    return *this;
}

const std::vector<Entitlement>& AuthorizationRequest::entitlements() const noexcept
{
    return m_entitlements;
}

AuthorizationRequest& AuthorizationRequest::withEntitlement(Entitlement entitlement)
{
    m_entitlements.push_back(std::move(entitlement));
    return *this;
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

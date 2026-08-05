#include <gtest/gtest.h>

#include <chrono>
#include <type_traits>
#include <utility>
#include <string>

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.policy;

namespace fnd = openproof::foundation;
namespace core = openproof::identity::core;
namespace idp = openproof::identity::provider;
namespace pol = openproof::policy;

namespace {

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

[[nodiscard]] pol::AuthorizationRequest baseRequest()
{
    return pol::AuthorizationRequest{core::IdentityId{"id-1"}, pol::Action{"agent.execute"},
                                     pol::Resource{"billing:invoice/42"}};
}

/** A stub engine returning a fixed decision, used to test the fail-closed wrapper. */
class FixedEngine final : public pol::PolicyEngine {
public:
    explicit FixedEngine(pol::AuthorizationDecision decision)
        : m_decision(std::move(decision))
    {
    }

    [[nodiscard]] pol::AuthorizationDecision
    evaluate(const pol::AuthorizationRequest&) override
    {
        return m_decision;
    }

private:
    pol::AuthorizationDecision m_decision;
};

/** An engine whose dependency is unavailable. It must not throw and must not allow. */
class UnavailableEngine final : public pol::PolicyEngine {
public:
    [[nodiscard]] pol::AuthorizationDecision
    evaluate(const pol::AuthorizationRequest&) override
    {
        return pol::AuthorizationDecision::indeterminate("policy store unreachable");
    }
};

// --- The four-valued outcome ------------------------------------------------

// Only Allow permits. This is the whole point of not using a boolean: an
// unmatched policy and a broken engine are distinct facts, and neither is
// permission.
TEST(AuthorizationDecisionTest, OnlyAllowPermits)
{
    EXPECT_TRUE(pol::AuthorizationDecision::allow("matched").isPermitted());
    EXPECT_FALSE(pol::AuthorizationDecision::deny("refused").isPermitted());
    EXPECT_FALSE(pol::AuthorizationDecision::notApplicable("no policy matched").isPermitted());
    EXPECT_FALSE(pol::AuthorizationDecision::indeterminate("engine failed").isPermitted());
}

TEST(AuthorizationDecisionTest, KindsRemainDistinguishable)
{
    EXPECT_EQ(pol::AuthorizationDecision::deny("r").kind(), pol::DecisionKind::Deny);
    EXPECT_EQ(pol::AuthorizationDecision::notApplicable("r").kind(),
              pol::DecisionKind::NotApplicable);
    EXPECT_EQ(pol::AuthorizationDecision::indeterminate("r").kind(),
              pol::DecisionKind::Indeterminate);

    // Not collapsed into one another.
    EXPECT_NE(pol::AuthorizationDecision::notApplicable("r").kind(), pol::DecisionKind::Deny);
    EXPECT_NE(pol::AuthorizationDecision::indeterminate("r").kind(), pol::DecisionKind::Deny);
}

TEST(AuthorizationDecisionTest, CarriesAReason)
{
    const auto decision = pol::AuthorizationDecision::deny("subject lacks role owner");
    EXPECT_EQ(decision.reason(), "subject lacks role owner");
    EXPECT_FALSE(pol::decisionKindName(decision.kind()).empty());
}

// --- Fail-closed ------------------------------------------------------------

TEST(EvaluateProtectedTest, PermitsOnlyAnExplicitAllow)
{
    FixedEngine allow{pol::AuthorizationDecision::allow("ok")};
    EXPECT_TRUE(pol::evaluateProtected(&allow, baseRequest()).isPermitted());

    FixedEngine deny{pol::AuthorizationDecision::deny("nope")};
    EXPECT_FALSE(pol::evaluateProtected(&deny, baseRequest()).isPermitted());
}

// Infrastructure failure must never become authorization success.
TEST(EvaluateProtectedTest, AnUnavailableEngineDeniesAndStaysDiagnosable)
{
    UnavailableEngine engine;

    const pol::AuthorizationDecision decision = pol::evaluateProtected(&engine, baseRequest());

    EXPECT_FALSE(decision.isPermitted());
    EXPECT_EQ(decision.kind(), pol::DecisionKind::Indeterminate)
        << "an engine failure must stay distinguishable from an explicit denial";
}

TEST(EvaluateProtectedTest, NoPolicyMatchedIsNotPermission)
{
    FixedEngine engine{pol::AuthorizationDecision::notApplicable("no rule matched")};

    const pol::AuthorizationDecision decision = pol::evaluateProtected(&engine, baseRequest());

    EXPECT_FALSE(decision.isPermitted());
    EXPECT_EQ(decision.kind(), pol::DecisionKind::NotApplicable);
}

// A composition root that forgot to install an engine must deny, not crash and
// not permit.
TEST(EvaluateProtectedTest, AMissingEngineDeniesWithoutDereferencing)
{
    const pol::AuthorizationDecision decision = pol::evaluateProtected(nullptr, baseRequest());

    EXPECT_FALSE(decision.isPermitted());
    EXPECT_EQ(decision.kind(), pol::DecisionKind::Indeterminate);
}

// --- Authentication does not imply authorization ----------------------------

// A fully authenticated, high-assurance subject is still denied when no policy
// permits the action. Authentication answers "who"; it grants nothing.
TEST(AuthorizationRequestTest, AuthenticationAloneGrantsNothing)
{
    pol::AuthenticationContext authenticated{
        idp::ProviderId{"some-provider"}, idp::AssuranceLevel::Ial4,
        idp::AuthenticationStrength{idp::AuthenticationFactor::Possession
                                        | idp::AuthenticationFactor::Inherence,
                                    true},
        kNow};

    pol::AuthorizationRequest request = baseRequest();
    request.withAuthentication(std::move(authenticated));

    EXPECT_TRUE(request.authentication().isAuthenticated());
    EXPECT_EQ(request.authentication().claimedAssurance(), idp::AssuranceLevel::Ial4);

    FixedEngine engine{pol::AuthorizationDecision::notApplicable("no rule matched")};
    EXPECT_FALSE(pol::evaluateProtected(&engine, request).isPermitted());
}

// The converse: a decision object carries no identity, so an Allow cannot be
// mistaken for evidence that anyone authenticated.
TEST(AuthorizationRequestTest, AnUnauthenticatedContextIsTheDefault)
{
    const pol::AuthorizationRequest request = baseRequest();

    EXPECT_FALSE(request.authentication().isAuthenticated());
    EXPECT_EQ(request.authentication().claimedAssurance(), idp::AssuranceLevel::Ial0);
}

// --- Organization scoping ---------------------------------------------------

// Roles are organization-scoped. A request without an organization carries no
// organization roles, so a global role cannot stand in for one.
TEST(AuthorizationRequestTest, RolesAreCarriedWithOrganizationContext)
{
    pol::AuthorizationRequest request = baseRequest();
    EXPECT_FALSE(request.organization().has_value());

    request.withOrganization(core::OrganizationId{"org-a"}).withRole(pol::Role{"owner"});

    ASSERT_TRUE(request.organization().has_value());
    EXPECT_EQ(request.organization()->value(), "org-a");
    EXPECT_TRUE(request.hasRole(pol::Role{"owner"}));
    EXPECT_FALSE(request.hasRole(pol::Role{"viewer"}));
}

TEST(AuthorizationRequestTest, EntitlementsAreConsumedNotComputed)
{
    pol::AuthorizationRequest request = baseRequest();
    request.withEntitlement(pol::Entitlement{"analytics.pro"});

    EXPECT_TRUE(request.hasEntitlement(pol::Entitlement{"analytics.pro"}));
    EXPECT_FALSE(request.hasEntitlement(pol::Entitlement{"storage.pro"}));
}

TEST(AuthorizationRequestTest, CarriesSubjectActionAndResource)
{
    const pol::AuthorizationRequest request = baseRequest();

    EXPECT_EQ(request.subject().value(), "id-1");
    EXPECT_EQ(request.action().value(), "agent.execute");
    EXPECT_EQ(request.resource().value(), "billing:invoice/42");
}

// Policy vocabulary must not be interchangeable with identity vocabulary.
static_assert(!std::is_convertible_v<pol::Role, pol::Permission>);
static_assert(!std::is_convertible_v<pol::Entitlement, pol::Role>);
static_assert(!std::is_convertible_v<pol::Action, pol::Resource>);
static_assert(!std::is_convertible_v<core::IdentityId, pol::Resource>);

}

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <type_traits>
#include <utility>
#include <string>

import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.organization;
import openproof.policy;
import openproof.security;

namespace auth = openproof::authentication;
namespace fnd = openproof::foundation;
namespace core = openproof::identity::core;
namespace idp = openproof::identity::provider;
namespace org = openproof::organization;
namespace pol = openproof::policy;
namespace sec = openproof::security;

namespace {

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

class PolicyTestProvider final : public idp::AuthenticationProvider {
public:
    [[nodiscard]] idp::ProviderId id() const override
    {
        return idp::ProviderId{"policy-test"};
    }

    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override
    {
        return idp::InteractionModel::ChallengeResponse;
    }

    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override
    {
        return idp::AssuranceLevel::Ial4;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest&) override
    {
        return idp::AuthenticationChallenge{idp::ChallengeId{"challenge-policy"},
                                            kNow + std::chrono::minutes{5}};
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse& response) override
    {
        const auto proof = response.parameters().find("proof");
        if (proof == response.parameters().end() || proof->second.expose() != "valid") {
            return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        }
        return idp::AuthenticationOutcome::create(
            id(), idp::ExternalSubject{"subject-policy"}, idp::VerifiedClaims{},
            idp::AssuranceLevel::Ial4,
            idp::AuthenticationStrength{idp::AuthenticationFactor::Possession
                                            | idp::AuthenticationFactor::Inherence,
                                        true},
            idp::ProviderEvidence{}, kNow);
    }
};

[[nodiscard]] idp::BindingDigest bindingOf(std::string_view value)
{
    return sec::sha256(value).value_or(idp::BindingDigest{});
}

[[nodiscard]] auth::VerifiedAuthentication verifiedAuthentication()
{
    idp::ProviderRegistry providers;
    EXPECT_TRUE(providers.registerProvider(std::make_unique<PolicyTestProvider>()).has_value());
    idp::InMemoryAuthenticationTransactionStore transactions;
    fnd::ManualClockSource clock{kNow};
    auth::ProviderTrustPolicy trust;
    EXPECT_TRUE(trust.trust(idp::ProviderId{"policy-test"}, idp::AssuranceLevel::Ial4)
                    .has_value());
    core::InMemoryExternalIdentityDirectory identities;
    core::IdentityLink link =
        core::IdentityLink::request(
            core::IdentityId{"id-1"},
            core::ExternalIdentityRef{idp::ProviderId{"policy-test"},
                                      idp::ExternalSubject{"subject-policy"}},
            kNow, std::chrono::minutes{5})
            .value();
    EXPECT_TRUE(link.requireVerification(kNow).has_value());
    EXPECT_TRUE(link.markVerified(kNow).has_value());
    EXPECT_TRUE(link.complete(kNow).has_value());
    EXPECT_TRUE(identities.attach(link).has_value());
    auth::AuthenticationService service{providers, transactions, identities, clock,
                                        std::move(trust), std::chrono::minutes{5}};

    idp::AuthenticationRequest request{idp::ProviderId{"policy-test"}, idp::ClientContext{}};
    request.setRequestedAssurance(idp::AssuranceLevel::Ial4);
    const idp::BindingDigest binding = bindingOf("policy-preauth");
    auto started = service.begin(request, binding, fnd::CorrelationId{"corr-policy"});
    EXPECT_TRUE(started.has_value());

    idp::AuthenticationResponse response{started->challenge().id(), idp::ClientContext{}};
    response.setParameter("proof", idp::CredentialValue{"valid"});
    auto completed = service.complete(started->transactionId(), started->continuationToken(),
                                      binding, response);
    EXPECT_TRUE(completed.has_value());
    return std::move(completed).value();
}

[[nodiscard]] core::Identity activeIdentity(std::string id = "id-1")
{
    return core::Identity::create(core::IdentityId{std::move(id)}, core::SubjectKind::Human, kNow)
        .value();
}

[[nodiscard]] org::Membership activeMembership(std::string identity = "id-1")
{
    org::Membership membership =
        org::Membership::invite(core::OrganizationId{"org-a"},
                                core::IdentityId{std::move(identity)}, kNow)
            .value();
    EXPECT_TRUE(membership.accept().has_value());
    EXPECT_TRUE(membership.grantRole(org::Role{"owner"}).has_value());
    return membership;
}

[[nodiscard]] fnd::Result<pol::AuthorizationRequest> persistedRequest(
    const auth::VerifiedAuthentication& authentication, core::Identity identity,
    org::Membership membership,
    org::OrganizationStatus organizationStatus = org::OrganizationStatus::Active)
{
    org::InMemoryOrganizationRepository organizations;
    core::InMemoryIdentityRepository identities;
    org::InMemoryMembershipRepository memberships;

    org::Organization organization =
        org::Organization::create(core::OrganizationId{"org-a"}, "Organization A", kNow)
            .value();
    if (organizationStatus != org::OrganizationStatus::Active) {
        EXPECT_TRUE(organization.changeStatus(organizationStatus).has_value());
    }
    EXPECT_TRUE(organizations.add(std::move(organization)).has_value());
    EXPECT_TRUE(identities.add(core::OrganizationId{"org-a"}, std::move(identity)).has_value());
    EXPECT_TRUE(memberships.add(std::move(membership)).has_value());

    return pol::AuthorizationRequest::create(
        authentication, core::OrganizationId{"org-a"}, organizations, identities,
        memberships, pol::Action{"agent.execute"}, pol::Resource{"billing:invoice/42"});
}

[[nodiscard]] pol::AuthorizationRequest baseRequest()
{
    const auth::VerifiedAuthentication authentication = verifiedAuthentication();
    return persistedRequest(authentication, activeIdentity(), activeMembership())
        .value();
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
    const pol::AuthorizationRequest request = baseRequest();

    EXPECT_TRUE(request.authentication().isAuthenticated());
    EXPECT_EQ(request.authentication().claimedAssurance(), idp::AssuranceLevel::Ial4);

    FixedEngine engine{pol::AuthorizationDecision::notApplicable("no rule matched")};
    EXPECT_FALSE(pol::evaluateProtected(&engine, request).isPermitted());
}

// Raw provider values cannot construct an authentication context. Only the
// wrapper minted by AuthenticationService can cross this boundary.
TEST(AuthorizationRequestTest, RawProviderValuesCannotForgeAuthenticationContext)
{
    const pol::AuthorizationRequest request = baseRequest();

    EXPECT_TRUE(request.authentication().isAuthenticated());
    static_assert(!std::is_constructible_v<pol::AuthenticationContext,
                                           idp::ProviderId, idp::AssuranceLevel,
                                           idp::AuthenticationStrength, fnd::Instant>);
}

// --- Organization scoping ---------------------------------------------------

// Roles are organization-scoped. A request without an organization carries no
// organization roles, so a global role cannot stand in for one.
TEST(AuthorizationRequestTest, RolesAreCarriedWithOrganizationContext)
{
    const pol::AuthorizationRequest request = baseRequest();

    EXPECT_EQ(request.organization().value(), "org-a");
    EXPECT_TRUE(request.hasRole(pol::Role{"owner"}));
    EXPECT_FALSE(request.hasRole(pol::Role{"viewer"}));
}

TEST(AuthorizationRequestTest, UntrustedEntitlementsCannotBeInjected)
{
    const pol::AuthorizationRequest request = baseRequest();

    EXPECT_FALSE(request.hasEntitlement(pol::Entitlement{"analytics.pro"}));
    EXPECT_FALSE(request.hasEntitlement(pol::Entitlement{"storage.pro"}));
}

TEST(AuthorizationRequestTest, RefusesAMembershipBelongingToAnotherIdentity)
{
    const auth::VerifiedAuthentication authentication = verifiedAuthentication();
    const core::Identity identity = activeIdentity("id-1");
    const org::Membership foreignMembership = activeMembership("id-2");

    const auto request = persistedRequest(authentication, identity, foreignMembership);

    ASSERT_FALSE(request.has_value());
    EXPECT_EQ(request.error().code(), fnd::ErrorCode::PermissionDenied);
}

TEST(AuthorizationRequestTest, RefusesToCombineAuthenticationWithAnotherIdentity)
{
    const auth::VerifiedAuthentication authentication = verifiedAuthentication();
    const core::Identity otherIdentity = activeIdentity("id-2");
    const org::Membership otherMembership = activeMembership("id-2");

    const auto request = persistedRequest(authentication, otherIdentity, otherMembership);

    ASSERT_FALSE(request.has_value());
    EXPECT_EQ(request.error().code(), fnd::ErrorCode::PermissionDenied);
}

TEST(AuthorizationRequestTest, RefusesAnInactiveMembership)
{
    const auth::VerifiedAuthentication authentication = verifiedAuthentication();
    org::Membership membership = activeMembership();
    ASSERT_TRUE(membership.suspend().has_value());

    const auto request = persistedRequest(authentication, activeIdentity(), membership);

    ASSERT_FALSE(request.has_value());
    EXPECT_EQ(request.error().code(), fnd::ErrorCode::PermissionDenied);
}

TEST(AuthorizationRequestTest, RefusesAnInactiveCanonicalIdentityFromTheRepository)
{
    const auth::VerifiedAuthentication authentication = verifiedAuthentication();
    core::Identity identity = activeIdentity();
    ASSERT_TRUE(identity.changeStatus(core::IdentityStatus::Suspended).has_value());

    const auto request = persistedRequest(authentication, identity, activeMembership());

    ASSERT_FALSE(request.has_value());
    EXPECT_EQ(request.error().code(), fnd::ErrorCode::FailedPrecondition);
}

TEST(AuthorizationRequestTest, RefusesAnInactiveOrganizationFromTheRepository)
{
    const auth::VerifiedAuthentication authentication = verifiedAuthentication();

    const auto request = persistedRequest(authentication, activeIdentity(), activeMembership(),
                                          org::OrganizationStatus::Suspended);

    ASSERT_FALSE(request.has_value());
    EXPECT_EQ(request.error().code(), fnd::ErrorCode::PermissionDenied);
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
static_assert(!std::is_constructible_v<pol::AuthorizationRequest, core::IdentityId,
                                       pol::Action, pol::Resource>);
static_assert(!std::is_constructible_v<auth::VerifiedAuthentication,
                                       idp::AuthenticationOutcome, core::IdentityId>);

}

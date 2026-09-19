#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.security;
import openproof.session;

namespace auth = openproof::authentication;
namespace core = openproof::identity::core;
namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace sec = openproof::security;
namespace sess = openproof::session;

namespace {

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

class SessionTestProvider final : public idp::AuthenticationProvider {
public:
    [[nodiscard]] idp::ProviderId id() const override
    {
        return idp::ProviderId{"session-test"};
    }

    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override
    {
        return idp::InteractionModel::ChallengeResponse;
    }

    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override
    {
        return idp::AssuranceLevel::Ial3;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest&) override
    {
        return idp::AuthenticationChallenge{idp::ChallengeId{"session-challenge"},
                                            kNow + std::chrono::minutes{5}};
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse&) override
    {
        return idp::AuthenticationOutcome::create(
            id(), idp::ExternalSubject{"external-1"}, idp::VerifiedClaims{},
            idp::AssuranceLevel::Ial3,
            idp::AuthenticationStrength{idp::AuthenticationFactor::Possession
                                            | idp::AuthenticationFactor::Inherence,
                                        true},
            idp::ProviderEvidence{}, kNow);
    }
};

[[nodiscard]] idp::BindingDigest binding()
{
    return sec::sha256("session-binding").value();
}

[[nodiscard]] auth::VerifiedAuthentication verifiedAuthentication()
{
    idp::ProviderRegistry providers;
    EXPECT_TRUE(providers.registerProvider(std::make_unique<SessionTestProvider>()).has_value());
    idp::InMemoryAuthenticationTransactionStore transactions;
    core::InMemoryExternalIdentityDirectory identities;
    core::IdentityLink link =
        core::IdentityLink::request(
            core::IdentityId{"identity-1"},
            core::ExternalIdentityRef{idp::ProviderId{"session-test"},
                                      idp::ExternalSubject{"external-1"}},
            kNow, std::chrono::minutes{5})
            .value();
    EXPECT_TRUE(link.requireVerification(kNow).has_value());
    EXPECT_TRUE(link.markVerified(kNow).has_value());
    EXPECT_TRUE(link.complete(kNow).has_value());
    EXPECT_TRUE(identities.attach(link).has_value());

    auth::ProviderTrustPolicy trust;
    EXPECT_TRUE(trust.trust(idp::ProviderId{"session-test"}, idp::AssuranceLevel::Ial3)
                    .has_value());
    fnd::ManualClockSource clock{kNow};
    auth::AuthenticationService service{providers, transactions, identities, clock,
                                        std::move(trust), std::chrono::minutes{5}};
    idp::AuthenticationRequest request{idp::ProviderId{"session-test"},
                                       idp::ClientContext{}};
    request.setRequestedAssurance(idp::AssuranceLevel::Ial3);
    auto started = service.begin(request, binding(), fnd::CorrelationId{"session-corr"});
    EXPECT_TRUE(started.has_value());
    idp::AuthenticationResponse response{started->challenge().id(), idp::ClientContext{}};
    auto completed = service.complete(started->transactionId(), started->continuationToken(),
                                      binding(), response);
    EXPECT_TRUE(completed.has_value());
    return std::move(completed).value();
}

[[nodiscard]] sess::SessionKey sessionKey()
{
    return sess::SessionKey::create(
               fnd::SecretString{"0123456789abcdef0123456789abcdef"})
        .value();
}

[[nodiscard]] sess::SessionPolicy sessionPolicy(
    fnd::Duration absolute = std::chrono::hours{8},
    fnd::Duration idle = std::chrono::minutes{30})
{
    return sess::SessionPolicy::create(absolute, idle).value();
}

struct Fixture {
    Fixture()
        : clock(kNow)
        , service(sessions, clock, sessionKey(), sessionPolicy())
    {
    }

    sess::InMemorySessionRepository sessions;
    fnd::ManualClockSource clock;
    sess::SessionService service;
};

class DelegatedAuthenticator final : public sess::DelegatedAccessAuthenticator {
public:
    explicit DelegatedAuthenticator(std::vector<std::string> scopes,
                                    bool senderConstrained = false)
        : m_scopes(std::move(scopes)), m_senderConstrained(senderConstrained) {}

    [[nodiscard]] fnd::Result<sess::DelegatedAccess>
    authenticateDelegated(const fnd::SecretString& token) override
    {
        if (token.expose() != "delegated-token") {
            return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        }
        auto authenticated = sess::AuthenticatedSession::fromDelegatedAccess(
            core::IdentityId{"delegated-identity"}, idp::ProviderId{"oauth"},
            idp::AssuranceLevel::Ial2,
            idp::AuthenticationStrength{idp::AuthenticationFactor::Knowledge, false},
            kNow, kNow, kNow + std::chrono::minutes{15});
        if (!authenticated) return fnd::fail(authenticated.error());
        std::optional<sess::DelegatedSenderConstraint> constraint;
        if (m_senderConstrained) {
            constraint.emplace(sess::DelegatedSenderConstraintKind::Dpop, "thumbprint");
        }
        return sess::DelegatedAccess{
            std::move(authenticated).value(), "native-client", m_scopes, {},
            std::move(constraint)};
    }

private:
    std::vector<std::string> m_scopes;
    bool m_senderConstrained{};
};

TEST(SessionKeyTest, RejectsKeysShorterThanThirtyTwoBytes)
{
    const auto key = sess::SessionKey::create(fnd::SecretString{"too-short"});
    ASSERT_FALSE(key.has_value());
    EXPECT_EQ(key.error().code(), fnd::ErrorCode::InvalidArgument);
}

TEST(SessionPolicyTest, RejectsInvalidLifetimeRelationships)
{
    EXPECT_FALSE(sess::SessionPolicy::create(std::chrono::hours{1},
                                             std::chrono::hours{2})
                     .has_value());
    EXPECT_FALSE(sess::SessionPolicy::create(fnd::Duration::zero(),
                                             std::chrono::minutes{1})
                     .has_value());
}

TEST(SessionServiceTest, IssuesAndAuthenticatesAnOpaqueSession)
{
    Fixture fixture;
    const auth::VerifiedAuthentication authentication = verifiedAuthentication();
    auto grant = fixture.service.issue(authentication);

    ASSERT_TRUE(grant.has_value());
    EXPECT_FALSE(grant->id().empty());
    EXPECT_EQ(grant->token().expose().size(), 43U);
    EXPECT_EQ(fixture.sessions.size(), 1U);

    auto accepted = fixture.service.authenticate(grant->token());
    ASSERT_TRUE(accepted.has_value());
    EXPECT_EQ(accepted->session().identity(), core::IdentityId{"identity-1"});
    EXPECT_EQ(accepted->session().assurance(), idp::AssuranceLevel::Ial3);
}

TEST(SessionServiceTest, DelegatedAccountAccessRequiresExplicitScope)
{
    Fixture fixture;
    DelegatedAuthenticator permitted{{"openid", "account"}};
    DelegatedAuthenticator insufficient{{"openid", "profile"}};
    const fnd::SecretString token{"delegated-token"};

    auto accepted = fixture.service.authenticate(token, &permitted, "account");
    ASSERT_TRUE(accepted);
    EXPECT_EQ(accepted->session().identity(), core::IdentityId{"delegated-identity"});

    auto rejected = fixture.service.authenticate(token, &insufficient, "account");
    ASSERT_FALSE(rejected);
    EXPECT_EQ(rejected.error().code(), fnd::ErrorCode::PermissionDenied);
}

TEST(SessionServiceTest, FirstPartySessionDoesNotNeedDelegatedScope)
{
    Fixture fixture;
    auto grant = fixture.service.issue(verifiedAuthentication()).value();
    DelegatedAuthenticator insufficient{{"openid"}};

    auto accepted = fixture.service.authenticate(
        grant.token(), &insufficient, "account");

    ASSERT_TRUE(accepted);
    EXPECT_EQ(accepted->session().identity(), core::IdentityId{"identity-1"});
}

TEST(SessionServiceTest, SenderConstrainedAccessFailsClosedWithoutProofVerifier)
{
    Fixture fixture;
    DelegatedAuthenticator constrained{{"account"}, true};

    auto rejected = fixture.service.authenticate(
        fnd::SecretString{"delegated-token"}, &constrained, "account");

    ASSERT_FALSE(rejected);
    EXPECT_EQ(rejected.error().code(), fnd::ErrorCode::AuthenticationFailed);
}

TEST(SessionServiceTest, RotationImmediatelyInvalidatesTheOldToken)
{
    Fixture fixture;
    auto grant = fixture.service.issue(verifiedAuthentication()).value();
    const fnd::SecretString oldToken = grant.token().clone();

    auto replacement = fixture.service.rotate(oldToken);
    ASSERT_TRUE(replacement.has_value());
    EXPECT_NE(replacement->token().expose(), oldToken.expose());
    EXPECT_FALSE(fixture.service.authenticate(oldToken).has_value());
    EXPECT_TRUE(fixture.service.authenticate(replacement->token()).has_value());
}

TEST(SessionServiceTest, RevocationImmediatelyInvalidatesTheToken)
{
    Fixture fixture;
    auto grant = fixture.service.issue(verifiedAuthentication()).value();
    ASSERT_TRUE(fixture.service.revoke(grant.id()).has_value());

    const auto rejected = fixture.service.authenticate(grant.token());
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error().code(), fnd::ErrorCode::AuthenticationFailed);
}

TEST(SessionServiceTest, RevokeAllInvalidatesEverySessionForOnlyThatIdentity)
{
    Fixture fixture;
    auto first = fixture.service.issue(verifiedAuthentication()).value();
    auto second = fixture.service.issue(verifiedAuthentication()).value();

    const auto revoked = fixture.service.revokeAll(core::IdentityId{"identity-1"});
    ASSERT_TRUE(revoked.has_value());
    EXPECT_EQ(*revoked, 2U);
    EXPECT_FALSE(fixture.service.authenticate(first.token()).has_value());
    EXPECT_FALSE(fixture.service.authenticate(second.token()).has_value());
}

TEST(SessionServiceTest, StoresClientMetadataAndListsActiveSessions)
{
    Fixture fixture;
    idp::ClientContext client;
    client.setUserAgent("Mozilla/5.0 Test Browser");
    client.setRemoteAddress("203.0.113.42");

    auto grant = fixture.service.issue(verifiedAuthentication(), client);
    ASSERT_TRUE(grant);
    auto listed = fixture.service.list(core::IdentityId{"identity-1"});

    ASSERT_TRUE(listed);
    ASSERT_EQ(listed->size(), 1U);
    EXPECT_EQ(listed->front().id(), grant->id());
    ASSERT_TRUE(listed->front().userAgent().has_value());
    ASSERT_TRUE(listed->front().remoteAddress().has_value());
    EXPECT_EQ(*listed->front().userAgent(), "Mozilla/5.0 Test Browser");
    EXPECT_EQ(*listed->front().remoteAddress(), "203.0.113.42");
}

TEST(SessionServiceTest, RevokeOwnedChecksTheCanonicalIdentity)
{
    Fixture fixture;
    auto grant = fixture.service.issue(verifiedAuthentication()).value();

    const auto refused = fixture.service.revokeOwned(
        core::IdentityId{"identity-2"}, grant.id());
    ASSERT_FALSE(refused);
    EXPECT_EQ(refused.error().code(), fnd::ErrorCode::NotFound);
    EXPECT_TRUE(fixture.service.authenticate(grant.token()).has_value());

    EXPECT_TRUE(fixture.service.revokeOwned(
        core::IdentityId{"identity-1"}, grant.id()).has_value());
    EXPECT_FALSE(fixture.service.authenticate(grant.token()).has_value());
}

TEST(SessionServiceTest, AbsoluteExpiryIsInclusive)
{
    sess::InMemorySessionRepository sessions;
    fnd::ManualClockSource clock{kNow};
    sess::SessionService service{
        sessions, clock, sessionKey(),
        sessionPolicy(std::chrono::hours{1}, std::chrono::minutes{30})};
    auto grant = service.issue(verifiedAuthentication()).value();

    clock.advance(std::chrono::hours{1});
    EXPECT_FALSE(service.authenticate(grant.token()).has_value());
}

TEST(SessionServiceTest, SuccessfulUseSlidesTheIdleDeadline)
{
    Fixture fixture;
    auto grant = fixture.service.issue(verifiedAuthentication()).value();

    fixture.clock.advance(std::chrono::minutes{20});
    ASSERT_TRUE(fixture.service.authenticate(grant.token()).has_value());
    fixture.clock.advance(std::chrono::minutes{20});
    EXPECT_TRUE(fixture.service.authenticate(grant.token()).has_value());
    fixture.clock.advance(std::chrono::minutes{30});
    EXPECT_FALSE(fixture.service.authenticate(grant.token()).has_value());
}

TEST(SessionServiceTest, UnknownAndRevokedTokensHaveTheSameClientFailure)
{
    Fixture fixture;
    auto grant = fixture.service.issue(verifiedAuthentication()).value();
    ASSERT_TRUE(fixture.service.revoke(grant.id()).has_value());
    const auto revoked = fixture.service.authenticate(grant.token());
    const fnd::SecretString unknown{"unknown-but-nonempty"};
    const auto missing = fixture.service.authenticate(unknown);

    ASSERT_FALSE(revoked.has_value());
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(revoked.error(), missing.error());
}

TEST(SessionServiceTest, ConcurrentRotationHasExactlyOneWinner)
{
    Fixture fixture;
    auto grant = fixture.service.issue(verifiedAuthentication()).value();
    const fnd::SecretString firstToken = grant.token().clone();
    const fnd::SecretString secondToken = grant.token().clone();
    std::atomic<int> successes{0};

    std::thread first{[&] {
        if (fixture.service.rotate(firstToken).has_value()) {
            successes.fetch_add(1, std::memory_order_relaxed);
        }
    }};
    std::thread second{[&] {
        if (fixture.service.rotate(secondToken).has_value()) {
            successes.fetch_add(1, std::memory_order_relaxed);
        }
    }};
    first.join();
    second.join();

    EXPECT_EQ(successes.load(std::memory_order_relaxed), 1);
}

static_assert(!std::is_copy_constructible_v<sess::SessionKey>);
static_assert(!std::is_copy_constructible_v<sess::SessionGrant>);

}

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

import openproof.authentication;
import openproof.foundation;
import openproof.identity.provider;
import openproof.security;

namespace auth = openproof::authentication;
namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace sec = openproof::security;

namespace {

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};
constexpr fnd::Duration kServiceLifetime{std::chrono::minutes{5}};

[[nodiscard]] idp::BindingDigest bindingOf(std::string_view value)
{
    const auto digest = sec::sha256(value);
    EXPECT_TRUE(digest.has_value());
    return digest.value_or(idp::BindingDigest{});
}

class ControlledProvider final : public idp::AuthenticationProvider {
public:
    explicit ControlledProvider(std::string id)
        : m_id(std::move(id))
    {
    }

    [[nodiscard]] idp::ProviderId id() const override
    {
        return idp::ProviderId{m_id};
    }

    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override
    {
        return idp::InteractionModel::Redirect;
    }

    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override
    {
        return declaredMaximum;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest&) override
    {
        ++beginCalls;
        return idp::AuthenticationChallenge{idp::ChallengeId{challengeId},
                                            kNow + std::chrono::minutes{10}};
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse& response) override
    {
        ++completeCalls;
        const auto proof = response.parameters().find("proof");
        if (proof == response.parameters().end() || proof->second.expose() != "valid") {
            return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        }

        return idp::AuthenticationOutcome::create(
            idp::ProviderId{outcomeProvider.empty() ? m_id : outcomeProvider},
            idp::ExternalSubject{"subject-1"}, idp::VerifiedClaims{}, outcomeAssurance,
            idp::AuthenticationStrength{idp::AuthenticationFactor::Possession, true},
            idp::ProviderEvidence{}, verifiedAt);
    }

    idp::AssuranceLevel declaredMaximum{idp::AssuranceLevel::Ial3};
    idp::AssuranceLevel outcomeAssurance{idp::AssuranceLevel::Ial2};
    fnd::Instant verifiedAt{kNow};
    std::string outcomeProvider;
    std::string challengeId{"challenge-1"};
    int beginCalls{0};
    int completeCalls{0};

private:
    std::string m_id;
};

struct Fixture {
    Fixture()
        : clock(kNow)
    {
        auto owned = std::make_unique<ControlledProvider>("provider-a");
        implementation = owned.get();
        EXPECT_TRUE(registry.registerProvider(std::move(owned)).has_value());
    }

    [[nodiscard]] auth::AuthenticationService service(
        idp::AssuranceLevel trustedMaximum = idp::AssuranceLevel::Ial3)
    {
        auth::ProviderTrustPolicy policy;
        EXPECT_TRUE(policy.trust(idp::ProviderId{"provider-a"}, trustedMaximum).has_value());
        return auth::AuthenticationService{registry, transactions, clock, std::move(policy),
                                           kServiceLifetime};
    }

    [[nodiscard]] idp::AuthenticationRequest request(
        idp::AssuranceLevel requested = idp::AssuranceLevel::Ial2) const
    {
        idp::AuthenticationRequest value{idp::ProviderId{"provider-a"}, idp::ClientContext{}};
        value.setRequestedAssurance(requested);
        return value;
    }

    idp::ProviderRegistry registry;
    idp::InMemoryAuthenticationTransactionStore transactions;
    fnd::ManualClockSource clock;
    ControlledProvider* implementation{nullptr};
};

[[nodiscard]] idp::AuthenticationResponse validResponse(const idp::ChallengeId& challengeId)
{
    idp::AuthenticationResponse response{challengeId, idp::ClientContext{}};
    response.setParameter("proof", idp::CredentialValue{"valid"});
    return response;
}

TEST(AuthenticationServiceTest, CompletesOnlyThroughASingleUseBoundTransaction)
{
    Fixture fixture;
    auto service = fixture.service();
    const idp::BindingDigest binding = bindingOf("pre-auth-cookie");

    auto started = service.begin(fixture.request(), binding, fnd::CorrelationId{"corr-1"});
    ASSERT_TRUE(started.has_value());
    EXPECT_FALSE(started->transactionId().empty());
    EXPECT_FALSE(started->continuationToken().empty());

    const idp::AuthenticationResponse response = validResponse(started->challenge().id());
    const auto completed = service.complete(started->transactionId(),
                                            started->continuationToken(), binding, response);
    ASSERT_TRUE(completed.has_value());
    EXPECT_EQ(completed->provider(), idp::ProviderId{"provider-a"});
    EXPECT_EQ(fixture.implementation->completeCalls, 1);

    const auto replay = service.complete(started->transactionId(),
                                         started->continuationToken(), binding, response);
    ASSERT_FALSE(replay.has_value());
    EXPECT_EQ(fixture.implementation->completeCalls, 1)
        << "a replay must be rejected before provider verification runs again";
}

TEST(AuthenticationServiceTest, RefusesAProviderWithoutIndependentTrustPolicy)
{
    Fixture fixture;
    auth::ProviderTrustPolicy emptyPolicy;
    auth::AuthenticationService service{fixture.registry, fixture.transactions, fixture.clock,
                                        std::move(emptyPolicy), kServiceLifetime};

    const auto started = service.begin(fixture.request(), bindingOf("agent"),
                                       fnd::CorrelationId{"corr-1"});

    ASSERT_FALSE(started.has_value());
    EXPECT_EQ(started.error().code(), fnd::ErrorCode::AuthenticationFailed);
    EXPECT_EQ(fixture.implementation->beginCalls, 0);
}

TEST(AuthenticationServiceTest, RefusesRequestedAssuranceAboveTheEffectiveCap)
{
    Fixture fixture;
    auto service = fixture.service(idp::AssuranceLevel::Ial1);

    const auto started = service.begin(fixture.request(idp::AssuranceLevel::Ial2),
                                       bindingOf("agent"), fnd::CorrelationId{"corr-1"});

    ASSERT_FALSE(started.has_value());
    EXPECT_EQ(started.error().code(), fnd::ErrorCode::AssuranceInsufficient);
    EXPECT_EQ(fixture.implementation->beginCalls, 0);
}

TEST(AuthenticationServiceTest, RefusesAnOutcomeUnderAnotherProviderIdentifier)
{
    Fixture fixture;
    fixture.implementation->outcomeProvider = "attacker-provider";
    auto service = fixture.service();
    const idp::BindingDigest binding = bindingOf("agent");
    auto started = service.begin(fixture.request(), binding, fnd::CorrelationId{"corr-1"});
    ASSERT_TRUE(started.has_value());

    const idp::AuthenticationResponse response = validResponse(started->challenge().id());
    const auto completed = service.complete(started->transactionId(),
                                            started->continuationToken(), binding, response);

    ASSERT_FALSE(completed.has_value());
    EXPECT_EQ(completed.error().code(), fnd::ErrorCode::AuthenticationFailed);
}

TEST(AuthenticationServiceTest, RefusesAnOutcomeAboveEitherAssuranceCap)
{
    Fixture fixture;
    fixture.implementation->outcomeAssurance = idp::AssuranceLevel::Ial3;
    auto service = fixture.service(idp::AssuranceLevel::Ial2);
    const idp::BindingDigest binding = bindingOf("agent");
    auto started = service.begin(fixture.request(), binding, fnd::CorrelationId{"corr-1"});
    ASSERT_TRUE(started.has_value());

    const idp::AuthenticationResponse response = validResponse(started->challenge().id());
    const auto completed = service.complete(started->transactionId(),
                                            started->continuationToken(), binding, response);

    ASSERT_FALSE(completed.has_value());
    EXPECT_EQ(completed.error().code(), fnd::ErrorCode::AuthenticationFailed);
}

TEST(AuthenticationServiceTest, ChallengeSubstitutionBurnsTheTransaction)
{
    Fixture fixture;
    auto service = fixture.service();
    const idp::BindingDigest binding = bindingOf("agent");
    auto started = service.begin(fixture.request(), binding, fnd::CorrelationId{"corr-1"});
    ASSERT_TRUE(started.has_value());

    const idp::AuthenticationResponse substituted =
        validResponse(idp::ChallengeId{"different-challenge"});
    const auto first = service.complete(started->transactionId(),
                                        started->continuationToken(), binding, substituted);
    ASSERT_FALSE(first.has_value());
    EXPECT_EQ(fixture.implementation->completeCalls, 0);

    const idp::AuthenticationResponse correct = validResponse(started->challenge().id());
    const auto second = service.complete(started->transactionId(),
                                         started->continuationToken(), binding, correct);
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(fixture.implementation->completeCalls, 0);
}

TEST(AuthenticationServiceTest, CrossSessionSubstitutionNeverReachesTheProvider)
{
    Fixture fixture;
    auto service = fixture.service();
    const idp::BindingDigest victimBinding = bindingOf("victim");
    auto started = service.begin(fixture.request(), victimBinding, fnd::CorrelationId{"corr-1"});
    ASSERT_TRUE(started.has_value());

    const idp::AuthenticationResponse response = validResponse(started->challenge().id());
    const auto completed = service.complete(started->transactionId(),
                                            started->continuationToken(),
                                            bindingOf("attacker"), response);

    ASSERT_FALSE(completed.has_value());
    EXPECT_EQ(fixture.implementation->completeCalls, 0);
}

TEST(AuthenticationServiceTest, RefusesCompletionBelowTheOriginallyRequestedAssurance)
{
    Fixture fixture;
    fixture.implementation->outcomeAssurance = idp::AssuranceLevel::Ial1;
    auto service = fixture.service();
    const idp::BindingDigest binding = bindingOf("agent");
    auto started = service.begin(fixture.request(idp::AssuranceLevel::Ial2), binding,
                                 fnd::CorrelationId{"corr-1"});
    ASSERT_TRUE(started.has_value());

    const idp::AuthenticationResponse response = validResponse(started->challenge().id());
    const auto completed = service.complete(started->transactionId(),
                                            started->continuationToken(), binding, response);

    ASSERT_FALSE(completed.has_value());
    EXPECT_EQ(completed.error().code(), fnd::ErrorCode::AssuranceInsufficient);
}

TEST(AuthenticationServiceTest, RefusesVerificationTimeOutsideTheTransactionWindow)
{
    Fixture fixture;
    fixture.implementation->verifiedAt = kNow - std::chrono::milliseconds{1};
    auto service = fixture.service();
    const idp::BindingDigest binding = bindingOf("agent");
    auto started = service.begin(fixture.request(), binding, fnd::CorrelationId{"corr-1"});
    ASSERT_TRUE(started.has_value());

    const idp::AuthenticationResponse response = validResponse(started->challenge().id());
    const auto completed = service.complete(started->transactionId(),
                                            started->continuationToken(), binding, response);

    ASSERT_FALSE(completed.has_value());
    EXPECT_EQ(completed.error().code(), fnd::ErrorCode::AuthenticationFailed);
}

TEST(ProviderTrustPolicyTest, DuplicateRulesCannotSilentlyReplaceAReviewedCap)
{
    auth::ProviderTrustPolicy policy;
    ASSERT_TRUE(policy.trust(idp::ProviderId{"provider-a"}, idp::AssuranceLevel::Ial2)
                    .has_value());

    const fnd::Status duplicate =
        policy.trust(idp::ProviderId{"provider-a"}, idp::AssuranceLevel::Ial4);

    ASSERT_FALSE(duplicate.has_value());
    EXPECT_EQ(duplicate.error().code(), fnd::ErrorCode::AlreadyExists);
    EXPECT_EQ(policy.maximumFor(idp::ProviderId{"provider-a"}), idp::AssuranceLevel::Ial2);
}

}

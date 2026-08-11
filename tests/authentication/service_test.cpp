#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.security;

namespace auth = openproof::authentication;
namespace fnd = openproof::foundation;
namespace core = openproof::identity::core;
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
        if (throwOnBegin) {
            throw std::runtime_error{"provider start failure"};
        }
        if (failBegin) {
            return fnd::fail(fnd::Error{fnd::ErrorCode::NotFound,
                                        "provider leaked that the account is absent"});
        }
        return idp::AuthenticationChallenge{idp::ChallengeId{challengeId},
                                            kNow + std::chrono::minutes{10}};
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse& response) override
    {
        ++completeCalls;
        if (throwOnComplete) {
            throw std::runtime_error{"provider completion failure"};
        }
        if (failComplete) {
            return fnd::fail(fnd::Error{fnd::ErrorCode::NotFound,
                                        "provider leaked that the account is absent"});
        }
        const auto proof = response.parameters().find("proof");
        if (proof == response.parameters().end() || proof->second.expose() != "valid") {
            return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        }
        if (advancingClock != nullptr) {
            advancingClock->advance(std::chrono::milliseconds{1});
            verifiedAt = advancingClock->now();
        }

        return idp::AuthenticationOutcome::create(
            idp::ProviderId{outcomeProvider.empty() ? m_id : outcomeProvider},
            idp::ExternalSubject{outcomeSubject}, idp::VerifiedClaims{}, outcomeAssurance,
            idp::AuthenticationStrength{idp::AuthenticationFactor::Possession, true},
            idp::ProviderEvidence{}, verifiedAt);
    }

    idp::AssuranceLevel declaredMaximum{idp::AssuranceLevel::Ial3};
    idp::AssuranceLevel outcomeAssurance{idp::AssuranceLevel::Ial2};
    fnd::Instant verifiedAt{kNow};
    std::string outcomeProvider;
    std::string outcomeSubject{"subject-1"};
    std::string challengeId{"challenge-1"};
    bool failBegin{false};
    bool failComplete{false};
    bool throwOnBegin{false};
    bool throwOnComplete{false};
    fnd::ManualClockSource* advancingClock{nullptr};
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

        core::IdentityLink link =
            core::IdentityLink::request(
                core::IdentityId{"identity-1"},
                core::ExternalIdentityRef{idp::ProviderId{"provider-a"},
                                          idp::ExternalSubject{"subject-1"}},
                kNow, kServiceLifetime)
                .value();
        EXPECT_TRUE(link.requireVerification(kNow).has_value());
        EXPECT_TRUE(link.markVerified(kNow).has_value());
        EXPECT_TRUE(link.complete(kNow).has_value());
        EXPECT_TRUE(identities.attach(link).has_value());
    }

    [[nodiscard]] auth::AuthenticationService service(
        idp::AssuranceLevel trustedMaximum = idp::AssuranceLevel::Ial3)
    {
        auth::ProviderTrustPolicy policy;
        EXPECT_TRUE(policy.trust(idp::ProviderId{"provider-a"}, trustedMaximum).has_value());
        return auth::AuthenticationService{registry, transactions, identities, clock,
                                           std::move(policy), kServiceLifetime};
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
    core::InMemoryExternalIdentityDirectory identities;
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
    EXPECT_EQ(completed->outcome().provider(), idp::ProviderId{"provider-a"});
    EXPECT_EQ(completed->identity(), core::IdentityId{"identity-1"});
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
    auth::AuthenticationService service{fixture.registry, fixture.transactions,
                                        fixture.identities, fixture.clock,
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

TEST(AuthenticationServiceTest, NormalizesProviderErrorsAtBothBrokerBoundaries)
{
    Fixture startFixture;
    startFixture.implementation->failBegin = true;
    auto startService = startFixture.service();
    const auto started = startService.begin(startFixture.request(), bindingOf("agent"),
                                            fnd::CorrelationId{"corr-1"});
    ASSERT_FALSE(started.has_value());
    EXPECT_EQ(started.error().code(), fnd::ErrorCode::AuthenticationFailed);
    EXPECT_EQ(started.error().message(),
              fnd::defaultErrorMessage(fnd::ErrorCode::AuthenticationFailed));

    Fixture completionFixture;
    completionFixture.implementation->failComplete = true;
    auto completionService = completionFixture.service();
    const idp::BindingDigest binding = bindingOf("agent");
    auto pending = completionService.begin(completionFixture.request(), binding,
                                           fnd::CorrelationId{"corr-2"});
    ASSERT_TRUE(pending.has_value());
    const auto completed = completionService.complete(
        pending->transactionId(), pending->continuationToken(), binding,
        validResponse(pending->challenge().id()));
    ASSERT_FALSE(completed.has_value());
    EXPECT_EQ(completed.error().code(), fnd::ErrorCode::AuthenticationFailed);
    EXPECT_EQ(completed.error().message(),
              fnd::defaultErrorMessage(fnd::ErrorCode::AuthenticationFailed));
}

TEST(AuthenticationServiceTest, ContainsProviderExceptionsAtBothBrokerBoundaries)
{
    Fixture startFixture;
    startFixture.implementation->throwOnBegin = true;
    auto startService = startFixture.service();
    const auto started = startService.begin(startFixture.request(), bindingOf("agent"),
                                            fnd::CorrelationId{"corr-1"});
    ASSERT_FALSE(started.has_value());
    EXPECT_EQ(started.error().code(), fnd::ErrorCode::AuthenticationFailed);

    Fixture completionFixture;
    completionFixture.implementation->throwOnComplete = true;
    auto completionService = completionFixture.service();
    const idp::BindingDigest binding = bindingOf("agent");
    auto pending = completionService.begin(completionFixture.request(), binding,
                                           fnd::CorrelationId{"corr-2"});
    ASSERT_TRUE(pending.has_value());
    const auto completed = completionService.complete(
        pending->transactionId(), pending->continuationToken(), binding,
        validResponse(pending->challenge().id()));
    ASSERT_FALSE(completed.has_value());
    EXPECT_EQ(completed.error().code(), fnd::ErrorCode::AuthenticationFailed);
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

TEST(AuthenticationServiceTest, RefusesAnExternalSubjectWithoutAnExplicitIdentityLink)
{
    Fixture fixture;
    fixture.implementation->outcomeSubject = "unlinked-subject";
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

TEST(AuthenticationServiceTest, AllowsProviderToFinishAfterCompletionBegins)
{
    Fixture fixture;
    fixture.implementation->advancingClock = &fixture.clock;
    auto service = fixture.service();
    const idp::BindingDigest binding = bindingOf("agent");
    auto started = service.begin(fixture.request(), binding,
                                 fnd::CorrelationId{"corr-1"});
    ASSERT_TRUE(started);

    const auto completed = service.complete(
        started->transactionId(), started->continuationToken(), binding,
        validResponse(started->challenge().id()));

    ASSERT_TRUE(completed) << completed.error().internalDetail();
    EXPECT_EQ(completed->outcome().verifiedAt(),
              kNow + std::chrono::milliseconds{1});
}

TEST(AuthenticationServiceTest, StillRefusesAProviderTimestampAfterCompletion)
{
    Fixture fixture;
    fixture.implementation->verifiedAt = kNow + std::chrono::minutes{1};
    auto service = fixture.service();
    const idp::BindingDigest binding = bindingOf("agent");
    auto started = service.begin(fixture.request(), binding,
                                 fnd::CorrelationId{"corr-1"});
    ASSERT_TRUE(started);

    const auto completed = service.complete(
        started->transactionId(), started->continuationToken(), binding,
        validResponse(started->challenge().id()));

    ASSERT_FALSE(completed);
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

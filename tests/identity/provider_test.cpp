#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <vector>

import openproof.foundation;
import openproof.identity.provider;

namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;

namespace {

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

/**
 * A minimal provider used to prove the SPI is implementable and substitutable.
 * It is a test double, not a demonstration of how to verify anything: a real
 * provider must cryptographically verify its response.
 */
class StubProvider final : public idp::AuthenticationProvider {
public:
    StubProvider(std::string id, idp::InteractionModel model, idp::AssuranceLevel maximumAssurance)
        : m_id(std::move(id))
        , m_model(model)
        , m_maximumAssurance(maximumAssurance)
    {
    }

    [[nodiscard]] idp::ProviderId id() const override
    {
        return idp::ProviderId{m_id};
    }

    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override
    {
        return m_model;
    }

    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override
    {
        return m_maximumAssurance;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest& request) override
    {
        idp::AuthenticationChallenge challenge{idp::ChallengeId{"challenge-1"},
                                               kNow + std::chrono::milliseconds{60'000}};
        challenge.setParameter("nonce", "server-issued-nonce");
        challenge.setParameter("provider", std::string{request.provider().value()});
        return challenge;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse& response) override
    {
        const auto proof = response.parameters().find("proof");
        if (proof == response.parameters().end() || proof->second.expose() != "valid") {
            // A failed verification denies; it never downgrades to a weaker
            // outcome.
            return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        }

        idp::VerifiedClaims claims;
        claims.set(idp::ClaimName::Email, "ada@example.com");
        claims.set(idp::ClaimName::EmailVerified, "true");

        idp::ProviderEvidence evidence;
        evidence.add("issuer", "https://issuer.example.com");
        evidence.add("key_id", "kid-1");

        return idp::AuthenticationOutcome::create(
            id(), idp::ExternalSubject{"external-subject-1"}, std::move(claims),
            m_maximumAssurance,
            idp::AuthenticationStrength{idp::AuthenticationFactor::Possession, true},
            std::move(evidence), kNow);
    }

private:
    std::string m_id;
    idp::InteractionModel m_model;
    idp::AssuranceLevel m_maximumAssurance;
};

TEST(AssuranceTest, LevelsAreOrdered)
{
    EXPECT_TRUE(idp::meetsAssurance(idp::AssuranceLevel::Ial3, idp::AssuranceLevel::Ial2));
    EXPECT_TRUE(idp::meetsAssurance(idp::AssuranceLevel::Ial2, idp::AssuranceLevel::Ial2));
    EXPECT_FALSE(idp::meetsAssurance(idp::AssuranceLevel::Ial1, idp::AssuranceLevel::Ial2));
    EXPECT_FALSE(idp::meetsAssurance(idp::AssuranceLevel::Ial0, idp::AssuranceLevel::Ial1));
}

// Ial0 means "unverified". It must never satisfy a real requirement, and a
// future enumerator inserted below Ial1 must not silently start granting
// access. This would be a postcondition on meetsAssurance if GCC 16.1.0 could
// carry one on an inline function exported from a module.
TEST(AssuranceTest, UnverifiedNeverSatisfiesAnyRealRequirement)
{
    constexpr idp::AssuranceLevel kRequirements[] = {
        idp::AssuranceLevel::Ial1, idp::AssuranceLevel::Ial2,
        idp::AssuranceLevel::Ial3, idp::AssuranceLevel::Ial4,
    };

    for (const idp::AssuranceLevel required : kRequirements) {
        EXPECT_FALSE(idp::meetsAssurance(idp::AssuranceLevel::Ial0, required))
            << "Ial0 satisfied " << idp::assuranceLevelName(required);
    }

    // Ial0 as a requirement means "no assurance required" and is satisfied by
    // anything, including Ial0 itself.
    EXPECT_TRUE(idp::meetsAssurance(idp::AssuranceLevel::Ial0, idp::AssuranceLevel::Ial0));
}

TEST(AssuranceTest, LevelNamesAreStable)
{
    EXPECT_EQ(idp::assuranceLevelName(idp::AssuranceLevel::Ial0), "ial0");
    EXPECT_EQ(idp::assuranceLevelName(idp::AssuranceLevel::Ial4), "ial4");
}

TEST(AuthenticationStrengthTest, RecognizesMultipleFactors)
{
    const idp::AuthenticationStrength single{idp::AuthenticationFactor::Possession, false};
    const idp::AuthenticationStrength multiple{
        idp::AuthenticationFactor::Possession | idp::AuthenticationFactor::Inherence, true};

    EXPECT_FALSE(single.isMultiFactor());
    EXPECT_FALSE(single.isPhishingResistant());
    EXPECT_TRUE(multiple.isMultiFactor());
    EXPECT_TRUE(multiple.isPhishingResistant());
    EXPECT_TRUE(containsFactor(multiple.factors(), idp::AuthenticationFactor::Inherence));
    EXPECT_FALSE(containsFactor(multiple.factors(), idp::AuthenticationFactor::Knowledge));
}

TEST(AuthenticationStrengthTest, DefaultsToNoDemonstratedFactors)
{
    const idp::AuthenticationStrength strength;

    EXPECT_FALSE(strength.isMultiFactor());
    EXPECT_FALSE(strength.isPhishingResistant());
    EXPECT_EQ(strength.factors(), idp::AuthenticationFactor::None);
}

TEST(VerifiedClaimsTest, StoresNormalizedAndExtensionClaims)
{
    idp::VerifiedClaims claims;
    claims.set(idp::ClaimName::Email, "ada@example.com");
    claims.set(idp::ClaimName::EmailVerified, "true");
    claims.setExtension("farcaster_fid", "12345");

    EXPECT_EQ(claims.get(idp::ClaimName::Email), "ada@example.com");
    EXPECT_TRUE(claims.isTrue(idp::ClaimName::EmailVerified));
    EXPECT_FALSE(claims.isTrue(idp::ClaimName::PhoneNumberVerified));
    EXPECT_EQ(claims.getExtension("farcaster_fid"), "12345");
    EXPECT_FALSE(claims.get(idp::ClaimName::DisplayName).has_value());
    EXPECT_EQ(claims.size(), 3U);
}

TEST(VerifiedClaimsTest, ClaimKeysAreStable)
{
    EXPECT_EQ(idp::claimNameKey(idp::ClaimName::EmailVerified), "email_verified");
}

TEST(AuthenticationOutcomeTest, RequiresAProviderAndASubject)
{
    const auto missingSubject = idp::AuthenticationOutcome::create(
        idp::ProviderId{"google"}, idp::ExternalSubject{}, idp::VerifiedClaims{},
        idp::AssuranceLevel::Ial2, idp::AuthenticationStrength{}, idp::ProviderEvidence{}, kNow);

    ASSERT_FALSE(missingSubject.has_value());
    EXPECT_EQ(missingSubject.error().code(), fnd::ErrorCode::InvalidArgument);

    const auto missingProvider = idp::AuthenticationOutcome::create(
        idp::ProviderId{}, idp::ExternalSubject{"sub-1"}, idp::VerifiedClaims{},
        idp::AssuranceLevel::Ial2, idp::AuthenticationStrength{}, idp::ProviderEvidence{}, kNow);

    ASSERT_FALSE(missingProvider.has_value());
    EXPECT_EQ(missingProvider.error().code(), fnd::ErrorCode::InvalidArgument);
}

TEST(AuthenticationOutcomeTest, CarriesTheNormalizedResult)
{
    idp::VerifiedClaims claims;
    claims.set(idp::ClaimName::Email, "ada@example.com");

    idp::ProviderEvidence evidence;
    evidence.add("issuer", "https://accounts.example.com");

    const auto outcome = idp::AuthenticationOutcome::create(
        idp::ProviderId{"google"}, idp::ExternalSubject{"sub-1"}, std::move(claims),
        idp::AssuranceLevel::Ial2,
        idp::AuthenticationStrength{idp::AuthenticationFactor::Possession, true},
        std::move(evidence), kNow);

    ASSERT_TRUE(outcome.has_value());
    EXPECT_EQ(outcome->provider().value(), "google");
    EXPECT_EQ(outcome->subject().value(), "sub-1");
    EXPECT_EQ(outcome->claims().get(idp::ClaimName::Email), "ada@example.com");
    EXPECT_EQ(outcome->claimedAssurance(), idp::AssuranceLevel::Ial2);
    EXPECT_TRUE(outcome->strength().isPhishingResistant());
    EXPECT_EQ(outcome->evidence().get("issuer"), "https://accounts.example.com");
    EXPECT_EQ(outcome->verifiedAt(), kNow);
}

TEST(ChallengeTest, ExpiresInclusivelyAtItsDeadline)
{
    const idp::AuthenticationChallenge challenge{idp::ChallengeId{"c-1"},
                                                 kNow + std::chrono::milliseconds{1000}};

    EXPECT_FALSE(challenge.isExpiredAt(kNow));
    EXPECT_FALSE(challenge.isExpiredAt(kNow + std::chrono::milliseconds{999}));
    // The boundary resolves in the safe direction.
    EXPECT_TRUE(challenge.isExpiredAt(kNow + std::chrono::milliseconds{1000}));
    EXPECT_TRUE(challenge.isExpiredAt(kNow + std::chrono::milliseconds{1001}));
}

TEST(ProviderRegistryTest, StartsEmpty)
{
    const idp::ProviderRegistry registry;

    EXPECT_EQ(registry.size(), 0U);
    EXPECT_EQ(registry.find(idp::ProviderId{"google"}), nullptr);
    EXPECT_FALSE(registry.contains(idp::ProviderId{"google"}));
    EXPECT_TRUE(registry.ids().empty());
}

TEST(ProviderRegistryTest, RegistersAndResolvesProviders)
{
    idp::ProviderRegistry registry;

    ASSERT_TRUE(registry
                    .registerProvider(std::make_unique<StubProvider>(
                        "google", idp::InteractionModel::Redirect, idp::AssuranceLevel::Ial2))
                    .has_value());
    ASSERT_TRUE(registry
                    .registerProvider(std::make_unique<StubProvider>(
                        "passkey", idp::InteractionModel::ChallengeResponse, idp::AssuranceLevel::Ial3))
                    .has_value());

    EXPECT_EQ(registry.size(), 2U);

    idp::AuthenticationProvider* const google = registry.find(idp::ProviderId{"google"});
    ASSERT_NE(google, nullptr);
    EXPECT_EQ(google->interactionModel(), idp::InteractionModel::Redirect);
    EXPECT_EQ(google->maximumClaimableAssurance(), idp::AssuranceLevel::Ial2);

    const std::vector<idp::ProviderId> ids = registry.ids();
    ASSERT_EQ(ids.size(), 2U);
    EXPECT_EQ(ids[0].value(), "google");
    EXPECT_EQ(ids[1].value(), "passkey");
}

// Silent replacement would let a later registration take over an identifier that
// live sessions and audit records already reference.
TEST(ProviderRegistryTest, RejectsADuplicateIdentifierInsteadOfReplacing)
{
    idp::ProviderRegistry registry;

    ASSERT_TRUE(registry
                    .registerProvider(std::make_unique<StubProvider>(
                        "google", idp::InteractionModel::Redirect, idp::AssuranceLevel::Ial2))
                    .has_value());

    const auto duplicate = registry.registerProvider(std::make_unique<StubProvider>(
        "google", idp::InteractionModel::Redirect, idp::AssuranceLevel::Ial4));

    ASSERT_FALSE(duplicate.has_value());
    EXPECT_EQ(duplicate.error().code(), fnd::ErrorCode::AlreadyExists);

    // The original registration must survive unchanged.
    idp::AuthenticationProvider* const google = registry.find(idp::ProviderId{"google"});
    ASSERT_NE(google, nullptr);
    EXPECT_EQ(google->interactionModel(), idp::InteractionModel::Redirect);
    EXPECT_EQ(google->maximumClaimableAssurance(), idp::AssuranceLevel::Ial2);
    EXPECT_EQ(registry.size(), 1U);
}

TEST(ProviderRegistryTest, RejectsNullAndUnidentifiedProviders)
{
    idp::ProviderRegistry registry;

    const auto nullProvider = registry.registerProvider(nullptr);
    ASSERT_FALSE(nullProvider.has_value());
    EXPECT_EQ(nullProvider.error().code(), fnd::ErrorCode::InvalidArgument);

    const auto unnamed = registry.registerProvider(
        std::make_unique<StubProvider>("", idp::InteractionModel::Assertion, idp::AssuranceLevel::Ial1));
    ASSERT_FALSE(unnamed.has_value());
    EXPECT_EQ(unnamed.error().code(), fnd::ErrorCode::InvalidArgument);

    EXPECT_EQ(registry.size(), 0U);
}

// The whole point of the SPI: the caller drives a complete exchange without
// knowing which protocol is behind it.
TEST(ProviderSpiTest, DrivesAChallengeResponseExchangeProtocolAgnostically)
{
    idp::ProviderRegistry registry;
    ASSERT_TRUE(registry
                    .registerProvider(std::make_unique<StubProvider>(
                        "any-protocol", idp::InteractionModel::ChallengeResponse, idp::AssuranceLevel::Ial3))
                    .has_value());

    idp::AuthenticationProvider* const provider = registry.find(idp::ProviderId{"any-protocol"});
    ASSERT_NE(provider, nullptr);

    idp::ClientContext client;
    client.setRemoteAddress("198.51.100.10");
    client.setUserAgent("openproof-test");

    idp::AuthenticationRequest request{provider->id(), client};
    request.setRequestedAssurance(idp::AssuranceLevel::Ial2);

    const auto challenge = provider->beginAuthentication(request);
    ASSERT_TRUE(challenge.has_value());
    EXPECT_FALSE(challenge->id().empty());
    EXPECT_FALSE(challenge->isExpiredAt(kNow));
    EXPECT_EQ(challenge->parameters().at("nonce"), "server-issued-nonce");

    idp::AuthenticationResponse response{challenge->id(), client};
    response.setParameter("proof", idp::CredentialValue{"valid"});

    const auto outcome = provider->completeAuthentication(response);
    ASSERT_TRUE(outcome.has_value());
    EXPECT_EQ(outcome->provider().value(), "any-protocol");
    EXPECT_EQ(outcome->subject().value(), "external-subject-1");
    EXPECT_TRUE(outcome->claims().isTrue(idp::ClaimName::EmailVerified));
    EXPECT_EQ(outcome->claimedAssurance(), idp::AssuranceLevel::Ial3);
}

TEST(ProviderSpiTest, DeniesRatherThanDowngradingOnFailedVerification)
{
    StubProvider provider{"wallet", idp::InteractionModel::ChallengeResponse, idp::AssuranceLevel::Ial3};

    idp::AuthenticationResponse response{idp::ChallengeId{"challenge-1"}, idp::ClientContext{}};
    response.setParameter("proof", idp::CredentialValue{"forged"});

    const auto outcome = provider.completeAuthentication(response);

    ASSERT_FALSE(outcome.has_value());
    EXPECT_EQ(outcome.error().code(), fnd::ErrorCode::AuthenticationFailed);
}

TEST(InteractionModelTest, NamesCoverEveryDeclaredModel)
{
    constexpr idp::InteractionModel kAllModels[] = {
        idp::InteractionModel::Redirect,  idp::InteractionModel::ChallengeResponse,
        idp::InteractionModel::OutOfBand, idp::InteractionModel::Assertion,
        idp::InteractionModel::Delegated,
    };

    for (const idp::InteractionModel model : kAllModels) {
        EXPECT_FALSE(idp::interactionModelName(model).empty());
    }
}

}

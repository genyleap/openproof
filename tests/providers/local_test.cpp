#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <thread>

import openproof.credentials;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.provider.local;

namespace {

namespace cred = openproof::credentials;
namespace fnd = openproof::foundation;
namespace core = openproof::identity::core;
namespace idp = openproof::identity::provider;
namespace local = openproof::provider::local;

constexpr fnd::Instant kNow{std::chrono::seconds{1'770'000'000}};

[[nodiscard]] fnd::Result<std::unique_ptr<local::InMemoryLocalAccountDirectory>>
accountDirectory()
{
    auto policy = cred::PasswordPolicy::create(
        1024U, 8U, 1U, 16U, 32U, 2U * 1024U * 1024U);
    if (!policy.has_value()) {
        return fnd::fail(policy.error());
    }
    auto hasher = cred::PasswordHasher::create(
        fnd::SecretString{std::string(32U, 'p')}, policy.value());
    if (!hasher.has_value()) {
        return fnd::fail(hasher.error());
    }
    return local::InMemoryLocalAccountDirectory::create(
        std::move(hasher).value(), cred::TotpPolicy::recommended());
}

[[nodiscard]] idp::AuthenticationRequest requestFor(std::string subject)
{
    idp::AuthenticationRequest request{idp::ProviderId{"local"}, idp::ClientContext{}};
    request.setParameter("subject", std::move(subject));
    return request;
}

[[nodiscard]] idp::AuthenticationResponse responseFor(
    const idp::ChallengeId& challenge, std::string password)
{
    idp::AuthenticationResponse response{challenge, idp::ClientContext{}};
    response.setParameter("password", idp::CredentialValue{std::move(password)});
    return response;
}

TEST(LocalProviderTest, PasswordOnlyProducesKnowledgeFactorAtIal1)
{
    auto directory = accountDirectory();
    ASSERT_TRUE(directory);
    ASSERT_TRUE(directory.value()->enroll(
        idp::ExternalSubject{"alice"}, fnd::SecretString{"correct-password"}, std::nullopt));
    fnd::ManualClockSource clock{kNow};
    local::LocalAuthenticationProvider provider{
        idp::ProviderId{"local"}, *directory.value(), clock, std::chrono::minutes{2}};

    auto challenge = provider.beginAuthentication(requestFor("alice"));
    ASSERT_TRUE(challenge);
    auto outcome = provider.completeAuthentication(
        responseFor(challenge->id(), "correct-password"));
    ASSERT_TRUE(outcome);
    EXPECT_EQ(outcome->subject(), idp::ExternalSubject{"alice"});
    EXPECT_EQ(outcome->claimedAssurance(), idp::AssuranceLevel::Ial1);
    EXPECT_TRUE(idp::containsFactor(outcome->strength().factors(),
                                    idp::AuthenticationFactor::Knowledge));
    EXPECT_FALSE(outcome->strength().isMultiFactor());
}

TEST(LocalProviderTest, PasswordAndTotpProduceTwoFactorsAndIal2)
{
    auto directory = accountDirectory();
    ASSERT_TRUE(directory);
    auto secret = cred::TotpSecret::create(
        fnd::SecretString{"12345678901234567890"});
    ASSERT_TRUE(secret);
    auto code = cred::totpAt(secret.value(), cred::TotpPolicy::recommended(), kNow);
    ASSERT_TRUE(code);
    ASSERT_TRUE(directory.value()->enroll(
        idp::ExternalSubject{"alice"}, fnd::SecretString{"correct-password"},
        std::optional<cred::TotpSecret>{std::move(secret).value()}));
    fnd::ManualClockSource clock{kNow};
    local::LocalAuthenticationProvider provider{
        idp::ProviderId{"local"}, *directory.value(), clock, std::chrono::minutes{2}};

    auto challenge = provider.beginAuthentication(requestFor("alice"));
    ASSERT_TRUE(challenge);
    auto response = responseFor(challenge->id(), "correct-password");
    response.setParameter("totp", idp::CredentialValue{code.value()});
    auto outcome = provider.completeAuthentication(response);
    ASSERT_TRUE(outcome);
    EXPECT_EQ(outcome->claimedAssurance(), idp::AssuranceLevel::Ial2);
    EXPECT_TRUE(outcome->strength().isMultiFactor());
    EXPECT_FALSE(outcome->strength().isPhishingResistant());

    auto secondChallenge = provider.beginAuthentication(requestFor("alice"));
    ASSERT_TRUE(secondChallenge);
    auto replay = responseFor(secondChallenge->id(), "correct-password");
    replay.setParameter("totp", idp::CredentialValue{code.value()});
    auto rejected = provider.completeAuthentication(replay);
    ASSERT_FALSE(rejected);
    EXPECT_EQ(rejected.error().code(), fnd::ErrorCode::AuthenticationFailed);
}

TEST(LocalProviderTest, RecoveryCodeIsSecondFactorAndWrongPasswordDoesNotConsumeIt)
{
    auto directory = accountDirectory();
    ASSERT_TRUE(directory);
    auto secret = cred::TotpSecret::create(
        fnd::SecretString{"12345678901234567890"});
    ASSERT_TRUE(secret);
    ASSERT_TRUE(directory.value()->enroll(
        idp::ExternalSubject{"alice"}, fnd::SecretString{"correct-password"},
        std::optional<cred::TotpSecret>{std::move(secret).value()}));

    core::InMemoryExternalIdentityDirectory identities;
    const core::IdentityId identity{"identity-1"};
    auto link = core::IdentityLink::request(
        identity,
        core::ExternalIdentityRef{idp::ProviderId{"local"},
                                  idp::ExternalSubject{"alice"}},
        kNow, std::chrono::minutes{5});
    ASSERT_TRUE(link);
    ASSERT_TRUE(link->requireVerification(kNow));
    ASSERT_TRUE(link->markVerified(kNow));
    ASSERT_TRUE(link->complete(kNow));
    ASSERT_TRUE(identities.attach(link.value()));

    cred::InMemoryRecoveryCodeRepository recoveryRepository;
    auto recovery = cred::RecoveryCodeService::create(
        recoveryRepository,
        fnd::SecretString{"abcdef0123456789abcdef0123456789"});
    ASSERT_TRUE(recovery);
    auto batch = recovery->issue(identity, 1U);
    ASSERT_TRUE(batch);
    ASSERT_EQ(batch->codes().size(), 1U);
    const std::string code{batch->codes().front().expose()};

    fnd::ManualClockSource clock{kNow};
    local::LocalAuthenticationProvider provider{
        idp::ProviderId{"local"}, *directory.value(), clock, std::chrono::minutes{2},
        &identities, &recovery.value()};

    auto wrongChallenge = provider.beginAuthentication(requestFor("alice"));
    ASSERT_TRUE(wrongChallenge);
    auto wrong = responseFor(wrongChallenge->id(), "wrong-password");
    wrong.setParameter("recovery_code", idp::CredentialValue{code});
    auto wrongOutcome = provider.completeAuthentication(wrong);
    ASSERT_FALSE(wrongOutcome);

    auto challenge = provider.beginAuthentication(requestFor("alice"));
    ASSERT_TRUE(challenge);
    auto response = responseFor(challenge->id(), "correct-password");
    response.setParameter("recovery_code", idp::CredentialValue{code});
    auto outcome = provider.completeAuthentication(response);
    ASSERT_TRUE(outcome) << outcome.error().internalDetail();
    EXPECT_EQ(outcome->claimedAssurance(), idp::AssuranceLevel::Ial2);
    EXPECT_TRUE(outcome->strength().isMultiFactor());
    EXPECT_TRUE(idp::containsFactor(
        outcome->strength().factors(), idp::AuthenticationFactor::Knowledge));
    EXPECT_TRUE(idp::containsFactor(
        outcome->strength().factors(), idp::AuthenticationFactor::Possession));

    auto replayChallenge = provider.beginAuthentication(requestFor("alice"));
    ASSERT_TRUE(replayChallenge);
    auto replay = responseFor(replayChallenge->id(), "correct-password");
    replay.setParameter("recovery_code", idp::CredentialValue{code});
    auto replayed = provider.completeAuthentication(replay);
    ASSERT_FALSE(replayed);
    EXPECT_EQ(replayed.error().code(), fnd::ErrorCode::AuthenticationFailed);
}

TEST(LocalProviderTest, FailedAttemptBurnsChallengeAndDoesNotRevealAccountExistence)
{
    auto directory = accountDirectory();
    ASSERT_TRUE(directory);
    ASSERT_TRUE(directory.value()->enroll(
        idp::ExternalSubject{"alice"}, fnd::SecretString{"correct-password"}, std::nullopt));
    fnd::ManualClockSource clock{kNow};
    local::LocalAuthenticationProvider provider{
        idp::ProviderId{"local"}, *directory.value(), clock, std::chrono::minutes{2}};

    auto existingChallenge = provider.beginAuthentication(requestFor("alice"));
    auto unknownChallenge = provider.beginAuthentication(requestFor("nobody"));
    ASSERT_TRUE(existingChallenge);
    ASSERT_TRUE(unknownChallenge);
    auto wrong = provider.completeAuthentication(
        responseFor(existingChallenge->id(), "wrong-password"));
    auto unknown = provider.completeAuthentication(
        responseFor(unknownChallenge->id(), "wrong-password"));
    ASSERT_FALSE(wrong);
    ASSERT_FALSE(unknown);
    EXPECT_EQ(wrong.error(), unknown.error());

    auto replay = provider.completeAuthentication(
        responseFor(existingChallenge->id(), "correct-password"));
    ASSERT_FALSE(replay);
    EXPECT_EQ(replay.error().code(), fnd::ErrorCode::AuthenticationFailed);
}

TEST(LocalProviderTest, ExpiryIsInclusive)
{
    auto directory = accountDirectory();
    ASSERT_TRUE(directory);
    ASSERT_TRUE(directory.value()->enroll(
        idp::ExternalSubject{"alice"}, fnd::SecretString{"correct-password"}, std::nullopt));
    fnd::ManualClockSource clock{kNow};
    local::LocalAuthenticationProvider provider{
        idp::ProviderId{"local"}, *directory.value(), clock, std::chrono::minutes{2}};
    auto challenge = provider.beginAuthentication(requestFor("alice"));
    ASSERT_TRUE(challenge);
    clock.advance(std::chrono::minutes{2});
    auto result = provider.completeAuthentication(
        responseFor(challenge->id(), "correct-password"));
    EXPECT_FALSE(result);
}

TEST(LocalProviderTest, ConcurrentCompletionHasExactlyOneWinner)
{
    auto directory = accountDirectory();
    ASSERT_TRUE(directory);
    ASSERT_TRUE(directory.value()->enroll(
        idp::ExternalSubject{"alice"}, fnd::SecretString{"correct-password"}, std::nullopt));
    fnd::ManualClockSource clock{kNow};
    local::LocalAuthenticationProvider provider{
        idp::ProviderId{"local"}, *directory.value(), clock, std::chrono::minutes{2}};
    auto challenge = provider.beginAuthentication(requestFor("alice"));
    ASSERT_TRUE(challenge);

    bool first = false;
    bool second = false;
    std::thread left{[&] {
        first = provider.completeAuthentication(
            responseFor(challenge->id(), "correct-password")).has_value();
    }};
    std::thread right{[&] {
        second = provider.completeAuthentication(
            responseFor(challenge->id(), "correct-password")).has_value();
    }};
    left.join();
    right.join();
    EXPECT_NE(first, second);
}

}

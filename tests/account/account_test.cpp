#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

import openproof.account;
import openproof.credentials;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.profile;
import openproof.identity.provider;
import openproof.provider.local;
import openproof.session;

namespace {

namespace account = openproof::account;
namespace cred = openproof::credentials;
namespace fnd = openproof::foundation;
namespace core = openproof::identity::core;
namespace profile = openproof::identity::profile;
namespace idp = openproof::identity::provider;
namespace local = openproof::provider::local;
namespace sess = openproof::session;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'790'000'000'000}};

class CapturingDelivery final : public account::VerificationDelivery {
public:
    [[nodiscard]] fnd::Status deliver(const account::VerificationDispatch& dispatch) override
    {
        id = dispatch.id().value();
        identity = dispatch.identity().value();
        destination = std::string{dispatch.destination()};
        secret = std::string{dispatch.secret().expose()};
        purpose = dispatch.purpose();
        return fnd::ok();
    }

    std::string id;
    std::string identity;
    std::string destination;
    std::string secret;
    account::VerificationPurpose purpose{account::VerificationPurpose::SignupEmail};
};

[[nodiscard]] std::unique_ptr<local::InMemoryLocalAccountDirectory> localDirectory()
{
    auto policy = cred::PasswordPolicy::create(
        1024U, 8U, 1U, 16U, 32U, 2U * 1024U * 1024U);
    EXPECT_TRUE(policy);
    auto hasher = cred::PasswordHasher::create(
        fnd::SecretString{std::string(32U, 'p')}, policy.value());
    EXPECT_TRUE(hasher);
    auto directory = local::InMemoryLocalAccountDirectory::create(
        std::move(hasher).value(), cred::TotpPolicy::recommended());
    EXPECT_TRUE(directory);
    return directory ? std::move(directory).value() : nullptr;
}
[[nodiscard]] sess::SessionKey sessionKey()
{
    return sess::SessionKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
}

[[nodiscard]] sess::SessionPolicy sessionPolicy()
{
    return sess::SessionPolicy::create(
        std::chrono::hours{8}, std::chrono::minutes{30}).value();
}

struct Fixture {
    Fixture()
        : localAccounts(localDirectory())
        , sessions(sessionRepository, clock, sessionKey(), sessionPolicy())
    {
        auto key = account::VerificationKey::create(
            fnd::SecretString{"0123456789abcdef0123456789abcdef"});
        EXPECT_TRUE(key);
        auto policy = account::AccountPolicy::create(
            std::chrono::hours{24}, std::chrono::minutes{10},
            std::chrono::minutes{30}, 8U);
        EXPECT_TRUE(policy);
        service = std::make_unique<account::AccountService>(
            organization, localProvider, phoneProvider,
            identities, externalIdentities, profiles, *localAccounts,
            accountRepository, sessions, clock,
            std::move(key).value(), policy.value(), delivery);
    }

    core::IdentityId addActiveIdentity(std::string id, std::optional<std::string> email = std::nullopt,
                                       bool verified = false)
    {
        core::IdentityId identity{std::move(id)};
        auto canonical = core::Identity::create(identity, core::SubjectKind::Human, kNow);
        EXPECT_TRUE(canonical);
        EXPECT_TRUE(identities.add(organization, canonical.value()));

        auto value = profile::IdentityProfile::create(identity, kNow);
        EXPECT_TRUE(value);
        if (email.has_value()) {
            EXPECT_TRUE(value->setEmail(std::move(email).value(), verified, kNow));
        }
        EXPECT_TRUE(profiles.save(value.value()));
        return identity;
    }

    const core::OrganizationId organization{"org-test"};
    const idp::ProviderId localProvider{"local"};
    const idp::ProviderId phoneProvider{"phone"};
    fnd::ManualClockSource clock{kNow};
    core::InMemoryIdentityRepository identities;
    core::InMemoryExternalIdentityDirectory externalIdentities;
    profile::InMemoryIdentityProfileRepository profiles;
    std::unique_ptr<local::InMemoryLocalAccountDirectory> localAccounts;
    account::InMemoryAccountRepository accountRepository;
    sess::InMemorySessionRepository sessionRepository;
    sess::SessionService sessions;
    CapturingDelivery delivery;
    std::unique_ptr<account::AccountService> service;
};
TEST(AccountEmailLinkingTest, SameVerifiedProfileEmailStillDispatchesFreshProof)
{
    Fixture fixture;
    const auto identity = fixture.addActiveIdentity(
        "id-same-email", std::string{"provider@example.com"}, true);

    ASSERT_TRUE(fixture.service->beginEmailChange(identity, "provider@example.com"));
    EXPECT_EQ(fixture.delivery.purpose, account::VerificationPurpose::ChangeEmail);
    EXPECT_EQ(fixture.delivery.destination, "provider@example.com");
    EXPECT_FALSE(fixture.delivery.secret.empty());
}

TEST(AccountEmailLinkingTest, FederatedIdentityCanEnablePasswordOnlyWithFreshEmailProof)
{
    Fixture fixture;
    const auto identity = fixture.addActiveIdentity(
        "id-federated", std::string{"provider@example.com"}, true);

    ASSERT_TRUE(fixture.service->beginEmailChange(identity, "login@example.com"));
    ASSERT_EQ(fixture.delivery.purpose, account::VerificationPurpose::ChangeEmail);
    ASSERT_EQ(fixture.delivery.destination, "login@example.com");

    const fnd::SecretString proof{fixture.delivery.secret};
    const fnd::SecretString password{"correct-password"};
    ASSERT_TRUE(fixture.service->completeEmailChange(
        identity, account::VerificationId{fixture.delivery.id}, proof, &password));

    auto saved = fixture.profiles.find(identity);
    ASSERT_TRUE(saved);
    ASSERT_TRUE(saved->has_value());
    ASSERT_TRUE(saved->value().email().has_value());
    EXPECT_EQ(*saved->value().email(), "login@example.com");
    EXPECT_TRUE(saved->value().emailVerified());

    const core::ExternalIdentityRef localRef{
        fixture.localProvider, idp::ExternalSubject{"login@example.com"}};
    auto owner = fixture.externalIdentities.ownerOf(localRef);
    ASSERT_TRUE(owner);
    ASSERT_TRUE(owner->has_value());
    EXPECT_EQ(owner->value(), identity);

    auto verified = fixture.localAccounts->verify(
        idp::ExternalSubject{"login@example.com"}, password, std::nullopt, kNow);
    ASSERT_TRUE(verified);
    EXPECT_EQ(verified.value(), local::LocalVerification::Password);
}

TEST(AccountEmailLinkingTest, VerifyingContactEmailWithoutPasswordDoesNotCreateLocalSignIn)
{
    Fixture fixture;
    const auto identity = fixture.addActiveIdentity("id-contact-only");

    ASSERT_TRUE(fixture.service->beginEmailChange(identity, "contact@example.com"));
    const fnd::SecretString proof{fixture.delivery.secret};
    ASSERT_TRUE(fixture.service->completeEmailChange(
        identity, account::VerificationId{fixture.delivery.id}, proof));

    auto saved = fixture.profiles.find(identity);
    ASSERT_TRUE(saved);
    ASSERT_TRUE(saved->has_value());
    ASSERT_TRUE(saved->value().email().has_value());
    EXPECT_EQ(*saved->value().email(), "contact@example.com");
    EXPECT_TRUE(saved->value().emailVerified());

    const core::ExternalIdentityRef localRef{
        fixture.localProvider, idp::ExternalSubject{"contact@example.com"}};
    auto owner = fixture.externalIdentities.ownerOf(localRef);
    ASSERT_TRUE(owner);
    EXPECT_FALSE(owner->has_value());
}
TEST(AccountEmailLinkingTest, WrongIdentityDoesNotConsumeEmailProof)
{
    Fixture fixture;
    const auto owner = fixture.addActiveIdentity("id-owner");
    const auto other = fixture.addActiveIdentity("id-other");

    ASSERT_TRUE(fixture.service->beginEmailChange(owner, "owner@example.com"));
    const account::VerificationId verification{fixture.delivery.id};
    const fnd::SecretString proof{fixture.delivery.secret};

    auto rejected = fixture.service->completeEmailChange(other, verification, proof);
    ASSERT_FALSE(rejected);
    EXPECT_EQ(rejected.error().code(), fnd::ErrorCode::AuthenticationFailed);

    ASSERT_TRUE(fixture.service->completeEmailChange(owner, verification, proof));
    auto saved = fixture.profiles.find(owner);
    ASSERT_TRUE(saved);
    ASSERT_TRUE(saved->has_value());
    ASSERT_TRUE(saved->value().email().has_value());
    EXPECT_EQ(*saved->value().email(), "owner@example.com");
    EXPECT_TRUE(saved->value().emailVerified());
}

TEST(AccountEmailLinkingTest, InvalidPasswordDoesNotConsumeEmailProof)
{
    Fixture fixture;
    const auto identity = fixture.addActiveIdentity("id-retry");

    ASSERT_TRUE(fixture.service->beginEmailChange(identity, "retry@example.com"));
    const account::VerificationId verification{fixture.delivery.id};
    const fnd::SecretString proof{fixture.delivery.secret};
    const fnd::SecretString tooShort{"short"};

    auto rejected = fixture.service->completeEmailChange(
        identity, verification, proof, &tooShort);
    ASSERT_FALSE(rejected);
    EXPECT_EQ(rejected.error().code(), fnd::ErrorCode::InvalidArgument);

    const fnd::SecretString validPassword{"correct-password"};
    ASSERT_TRUE(fixture.service->completeEmailChange(
        identity, verification, proof, &validPassword));

    auto verified = fixture.localAccounts->verify(
        idp::ExternalSubject{"retry@example.com"}, validPassword, std::nullopt, kNow);
    EXPECT_TRUE(verified);
}

TEST(AccountEmailLinkingTest, ExistingPasswordSignInRebindsOnlyAfterVerifiedEmailChange)
{
    Fixture fixture;
    const fnd::SecretString originalPassword{"correct-password"};
    auto signup = fixture.service->signup(
        "old@example.com", originalPassword, std::string{"Example"});
    ASSERT_TRUE(signup);
    const auto identity = signup.value();

    const fnd::SecretString signupProof{fixture.delivery.secret};
    ASSERT_TRUE(fixture.service->verifyEmail(
        account::VerificationId{fixture.delivery.id}, signupProof));

    ASSERT_TRUE(fixture.service->beginEmailChange(identity, "new@example.com"));
    const fnd::SecretString changeProof{fixture.delivery.secret};
    ASSERT_TRUE(fixture.service->completeEmailChange(
        identity, account::VerificationId{fixture.delivery.id}, changeProof));

    auto oldLogin = fixture.localAccounts->verify(
        idp::ExternalSubject{"old@example.com"}, originalPassword, std::nullopt, kNow);
    EXPECT_FALSE(oldLogin);

    auto newLogin = fixture.localAccounts->verify(
        idp::ExternalSubject{"new@example.com"}, originalPassword, std::nullopt, kNow);
    ASSERT_TRUE(newLogin);
    EXPECT_EQ(newLogin.value(), local::LocalVerification::Password);

    const core::ExternalIdentityRef oldRef{
        fixture.localProvider, idp::ExternalSubject{"old@example.com"}};
    const core::ExternalIdentityRef newRef{
        fixture.localProvider, idp::ExternalSubject{"new@example.com"}};
    auto oldOwner = fixture.externalIdentities.ownerOf(oldRef);
    auto newOwner = fixture.externalIdentities.ownerOf(newRef);
    ASSERT_TRUE(oldOwner);
    ASSERT_TRUE(newOwner);
    EXPECT_FALSE(oldOwner->has_value());
    ASSERT_TRUE(newOwner->has_value());
    EXPECT_EQ(newOwner->value(), identity);
}

} // namespace

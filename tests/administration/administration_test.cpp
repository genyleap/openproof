#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <type_traits>
#include <vector>

import openproof.administration;
import openproof.credentials;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.organization;

namespace {

namespace admin = openproof::administration;
namespace cred = openproof::credentials;
namespace core = openproof::identity::core;
namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace org = openproof::organization;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

[[nodiscard]] cred::TotpSecret totp()
{
    return cred::TotpSecret::create(
        fnd::SecretString{"12345678901234567890"}).value();
}

TEST(InitialAdministratorTest, BuildsExplicitLinkedActiveOwnerCeremony)
{
    auto command = admin::InitialAdministrator::create(
        core::OrganizationId{"org"}, "Example Organization",
        core::IdentityId{"identity-1"}, idp::ProviderId{"local"},
        idp::ExternalSubject{"alice@example.test"},
        fnd::SecretString{"a-long-bootstrap-password"}, totp(), kNow);

    ASSERT_TRUE(command);
    EXPECT_TRUE(command->organization().isUsable());
    EXPECT_TRUE(command->identity().canAuthenticate());
    EXPECT_EQ(command->link().state(), core::LinkState::Linked);
    EXPECT_EQ(command->link().owner(), core::IdentityId{"identity-1"});
    EXPECT_EQ(command->membership().state(), org::MembershipState::Active);
    EXPECT_TRUE(command->membership().hasRole(org::Role{"owner"}));
    static_assert(!std::is_copy_constructible_v<admin::InitialAdministrator>);
}

TEST(InitialAdministratorTest, RejectsWeakOrOversizedBoundaryValues)
{
    EXPECT_FALSE(admin::InitialAdministrator::create(
        core::OrganizationId{"org"}, "Example",
        core::IdentityId{"identity-1"}, idp::ProviderId{"local"},
        idp::ExternalSubject{"alice"}, fnd::SecretString{"too-short"},
        totp(), kNow));
    EXPECT_FALSE(admin::InitialAdministrator::create(
        core::OrganizationId{std::string(201U, 'o')}, "Example",
        core::IdentityId{"identity-1"}, idp::ProviderId{"local"},
        idp::ExternalSubject{"alice"},
        fnd::SecretString{"a-long-bootstrap-password"}, totp(), kNow));
}

TEST(InitialAdministratorTest, ExternalSubjectCannotBeCanonicalIdentityId)
{
    auto command = admin::InitialAdministrator::create(
        core::OrganizationId{"org"}, "Example",
        core::IdentityId{"alice"}, idp::ProviderId{"local"},
        idp::ExternalSubject{"alice"},
        fnd::SecretString{"a-long-bootstrap-password"}, totp(), kNow);
    EXPECT_FALSE(command);
    EXPECT_EQ(command.error().code(), fnd::ErrorCode::InvalidArgument);
}

TEST(LocalMemberEnrollmentTest, BuildsLinkedActiveMemberWithCanonicalRoles)
{
    auto command = admin::LocalMemberEnrollment::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        idp::ProviderId{"local"}, idp::ExternalSubject{"bob@example.test"},
        std::vector<org::Role>{org::Role{"viewer"}, org::Role{"member"}},
        fnd::SecretString{std::string(43U, 'p')}, totp(), kNow);

    ASSERT_TRUE(command);
    EXPECT_TRUE(command->identity().canAuthenticate());
    EXPECT_EQ(command->link().state(), core::LinkState::Linked);
    EXPECT_EQ(command->link().owner(), core::IdentityId{"identity-2"});
    EXPECT_EQ(command->membership().state(), org::MembershipState::Active);
    ASSERT_EQ(command->membership().roles().size(), 2U);
    EXPECT_EQ(command->membership().roles()[0], org::Role{"member"});
    EXPECT_EQ(command->membership().roles()[1], org::Role{"viewer"});
    static_assert(!std::is_copy_constructible_v<admin::LocalMemberEnrollment>);
}

TEST(LocalMemberEnrollmentTest, RejectsDuplicateRolesAndCanonicalSubjectReuse)
{
    EXPECT_FALSE(admin::LocalMemberEnrollment::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        idp::ProviderId{"local"}, idp::ExternalSubject{"bob@example.test"},
        std::vector<org::Role>{org::Role{"member"}, org::Role{"member"}},
        fnd::SecretString{std::string(43U, 'p')}, totp(), kNow));
    EXPECT_FALSE(admin::LocalMemberEnrollment::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        idp::ProviderId{"local"}, idp::ExternalSubject{"identity-2"},
        std::vector<org::Role>{org::Role{"member"}},
        fnd::SecretString{std::string(43U, 'p')}, totp(), kNow));
}

TEST(MemberRoleReplacementTest, CanonicalizesAndValidatesTheCompleteRoleSet)
{
    auto replacement = admin::MemberRoleReplacement::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        std::vector<org::Role>{org::Role{"viewer"}, org::Role{"member"}}, kNow);
    ASSERT_TRUE(replacement);
    ASSERT_EQ(replacement->roles().size(), 2U);
    EXPECT_EQ(replacement->roles()[0], org::Role{"member"});
    EXPECT_EQ(replacement->roles()[1], org::Role{"viewer"});
    EXPECT_FALSE(admin::MemberRoleReplacement::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        std::vector<org::Role>{org::Role{"member"}, org::Role{"member"}}, kNow));
    EXPECT_FALSE(admin::MemberRoleReplacement::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"}, {}, kNow));
}

TEST(MemberLifecycleChangeTest, AcceptsOnlyKnownExplicitTransitions)
{
    for (const auto action : {admin::MemberLifecycleAction::Suspend,
                              admin::MemberLifecycleAction::Reinstate,
                              admin::MemberLifecycleAction::Remove}) {
        auto change = admin::MemberLifecycleChange::create(
            core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
            action, kNow);
        ASSERT_TRUE(change);
        EXPECT_FALSE(admin::memberLifecycleActionName(action).empty());
    }
    EXPECT_FALSE(admin::MemberLifecycleChange::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        static_cast<admin::MemberLifecycleAction>(99), kNow));
}

TEST(LocalCredentialResetTest, IsMoveOnlyAndRejectsWeakGeneratedMaterial)
{
    auto reset = admin::LocalCredentialReset::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        fnd::SecretString{std::string(43U, 'p')}, totp(), kNow);
    ASSERT_TRUE(reset);
    EXPECT_EQ(reset->identityId(), core::IdentityId{"identity-2"});
    EXPECT_FALSE(admin::LocalCredentialReset::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        fnd::SecretString{"weak"}, totp(), kNow));
    static_assert(!std::is_copy_constructible_v<admin::LocalCredentialReset>);
}

}

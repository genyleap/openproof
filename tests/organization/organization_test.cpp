#include <gtest/gtest.h>

#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>

import openproof.foundation;
import openproof.identity.core;
import openproof.organization;
import openproof.policy;

namespace fnd = openproof::foundation;
namespace org = openproof::organization;
namespace pol = openproof::policy;

namespace {

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

[[nodiscard]] org::Organization makeOrganization(const char* id, const char* name)
{
    auto created = org::Organization::create(org::OrganizationId{id}, std::string{name}, kNow);
    EXPECT_TRUE(created.has_value());
    return std::move(created).value();
}

[[nodiscard]] org::Membership makeMembership(const char* organization, const char* identity)
{
    auto created = org::Membership::invite(org::OrganizationId{organization},
                                           org::IdentityId{identity}, kNow);
    EXPECT_TRUE(created.has_value());
    return std::move(created).value();
}

TEST(OrganizationTest, CreatesActiveAndUsable)
{
    const org::Organization organization = makeOrganization("org-acme", "Acme");

    EXPECT_EQ(organization.id().value(), "org-acme");
    EXPECT_EQ(organization.displayName(), "Acme");
    EXPECT_EQ(organization.status(), org::OrganizationStatus::Active);
    EXPECT_TRUE(organization.isUsable());
}

TEST(OrganizationTest, RejectsEmptyIdentifierOrName)
{
    EXPECT_FALSE(org::Organization::create(org::OrganizationId{}, "Acme", kNow).has_value());
    EXPECT_FALSE(
        org::Organization::create(org::OrganizationId{"org-acme"}, "", kNow).has_value());
}

TEST(OrganizationTest, SuspensionRemovesUsabilityAndIsReversible)
{
    org::Organization organization = makeOrganization("org-acme", "Acme");

    ASSERT_TRUE(organization.changeStatus(org::OrganizationStatus::Suspended).has_value());
    EXPECT_FALSE(organization.isUsable());

    ASSERT_TRUE(organization.changeStatus(org::OrganizationStatus::Active).has_value());
    EXPECT_TRUE(organization.isUsable());
}

TEST(OrganizationTest, ArchiveIsTerminal)
{
    org::Organization organization = makeOrganization("org-acme", "Acme");
    ASSERT_TRUE(organization.changeStatus(org::OrganizationStatus::Archived).has_value());

    const auto revived = organization.changeStatus(org::OrganizationStatus::Active);
    ASSERT_FALSE(revived.has_value());
    EXPECT_EQ(revived.error().code(), fnd::ErrorCode::FailedPrecondition);
    EXPECT_FALSE(organization.rename("Renamed").has_value());
}

TEST(MembershipTest, InvitationGrantsNothing)
{
    const org::Membership membership = makeMembership("org-acme", "id-1");

    EXPECT_EQ(membership.state(), org::MembershipState::Invited);
    EXPECT_FALSE(org::permitsAccess(membership.state()))
        << "an invitation is an offer, not an access grant";
    EXPECT_TRUE(membership.roles().empty());
}

TEST(MembershipTest, AcceptanceActivates)
{
    org::Membership membership = makeMembership("org-acme", "id-1");

    ASSERT_TRUE(membership.accept().has_value());
    EXPECT_EQ(membership.state(), org::MembershipState::Active);
    EXPECT_TRUE(org::permitsAccess(membership.state()));

    // An invitation can only be accepted once.
    EXPECT_FALSE(membership.accept().has_value());
}

TEST(MembershipTest, GrantsAndRevokesRoles)
{
    org::Membership membership = makeMembership("org-acme", "id-1");
    ASSERT_TRUE(membership.accept().has_value());

    ASSERT_TRUE(membership.grantRole(pol::Role{"admin"}).has_value());
    ASSERT_TRUE(membership.grantRole(pol::Role{"viewer"}).has_value());
    EXPECT_TRUE(membership.hasRole(pol::Role{"admin"}));
    EXPECT_EQ(membership.roles().size(), 2U);

    // Granting an already-held role is idempotent, not a duplicate.
    ASSERT_TRUE(membership.grantRole(pol::Role{"admin"}).has_value());
    EXPECT_EQ(membership.roles().size(), 2U);

    ASSERT_TRUE(membership.revokeRole(pol::Role{"admin"}).has_value());
    EXPECT_FALSE(membership.hasRole(pol::Role{"admin"}));
}

// Revoking a role that was never held must not report success, or a caller
// could believe it removed authority it never found.
TEST(MembershipTest, RevokingAnUnheldRoleIsReportedHonestly)
{
    org::Membership membership = makeMembership("org-acme", "id-1");
    ASSERT_TRUE(membership.accept().has_value());

    const auto revoked = membership.revokeRole(pol::Role{"never-granted"});
    ASSERT_FALSE(revoked.has_value());
    EXPECT_EQ(revoked.error().code(), fnd::ErrorCode::NotFound);
}

// A suspended member keeps roles so reinstatement need not re-grant them, but
// those roles must grant nothing meanwhile.
TEST(MembershipTest, SuspensionMakesRolesInertWithoutDiscardingThem)
{
    org::Membership membership = makeMembership("org-acme", "id-1");
    ASSERT_TRUE(membership.accept().has_value());
    ASSERT_TRUE(membership.grantRole(pol::Role{"admin"}).has_value());

    ASSERT_TRUE(membership.suspend().has_value());
    EXPECT_FALSE(membership.hasRole(pol::Role{"admin"}))
        << "a suspended member must hold no effective role";
    EXPECT_EQ(membership.roles().size(), 1U) << "the grant is retained for reinstatement";

    ASSERT_TRUE(membership.reinstate().has_value());
    EXPECT_TRUE(membership.hasRole(pol::Role{"admin"}));
}

// Privilege resurrection: a removed member who is later re-invited must not
// silently regain the authority they previously held.
TEST(MembershipTest, RemovalDropsRoles)
{
    org::Membership membership = makeMembership("org-acme", "id-1");
    ASSERT_TRUE(membership.accept().has_value());
    ASSERT_TRUE(membership.grantRole(pol::Role{"admin"}).has_value());

    ASSERT_TRUE(membership.remove().has_value());
    EXPECT_EQ(membership.state(), org::MembershipState::Removed);
    EXPECT_TRUE(membership.roles().empty()) << "removal must not retain authority";
    EXPECT_FALSE(membership.hasRole(pol::Role{"admin"}));

    EXPECT_FALSE(membership.grantRole(pol::Role{"admin"}).has_value())
        << "authority must not attach to a relationship that no longer exists";
}

TEST(OrganizationRepositoryTest, StoresAndRetrieves)
{
    org::InMemoryOrganizationRepository repository;
    ASSERT_TRUE(repository.add(makeOrganization("org-acme", "Acme")).has_value());

    const auto found = repository.findById(org::OrganizationId{"org-acme"});
    ASSERT_TRUE(found.has_value());
    ASSERT_TRUE(found.value().has_value());
    EXPECT_EQ(found.value()->displayName(), "Acme");

    const auto duplicate = repository.add(makeOrganization("org-acme", "Impostor"));
    ASSERT_FALSE(duplicate.has_value());
    EXPECT_EQ(duplicate.error().code(), fnd::ErrorCode::AlreadyExists);
}

TEST(MembershipRepositoryTest, ScopesLookupsToTheOrganization)
{
    org::InMemoryMembershipRepository repository;
    ASSERT_TRUE(repository.add(makeMembership("org-acme", "id-1")).has_value());

    const auto own = repository.find(org::OrganizationId{"org-acme"}, org::IdentityId{"id-1"});
    ASSERT_TRUE(own.has_value());
    EXPECT_TRUE(own.value().has_value());

    const auto foreign =
        repository.find(org::OrganizationId{"org-globex"}, org::IdentityId{"id-1"});
    ASSERT_TRUE(foreign.has_value());
    EXPECT_FALSE(foreign.value().has_value())
        << "a membership in another tenant must not be addressable";
}

TEST(MembershipRepositoryTest, RejectsASecondMembershipForTheSamePair)
{
    org::InMemoryMembershipRepository repository;
    ASSERT_TRUE(repository.add(makeMembership("org-acme", "id-1")).has_value());

    const auto duplicate = repository.add(makeMembership("org-acme", "id-1"));
    ASSERT_FALSE(duplicate.has_value());
    EXPECT_EQ(duplicate.error().code(), fnd::ErrorCode::AlreadyExists);
}

// One identity, different roles in different tenants, with no leakage.
TEST(MembershipRepositoryTest, RolesAreScopedPerOrganization)
{
    org::InMemoryMembershipRepository repository;

    org::Membership atAcme = makeMembership("org-acme", "id-1");
    ASSERT_TRUE(atAcme.accept().has_value());
    ASSERT_TRUE(atAcme.grantRole(pol::Role{"owner"}).has_value());
    ASSERT_TRUE(repository.add(std::move(atAcme)).has_value());

    org::Membership atGlobex = makeMembership("org-globex", "id-1");
    ASSERT_TRUE(atGlobex.accept().has_value());
    ASSERT_TRUE(atGlobex.grantRole(pol::Role{"viewer"}).has_value());
    ASSERT_TRUE(repository.add(std::move(atGlobex)).has_value());

    const auto acme = repository.find(org::OrganizationId{"org-acme"}, org::IdentityId{"id-1"});
    const auto globex =
        repository.find(org::OrganizationId{"org-globex"}, org::IdentityId{"id-1"});

    ASSERT_TRUE(acme.has_value());
    ASSERT_TRUE(globex.has_value());
    ASSERT_TRUE(acme.value().has_value());
    ASSERT_TRUE(globex.value().has_value());

    EXPECT_TRUE(acme.value()->hasRole(pol::Role{"owner"}));
    EXPECT_FALSE(acme.value()->hasRole(pol::Role{"viewer"}));
    EXPECT_TRUE(globex.value()->hasRole(pol::Role{"viewer"}));
    EXPECT_FALSE(globex.value()->hasRole(pol::Role{"owner"}))
        << "a role held in one tenant must not leak into another";
}

TEST(MembershipRepositoryTest, ListsMembersAndOrganizations)
{
    org::InMemoryMembershipRepository repository;
    ASSERT_TRUE(repository.add(makeMembership("org-acme", "id-1")).has_value());
    ASSERT_TRUE(repository.add(makeMembership("org-acme", "id-2")).has_value());
    ASSERT_TRUE(repository.add(makeMembership("org-globex", "id-1")).has_value());

    const auto members = repository.membersOf(org::OrganizationId{"org-acme"});
    ASSERT_TRUE(members.has_value());
    EXPECT_EQ(members.value().size(), 2U);

    const auto organizations = repository.organizationsOf(org::IdentityId{"id-1"});
    ASSERT_TRUE(organizations.has_value());
    EXPECT_EQ(organizations.value().size(), 2U);

    const auto count = repository.countIn(org::OrganizationId{"org-acme"});
    ASSERT_TRUE(count.has_value());
    EXPECT_EQ(count.value(), 2U);
}

TEST(MembershipRepositoryTest, SaveRequiresAnExistingMembership)
{
    org::InMemoryMembershipRepository repository;

    const auto missing = repository.save(makeMembership("org-acme", "id-1"));
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().code(), fnd::ErrorCode::NotFound);
}

TEST(MembershipRepositoryTest, SavePersistsRoleChanges)
{
    org::InMemoryMembershipRepository repository;
    ASSERT_TRUE(repository.add(makeMembership("org-acme", "id-1")).has_value());

    auto loaded = repository.find(org::OrganizationId{"org-acme"}, org::IdentityId{"id-1"});
    ASSERT_TRUE(loaded.has_value());
    ASSERT_TRUE(loaded.value().has_value());

    org::Membership membership = std::move(loaded).value().value();
    ASSERT_TRUE(membership.accept().has_value());
    ASSERT_TRUE(membership.grantRole(pol::Role{"admin"}).has_value());
    ASSERT_TRUE(repository.save(membership).has_value());

    const auto reloaded = repository.find(org::OrganizationId{"org-acme"}, org::IdentityId{"id-1"});
    ASSERT_TRUE(reloaded.has_value());
    ASSERT_TRUE(reloaded.value().has_value());
    EXPECT_TRUE(reloaded.value()->hasRole(pol::Role{"admin"}));
}

TEST(MembershipTest, StateNamesAreStable)
{
    EXPECT_EQ(org::membershipStateName(org::MembershipState::Invited), "invited");
    EXPECT_EQ(org::membershipStateName(org::MembershipState::Removed), "removed");
    EXPECT_EQ(org::organizationStatusName(org::OrganizationStatus::Archived), "archived");
}

}

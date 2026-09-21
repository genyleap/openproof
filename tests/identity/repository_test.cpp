#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

import openproof.foundation;
import openproof.identity.core;

namespace fnd = openproof::foundation;
namespace core = openproof::identity::core;

namespace {

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

[[nodiscard]] core::Identity makeIdentity(const char* id,
                                          core::SubjectKind kind = core::SubjectKind::Human)
{
    auto created = core::Identity::create(core::IdentityId{id}, kind, kNow);
    EXPECT_TRUE(created.has_value());
    return std::move(created).value();
}

class IdentityRepositoryTest : public ::testing::Test {
protected:
    core::InMemoryIdentityRepository m_repository;
    const core::OrganizationId m_acme{"org-acme"};
    const core::OrganizationId m_globex{"org-globex"};
};

TEST_F(IdentityRepositoryTest, StartsEmpty)
{
    const auto count = m_repository.countIn(m_acme);
    ASSERT_TRUE(count.has_value());
    EXPECT_EQ(count.value(), 0U);
}

TEST_F(IdentityRepositoryTest, StoresAndRetrievesWithinAnOrganization)
{
    ASSERT_TRUE(m_repository.add(m_acme, makeIdentity("id-1")).has_value());

    const auto found = m_repository.findById(m_acme, core::IdentityId{"id-1"});
    ASSERT_TRUE(found.has_value());
    ASSERT_TRUE(found.value().has_value());
    EXPECT_EQ(found.value()->id().value(), "id-1");
    EXPECT_EQ(found.value()->kind(), core::SubjectKind::Human);
    EXPECT_EQ(found.value()->status(), core::IdentityStatus::Active);
}

TEST_F(IdentityRepositoryTest, AbsentKeyIsAnEmptyOptionalNotAnError)
{
    const auto found = m_repository.findById(m_acme, core::IdentityId{"absent"});
    ASSERT_TRUE(found.has_value());
    EXPECT_FALSE(found.value().has_value());
}

// The property this repository exists for. A generic CRUD interface keyed only
// by id cannot express it, which is why it was replaced.
TEST_F(IdentityRepositoryTest, AnotherTenantCannotReadAnIdentity)
{
    ASSERT_TRUE(m_repository.add(m_acme, makeIdentity("id-1")).has_value());

    const auto crossTenant = m_repository.findById(m_globex, core::IdentityId{"id-1"});
    ASSERT_TRUE(crossTenant.has_value());
    EXPECT_FALSE(crossTenant.value().has_value())
        << "an identity owned by another organization must not be readable";
}

// "Not found" and "not yours" must be indistinguishable, or the interface
// becomes an oracle for which identity keys exist in other tenants.
TEST_F(IdentityRepositoryTest, CrossTenantReadIsIndistinguishableFromAbsence)
{
    ASSERT_TRUE(m_repository.add(m_acme, makeIdentity("id-1")).has_value());

    const auto foreign = m_repository.findById(m_globex, core::IdentityId{"id-1"});
    const auto absent = m_repository.findById(m_globex, core::IdentityId{"never-existed"});

    ASSERT_TRUE(foreign.has_value());
    ASSERT_TRUE(absent.has_value());
    EXPECT_EQ(foreign.value().has_value(), absent.value().has_value());
}

TEST_F(IdentityRepositoryTest, AnotherTenantCannotChangeStatus)
{
    ASSERT_TRUE(m_repository.add(m_acme, makeIdentity("id-1")).has_value());

    const auto denied =
        m_repository.changeStatus(m_globex, core::IdentityId{"id-1"},
                                  core::IdentityStatus::Suspended);
    ASSERT_FALSE(denied.has_value());
    EXPECT_EQ(denied.error().code(), fnd::ErrorCode::NotFound);

    // The owning tenant's view is untouched.
    const auto found = m_repository.findById(m_acme, core::IdentityId{"id-1"});
    ASSERT_TRUE(found.has_value());
    ASSERT_TRUE(found.value().has_value());
    EXPECT_EQ(found.value()->status(), core::IdentityStatus::Active);
}

TEST_F(IdentityRepositoryTest, CountsAreScopedToTheOrganization)
{
    ASSERT_TRUE(m_repository.add(m_acme, makeIdentity("a-1")).has_value());
    ASSERT_TRUE(m_repository.add(m_acme, makeIdentity("a-2")).has_value());
    ASSERT_TRUE(m_repository.add(m_globex, makeIdentity("g-1")).has_value());

    const auto acme = m_repository.countIn(m_acme);
    const auto globex = m_repository.countIn(m_globex);

    ASSERT_TRUE(acme.has_value());
    ASSERT_TRUE(globex.has_value());
    EXPECT_EQ(acme.value(), 2U);
    EXPECT_EQ(globex.value(), 1U);
    EXPECT_EQ(m_repository.size(), 3U);
}

TEST_F(IdentityRepositoryTest, ListingByKindIsScopedToTheOrganization)
{
    ASSERT_TRUE(m_repository.add(m_acme, makeIdentity("a-human", core::SubjectKind::Human))
                    .has_value());
    ASSERT_TRUE(m_repository.add(m_acme, makeIdentity("a-service", core::SubjectKind::Service))
                    .has_value());
    ASSERT_TRUE(m_repository.add(m_globex, makeIdentity("g-service", core::SubjectKind::Service))
                    .has_value());

    const auto services = m_repository.idsOfKind(m_acme, core::SubjectKind::Service);
    ASSERT_TRUE(services.has_value());
    ASSERT_EQ(services.value().size(), 1U);
    EXPECT_EQ(services.value().front().value(), "a-service");
}

// Keys are globally unique. Permitting the same key in two tenants would make it
// ambiguous the moment anything references it without its tenant.
TEST_F(IdentityRepositoryTest, DuplicateKeysAreRejectedAcrossOrganizations)
{
    ASSERT_TRUE(m_repository.add(m_acme, makeIdentity("shared")).has_value());

    const auto duplicate = m_repository.add(m_globex, makeIdentity("shared"));
    ASSERT_FALSE(duplicate.has_value());
    EXPECT_EQ(duplicate.error().code(), fnd::ErrorCode::AlreadyExists);
    EXPECT_EQ(m_repository.size(), 1U);
}

TEST_F(IdentityRepositoryTest, StatusChangesPersist)
{
    ASSERT_TRUE(m_repository.add(m_acme, makeIdentity("id-1")).has_value());

    ASSERT_TRUE(m_repository
                    .changeStatus(m_acme, core::IdentityId{"id-1"},
                                  core::IdentityStatus::Suspended)
                    .has_value());

    const auto found = m_repository.findById(m_acme, core::IdentityId{"id-1"});
    ASSERT_TRUE(found.has_value());
    ASSERT_TRUE(found.value().has_value());
    EXPECT_EQ(found.value()->status(), core::IdentityStatus::Suspended);
    EXPECT_FALSE(found.value()->canAuthenticate());
}

// There is no remove(). Retirement is a status change so the tombstone that
// audit integrity depends on survives.
TEST_F(IdentityRepositoryTest, DeletionIsATombstoneNotARemoval)
{
    ASSERT_TRUE(m_repository.add(m_acme, makeIdentity("id-1")).has_value());
    ASSERT_TRUE(
        m_repository.changeStatus(m_acme, core::IdentityId{"id-1"}, core::IdentityStatus::Deleted)
            .has_value());

    const auto found = m_repository.findById(m_acme, core::IdentityId{"id-1"});
    ASSERT_TRUE(found.has_value());
    ASSERT_TRUE(found.value().has_value()) << "a deleted identity must remain as a tombstone";
    EXPECT_EQ(found.value()->status(), core::IdentityStatus::Deleted);
    EXPECT_FALSE(found.value()->canAuthenticate());

    // Deleted is terminal; the key can never be resurrected and reattached.
    const auto resurrect =
        m_repository.changeStatus(m_acme, core::IdentityId{"id-1"}, core::IdentityStatus::Active);
    ASSERT_FALSE(resurrect.has_value());
    EXPECT_EQ(resurrect.error().code(), fnd::ErrorCode::FailedPrecondition);
}

TEST_F(IdentityRepositoryTest, MissingIdentityCannotChangeStatus)
{
    const auto result =
        m_repository.changeStatus(m_acme, core::IdentityId{"absent"},
                                  core::IdentityStatus::Suspended);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code(), fnd::ErrorCode::NotFound);
}

// Domain code depends on the port, never the adapter, so persistent storage can
// replace the in-memory implementation without changing domain consumers.
TEST_F(IdentityRepositoryTest, IsUsableThroughTheAbstractPort)
{
    const std::unique_ptr<core::IdentityRepository> repository =
        std::make_unique<core::InMemoryIdentityRepository>();

    ASSERT_TRUE(repository->add(m_acme, makeIdentity("id-1")).has_value());

    const auto found = repository->findById(m_acme, core::IdentityId{"id-1"});
    ASSERT_TRUE(found.has_value());
    ASSERT_TRUE(found.value().has_value());
    EXPECT_EQ(found.value()->id().value(), "id-1");
}

}

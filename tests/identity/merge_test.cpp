#include <gtest/gtest.h>

#include <chrono>
#include <optional>
#include <utility>
#include <vector>

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

namespace fnd = openproof::foundation;
namespace core = openproof::identity::core;
namespace idp = openproof::identity::provider;

namespace {

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};
constexpr fnd::Duration kValidFor{std::chrono::minutes{15}};

[[nodiscard]] core::Identity makeIdentity(const char* id)
{
    auto created = core::Identity::create(core::IdentityId{id}, core::SubjectKind::Human, kNow);
    EXPECT_TRUE(created.has_value());
    return std::move(created).value();
}

[[nodiscard]] core::ExternalIdentityRef externalRef(const char* provider, const char* subject)
{
    return core::ExternalIdentityRef{idp::ProviderId{provider}, idp::ExternalSubject{subject}};
}

/** Drives a link all the way to Linked so the directory will accept it. */
[[nodiscard]] core::IdentityLink linkedTo(const core::IdentityId& owner,
                                          const core::ExternalIdentityRef& external)
{
    auto link = core::IdentityLink::request(owner, external, kNow, kValidFor);
    EXPECT_TRUE(link.has_value());
    EXPECT_TRUE(link->requireVerification(kNow).has_value());
    EXPECT_TRUE(link->markVerified(kNow).has_value());
    EXPECT_TRUE(link->complete(kNow).has_value());
    return std::move(link).value();
}

class MergeFixture : public ::testing::Test {
protected:
    void SetUp() override
    {
        ASSERT_TRUE(m_identities.add(m_acme, makeIdentity("source")).has_value());
        ASSERT_TRUE(m_identities.add(m_acme, makeIdentity("target")).has_value());
    }

    [[nodiscard]] core::IdentityMerge verifiedMerge()
    {
        auto merge = core::IdentityMerge::request(m_acme, core::IdentityId{"source"},
                                                  core::IdentityId{"target"}, kNow, kValidFor);
        EXPECT_TRUE(merge.has_value());
        EXPECT_TRUE(merge->requireVerification(kNow).has_value());
        EXPECT_TRUE(merge->markVerified(kNow).has_value());
        return std::move(merge).value();
    }

    core::InMemoryIdentityRepository m_identities;
    core::InMemoryExternalIdentityDirectory m_directory;
    const core::OrganizationId m_acme{"org-acme"};
    const core::OrganizationId m_globex{"org-globex"};
};

TEST_F(MergeFixture, RequestStartsUnverified)
{
    const auto merge = core::IdentityMerge::request(m_acme, core::IdentityId{"source"},
                                                    core::IdentityId{"target"}, kNow, kValidFor);
    ASSERT_TRUE(merge.has_value());
    EXPECT_EQ(merge->state(), core::MergeState::Requested);
    EXPECT_EQ(merge->source().value(), "source");
    EXPECT_EQ(merge->target().value(), "target");
    EXPECT_FALSE(merge->isExpiredAt(kNow));
}

// Merging an identity into itself would mark the survivor as merged, disabling
// the account the operation was meant to preserve.
TEST_F(MergeFixture, RefusesToMergeAnIdentityIntoItself)
{
    const auto merge = core::IdentityMerge::request(m_acme, core::IdentityId{"source"},
                                                    core::IdentityId{"source"}, kNow, kValidFor);
    ASSERT_FALSE(merge.has_value());
    EXPECT_EQ(merge.error().code(), fnd::ErrorCode::InvalidArgument);
}

// The core §72 acceptance criterion: merge is explicit. There is no path from
// Requested to Applied.
TEST_F(MergeFixture, CannotApplyWithoutVerification)
{
    auto merge = core::IdentityMerge::request(m_acme, core::IdentityId{"source"},
                                              core::IdentityId{"target"}, kNow, kValidFor);
    ASSERT_TRUE(merge.has_value());

    const auto applied = core::applyMerge(merge.value(), m_identities, m_directory, kNow);
    ASSERT_FALSE(applied.has_value());
    EXPECT_EQ(applied.error().code(), fnd::ErrorCode::FailedPrecondition);

    // And the source is untouched.
    const auto source = m_identities.findById(m_acme, core::IdentityId{"source"});
    ASSERT_TRUE(source.has_value());
    ASSERT_TRUE(source.value().has_value());
    EXPECT_EQ(source.value()->status(), core::IdentityStatus::Active);
}

TEST_F(MergeFixture, CannotMarkVerifiedWithoutRequiringVerificationFirst)
{
    auto merge = core::IdentityMerge::request(m_acme, core::IdentityId{"source"},
                                              core::IdentityId{"target"}, kNow, kValidFor);
    ASSERT_TRUE(merge.has_value());

    const auto verified = merge->markVerified(kNow);
    ASSERT_FALSE(verified.has_value());
    EXPECT_EQ(verified.error().code(), fnd::ErrorCode::FailedPrecondition);
}

TEST_F(MergeFixture, AppliesAVerifiedMergeAndRetiresTheSource)
{
    auto merge = verifiedMerge();

    const auto record = core::applyMerge(merge, m_identities, m_directory, kNow);
    ASSERT_TRUE(record.has_value());
    EXPECT_EQ(merge.state(), core::MergeState::Applied);
    EXPECT_EQ(record->source().value(), "source");
    EXPECT_EQ(record->target().value(), "target");

    const auto source = m_identities.findById(m_acme, core::IdentityId{"source"});
    ASSERT_TRUE(source.has_value());
    ASSERT_TRUE(source.value().has_value()) << "the absorbed identity must survive as a tombstone";
    EXPECT_EQ(source.value()->status(), core::IdentityStatus::Merged);
    EXPECT_FALSE(source.value()->canAuthenticate());

    const auto target = m_identities.findById(m_acme, core::IdentityId{"target"});
    ASSERT_TRUE(target.has_value());
    ASSERT_TRUE(target.value().has_value());
    EXPECT_EQ(target.value()->status(), core::IdentityStatus::Active);
}

TEST_F(MergeFixture, MovesExternalAssociationsToTheTarget)
{
    const core::ExternalIdentityRef first = externalRef("provider-a", "subject-1");
    const core::ExternalIdentityRef second = externalRef("provider-b", "subject-2");
    ASSERT_TRUE(m_directory.attach(linkedTo(core::IdentityId{"source"}, first)).has_value());
    ASSERT_TRUE(m_directory.attach(linkedTo(core::IdentityId{"source"}, second)).has_value());

    auto merge = verifiedMerge();
    const auto record = core::applyMerge(merge, m_identities, m_directory, kNow);
    ASSERT_TRUE(record.has_value());
    EXPECT_EQ(record->movedAssociations().size(), 2U);

    for (const core::ExternalIdentityRef& external : {first, second}) {
        const auto owner = m_directory.ownerOf(external);
        ASSERT_TRUE(owner.has_value());
        ASSERT_TRUE(owner.value().has_value());
        EXPECT_EQ(owner.value()->value(), "target");
    }

    const auto remaining = m_directory.externalIdentitiesOf(core::IdentityId{"source"});
    ASSERT_TRUE(remaining.has_value());
    EXPECT_TRUE(remaining.value().empty());
}

// §52: a merge must not cross tenants. It cannot even be attempted, because the
// identities are resolved through an organization-scoped repository.
TEST_F(MergeFixture, CannotMergeAcrossOrganizations)
{
    ASSERT_TRUE(m_identities.add(m_globex, makeIdentity("foreign")).has_value());

    auto merge = core::IdentityMerge::request(m_acme, core::IdentityId{"source"},
                                              core::IdentityId{"foreign"}, kNow, kValidFor);
    ASSERT_TRUE(merge.has_value());
    ASSERT_TRUE(merge->requireVerification(kNow).has_value());
    ASSERT_TRUE(merge->markVerified(kNow).has_value());

    const auto applied = core::applyMerge(merge.value(), m_identities, m_directory, kNow);
    ASSERT_FALSE(applied.has_value());
    EXPECT_EQ(applied.error().code(), fnd::ErrorCode::NotFound);

    // Neither identity changed.
    const auto foreign = m_identities.findById(m_globex, core::IdentityId{"foreign"});
    ASSERT_TRUE(foreign.has_value());
    ASSERT_TRUE(foreign.value().has_value());
    EXPECT_EQ(foreign.value()->status(), core::IdentityStatus::Active);
}

TEST_F(MergeFixture, CannotMergeIntoAnAlreadyMergedIdentity)
{
    auto first = verifiedMerge();
    ASSERT_TRUE(core::applyMerge(first, m_identities, m_directory, kNow).has_value());

    ASSERT_TRUE(m_identities.add(m_acme, makeIdentity("third")).has_value());

    // "source" is now Merged; using it again as a source must fail, or a chain
    // of merges would leave the final owner ambiguous.
    auto second = core::IdentityMerge::request(m_acme, core::IdentityId{"source"},
                                               core::IdentityId{"third"}, kNow, kValidFor);
    ASSERT_TRUE(second.has_value());
    ASSERT_TRUE(second->requireVerification(kNow).has_value());
    ASSERT_TRUE(second->markVerified(kNow).has_value());

    const auto applied = core::applyMerge(second.value(), m_identities, m_directory, kNow);
    ASSERT_FALSE(applied.has_value());
    EXPECT_EQ(applied.error().code(), fnd::ErrorCode::FailedPrecondition);
}

TEST_F(MergeFixture, ExpiredMergeCannotBeApplied)
{
    auto merge = verifiedMerge();
    const fnd::Instant afterExpiry = kNow + kValidFor + std::chrono::seconds{1};

    const auto applied = core::applyMerge(merge, m_identities, m_directory, afterExpiry);
    ASSERT_FALSE(applied.has_value());
    EXPECT_EQ(applied.error().code(), fnd::ErrorCode::FailedPrecondition);
    EXPECT_EQ(merge.state(), core::MergeState::Expired);
}

TEST_F(MergeFixture, ExpiryBoundaryResolvesInTheSafeDirection)
{
    const auto merge = core::IdentityMerge::request(m_acme, core::IdentityId{"source"},
                                                    core::IdentityId{"target"}, kNow, kValidFor);
    ASSERT_TRUE(merge.has_value());

    EXPECT_FALSE(merge->isExpiredAt(kNow + kValidFor - std::chrono::milliseconds{1}));
    EXPECT_TRUE(merge->isExpiredAt(kNow + kValidFor));
}

TEST_F(MergeFixture, RejectedMergeIsTerminal)
{
    auto merge = verifiedMerge();
    ASSERT_TRUE(merge.reject(kNow).has_value());
    EXPECT_EQ(merge.state(), core::MergeState::Rejected);

    EXPECT_FALSE(merge.markApplied(kNow).has_value());
    const auto applied = core::applyMerge(merge, m_identities, m_directory, kNow);
    EXPECT_FALSE(applied.has_value());
}

// A merge that was already applied must not be replayable.
TEST_F(MergeFixture, AppliedMergeCannotBeAppliedTwice)
{
    auto merge = verifiedMerge();
    ASSERT_TRUE(core::applyMerge(merge, m_identities, m_directory, kNow).has_value());

    const auto again = core::applyMerge(merge, m_identities, m_directory, kNow);
    ASSERT_FALSE(again.has_value());
    EXPECT_EQ(again.error().code(), fnd::ErrorCode::FailedPrecondition);
}

// reassign is the primitive merge uses. On its own it must not be usable to
// take an association from someone else.
TEST_F(MergeFixture, ReassignRefusesWhenTheExpectedOwnerIsWrong)
{
    const core::ExternalIdentityRef external = externalRef("provider-a", "subject-1");
    ASSERT_TRUE(m_directory.attach(linkedTo(core::IdentityId{"source"}, external)).has_value());

    const auto stolen =
        m_directory.reassign(external, core::IdentityId{"target"}, core::IdentityId{"target"});
    ASSERT_FALSE(stolen.has_value());
    EXPECT_EQ(stolen.error().code(), fnd::ErrorCode::PermissionDenied);

    const auto owner = m_directory.ownerOf(external);
    ASSERT_TRUE(owner.has_value());
    ASSERT_TRUE(owner.value().has_value());
    EXPECT_EQ(owner.value()->value(), "source");
}

TEST_F(MergeFixture, MergeStateNamesAreStable)
{
    EXPECT_EQ(core::mergeStateName(core::MergeState::Requested), "requested");
    EXPECT_EQ(core::mergeStateName(core::MergeState::VerificationRequired),
              "verification_required");
    EXPECT_EQ(core::mergeStateName(core::MergeState::Applied), "applied");
    EXPECT_TRUE(core::isTerminalMergeState(core::MergeState::Applied));
    EXPECT_FALSE(core::isTerminalMergeState(core::MergeState::Verified));
}

}

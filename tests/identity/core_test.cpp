#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <type_traits>
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
constexpr fnd::Duration kLifetime{std::chrono::milliseconds{600'000}};

// ---------------------------------------------------------------------------
// Invariant 1: an external identifier can never become a canonical identity key.
// Proven at compile time -- no test can be forgotten, and no future refactor can
// quietly introduce the conversion.
// ---------------------------------------------------------------------------

static_assert(!std::is_same_v<core::IdentityId, idp::ExternalSubject>);
static_assert(!std::is_convertible_v<idp::ExternalSubject, core::IdentityId>,
              "A provider subject must never convert to a canonical OpenProof identity key.");
static_assert(!std::is_convertible_v<core::IdentityId, idp::ExternalSubject>);
static_assert(!std::is_convertible_v<idp::ProviderId, core::IdentityId>);
static_assert(!std::is_convertible_v<core::OrganizationId, core::IdentityId>,
              "An organization key must never be usable as a subject key.");
static_assert(!std::is_convertible_v<std::string, core::IdentityId>,
              "Identity keys must be constructed explicitly, never from a bare string.");

[[nodiscard]] core::Identity makeIdentity(std::string id,
                                          core::SubjectKind kind = core::SubjectKind::Human)
{
    auto identity = core::Identity::create(core::IdentityId{std::move(id)}, kind, kNow);
    EXPECT_TRUE(identity.has_value());
    return std::move(identity).value();
}

[[nodiscard]] core::ExternalIdentityRef externalRef(std::string providerId, std::string subject)
{
    return core::ExternalIdentityRef{idp::ProviderId{std::move(providerId)},
                                     idp::ExternalSubject{std::move(subject)}};
}

/** Drives a link all the way to Linked through every mandated state. */
[[nodiscard]] core::IdentityLink linkedRequest(const std::string& owner,
                                               const core::ExternalIdentityRef& external)
{
    auto link = core::IdentityLink::request(core::IdentityId{owner}, external, kNow, kLifetime);
    EXPECT_TRUE(link.has_value());
    core::IdentityLink value = std::move(link).value();

    EXPECT_TRUE(value.requireVerification(kNow).has_value());
    EXPECT_TRUE(value.markVerified(kNow).has_value());
    EXPECT_TRUE(value.complete(kNow).has_value());
    return value;
}

// --- Identity ---------------------------------------------------------------

TEST(IdentityTest, IsCreatedActive)
{
    const core::Identity identity = makeIdentity("id-1");

    EXPECT_EQ(identity.id().value(), "id-1");
    EXPECT_EQ(identity.status(), core::IdentityStatus::Active);
    EXPECT_TRUE(identity.canAuthenticate());
}

TEST(IdentityTest, RejectsAnEmptyIdentifier)
{
    const auto identity = core::Identity::create(core::IdentityId{}, core::SubjectKind::Human, kNow);

    ASSERT_FALSE(identity.has_value());
    EXPECT_EQ(identity.error().code(), fnd::ErrorCode::InvalidArgument);
}

// Not every subject is a person; service-to-service authentication is first class.
TEST(IdentityTest, SupportsNonHumanSubjects)
{
    for (const core::SubjectKind kind :
         {core::SubjectKind::Human, core::SubjectKind::Service, core::SubjectKind::Workload,
          core::SubjectKind::Organization}) {
        const core::Identity identity = makeIdentity("id-1", kind);
        EXPECT_EQ(identity.kind(), kind);
        EXPECT_FALSE(core::subjectKindName(kind).empty());
    }
}

// Only Active permits authentication. Written as an allow-list so a status added
// later is denied by default.
TEST(IdentityTest, OnlyActiveIdentitiesMayAuthenticate)
{
    EXPECT_TRUE(core::permitsAuthentication(core::IdentityStatus::Active));
    EXPECT_FALSE(core::permitsAuthentication(core::IdentityStatus::Suspended));
    EXPECT_FALSE(core::permitsAuthentication(core::IdentityStatus::Locked));
    EXPECT_FALSE(core::permitsAuthentication(core::IdentityStatus::Deactivated));
    EXPECT_FALSE(core::permitsAuthentication(core::IdentityStatus::Deleted));
}

TEST(IdentityTest, SuspensionBlocksAuthenticationAndIsReversible)
{
    core::Identity identity = makeIdentity("id-1");

    ASSERT_TRUE(identity.changeStatus(core::IdentityStatus::Suspended).has_value());
    EXPECT_FALSE(identity.canAuthenticate());

    ASSERT_TRUE(identity.changeStatus(core::IdentityStatus::Active).has_value());
    EXPECT_TRUE(identity.canAuthenticate());
}

TEST(IdentityTest, DeletionIsTerminal)
{
    core::Identity identity = makeIdentity("id-1");
    ASSERT_TRUE(identity.changeStatus(core::IdentityStatus::Deleted).has_value());

    const fnd::Status revived = identity.changeStatus(core::IdentityStatus::Active);
    ASSERT_FALSE(revived.has_value());
    EXPECT_EQ(revived.error().code(), fnd::ErrorCode::FailedPrecondition);
    EXPECT_FALSE(identity.canAuthenticate());
}

// --- Link state machine -----------------------------------------------------

TEST(IdentityLinkTest, FollowsTheMandatedPath)
{
    auto link = core::IdentityLink::request(core::IdentityId{"id-1"},
                                            externalRef("provider-a", "sub-1"), kNow, kLifetime);
    ASSERT_TRUE(link.has_value());
    core::IdentityLink value = std::move(link).value();

    EXPECT_EQ(value.state(), core::LinkState::LinkRequested);
    ASSERT_TRUE(value.requireVerification(kNow).has_value());
    EXPECT_EQ(value.state(), core::LinkState::VerificationRequired);
    ASSERT_TRUE(value.markVerified(kNow).has_value());
    EXPECT_EQ(value.state(), core::LinkState::Verified);
    ASSERT_TRUE(value.complete(kNow).has_value());
    EXPECT_EQ(value.state(), core::LinkState::Linked);
}

// The single most important transition rule: nothing reaches Linked except from
// Verified. A request cannot be "completed" straight from creation.
TEST(IdentityLinkTest, CannotReachLinkedWithoutVerification)
{
    auto link = core::IdentityLink::request(core::IdentityId{"id-1"},
                                            externalRef("provider-a", "sub-1"), kNow, kLifetime);
    ASSERT_TRUE(link.has_value());
    core::IdentityLink value = std::move(link).value();

    const fnd::Status shortcut = value.complete(kNow);
    ASSERT_FALSE(shortcut.has_value());
    EXPECT_EQ(shortcut.error().code(), fnd::ErrorCode::FailedPrecondition);
    EXPECT_EQ(value.state(), core::LinkState::LinkRequested);

    // Nor by skipping the verification demand.
    core::IdentityLink other = std::move(
        core::IdentityLink::request(core::IdentityId{"id-1"}, externalRef("provider-a", "sub-1"),
                                    kNow, kLifetime)
            .value());
    EXPECT_FALSE(other.markVerified(kNow).has_value());
}

TEST(IdentityLinkTest, TerminalStatesAdmitNoFurtherTransitions)
{
    core::IdentityLink link = linkedRequest("id-1", externalRef("provider-a", "sub-1"));

    ASSERT_TRUE(link.revoke(kNow).has_value());
    EXPECT_TRUE(core::isTerminalLinkState(link.state()));

    EXPECT_FALSE(link.complete(kNow).has_value());
    EXPECT_FALSE(link.requireVerification(kNow).has_value());
    EXPECT_FALSE(link.markVerified(kNow).has_value());
    EXPECT_EQ(link.state(), core::LinkState::Revoked);
}

TEST(IdentityLinkTest, AnExpiredRequestCannotBeAdvanced)
{
    auto link = core::IdentityLink::request(core::IdentityId{"id-1"},
                                            externalRef("provider-a", "sub-1"), kNow, kLifetime);
    ASSERT_TRUE(link.has_value());
    core::IdentityLink value = std::move(link).value();

    const fnd::Instant afterDeadline = value.expiresAt();
    const fnd::Status advanced = value.requireVerification(afterDeadline);

    ASSERT_FALSE(advanced.has_value());
    EXPECT_EQ(advanced.error().code(), fnd::ErrorCode::FailedPrecondition);
    EXPECT_EQ(value.state(), core::LinkState::Expired);
}

// --- Directory: no implicit merge -------------------------------------------

TEST(ExternalIdentityDirectoryTest, AttachesOnlyACompletedLink)
{
    core::InMemoryExternalIdentityDirectory directory;

    auto pending = core::IdentityLink::request(core::IdentityId{"id-1"},
                                               externalRef("provider-a", "sub-1"), kNow, kLifetime);
    ASSERT_TRUE(pending.has_value());

    const fnd::Status attached = directory.attach(pending.value());
    ASSERT_FALSE(attached.has_value());
    EXPECT_EQ(attached.error().code(), fnd::ErrorCode::FailedPrecondition);
    EXPECT_EQ(directory.size(), 0U);
}

TEST(ExternalIdentityDirectoryTest, RecordsOwnership)
{
    core::InMemoryExternalIdentityDirectory directory;
    const core::ExternalIdentityRef external = externalRef("provider-a", "sub-1");

    ASSERT_TRUE(directory.attach(linkedRequest("id-1", external)).has_value());

    const auto owner = directory.ownerOf(external);
    ASSERT_TRUE(owner.has_value());
    ASSERT_TRUE(owner.value().has_value());
    EXPECT_EQ(owner.value()->value(), "id-1");
}

// The headline invariant: an external identity already owned by one canonical
// identity is never transferred to another. Silent transfer is account takeover.
TEST(ExternalIdentityDirectoryTest, RefusesToTransferAnAlreadyOwnedExternalIdentity)
{
    core::InMemoryExternalIdentityDirectory directory;
    const core::ExternalIdentityRef external = externalRef("provider-a", "sub-1");

    ASSERT_TRUE(directory.attach(linkedRequest("victim", external)).has_value());

    const fnd::Status hijack = directory.attach(linkedRequest("attacker", external));

    ASSERT_FALSE(hijack.has_value());
    EXPECT_EQ(hijack.error().code(), fnd::ErrorCode::Conflict);

    // Ownership must be entirely unchanged.
    const auto owner = directory.ownerOf(external);
    ASSERT_TRUE(owner.has_value());
    ASSERT_TRUE(owner.value().has_value());
    EXPECT_EQ(owner.value()->value(), "victim");
    EXPECT_EQ(directory.size(), 1U);
}

TEST(ExternalIdentityDirectoryTest, ReattachingTheSameOwnerIsIdempotent)
{
    core::InMemoryExternalIdentityDirectory directory;
    const core::ExternalIdentityRef external = externalRef("provider-a", "sub-1");

    ASSERT_TRUE(directory.attach(linkedRequest("id-1", external)).has_value());
    ASSERT_TRUE(directory.attach(linkedRequest("id-1", external)).has_value());
    EXPECT_EQ(directory.size(), 1U);
}

// Two providers asserting the same email address are still two separate external
// identities. Nothing in this platform lets a matching attribute create a link.
TEST(ExternalIdentityDirectoryTest, MatchingAttributesDoNotMergeIdentities)
{
    core::InMemoryExternalIdentityDirectory directory;

    // Both providers assert ada@example.com, but the subjects are provider-scoped
    // and the association is keyed on (provider, subject).
    const core::ExternalIdentityRef fromProviderA = externalRef("provider-a", "ada@example.com");
    const core::ExternalIdentityRef fromProviderB = externalRef("provider-b", "ada@example.com");

    ASSERT_TRUE(directory.attach(linkedRequest("id-1", fromProviderA)).has_value());

    // The second provider's identity is unowned: matching email created nothing.
    const auto owner = directory.ownerOf(fromProviderB);
    ASSERT_TRUE(owner.has_value());
    EXPECT_FALSE(owner.value().has_value())
        << "a matching email address must not imply a linked identity";

    // Attaching it to a *different* canonical identity is perfectly legal,
    // which is the proof that the two were never treated as the same person.
    ASSERT_TRUE(directory.attach(linkedRequest("id-2", fromProviderB)).has_value());
    EXPECT_EQ(directory.size(), 2U);
}

// The same subject string from two different providers must never collide.
TEST(ExternalIdentityDirectoryTest, SubjectsAreScopedToTheirProvider)
{
    core::InMemoryExternalIdentityDirectory directory;

    ASSERT_TRUE(directory.attach(linkedRequest("id-1", externalRef("provider-a", "12345")))
                    .has_value());
    ASSERT_TRUE(directory.attach(linkedRequest("id-2", externalRef("provider-b", "12345")))
                    .has_value());

    EXPECT_EQ(directory.size(), 2U);
}

TEST(ExternalIdentityDirectoryTest, DetachRequiresTheCorrectOwner)
{
    core::InMemoryExternalIdentityDirectory directory;
    const core::ExternalIdentityRef external = externalRef("provider-a", "sub-1");
    ASSERT_TRUE(directory.attach(linkedRequest("victim", external)).has_value());

    const fnd::Status wrongOwner = directory.detach(external, core::IdentityId{"attacker"});
    ASSERT_FALSE(wrongOwner.has_value());
    EXPECT_EQ(wrongOwner.error().code(), fnd::ErrorCode::PermissionDenied);
    EXPECT_EQ(directory.size(), 1U);

    ASSERT_TRUE(directory.detach(external, core::IdentityId{"victim"}).has_value());
    EXPECT_EQ(directory.size(), 0U);
}

TEST(ExternalIdentityDirectoryTest, ListsExternalIdentitiesOfAnOwner)
{
    core::InMemoryExternalIdentityDirectory directory;
    ASSERT_TRUE(directory.attach(linkedRequest("id-1", externalRef("provider-a", "sub-1")))
                    .has_value());
    ASSERT_TRUE(directory.attach(linkedRequest("id-1", externalRef("provider-b", "sub-2")))
                    .has_value());
    ASSERT_TRUE(directory.attach(linkedRequest("id-2", externalRef("provider-c", "sub-3")))
                    .has_value());

    const auto owned = directory.externalIdentitiesOf(core::IdentityId{"id-1"});
    ASSERT_TRUE(owned.has_value());
    EXPECT_EQ(owned.value().size(), 2U);

    const auto none = directory.externalIdentitiesOf(core::IdentityId{"id-absent"});
    ASSERT_TRUE(none.has_value());
    EXPECT_TRUE(none.value().empty());
}

TEST(ExternalIdentityDirectoryTest, StoresPresentationMetadataWithoutChangingOwnership)
{
    core::InMemoryExternalIdentityDirectory directory;
    const auto bare = externalRef("farcaster", "12345");
    ASSERT_TRUE(directory.attach(linkedRequest("id-1", bare)).has_value());

    const core::ExternalIdentityRef presentation{
        idp::ProviderId{"farcaster"}, idp::ExternalSubject{"12345"},
        std::string{"Alice"}, std::string{"alice"},
        std::string{"https://example.test/alice.png"}};
    ASSERT_TRUE(directory.updatePresentation(presentation).has_value());

    const auto owner = directory.ownerOf(presentation);
    ASSERT_TRUE(owner.has_value());
    ASSERT_TRUE(owner->has_value());
    EXPECT_EQ(owner->value().value(), "id-1");

    const auto owned = directory.externalIdentitiesOf(core::IdentityId{"id-1"});
    ASSERT_TRUE(owned.has_value());
    ASSERT_EQ(owned->size(), 1U);
    EXPECT_EQ(owned->front().displayName(), std::optional<std::string>{"Alice"});
    EXPECT_EQ(owned->front().preferredUsername(), std::optional<std::string>{"alice"});
    EXPECT_EQ(owned->front().pictureUrl(),
              std::optional<std::string>{"https://example.test/alice.png"});
}

TEST(ExternalIdentityDirectoryTest, ConcurrentProtectedDetachAlwaysLeavesOneSignInMethod)
{
    core::InMemoryExternalIdentityDirectory directory;
    const auto first = externalRef("provider-a", "sub-1");
    const auto second = externalRef("provider-b", "sub-2");
    const core::IdentityId owner{"id-1"};
    ASSERT_TRUE(directory.attach(linkedRequest("id-1", first)));
    ASSERT_TRUE(directory.attach(linkedRequest("id-1", second)));
    const std::vector<idp::ProviderId> providers{
        idp::ProviderId{"provider-a"}, idp::ProviderId{"provider-b"}};
    std::atomic<int> successes{0};
    std::atomic<int> preconditions{0};
    const auto remove = [&](const core::ExternalIdentityRef& external) {
        auto status = directory.detachIfAnotherAuthenticationMethod(
            external, owner, providers);
        if (status) ++successes;
        else if (status.error().code() == fnd::ErrorCode::FailedPrecondition) {
            ++preconditions;
        }
    };

    std::thread firstRemoval{remove, std::cref(first)};
    std::thread secondRemoval{remove, std::cref(second)};
    firstRemoval.join();
    secondRemoval.join();

    EXPECT_EQ(successes.load(), 1);
    EXPECT_EQ(preconditions.load(), 1);
    EXPECT_EQ(directory.size(), 1U);
}

}

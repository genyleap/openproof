#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.provider.passkey;

namespace {

namespace core = openproof::identity::core;
namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace passkey = openproof::provider::passkey;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

[[nodiscard]] passkey::PasskeyCredential credential(
    std::string id, const core::IdentityId& identity)
{
    return passkey::PasskeyCredential{
        std::move(id), identity,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        0U, kNow, kNow};
}

void attachPasskey(core::InMemoryExternalIdentityDirectory& identities,
                   const core::IdentityId& identity)
{
    const core::ExternalIdentityRef external{
        idp::ProviderId{"passkey"},
        idp::ExternalSubject{std::string{identity.value()}}};
    auto link = core::IdentityLink::request(
        identity, external, kNow, std::chrono::minutes{5}).value();
    ASSERT_TRUE(link.requireVerification(kNow));
    ASSERT_TRUE(link.markVerified(kNow));
    ASSERT_TRUE(link.complete(kNow));
    ASSERT_TRUE(identities.attach(link));
}

[[nodiscard]] passkey::PasskeyConfig config()
{
    return passkey::PasskeyConfig::create(
        "identity.example.test", "OpenProof Test",
        "https://identity.example.test",
        fnd::SecretString{std::string(32U, 'k')},
        std::chrono::minutes{5}).value();
}

TEST(PasskeyRepositoryTest, ConcurrentRemovalPreservesOneCredential)
{
    passkey::InMemoryPasskeyRepository repository;
    const core::IdentityId identity{"identity-1"};
    ASSERT_TRUE(repository.addCredential(credential("credential-a", identity)));
    ASSERT_TRUE(repository.addCredential(credential("credential-b", identity)));

    std::atomic<int> removed{0};
    std::thread first([&] {
        if (repository.removeCredentialIfAnotherExists(identity, "credential-a")) {
            removed.fetch_add(1, std::memory_order_relaxed);
        }
    });
    std::thread second([&] {
        if (repository.removeCredentialIfAnotherExists(identity, "credential-b")) {
            removed.fetch_add(1, std::memory_order_relaxed);
        }
    });
    first.join();
    second.join();

    EXPECT_EQ(removed.load(std::memory_order_relaxed), 1);
    auto remaining = repository.listCredentials(identity);
    ASSERT_TRUE(remaining);
    ASSERT_EQ(remaining->size(), 1U);
}

TEST(PasskeyServiceTest, RefusesFinalCredentialWhilePasskeyConnectionIsAttached)
{
    passkey::InMemoryPasskeyRepository repository;
    core::InMemoryExternalIdentityDirectory identities;
    fnd::ManualClockSource clock{kNow};
    auto passkeyConfig = config();
    passkey::PasskeyService service{repository, identities, clock, passkeyConfig};
    const core::IdentityId identity{"identity-1"};

    ASSERT_TRUE(repository.addCredential(credential("credential-a", identity)));
    attachPasskey(identities, identity);

    auto removed = service.remove(identity, "credential-a");

    ASSERT_FALSE(removed);
    EXPECT_EQ(removed.error().code(), fnd::ErrorCode::FailedPrecondition);
    auto remaining = repository.listCredentials(identity);
    ASSERT_TRUE(remaining);
    ASSERT_EQ(remaining->size(), 1U);
}
TEST(PasskeyServiceTest, RemovesFinalCredentialAfterPasskeyConnectionWasSafelyDetached)
{
    passkey::InMemoryPasskeyRepository repository;
    core::InMemoryExternalIdentityDirectory identities;
    fnd::ManualClockSource clock{kNow};
    auto passkeyConfig = config();
    passkey::PasskeyService service{repository, identities, clock, passkeyConfig};
    const core::IdentityId identity{"identity-1"};
    const core::ExternalIdentityRef external{
        idp::ProviderId{"passkey"},
        idp::ExternalSubject{std::string{identity.value()}}};

    ASSERT_TRUE(repository.addCredential(credential("credential-a", identity)));
    attachPasskey(identities, identity);
    ASSERT_TRUE(identities.detach(external, identity));

    auto removed = service.remove(identity, "credential-a");

    ASSERT_TRUE(removed) << removed.error().internalDetail();
    auto remaining = repository.listCredentials(identity);
    ASSERT_TRUE(remaining);
    EXPECT_TRUE(remaining->empty());
}
TEST(PasskeyServiceTest, RemovingOneOfMultipleCredentialsKeepsConnectionAttached)
{
    passkey::InMemoryPasskeyRepository repository;
    core::InMemoryExternalIdentityDirectory identities;
    fnd::ManualClockSource clock{kNow};
    auto passkeyConfig = config();
    passkey::PasskeyService service{repository, identities, clock, passkeyConfig};
    const core::IdentityId identity{"identity-1"};
    const core::ExternalIdentityRef external{
        idp::ProviderId{"passkey"},
        idp::ExternalSubject{std::string{identity.value()}}};

    ASSERT_TRUE(repository.addCredential(credential("credential-a", identity)));
    ASSERT_TRUE(repository.addCredential(credential("credential-b", identity)));
    attachPasskey(identities, identity);

    ASSERT_TRUE(service.remove(identity, "credential-a"));
    auto owner = identities.ownerOf(external);
    ASSERT_TRUE(owner);
    ASSERT_TRUE(owner->has_value());
    EXPECT_EQ(owner->value(), identity);

    auto finalRemoval = service.remove(identity, "credential-b");
    ASSERT_FALSE(finalRemoval);
    EXPECT_EQ(finalRemoval.error().code(), fnd::ErrorCode::FailedPrecondition);
}


TEST(PasskeyRepositoryTest, ZeroCounterCredentialRecordsSuccessfulUse)
{
    passkey::InMemoryPasskeyRepository repository;
    const core::IdentityId identity{"identity-zero"};
    const auto usedAt = kNow + std::chrono::minutes{5};
    ASSERT_TRUE(repository.addCredential(credential("credential-zero", identity)));

    ASSERT_TRUE(repository.advanceCounter("credential-zero", 0U, 0U, usedAt));

    auto stored = repository.findCredential("credential-zero");
    ASSERT_TRUE(stored);
    ASSERT_TRUE(stored->has_value());
    EXPECT_EQ(stored->value().signCount, 0U);
    EXPECT_EQ(stored->value().lastUsedAt, usedAt);

    ASSERT_TRUE(repository.advanceCounter("credential-zero", 0U, 0U, kNow));
    stored = repository.findCredential("credential-zero");
    ASSERT_TRUE(stored);
    ASSERT_TRUE(stored->has_value());
    EXPECT_EQ(stored->value().lastUsedAt, usedAt);
}

TEST(PasskeyRepositoryTest, SupportedCounterMustStillAdvanceStrictly)
{
    passkey::InMemoryPasskeyRepository repository;
    const core::IdentityId identity{"identity-counter"};
    auto value = credential("credential-counter", identity);
    value.signCount = 7U;
    ASSERT_TRUE(repository.addCredential(std::move(value)));

    auto unchanged = repository.advanceCounter("credential-counter", 7U, 7U, kNow + std::chrono::minutes{5});
    ASSERT_FALSE(unchanged);
    EXPECT_EQ(unchanged.error().code(), fnd::ErrorCode::Conflict);

    const auto usedAt = kNow + std::chrono::minutes{5};
    ASSERT_TRUE(repository.advanceCounter("credential-counter", 7U, 8U, usedAt));
    auto stored = repository.findCredential("credential-counter");
    ASSERT_TRUE(stored);
    ASSERT_TRUE(stored->has_value());
    EXPECT_EQ(stored->value().signCount, 8U);
    EXPECT_EQ(stored->value().lastUsedAt, usedAt);
}

} // namespace

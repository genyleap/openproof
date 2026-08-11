#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

import openproof.audit;
import openproof.foundation;

namespace audit = openproof::audit;
namespace fnd = openproof::foundation;

namespace {

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

[[nodiscard]] audit::AuditKey key(std::string value =
    "0123456789abcdef0123456789abcdef")
{
    return audit::AuditKey::create(fnd::SecretString{std::move(value)}).value();
}

[[nodiscard]] audit::AuditEvent event(std::string id)
{
    return audit::AuditEvent::create(
        audit::AuditEventId{std::move(id)}, kNow, fnd::CorrelationId{"corr-1"},
        std::nullopt, std::nullopt, "authentication", "session.issue", "success",
        {{"remote_ip", "192.0.2.1"}}).value();
}

}

TEST(AuditEventTest, RejectsControlCharactersAndOversizedFieldSets)
{
    EXPECT_FALSE(audit::AuditEvent::create(
        audit::AuditEventId{"id"}, kNow, fnd::CorrelationId{"corr"}, std::nullopt,
        std::nullopt, "authentication\n", "start", "failure").has_value());

    audit::AuditFields fields;
    for (std::size_t index = 0U; index < 65U; ++index) {
        fields.emplace("field_" + std::to_string(index), "value");
    }
    EXPECT_FALSE(audit::AuditEvent::create(
        audit::AuditEventId{"id"}, kNow, fnd::CorrelationId{"corr"}, std::nullopt,
        std::nullopt, "authentication", "start", "failure", std::move(fields))
                     .has_value());
}

TEST(AuditRepositoryTest, ProducesAndVerifiesAnAppendOnlyHashChain)
{
    audit::InMemoryAuditRepository repository;
    auto signingKey = key();
    auto first = repository.append(event("event-1"), signingKey);
    auto second = repository.append(event("event-2"), signingKey);

    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(first->sequence(), 1U);
    EXPECT_EQ(second->sequence(), 2U);
    EXPECT_FALSE(first->previousHash().has_value());
    ASSERT_TRUE(second->previousHash().has_value());
    EXPECT_EQ(second->previousHash().value(), first->hash());
    EXPECT_TRUE(repository.verify(signingKey).has_value());

    auto incorrectKey = key("abcdef0123456789abcdef0123456789");
    EXPECT_FALSE(repository.verify(incorrectKey).has_value());
}

TEST(AuditRepositoryTest, RejectsDuplicateEventIds)
{
    audit::InMemoryAuditRepository repository;
    auto signingKey = key();
    ASSERT_TRUE(repository.append(event("duplicate"), signingKey).has_value());
    const auto duplicate = repository.append(event("duplicate"), signingKey);
    ASSERT_FALSE(duplicate.has_value());
    EXPECT_EQ(duplicate.error().code(), fnd::ErrorCode::AlreadyExists);
}

TEST(AuditRepositoryTest, ConcurrentAppendsAllocateOneContinuousChain)
{
    audit::InMemoryAuditRepository repository;
    auto signingKey = key();
    std::vector<std::thread> workers;
    for (std::size_t index = 0U; index < 32U; ++index) {
        workers.emplace_back([&repository, &signingKey, index] {
            EXPECT_TRUE(repository.append(
                event("concurrent-" + std::to_string(index)), signingKey).has_value());
        });
    }
    for (auto& worker : workers) worker.join();

    auto records = repository.records();
    ASSERT_TRUE(records.has_value());
    ASSERT_EQ(records->size(), 32U);
    for (std::size_t index = 0U; index < records->size(); ++index) {
        EXPECT_EQ(records->at(index).sequence(), index + 1U);
    }
    EXPECT_TRUE(repository.verify(signingKey).has_value());
}

TEST(SecurityEventSinkTest, IsIdempotentByEventIdentifier)
{
    audit::InMemorySecurityEventSink sink;
    auto makeEvent = [] {
        return audit::SecurityEvent::create(
            audit::AuditEventId{"security-1"}, kNow, fnd::CorrelationId{"corr"},
            audit::SecuritySeverity::Critical, "credential-stuffing",
            {{"source", "rate-limiter"}}).value();
    };
    EXPECT_TRUE(sink.publish(makeEvent()).has_value());
    EXPECT_FALSE(sink.publish(makeEvent()).has_value());
    EXPECT_EQ(sink.events().size(), 1U);
}

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

import openproof.foundation;
import openproof.observability;

namespace fnd = openproof::foundation;
namespace obs = openproof::observability;

namespace {

constexpr fnd::Instant kFixedTime{std::chrono::milliseconds{1'770'000'000'000}};

class LogFixture : public ::testing::Test {
protected:
    void SetUp() override
    {
        m_sink = std::make_shared<obs::MemoryLogSink>();
        m_clock = std::make_shared<const fnd::ManualClockSource>(kFixedTime);
    }

    [[nodiscard]] obs::Logger makeLogger(obs::LogLevel level = obs::LogLevel::Trace) const
    {
        return obs::Logger{m_sink, m_clock, level};
    }

    [[nodiscard]] std::string onlyRecord() const
    {
        const std::vector<std::string> records = m_sink->records();
        EXPECT_EQ(records.size(), 1U);
        return records.empty() ? std::string{} : records.front();
    }

    std::shared_ptr<obs::MemoryLogSink> m_sink;
    std::shared_ptr<const fnd::ManualClockSource> m_clock;
};

TEST_F(LogFixture, EmitsOneJsonObjectPerRecord)
{
    makeLogger().info("service started");

    EXPECT_EQ(onlyRecord(),
              R"({"timestamp":"2026-02-02T02:40:00.000Z","level":"info",)"
              R"("message":"service started"})");
}

TEST_F(LogFixture, NestsCallerFieldsSoTheyCannotShadowTheEnvelope)
{
    const std::vector<obs::LogField> fields{
        obs::LogField::text("level", "not-the-envelope-level"),
        obs::LogField::integer("attempt", 3),
        obs::LogField::boolean("retry", true),
    };

    makeLogger().warn("upstream degraded", fields);

    const std::string record = onlyRecord();
    EXPECT_NE(record.find(R"("level":"warn")"), std::string::npos);
    EXPECT_NE(record.find(R"("fields":{)"), std::string::npos);
    EXPECT_NE(record.find(R"("level":"not-the-envelope-level")"), std::string::npos);
    EXPECT_NE(record.find(R"("attempt":3)"), std::string::npos);
    EXPECT_NE(record.find(R"("retry":true)"), std::string::npos);
}

TEST_F(LogFixture, DropsRecordsBelowTheMinimumLevel)
{
    const obs::Logger logger = makeLogger(obs::LogLevel::Warn);

    EXPECT_FALSE(logger.isEnabled(obs::LogLevel::Info));
    EXPECT_TRUE(logger.isEnabled(obs::LogLevel::Error));

    logger.trace("dropped");
    logger.debug("dropped");
    logger.info("dropped");
    EXPECT_EQ(m_sink->size(), 0U);

    logger.warn("kept");
    logger.error("kept");
    logger.critical("kept");
    EXPECT_EQ(m_sink->size(), 3U);
}

TEST_F(LogFixture, StampsCorrelationIdentifiersFromContext)
{
    obs::LogContext context;
    context.withRequestId(fnd::RequestId{"req-7"}).withCorrelationId(fnd::CorrelationId{"corr-9"});

    makeLogger().withContext(context).info("handling request");

    const std::string record = onlyRecord();
    EXPECT_NE(record.find(R"("request_id":"req-7")"), std::string::npos);
    EXPECT_NE(record.find(R"("correlation_id":"corr-9")"), std::string::npos);
}

TEST_F(LogFixture, OmitsCorrelationIdentifiersWhenAbsent)
{
    makeLogger().info("no context");

    const std::string record = onlyRecord();
    EXPECT_EQ(record.find("request_id"), std::string::npos);
    EXPECT_EQ(record.find("correlation_id"), std::string::npos);
}

TEST_F(LogFixture, RecordsBothChannelsOfAnError)
{
    const fnd::Error failure{fnd::ErrorCode::Unavailable, "The service is temporarily unavailable.",
                             "postgres shard 2 refused connection"};

    makeLogger().logError(obs::LogLevel::Error, failure);

    const std::string record = onlyRecord();
    EXPECT_NE(record.find(R"("error_code":"UNAVAILABLE")"), std::string::npos);
    EXPECT_NE(record.find("postgres shard 2 refused connection"), std::string::npos);
    EXPECT_NE(record.find("The service is temporarily unavailable."), std::string::npos);
}

TEST_F(LogFixture, EscapesHostileMessageContent)
{
    makeLogger().info(R"(injected","level":"critical)");

    const std::string record = onlyRecord();
    EXPECT_NE(record.find(R"(injected\",\"level\":\"critical)"), std::string::npos);
    // Exactly one level entry survives: the envelope's own.
    EXPECT_EQ(record.find(R"("level":"critical")"), std::string::npos);
}

TEST_F(LogFixture, UsesTheInjectedClockSoTimestampsAreDeterministic)
{
    const obs::Logger logger = makeLogger();
    logger.info("first");

    const std::vector<std::string> records = m_sink->records();
    ASSERT_EQ(records.size(), 1U);
    EXPECT_NE(records.front().find(R"("timestamp":"2026-02-02T02:40:00.000Z")"),
              std::string::npos);
}

TEST(LoggerConstructionTest, RejectsNullCollaborators)
{
    const auto clock = std::make_shared<const fnd::SystemClockSource>();
    const auto sink = std::make_shared<obs::MemoryLogSink>();

    EXPECT_THROW((obs::Logger{nullptr, clock, obs::LogLevel::Info}), std::invalid_argument);
    EXPECT_THROW((obs::Logger{sink, nullptr, obs::LogLevel::Info}), std::invalid_argument);
}

TEST(LogLevelTest, ParsesConfiguredNamesCaseInsensitively)
{
    EXPECT_EQ(obs::parseLogLevel("INFO"), obs::LogLevel::Info);
    EXPECT_EQ(obs::parseLogLevel("Warn"), obs::LogLevel::Warn);
    EXPECT_EQ(obs::parseLogLevel("warning"), obs::LogLevel::Warn);
    EXPECT_EQ(obs::parseLogLevel("fatal"), obs::LogLevel::Critical);
    EXPECT_FALSE(obs::parseLogLevel("verbose").has_value());
    EXPECT_FALSE(obs::parseLogLevel("").has_value());
}

TEST(LogLevelTest, NamesAreStable)
{
    EXPECT_EQ(obs::logLevelName(obs::LogLevel::Trace), "trace");
    EXPECT_EQ(obs::logLevelName(obs::LogLevel::Critical), "critical");
}

// The redaction claim, checked at compile time: a LogField cannot be built from
// a Secret, so a credential cannot reach a log record by mistake.
template <typename T>
concept LoggableAsText = requires(T&& value) { obs::LogField::text("key", std::forward<T>(value)); };

static_assert(LoggableAsText<std::string>);
static_assert(!LoggableAsText<fnd::SecretString>,
              "A Secret must not be accepted by any LogField factory.");

}

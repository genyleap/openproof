#include <gtest/gtest.h>

#include <chrono>
#include <optional>
#include <string>
#include <vector>

import openproof.foundation;
import openproof.telemetry;

namespace fnd = openproof::foundation;
namespace telemetry = openproof::telemetry;

namespace {

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

}

TEST(MetricRegistryTest, EnforcesSeriesCardinalityAndMetricType)
{
    telemetry::MetricRegistry metrics{2U};
    EXPECT_TRUE(metrics.increment("gateway_requests_total", {{"route", "one"}})
                    .has_value());
    EXPECT_TRUE(metrics.increment("gateway_requests_total", {{"route", "one"}}, 2.0)
                    .has_value());
    EXPECT_TRUE(metrics.observe("gateway_latency_seconds", {0.1, 1.0}, 0.2)
                    .has_value());
    EXPECT_FALSE(metrics.increment("third_series_total").has_value());
    EXPECT_FALSE(metrics.observe("gateway_requests_total", {1.0}, 0.5,
                                 {{"route", "one"}}).has_value());
    EXPECT_EQ(metrics.seriesCount(), 2U);
}

TEST(MetricRegistryTest, ExportsCumulativePrometheusHistogramBuckets)
{
    telemetry::MetricRegistry metrics{4U};
    ASSERT_TRUE(metrics.observe("request_seconds", {0.1, 0.5, 1.0}, 0.05,
                                {{"method", "GET"}}).has_value());
    ASSERT_TRUE(metrics.observe("request_seconds", {0.1, 0.5, 1.0}, 0.8,
                                {{"method", "GET"}}).has_value());
    const std::string text = metrics.prometheus();
    EXPECT_NE(text.find("request_seconds_bucket{le=\"0.1\",method=\"GET\"} 1"),
              std::string::npos);
    EXPECT_NE(text.find("request_seconds_bucket{le=\"1\",method=\"GET\"} 2"),
              std::string::npos);
    EXPECT_NE(text.find("request_seconds_count{method=\"GET\"} 2"),
              std::string::npos);
}

TEST(MetricRegistryTest, RejectsInvalidPrometheusLabelsAndValues)
{
    telemetry::MetricRegistry metrics{4U};
    EXPECT_FALSE(metrics.increment("counter", {{"bad:label", "value"}}).has_value());
    EXPECT_FALSE(metrics.increment("counter", {{"__reserved", "value"}}).has_value());
    EXPECT_FALSE(metrics.increment("counter", {}, -1.0).has_value());
    EXPECT_FALSE(metrics.observe("latency", {1.0, 0.5}, 0.2).has_value());
    EXPECT_FALSE(metrics.observe("latency", {1.0}, 0.2, {{"le", "forged"}}).has_value());
}

TEST(TraceContextTest, StrictlyParsesW3CTraceParent)
{
    const auto parsed = telemetry::TraceContext::parseTraceParent(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->sampled());
    EXPECT_EQ(parsed->traceParent(),
              "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
    EXPECT_FALSE(telemetry::TraceContext::parseTraceParent(
        "00-00000000000000000000000000000000-00f067aa0ba902b7-01").has_value());
    EXPECT_FALSE(telemetry::TraceContext::parseTraceParent(
        "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01").has_value());
}

TEST(TracerTest, ChildSpanPreservesTraceAndRecordsItsParent)
{
    fnd::ManualClockSource clock{kNow};
    telemetry::InMemorySpanSink sink;
    telemetry::Tracer tracer{clock, sink};
    auto parent = telemetry::TraceContext::parseTraceParent(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").value();
    auto span = tracer.start("gateway.proxy", parent, {{"route", "api"}});
    ASSERT_TRUE(span.has_value());
    EXPECT_EQ(span->context().traceId(), parent.traceId());
    EXPECT_NE(span->context().spanId(), parent.spanId());
    clock.advance(std::chrono::milliseconds{12});
    span->end("ok");

    const auto recorded = sink.spans();
    ASSERT_EQ(recorded.size(), 1U);
    EXPECT_EQ(recorded.front().parentSpanId(),
              std::optional<std::string>{std::string{parent.spanId()}});
    EXPECT_EQ(recorded.front().endedAt() - recorded.front().startedAt(),
              std::chrono::milliseconds{12});
}

TEST(TracerTest, DestructorClosesAnAbandonedSpan)
{
    fnd::ManualClockSource clock{kNow};
    telemetry::InMemorySpanSink sink;
    telemetry::Tracer tracer{clock, sink};
    {
        auto span = tracer.start("authentication.complete");
        ASSERT_TRUE(span.has_value());
    }
    ASSERT_EQ(sink.spans().size(), 1U);
    EXPECT_EQ(sink.spans().front().outcome(), "abandoned");
}

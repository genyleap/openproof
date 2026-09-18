#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

import openproof.foundation;
import openproof.gateway;
import openproof.operations.http;
import openproof.telemetry;

namespace {

namespace fnd = openproof::foundation;
namespace gateway = openproof::gateway;
namespace operations = openproof::operations::http;
namespace telemetry = openproof::telemetry;

class StubReadiness final : public operations::ReadinessCheck {
public:
    explicit StubReadiness(bool ready) : m_ready(ready) {}
    [[nodiscard]] fnd::Status check() override
    {
        return m_ready ? fnd::ok() : fnd::fail(fnd::ErrorCode::Unavailable);
    }
private:
    bool m_ready;
};

class Fallback final : public gateway::HttpHandler {
public:
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest) override
    {
        ++calls;
        return gateway::HttpResponse{418, {}, "fallback"};
    }
    std::size_t calls{};
};

[[nodiscard]] gateway::HttpRequest request(
    std::string target, gateway::HttpMethod method = gateway::HttpMethod::Get,
    std::vector<std::pair<std::string, std::string>> headers = {})
{
    return gateway::HttpRequest::create(
        method, std::move(target), std::move(headers), {}, "127.0.0.1",
        fnd::CorrelationId{"health-test"}).value();
}

TEST(HealthHttpApiTest, LivenessDoesNotDependOnPostgres)
{
    StubReadiness readiness{false};
    Fallback fallback;
    operations::HealthHttpApi api{readiness, fallback};

    const auto response = api.handle(request("/health/live"));
    EXPECT_EQ(response.status(), 200);
    EXPECT_EQ(response.body(), R"({"status":"ok"})");
}

TEST(HealthHttpApiTest, ReadinessFailsClosedWithoutLeakingDependencyDetail)
{
    StubReadiness readiness{false};
    Fallback fallback;
    operations::HealthHttpApi api{readiness, fallback};

    const auto response = api.handle(request("/health/ready"));
    EXPECT_EQ(response.status(), 503);
    EXPECT_EQ(response.body(), R"({"status":"unavailable"})");
    EXPECT_EQ(response.headers().at("cache-control"), "no-store");
}

TEST(HealthHttpApiTest, UnownedPathsContinueThroughTheHandlerChain)
{
    StubReadiness readiness{true};
    Fallback fallback;
    operations::HealthHttpApi api{readiness, fallback};

    EXPECT_EQ(api.handle(request("/elsewhere")).status(), 418);
}

TEST(MetricsHttpApiTest, RefusesUnauthenticatedScrapesWithoutCallingFallback)
{
    telemetry::MetricRegistry registry{128U};
    Fallback fallback;
    operations::MetricsHttpApi api{
        registry, fnd::SecretString{"0123456789abcdef0123456789abcdef"}, fallback};

    const auto response = api.handle(request("/metrics"));
    EXPECT_EQ(response.status(), 401);
    EXPECT_EQ(response.headers().at("cache-control"), "no-store");
    EXPECT_EQ(response.headers().at("www-authenticate"),
              "Bearer realm=\"openproof-metrics\"");
    EXPECT_EQ(fallback.calls, 0U);
    EXPECT_EQ(response.body().find("0123456789abcdef"), std::string_view::npos);
}

TEST(MetricsHttpApiTest, ExposesPrometheusOnlyForTheExactBearer)
{
    telemetry::MetricRegistry registry{128U};
    ASSERT_TRUE(registry.increment("openproof_boot_total"));
    Fallback fallback;
    operations::MetricsHttpApi api{
        registry, fnd::SecretString{"0123456789abcdef0123456789abcdef"}, fallback};

    const auto response = api.handle(request(
        "/metrics", gateway::HttpMethod::Get,
        {{"authorization", "Bearer 0123456789abcdef0123456789abcdef"}}));
    EXPECT_EQ(response.status(), 200);
    EXPECT_EQ(response.headers().at("content-type"),
              "text/plain; version=0.0.4; charset=utf-8");
    EXPECT_NE(response.body().find("openproof_boot_total 1"), std::string_view::npos);
    EXPECT_NE(response.body().find(
                  "openproof_metrics_scrapes_total{outcome=\"success\"} 1"),
              std::string_view::npos);
    EXPECT_EQ(response.body().find("0123456789abcdef"), std::string_view::npos);
}

TEST(MetricsHttpApiTest, InstrumentsFallbackWithoutPathOrIdentityLabels)
{
    telemetry::MetricRegistry registry{128U};
    Fallback fallback;
    operations::MetricsHttpApi api{
        registry, fnd::SecretString{"0123456789abcdef0123456789abcdef"}, fallback};

    EXPECT_EQ(api.handle(request("/users/private-id")).status(), 418);
    const std::string metrics = std::string{api.handle(request(
        "/metrics", gateway::HttpMethod::Get,
        {{"authorization", "Bearer 0123456789abcdef0123456789abcdef"}})).body()};
    EXPECT_NE(metrics.find(
                  "openproof_http_requests_total{method=\"GET\",status_class=\"4xx\"} 1"),
              std::string::npos);
    EXPECT_NE(metrics.find(
                  "openproof_http_request_duration_seconds_count{method=\"GET\",status_class=\"4xx\"} 1"),
              std::string::npos);
    EXPECT_EQ(metrics.find("users/private-id"), std::string::npos);
}

TEST(MetricsHttpApiTest, FixedHttpMetricsSurviveTheExtensionSeriesCeiling)
{
    telemetry::MetricRegistry registry{4U};
    ASSERT_TRUE(registry.increment("extension_one_total"));
    ASSERT_TRUE(registry.increment("extension_two_total"));
    ASSERT_TRUE(registry.increment("extension_three_total"));
    ASSERT_TRUE(registry.increment("extension_four_total"));
    Fallback fallback;
    operations::MetricsHttpApi api{
        registry, fnd::SecretString{"0123456789abcdef0123456789abcdef"}, fallback};

    EXPECT_EQ(api.handle(request("/one-more-series")).status(), 418);
    const std::string metrics = std::string{api.handle(request(
        "/metrics", gateway::HttpMethod::Get,
        {{"authorization", "Bearer 0123456789abcdef0123456789abcdef"}})).body()};
    EXPECT_NE(metrics.find(
                  "openproof_http_requests_total{method=\"GET\",status_class=\"4xx\"} 1"),
              std::string::npos);
    EXPECT_NE(metrics.find("openproof_metrics_updates_dropped_total 0"),
              std::string::npos);
}

TEST(MetricsHttpApiTest, HeadScrapeAuthenticatesButReturnsNoBody)
{
    telemetry::MetricRegistry registry{128U};
    Fallback fallback;
    operations::MetricsHttpApi api{
        registry, fnd::SecretString{"0123456789abcdef0123456789abcdef"}, fallback};

    const auto response = api.handle(request(
        "/metrics", gateway::HttpMethod::Head,
        {{"authorization", "Bearer 0123456789abcdef0123456789abcdef"}}));
    EXPECT_EQ(response.status(), 200);
    EXPECT_TRUE(response.body().empty());
}

TEST(MetricsHttpApiTest, RejectsMutationMethods)
{
    telemetry::MetricRegistry registry{128U};
    Fallback fallback;
    operations::MetricsHttpApi api{
        registry, fnd::SecretString{"0123456789abcdef0123456789abcdef"}, fallback};

    EXPECT_EQ(api.handle(request(
                  "/metrics", gateway::HttpMethod::Post)).status(),
              401);
    const auto response = api.handle(request(
        "/metrics", gateway::HttpMethod::Post,
        {{"authorization", "Bearer 0123456789abcdef0123456789abcdef"}}));
    EXPECT_EQ(response.status(), 405);
    EXPECT_EQ(response.headers().at("allow"), "GET, HEAD");
    EXPECT_EQ(fallback.calls, 0U);
}

} // namespace

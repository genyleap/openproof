#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

import openproof.foundation;
import openproof.gateway;
import openproof.operations.http;

namespace {

namespace fnd = openproof::foundation;
namespace gateway = openproof::gateway;
namespace operations = openproof::operations::http;

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
        return gateway::HttpResponse{418, {}, "fallback"};
    }
};

[[nodiscard]] gateway::HttpRequest request(std::string target)
{
    return gateway::HttpRequest::create(
        gateway::HttpMethod::Get, std::move(target), {}, {}, "127.0.0.1",
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

} // namespace

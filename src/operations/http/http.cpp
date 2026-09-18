module;

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

module openproof.operations.http;

import openproof.security;

namespace openproof::operations::http {
namespace {

[[nodiscard]] gateway::HttpResponse healthResponse(int status, bool ready)
{
    gateway::HttpResponse response{
        status,
        gateway::Headers{{"content-type", "application/json"}},
        ready ? R"({"status":"ok"})" : R"({"status":"unavailable"})"};
    response.setHeader("cache-control", "no-store");
    response.setHeader("x-content-type-options", "nosniff");
    return response;
}

constexpr std::array<std::string_view, 7U> methodNames{
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"};
constexpr std::array<std::string_view, 6U> statusClassNames{
    "1xx", "2xx", "3xx", "4xx", "5xx", "other"};
constexpr std::array<double, 10U> durationBoundaries{
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0};

[[nodiscard]] std::size_t methodIndex(gateway::HttpMethod method) noexcept
{
    switch (method) {
    case gateway::HttpMethod::Get: return 0U;
    case gateway::HttpMethod::Head: return 1U;
    case gateway::HttpMethod::Post: return 2U;
    case gateway::HttpMethod::Put: return 3U;
    case gateway::HttpMethod::Patch: return 4U;
    case gateway::HttpMethod::Delete: return 5U;
    case gateway::HttpMethod::Options: return 6U;
    }
    return 6U;
}

[[nodiscard]] std::size_t statusClassIndex(int status) noexcept
{
    return status >= 100 && status <= 599
        ? static_cast<std::size_t>(status / 100 - 1) : 5U;
}

[[nodiscard]] gateway::HttpResponse metricsError(int status, std::string body)
{
    gateway::HttpResponse response{
        status, gateway::Headers{{"content-type", "application/json"}},
        std::move(body)};
    response.setHeader("cache-control", "no-store");
    response.setHeader("x-content-type-options", "nosniff");
    return response;
}

} // namespace

struct MetricsHttpApi::MetricsState final {
    struct HttpCell final {
        std::atomic<std::uint64_t> requests{};
        // Store mutually exclusive buckets on the request path. Prometheus
        // cumulative buckets are derived only during the comparatively rare
        // scrape, avoiding up to ten contended increments per request.
        std::array<std::atomic<std::uint64_t>, durationBoundaries.size() + 1U> buckets{};
        std::atomic<double> durationSum{};
    };

    std::array<HttpCell, methodNames.size() * statusClassNames.size()> http{};
    std::atomic<std::uint64_t> deniedScrapes{};
    std::atomic<std::uint64_t> successfulScrapes{};
};

PostgresReadinessCheck::PostgresReadinessCheck(storage::postgres::ConnectionPool& pool)
    : m_pool(&pool)
{
}

foundation::Status PostgresReadinessCheck::check()
{
    return m_pool->healthCheck();
}

HealthHttpApi::HealthHttpApi(ReadinessCheck& readiness, gateway::HttpHandler& fallback)
    : m_readiness(&readiness), m_fallback(&fallback)
{
}

gateway::HttpResponse HealthHttpApi::handle(gateway::HttpRequest request)
{
    if (request.path() == "/health/live" && request.method() == gateway::HttpMethod::Get) {
        return healthResponse(200, true);
    }
    if (request.path() == "/health/ready" && request.method() == gateway::HttpMethod::Get) {
        return m_readiness->check().has_value()
            ? healthResponse(200, true) : healthResponse(503, false);
    }
    return m_fallback->handle(std::move(request));
}

MetricsHttpApi::MetricsHttpApi(
    telemetry::MetricRegistry& registry, foundation::SecretString bearerToken,
    gateway::HttpHandler& fallback)
    : m_registry(&registry), m_bearerToken(std::move(bearerToken)),
      m_fallback(&fallback), m_state(std::make_unique<MetricsState>())
{
}

MetricsHttpApi::~MetricsHttpApi() = default;

void MetricsHttpApi::record(
    gateway::HttpMethod method, int status, double elapsedSeconds) noexcept
{
    auto& cell = m_state->http[
        methodIndex(method) * statusClassNames.size() + statusClassIndex(status)];
    cell.requests.fetch_add(1U, std::memory_order_relaxed);
    std::size_t bucket = durationBoundaries.size();
    for (std::size_t index = 0U; index < durationBoundaries.size(); ++index) {
        if (elapsedSeconds <= durationBoundaries[index]) {
            bucket = index;
            break;
        }
    }
    cell.buckets[bucket].fetch_add(1U, std::memory_order_relaxed);
    cell.durationSum.fetch_add(elapsedSeconds, std::memory_order_relaxed);
}

std::string MetricsHttpApi::prometheus() const
{
    std::string output = m_registry->prometheus();
    output.append("openproof_metrics_updates_dropped_total 0\n");
    output.append("openproof_metrics_scrapes_total{outcome=\"denied\"} ")
        .append(std::to_string(
            m_state->deniedScrapes.load(std::memory_order_relaxed))).push_back('\n');
    output.append("openproof_metrics_scrapes_total{outcome=\"success\"} ")
        .append(std::to_string(
            m_state->successfulScrapes.load(std::memory_order_relaxed))).push_back('\n');

    for (std::size_t method = 0U; method < methodNames.size(); ++method) {
        for (std::size_t status = 0U; status < statusClassNames.size(); ++status) {
            const auto& cell = m_state->http[
                method * statusClassNames.size() + status];
            const auto requests = cell.requests.load(std::memory_order_relaxed);
            if (requests == 0U) continue;
            const std::string labels = std::format(
                "{{method=\"{}\",status_class=\"{}\"}}",
                methodNames[method], statusClassNames[status]);
            output.append("openproof_http_requests_total").append(labels)
                .append(" ").append(std::to_string(requests)).push_back('\n');
            std::uint64_t cumulative{};
            for (std::size_t bucket = 0U; bucket < durationBoundaries.size(); ++bucket) {
                cumulative += cell.buckets[bucket].load(std::memory_order_relaxed);
                output.append("openproof_http_request_duration_seconds_bucket{")
                    .append("method=\"").append(methodNames[method])
                    .append("\",status_class=\"").append(statusClassNames[status])
                    .append("\",le=\"").append(std::format("{}", durationBoundaries[bucket]))
                    .append("\"} ").append(std::to_string(cumulative)).push_back('\n');
            }
            output.append("openproof_http_request_duration_seconds_bucket{")
                .append("method=\"").append(methodNames[method])
                .append("\",status_class=\"").append(statusClassNames[status])
                .append("\",le=\"+Inf\"} ").append(std::to_string(requests)).push_back('\n');
            output.append("openproof_http_request_duration_seconds_sum").append(labels)
                .append(" ").append(std::format("{}", cell.durationSum.load(
                    std::memory_order_relaxed))).push_back('\n');
            output.append("openproof_http_request_duration_seconds_count").append(labels)
                .append(" ").append(std::to_string(requests)).push_back('\n');
        }
    }
    return output;
}

gateway::HttpResponse MetricsHttpApi::handle(gateway::HttpRequest request)
{
    const gateway::HttpMethod method = request.method();
    if (request.path() == "/metrics") {
        constexpr std::string_view prefix{"Bearer "};
        const auto authorization = request.header("authorization");
        const bool authorized = authorization.has_value()
            && authorization->starts_with(prefix)
            && authorization->size() == prefix.size() + m_bearerToken.size()
            && security::constantTimeEquals(
                authorization->substr(prefix.size()), m_bearerToken.expose());
        if (!authorized) {
            m_state->deniedScrapes.fetch_add(1U, std::memory_order_relaxed);
            auto response = metricsError(401, R"({"error":"unauthorized"})");
            response.setHeader(
                "www-authenticate", "Bearer realm=\"openproof-metrics\"");
            return response;
        }

        if (request.method() != gateway::HttpMethod::Get
            && request.method() != gateway::HttpMethod::Head) {
            auto response = metricsError(405, R"({"error":"method_not_allowed"})");
            response.setHeader("allow", "GET, HEAD");
            return response;
        }

        m_state->successfulScrapes.fetch_add(1U, std::memory_order_relaxed);
        gateway::HttpResponse response{
            200,
            gateway::Headers{{"content-type",
                              "text/plain; version=0.0.4; charset=utf-8"}},
            request.method() == gateway::HttpMethod::Head
                ? std::string{} : prometheus()};
        response.setHeader("cache-control", "no-store");
        response.setHeader("x-content-type-options", "nosniff");
        return response;
    }

    const auto started = std::chrono::steady_clock::now();
    gateway::HttpResponse response = m_fallback->handle(std::move(request));
    const double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started).count();
    record(method, response.status(), elapsed);
    return response;
}

} // namespace openproof::operations::http

module;

#include <string>
#include <utility>

module openproof.operations.http;

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

} // namespace

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

} // namespace openproof::operations::http

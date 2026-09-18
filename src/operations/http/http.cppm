module;

#include <memory>
#include <string>

export module openproof.operations.http;

import openproof.foundation;
import openproof.gateway;
import openproof.storage.postgres;
import openproof.telemetry;

export namespace openproof::operations::http {

/** Read-only dependency check used by the readiness endpoint. */
class ReadinessCheck {
public:
    ReadinessCheck(const ReadinessCheck&) = delete;
    ReadinessCheck& operator=(const ReadinessCheck&) = delete;
    virtual ~ReadinessCheck() = default;
    [[nodiscard]] virtual foundation::Status check() = 0;
protected:
    ReadinessCheck() = default;
};

/** PostgreSQL readiness check that performs a bounded `SELECT 1`. */
class PostgresReadinessCheck final : public ReadinessCheck {
public:
    explicit PostgresReadinessCheck(storage::postgres::ConnectionPool& pool);
    [[nodiscard]] foundation::Status check() override;
private:
    storage::postgres::ConnectionPool* m_pool;
};

/** Unauthenticated liveness/readiness endpoints for container orchestration. */
class HealthHttpApi final : public gateway::HttpHandler {
public:
    HealthHttpApi(ReadinessCheck& readiness, gateway::HttpHandler& fallback);
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;
private:
    ReadinessCheck* m_readiness;
    gateway::HttpHandler* m_fallback;
};

/**
 * Authenticated Prometheus exposition plus low-cardinality HTTP instrumentation.
 * Raw paths, identities, tokens and client addresses are never metric labels.
 */
class MetricsHttpApi final : public gateway::HttpHandler {
public:
    MetricsHttpApi(telemetry::MetricRegistry& registry,
                   foundation::SecretString bearerToken,
                   gateway::HttpHandler& fallback);
    ~MetricsHttpApi() override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;
private:
    struct MetricsState;
    void record(gateway::HttpMethod method, int status, double elapsedSeconds) noexcept;
    [[nodiscard]] std::string prometheus() const;
    telemetry::MetricRegistry* m_registry;
    foundation::SecretString m_bearerToken;
    gateway::HttpHandler* m_fallback;
    std::unique_ptr<MetricsState> m_state;
};

} // namespace openproof::operations::http

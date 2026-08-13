export module openproof.operations.http;

import openproof.foundation;
import openproof.gateway;
import openproof.storage.postgres;

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

} // namespace openproof::operations::http

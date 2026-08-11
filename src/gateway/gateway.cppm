module;

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.gateway;

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.organization;
import openproof.policy;
import openproof.session;

export namespace openproof::gateway {

enum class HttpMethod { Get, Head, Post, Put, Patch, Delete, Options };
[[nodiscard]] std::string_view httpMethodName(HttpMethod method) noexcept;
[[nodiscard]] foundation::Result<HttpMethod> parseHttpMethod(std::string_view method);

using Headers = std::map<std::string, std::string, std::less<>>;

class HttpRequest final {
public:
    [[nodiscard]] static foundation::Result<HttpRequest>
    create(HttpMethod method, std::string target,
           std::vector<std::pair<std::string, std::string>> headers,
           std::string body, std::string remoteAddress,
           foundation::CorrelationId correlation);

    [[nodiscard]] HttpMethod method() const noexcept;
    [[nodiscard]] std::string_view target() const noexcept;
    [[nodiscard]] std::string_view path() const noexcept;
    [[nodiscard]] std::string_view body() const noexcept;
    [[nodiscard]] std::string_view remoteAddress() const noexcept;
    [[nodiscard]] const foundation::CorrelationId& correlation() const noexcept;
    [[nodiscard]] const Headers& headers() const noexcept;
    [[nodiscard]] std::optional<std::string_view> header(std::string_view name) const;
    void setHeader(std::string name, std::string value);
    void eraseHeader(std::string_view name);

private:
    HttpRequest(HttpMethod method, std::string target, std::string path,
                Headers headers, std::string body, std::string remoteAddress,
                foundation::CorrelationId correlation);
    HttpMethod m_method{HttpMethod::Get};
    std::string m_target;
    std::string m_path;
    Headers m_headers;
    std::string m_body;
    std::string m_remoteAddress;
    foundation::CorrelationId m_correlation;
};

class HttpResponse final {
public:
    HttpResponse(int status, Headers headers, std::string body);
    [[nodiscard]] int status() const noexcept;
    [[nodiscard]] const Headers& headers() const noexcept;
    /** Additional occurrences of response fields whose names are already in headers(). */
    [[nodiscard]] const std::vector<std::pair<std::string, std::string>>&
    repeatedHeaders() const noexcept;
    [[nodiscard]] std::string_view body() const noexcept;
    /** Appends a field without collapsing legal repeated fields such as Set-Cookie. */
    void addHeader(std::string name, std::string value);
    void setHeader(std::string name, std::string value);
    void eraseHeader(std::string_view name);

private:
    int m_status{};
    Headers m_headers;
    std::vector<std::pair<std::string, std::string>> m_repeatedHeaders;
    std::string m_body;
};

/** Transport-neutral HTTP application consumed by the bounded listener. */
class HttpHandler {
public:
    HttpHandler(const HttpHandler&) = delete;
    HttpHandler& operator=(const HttpHandler&) = delete;
    virtual ~HttpHandler() = default;
    [[nodiscard]] virtual HttpResponse handle(HttpRequest request) = 0;
protected:
    HttpHandler() = default;
};

/** Extracts and removes one unambiguous bearer or platform session cookie. */
[[nodiscard]] foundation::Result<std::optional<foundation::SecretString>>
takeSessionCredential(HttpRequest& request);

struct RouteIdTag {};
using RouteId = foundation::StrongId<RouteIdTag>;
struct ServiceIdTag {};
using ServiceId = foundation::StrongId<ServiceIdTag>;
struct EndpointIdTag {};
using EndpointId = foundation::StrongId<EndpointIdTag>;

class Route final {
public:
    [[nodiscard]] static foundation::Result<Route>
    create(RouteId id, HttpMethod method, std::string pathPrefix,
           ServiceId service, bool protectedRoute,
           identity::core::OrganizationId organization,
           policy::Action action, policy::Resource resource);

    [[nodiscard]] const RouteId& id() const noexcept;
    [[nodiscard]] HttpMethod method() const noexcept;
    [[nodiscard]] std::string_view pathPrefix() const noexcept;
    [[nodiscard]] const ServiceId& service() const noexcept;
    [[nodiscard]] bool isProtected() const noexcept;
    [[nodiscard]] const identity::core::OrganizationId& organization() const noexcept;
    [[nodiscard]] const policy::Action& action() const noexcept;
    [[nodiscard]] const policy::Resource& resource() const noexcept;

private:
    Route(RouteId id, HttpMethod method, std::string pathPrefix,
          ServiceId service, bool protectedRoute,
          identity::core::OrganizationId organization,
          policy::Action action, policy::Resource resource);
    RouteId m_id;
    HttpMethod m_method{HttpMethod::Get};
    std::string m_pathPrefix;
    ServiceId m_service;
    bool m_protected{};
    identity::core::OrganizationId m_organization;
    policy::Action m_action;
    policy::Resource m_resource;
};

class Router final {
public:
    [[nodiscard]] foundation::Status add(Route route);
    /** Longest segment-boundary prefix wins; method mismatch is not a match. */
    [[nodiscard]] std::optional<Route> match(HttpMethod method, std::string_view path) const;
private:
    mutable std::mutex m_mutex;
    std::vector<Route> m_routes;
};

class Endpoint final {
public:
    [[nodiscard]] static foundation::Result<Endpoint>
    create(EndpointId id, std::string host, std::uint16_t port,
           bool tls, unsigned int weight);
    [[nodiscard]] const EndpointId& id() const noexcept;
    [[nodiscard]] std::string_view host() const noexcept;
    [[nodiscard]] std::uint16_t port() const noexcept;
    [[nodiscard]] bool tls() const noexcept;
    [[nodiscard]] unsigned int weight() const noexcept;
private:
    Endpoint(EndpointId id, std::string host, std::uint16_t port,
             bool tls, unsigned int weight);
    EndpointId m_id;
    std::string m_host;
    std::uint16_t m_port{};
    bool m_tls{};
    unsigned int m_weight{};
};

class ServiceDiscovery {
public:
    ServiceDiscovery(const ServiceDiscovery&) = delete;
    ServiceDiscovery& operator=(const ServiceDiscovery&) = delete;
    virtual ~ServiceDiscovery() = default;
    [[nodiscard]] virtual foundation::Result<std::vector<Endpoint>>
    resolve(const ServiceId& service) = 0;
protected:
    ServiceDiscovery() = default;
};

class StaticServiceDiscovery final : public ServiceDiscovery {
public:
    [[nodiscard]] foundation::Status set(ServiceId service,
                                         std::vector<Endpoint> endpoints);
    [[nodiscard]] foundation::Result<std::vector<Endpoint>>
    resolve(const ServiceId& service) override;
private:
    std::mutex m_mutex;
    std::map<ServiceId, std::vector<Endpoint>> m_services;
};

class WeightedRoundRobin final {
public:
    [[nodiscard]] foundation::Result<Endpoint>
    choose(const ServiceId& service, const std::vector<Endpoint>& endpoints,
           const std::vector<EndpointId>& excluded);
private:
    std::mutex m_mutex;
    std::map<ServiceId, std::uint64_t> m_sequences;
};

class TokenBucketRateLimiter final {
public:
    [[nodiscard]] static foundation::Result<TokenBucketRateLimiter>
    create(const foundation::ClockSource& clock, double capacity,
           double refillPerSecond, std::size_t maximumKeys);
    TokenBucketRateLimiter(const TokenBucketRateLimiter&) = delete;
    TokenBucketRateLimiter& operator=(const TokenBucketRateLimiter&) = delete;
    TokenBucketRateLimiter(TokenBucketRateLimiter&& other) noexcept;
    TokenBucketRateLimiter& operator=(TokenBucketRateLimiter&&) = delete;
    ~TokenBucketRateLimiter() = default;
    [[nodiscard]] bool allow(std::string_view key, double cost = 1.0);
private:
    struct Bucket final { double tokens{}; foundation::Instant updatedAt{}; };
    TokenBucketRateLimiter(const foundation::ClockSource& clock, double capacity,
                           double refillPerSecond, std::size_t maximumKeys);
    const foundation::ClockSource* m_clock;
    double m_capacity{};
    double m_refillPerSecond{};
    std::size_t m_maximumKeys{};
    std::mutex m_mutex;
    std::map<std::string, Bucket, std::less<>> m_buckets;
    Bucket m_overflowBucket;
    bool m_overflowInitialized{};
};

enum class CircuitState { Closed, Open, HalfOpen };

class CircuitBreaker final {
public:
    [[nodiscard]] static foundation::Result<CircuitBreaker>
    create(const foundation::ClockSource& clock, unsigned int failureThreshold,
           foundation::Duration openDuration);
    CircuitBreaker(const CircuitBreaker&) = delete;
    CircuitBreaker& operator=(const CircuitBreaker&) = delete;
    CircuitBreaker(CircuitBreaker&& other) noexcept;
    CircuitBreaker& operator=(CircuitBreaker&&) = delete;
    ~CircuitBreaker() = default;
    /** Reserves the single half-open probe when the open interval has elapsed. */
    [[nodiscard]] bool allow(const EndpointId& endpoint);
    void recordSuccess(const EndpointId& endpoint);
    void recordFailure(const EndpointId& endpoint);
    [[nodiscard]] CircuitState state(const EndpointId& endpoint) const;
private:
    struct Entry final {
        CircuitState state{CircuitState::Closed};
        unsigned int failures{};
        foundation::Instant openedAt{};
        bool probeInFlight{};
    };
    CircuitBreaker(const foundation::ClockSource& clock, unsigned int failureThreshold,
                   foundation::Duration openDuration);
    const foundation::ClockSource* m_clock;
    unsigned int m_failureThreshold{};
    foundation::Duration m_openDuration{};
    mutable std::mutex m_mutex;
    std::map<EndpointId, Entry> m_entries;
};

class ProxyTransport {
public:
    ProxyTransport(const ProxyTransport&) = delete;
    ProxyTransport& operator=(const ProxyTransport&) = delete;
    virtual ~ProxyTransport() = default;
    [[nodiscard]] virtual foundation::Result<HttpResponse>
    send(const Endpoint& endpoint, const HttpRequest& request,
         foundation::Duration timeout) = 0;
protected:
    ProxyTransport() = default;
};

class AccessController {
public:
    AccessController(const AccessController&) = delete;
    AccessController& operator=(const AccessController&) = delete;
    virtual ~AccessController() = default;
    [[nodiscard]] virtual policy::AuthorizationDecision authorize(
        const session::AuthenticatedSession& authenticatedSession,
        const Route& route,
        const foundation::CorrelationId& correlation) = 0;
protected:
    AccessController() = default;
};

class PolicyAccessController final : public AccessController {
public:
    PolicyAccessController(policy::PolicyEngine* policies,
                           const organization::OrganizationRepository& organizations,
                           const identity::core::IdentityRepository& identities,
                           const organization::MembershipRepository& memberships,
                           policy::AuthorizationDecisionSink* decisionSink = nullptr);
    [[nodiscard]] policy::AuthorizationDecision authorize(
        const session::AuthenticatedSession& authenticatedSession,
        const Route& route,
        const foundation::CorrelationId& correlation) override;
private:
    policy::PolicyEngine* m_policies;
    const organization::OrganizationRepository* m_organizations;
    const identity::core::IdentityRepository* m_identities;
    const organization::MembershipRepository* m_memberships;
    policy::AuthorizationDecisionSink* m_decisionSink;
};

/** Key used to authenticate the identity context emitted by the gateway. */
class TrustedContextKey final {
public:
    [[nodiscard]] static foundation::Result<TrustedContextKey>
    create(foundation::SecretString key);
    TrustedContextKey(const TrustedContextKey&) = delete;
    TrustedContextKey& operator=(const TrustedContextKey&) = delete;
    TrustedContextKey(TrustedContextKey&&) noexcept = default;
    TrustedContextKey& operator=(TrustedContextKey&&) noexcept = default;
    ~TrustedContextKey() = default;
    [[nodiscard]] const foundation::SecretString& secret() const noexcept;
private:
    explicit TrustedContextKey(foundation::SecretString key);
    foundation::SecretString m_key;
};

/**
 * Seals and verifies the complete trusted upstream context with HMAC-SHA256.
 * The signature binds the method, request target, correlation id, identity,
 * tenant, provider, assurance and issuance time. Verification also enforces a
 * bounded freshness window.
 */
class TrustedContextSigner final {
public:
    [[nodiscard]] static foundation::Result<TrustedContextSigner>
    create(const foundation::ClockSource& clock, TrustedContextKey key,
           foundation::Duration maximumAge);
    TrustedContextSigner(const TrustedContextSigner&) = delete;
    TrustedContextSigner& operator=(const TrustedContextSigner&) = delete;
    TrustedContextSigner(TrustedContextSigner&&) noexcept = default;
    TrustedContextSigner& operator=(TrustedContextSigner&&) noexcept = default;
    ~TrustedContextSigner() = default;
    [[nodiscard]] foundation::Status seal(HttpRequest& request) const;
    [[nodiscard]] foundation::Status verify(const HttpRequest& request) const;
private:
    TrustedContextSigner(const foundation::ClockSource& clock, TrustedContextKey key,
                         foundation::Duration maximumAge);
    const foundation::ClockSource* m_clock;
    TrustedContextKey m_key;
    foundation::Duration m_maximumAge{};
};

class Gateway final : public HttpHandler {
public:
    Gateway(const Router& router, session::SessionService& sessions,
            AccessController& access, TokenBucketRateLimiter& rateLimiter,
            ServiceDiscovery& discovery, WeightedRoundRobin& loadBalancer,
            CircuitBreaker& circuits, ProxyTransport& proxy,
            TrustedContextSigner& contextSigner,
            foundation::Duration upstreamTimeout);

    [[nodiscard]] HttpResponse handle(HttpRequest request) override;

private:
    [[nodiscard]] HttpResponse errorResponse(const foundation::Error& error,
                                             const HttpRequest& request) const;
    const Router* m_router;
    session::SessionService* m_sessions;
    AccessController* m_access;
    TokenBucketRateLimiter* m_rateLimiter;
    ServiceDiscovery* m_discovery;
    WeightedRoundRobin* m_loadBalancer;
    CircuitBreaker* m_circuits;
    ProxyTransport* m_proxy;
    TrustedContextSigner* m_contextSigner;
    foundation::Duration m_upstreamTimeout;
};

}

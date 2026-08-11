module;

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.gateway;

import openproof.security;

namespace openproof::gateway {
namespace {

[[nodiscard]] std::string lowercase(std::string_view text)
{
    std::string result;
    result.reserve(text.size());
    for (char value : text) {
        if (value >= 'A' && value <= 'Z') {
            value = static_cast<char>(value - 'A' + 'a');
        }
        result.push_back(value);
    }
    return result;
}

[[nodiscard]] bool isHeaderName(std::string_view name) noexcept
{
    if (name.empty()) return false;
    return std::ranges::all_of(name, [](char value) {
        const bool alphaNumeric = (value >= 'a' && value <= 'z')
            || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9');
        constexpr std::string_view punctuation{"!#$%&'*+-.^_`|~"};
        return alphaNumeric || punctuation.contains(value);
    });
}

[[nodiscard]] bool hasControl(std::string_view value) noexcept
{
    return std::ranges::any_of(value, [](char symbol) {
        const auto byte = static_cast<unsigned char>(symbol);
        return byte == 0x7FU || (byte < 0x20U && symbol != '\t');
    });
}

[[nodiscard]] bool invalidTargetCharacter(std::string_view value) noexcept
{
    return std::ranges::any_of(value, [](char symbol) {
        const auto byte = static_cast<unsigned char>(symbol);
        return byte <= 0x20U || byte == 0x7FU;
    });
}

[[nodiscard]] bool isAmbiguousSingleton(std::string_view name) noexcept
{
    return name == "authorization" || name == "host" || name == "content-length"
        || name == "transfer-encoding";
}

[[nodiscard]] bool prefixMatches(std::string_view path, std::string_view prefix) noexcept
{
    if (!path.starts_with(prefix)) return false;
    return prefix == "/" || path.size() == prefix.size()
        || prefix.back() == '/' || path[prefix.size()] == '/';
}

[[nodiscard]] bool retryable(HttpMethod method) noexcept
{
    return method == HttpMethod::Get || method == HttpMethod::Head
        || method == HttpMethod::Options;
}

void stripHopByHop(HttpRequest& request)
{
    std::vector<std::string> connectionHeaders;
    if (const auto connection = request.header("connection"); connection.has_value()) {
        std::size_t begin = 0U;
        while (begin <= connection->size()) {
            const std::size_t comma = connection->find(',', begin);
            std::string_view item = connection->substr(
                begin, comma == std::string_view::npos ? connection->size() - begin
                                                       : comma - begin);
            while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) item.remove_prefix(1U);
            while (!item.empty() && (item.back() == ' ' || item.back() == '\t')) item.remove_suffix(1U);
            if (!item.empty()) connectionHeaders.push_back(lowercase(item));
            if (comma == std::string_view::npos) break;
            begin = comma + 1U;
        }
    }
    for (const auto& name : connectionHeaders) request.eraseHeader(name);
    for (std::string_view name : {"connection", "proxy-connection", "keep-alive",
                                  "transfer-encoding", "te", "trailer", "upgrade"}) {
        request.eraseHeader(name);
    }
}

void stripTrustedIdentityHeaders(HttpRequest& request)
{
    std::vector<std::string> names;
    for (const auto& [name, value] : request.headers()) {
        static_cast<void>(value);
        if (name.starts_with("x-openproof-")) names.push_back(name);
    }
    for (const auto& name : names) request.eraseHeader(name);
}

void secureResponse(HttpResponse& response)
{
    for (std::string_view name : {"connection", "proxy-connection", "keep-alive",
                                  "transfer-encoding", "te", "trailer", "upgrade"}) {
        response.eraseHeader(name);
    }
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    response.setHeader("cache-control", "no-store");
}

void appendSignedPart(std::string& output, std::string_view value)
{
    output.append(std::to_string(value.size())).push_back(':');
    output.append(value);
}

[[nodiscard]] std::string trustedContextPayload(const HttpRequest& request)
{
    std::string output;
    appendSignedPart(output, httpMethodName(request.method()));
    appendSignedPart(output, request.target());
    for (std::string_view name : {
             "x-openproof-request-id", "x-openproof-identity",
             "x-openproof-organization", "x-openproof-provider",
             "x-openproof-assurance", "x-openproof-context-issued-at"}) {
        appendSignedPart(output, request.header(name).value_or(std::string_view{}));
    }
    return output;
}

}

std::string_view httpMethodName(HttpMethod method) noexcept
{
    switch (method) {
    case HttpMethod::Get: return "GET";
    case HttpMethod::Head: return "HEAD";
    case HttpMethod::Post: return "POST";
    case HttpMethod::Put: return "PUT";
    case HttpMethod::Patch: return "PATCH";
    case HttpMethod::Delete: return "DELETE";
    case HttpMethod::Options: return "OPTIONS";
    }
    return "GET";
}

foundation::Result<HttpMethod> parseHttpMethod(std::string_view method)
{
    if (method == "GET") return HttpMethod::Get;
    if (method == "HEAD") return HttpMethod::Head;
    if (method == "POST") return HttpMethod::Post;
    if (method == "PUT") return HttpMethod::Put;
    if (method == "PATCH") return HttpMethod::Patch;
    if (method == "DELETE") return HttpMethod::Delete;
    if (method == "OPTIONS") return HttpMethod::Options;
    return foundation::fail(foundation::ErrorCode::InvalidArgument,
                            "The HTTP method is not supported.");
}

HttpRequest::HttpRequest(HttpMethod method, std::string target, std::string path,
                         Headers headers, std::string body,
                         std::string remoteAddress, foundation::CorrelationId correlation)
    : m_method(method), m_target(std::move(target)), m_path(std::move(path)),
      m_headers(std::move(headers)), m_body(std::move(body)),
      m_remoteAddress(std::move(remoteAddress)), m_correlation(std::move(correlation))
{
}

foundation::Result<HttpRequest> HttpRequest::create(
    HttpMethod method, std::string target,
    std::vector<std::pair<std::string, std::string>> headers,
    std::string body, std::string remoteAddress,
    foundation::CorrelationId correlation)
{
    if (target.empty() || target.size() > 8192U || target.front() != '/'
        || target.starts_with("//") || target.contains('#')
        || invalidTargetCharacter(target) || remoteAddress.empty()
        || remoteAddress.size() > 256U || hasControl(remoteAddress)
        || correlation.empty() || headers.size() > 256U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The HTTP request target is invalid.");
    }
    const std::size_t query = target.find('?');
    const std::string path = target.substr(0U, query);
    if (path.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The HTTP request path is invalid.");
    }
    Headers normalized;
    for (auto& [rawName, value] : headers) {
        if (rawName.size() > 256U || value.size() > 16'384U
            || !isHeaderName(rawName) || hasControl(value)) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The HTTP request contains an invalid header.");
        }
        std::string name = lowercase(rawName);
        if (normalized.contains(name) && isAmbiguousSingleton(name)) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The HTTP request contains an ambiguous header.");
        }
        if (normalized.contains(name)) {
            normalized[name].append(name == "cookie" ? "; " : ",").append(value);
        } else {
            normalized.emplace(std::move(name), std::move(value));
        }
    }
    if (normalized.contains("content-length") && normalized.contains("transfer-encoding")) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The HTTP request framing is ambiguous.");
    }
    return HttpRequest{method, std::move(target), path, std::move(normalized),
                       std::move(body), std::move(remoteAddress), std::move(correlation)};
}

HttpMethod HttpRequest::method() const noexcept { return m_method; }
std::string_view HttpRequest::target() const noexcept { return m_target; }
std::string_view HttpRequest::path() const noexcept { return m_path; }
std::string_view HttpRequest::body() const noexcept { return m_body; }
std::string_view HttpRequest::remoteAddress() const noexcept { return m_remoteAddress; }
const foundation::CorrelationId& HttpRequest::correlation() const noexcept { return m_correlation; }
const Headers& HttpRequest::headers() const noexcept { return m_headers; }
std::optional<std::string_view> HttpRequest::header(std::string_view name) const
{
    const auto found = m_headers.find(lowercase(name));
    return found == m_headers.end() ? std::nullopt
                                    : std::optional<std::string_view>{found->second};
}
void HttpRequest::setHeader(std::string name, std::string value)
{
    m_headers.insert_or_assign(lowercase(name), std::move(value));
}
void HttpRequest::eraseHeader(std::string_view name) { m_headers.erase(lowercase(name)); }

HttpResponse::HttpResponse(int status, Headers headers, std::string body)
    : m_status(status), m_headers(std::move(headers)), m_body(std::move(body))
{
}
int HttpResponse::status() const noexcept { return m_status; }
const Headers& HttpResponse::headers() const noexcept { return m_headers; }
const std::vector<std::pair<std::string, std::string>>&
HttpResponse::repeatedHeaders() const noexcept
{
    return m_repeatedHeaders;
}
std::string_view HttpResponse::body() const noexcept { return m_body; }
void HttpResponse::addHeader(std::string name, std::string value)
{
    name = lowercase(name);
    if (m_headers.contains(name)) {
        m_repeatedHeaders.emplace_back(std::move(name), std::move(value));
        return;
    }
    m_headers.emplace(std::move(name), std::move(value));
}
void HttpResponse::setHeader(std::string name, std::string value)
{
    name = lowercase(name);
    std::erase_if(m_repeatedHeaders, [&name](const auto& header) {
        return header.first == name;
    });
    m_headers.insert_or_assign(std::move(name), std::move(value));
}
void HttpResponse::eraseHeader(std::string_view name)
{
    const auto normalized = lowercase(name);
    m_headers.erase(normalized);
    std::erase_if(m_repeatedHeaders, [&normalized](const auto& header) {
        return header.first == normalized;
    });
}

foundation::Result<std::optional<foundation::SecretString>>
takeSessionCredential(HttpRequest& request)
{
    std::optional<std::string> bearer;
    if (const auto authorization = request.header("authorization"); authorization.has_value()) {
        constexpr std::string_view prefix{"Bearer "};
        if (!authorization->starts_with(prefix) || authorization->size() <= prefix.size()
            || authorization->substr(prefix.size()).contains(' ')
            || authorization->substr(prefix.size()).contains('\t')) {
            request.eraseHeader("authorization");
            return foundation::fail(foundation::ErrorCode::AuthenticationRequired,
                                    "Authentication is required.");
        }
        bearer = std::string{authorization->substr(prefix.size())};
        request.eraseHeader("authorization");
    }

    std::optional<std::string> cookieToken;
    if (const auto cookie = request.header("cookie"); cookie.has_value()) {
        std::vector<std::string> retained;
        std::size_t begin = 0U;
        while (begin <= cookie->size()) {
            const std::size_t end = cookie->find(';', begin);
            std::string_view item = cookie->substr(
                begin, end == std::string_view::npos ? cookie->size() - begin : end - begin);
            while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) {
                item.remove_prefix(1U);
            }
            while (!item.empty() && (item.back() == ' ' || item.back() == '\t')) {
                item.remove_suffix(1U);
            }
            const std::size_t equals = item.find('=');
            if (equals != std::string_view::npos
                && item.substr(0U, equals) == "openproof_session") {
                const std::string_view value = item.substr(equals + 1U);
                const bool valid = !value.empty() && value.size() <= 128U
                    && std::ranges::all_of(value, [](char symbol) {
                           return (symbol >= 'A' && symbol <= 'Z')
                               || (symbol >= 'a' && symbol <= 'z')
                               || (symbol >= '0' && symbol <= '9')
                               || symbol == '-' || symbol == '_';
                       });
                if (!valid || cookieToken.has_value()) {
                    request.eraseHeader("cookie");
                    return foundation::fail(foundation::ErrorCode::AuthenticationRequired,
                                            "Authentication is required.");
                }
                cookieToken = std::string{value};
            } else if (!item.empty()) {
                retained.emplace_back(item);
            }
            if (end == std::string_view::npos) break;
            begin = end + 1U;
        }
        if (retained.empty()) {
            request.eraseHeader("cookie");
        } else {
            std::string rebuilt;
            for (const auto& item : retained) {
                if (!rebuilt.empty()) rebuilt.append("; ");
                rebuilt.append(item);
            }
            request.setHeader("cookie", std::move(rebuilt));
        }
    }
    if (bearer.has_value() && cookieToken.has_value()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationRequired,
                                "Authentication is required.");
    }
    if (bearer.has_value()) {
        return std::optional<foundation::SecretString>{
            foundation::SecretString{std::move(bearer).value()}};
    }
    if (cookieToken.has_value()) {
        return std::optional<foundation::SecretString>{
            foundation::SecretString{std::move(cookieToken).value()}};
    }
    return std::optional<foundation::SecretString>{};
}

Route::Route(RouteId id, HttpMethod method, std::string pathPrefix,
             ServiceId service, bool protectedRoute,
             identity::core::OrganizationId organization,
             policy::Action action, policy::Resource resource)
    : m_id(std::move(id)), m_method(method), m_pathPrefix(std::move(pathPrefix)),
      m_service(std::move(service)), m_protected(protectedRoute),
      m_organization(std::move(organization)), m_action(std::move(action)),
      m_resource(std::move(resource))
{
}

foundation::Result<Route> Route::create(
    RouteId id, HttpMethod method, std::string pathPrefix, ServiceId service,
    bool protectedRoute, identity::core::OrganizationId organization,
    policy::Action action, policy::Resource resource)
{
    if (id.empty() || service.empty() || pathPrefix.empty() || pathPrefix.front() != '/'
        || pathPrefix.starts_with("//")
        || pathPrefix.contains('?') || pathPrefix.contains('#') || hasControl(pathPrefix)
        || (pathPrefix.size() > 1U && pathPrefix.back() == '/')) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The gateway route is invalid.");
    }
    if (protectedRoute && (organization.empty() || action.empty() || resource.empty())) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A protected route requires organization, action and resource.");
    }
    return Route{std::move(id), method, std::move(pathPrefix), std::move(service),
                 protectedRoute, std::move(organization), std::move(action),
                 std::move(resource)};
}

const RouteId& Route::id() const noexcept { return m_id; }
HttpMethod Route::method() const noexcept { return m_method; }
std::string_view Route::pathPrefix() const noexcept { return m_pathPrefix; }
const ServiceId& Route::service() const noexcept { return m_service; }
bool Route::isProtected() const noexcept { return m_protected; }
const identity::core::OrganizationId& Route::organization() const noexcept { return m_organization; }
const policy::Action& Route::action() const noexcept { return m_action; }
const policy::Resource& Route::resource() const noexcept { return m_resource; }

foundation::Status Router::add(Route route)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    const bool duplicate = std::ranges::any_of(m_routes, [&route](const Route& existing) {
        return existing.id() == route.id()
            || (existing.method() == route.method()
                && existing.pathPrefix() == route.pathPrefix());
    });
    if (duplicate) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The gateway route already exists.");
    }
    m_routes.push_back(std::move(route));
    return foundation::ok();
}

std::optional<Route> Router::match(HttpMethod method, std::string_view path) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    const Route* best = nullptr;
    for (const Route& route : m_routes) {
        if (route.method() == method && prefixMatches(path, route.pathPrefix())
            && (best == nullptr || route.pathPrefix().size() > best->pathPrefix().size())) {
            best = &route;
        }
    }
    return best == nullptr ? std::nullopt : std::optional<Route>{*best};
}

Endpoint::Endpoint(EndpointId id, std::string host, std::uint16_t port,
                   bool tls, unsigned int weight)
    : m_id(std::move(id)), m_host(std::move(host)), m_port(port), m_tls(tls), m_weight(weight)
{
}

foundation::Result<Endpoint> Endpoint::create(
    EndpointId id, std::string host, std::uint16_t port, bool tls, unsigned int weight)
{
    if (id.empty() || host.empty() || host.size() > 253U || port == 0U
        || weight == 0U || weight > 1000U || invalidTargetCharacter(host)
        || host.contains('/') || host.contains('@')) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The upstream endpoint is invalid.");
    }
    return Endpoint{std::move(id), std::move(host), port, tls, weight};
}
const EndpointId& Endpoint::id() const noexcept { return m_id; }
std::string_view Endpoint::host() const noexcept { return m_host; }
std::uint16_t Endpoint::port() const noexcept { return m_port; }
bool Endpoint::tls() const noexcept { return m_tls; }
unsigned int Endpoint::weight() const noexcept { return m_weight; }

foundation::Status StaticServiceDiscovery::set(ServiceId service,
                                               std::vector<Endpoint> endpoints)
{
    if (service.empty() || endpoints.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A discovered service requires endpoints.");
    }
    std::vector<EndpointId> ids;
    for (const Endpoint& endpoint : endpoints) {
        if (std::ranges::find(ids, endpoint.id()) != ids.end()) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "A discovered service contains duplicate endpoints.");
        }
        ids.push_back(endpoint.id());
    }
    const std::lock_guard<std::mutex> guard{m_mutex};
    m_services.insert_or_assign(std::move(service), std::move(endpoints));
    return foundation::ok();
}

foundation::Result<std::vector<Endpoint>>
StaticServiceDiscovery::resolve(const ServiceId& service)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    const auto found = m_services.find(service);
    if (found == m_services.end()) {
        return foundation::fail(foundation::ErrorCode::Unavailable,
                                "The upstream service is unavailable.");
    }
    return found->second;
}

foundation::Result<Endpoint> WeightedRoundRobin::choose(
    const ServiceId& service, const std::vector<Endpoint>& endpoints,
    const std::vector<EndpointId>& excluded)
{
    std::uint64_t total = 0U;
    for (const Endpoint& endpoint : endpoints) {
        if (std::ranges::find(excluded, endpoint.id()) == excluded.end()) {
            total += endpoint.weight();
        }
    }
    if (total == 0U) {
        return foundation::fail(foundation::ErrorCode::Unavailable,
                                "No upstream endpoint is available.");
    }
    const std::lock_guard<std::mutex> guard{m_mutex};
    std::uint64_t& sequence = m_sequences[service];
    const std::uint64_t slot = sequence++ % total;
    std::uint64_t cursor = 0U;
    for (const Endpoint& endpoint : endpoints) {
        if (std::ranges::find(excluded, endpoint.id()) != excluded.end()) continue;
        cursor += endpoint.weight();
        if (slot < cursor) return endpoint;
    }
    return foundation::fail(foundation::ErrorCode::Internal,
                            "The load balancer could not select an endpoint.");
}

TokenBucketRateLimiter::TokenBucketRateLimiter(
    const foundation::ClockSource& clock, double capacity,
    double refillPerSecond, std::size_t maximumKeys)
    : m_clock(&clock), m_capacity(capacity), m_refillPerSecond(refillPerSecond),
      m_maximumKeys(maximumKeys)
{
}

foundation::Result<TokenBucketRateLimiter> TokenBucketRateLimiter::create(
    const foundation::ClockSource& clock, double capacity,
    double refillPerSecond, std::size_t maximumKeys)
{
    if (!std::isfinite(capacity) || !std::isfinite(refillPerSecond)
        || capacity < 1.0 || refillPerSecond <= 0.0 || maximumKeys == 0U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The rate-limit policy is invalid.");
    }
    return TokenBucketRateLimiter{clock, capacity, refillPerSecond, maximumKeys};
}

TokenBucketRateLimiter::TokenBucketRateLimiter(TokenBucketRateLimiter&& other) noexcept
    : m_clock(other.m_clock), m_capacity(other.m_capacity),
      m_refillPerSecond(other.m_refillPerSecond), m_maximumKeys(other.m_maximumKeys),
      m_buckets(std::move(other.m_buckets)), m_overflowBucket(other.m_overflowBucket),
      m_overflowInitialized(other.m_overflowInitialized)
{
}

bool TokenBucketRateLimiter::allow(std::string_view key, double cost)
{
    if (key.empty() || !std::isfinite(cost) || cost <= 0.0 || cost > m_capacity) return false;
    const foundation::Instant now = m_clock->now();
    const std::lock_guard<std::mutex> guard{m_mutex};
    auto found = m_buckets.find(key);
    Bucket* selected = nullptr;
    if (found == m_buckets.end()) {
        if (m_buckets.size() >= m_maximumKeys) {
            if (!m_overflowInitialized) {
                m_overflowBucket = Bucket{m_capacity, now};
                m_overflowInitialized = true;
            }
            selected = &m_overflowBucket;
        } else {
            found = m_buckets.emplace(std::string{key}, Bucket{m_capacity, now}).first;
        }
    }
    if (selected == nullptr) selected = &found->second;
    Bucket& bucket = *selected;
    const auto elapsed = now - bucket.updatedAt;
    if (elapsed > foundation::Duration::zero()) {
        const double seconds = static_cast<double>(elapsed.count()) / 1000.0;
        bucket.tokens = std::min(m_capacity, bucket.tokens + seconds * m_refillPerSecond);
        bucket.updatedAt = now;
    }
    if (bucket.tokens < cost) return false;
    bucket.tokens -= cost;
    return true;
}

CircuitBreaker::CircuitBreaker(const foundation::ClockSource& clock,
                               unsigned int failureThreshold,
                               foundation::Duration openDuration)
    : m_clock(&clock), m_failureThreshold(failureThreshold), m_openDuration(openDuration)
{
}

foundation::Result<CircuitBreaker> CircuitBreaker::create(
    const foundation::ClockSource& clock, unsigned int failureThreshold,
    foundation::Duration openDuration)
{
    if (failureThreshold == 0U || openDuration <= foundation::Duration::zero()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The circuit-breaker policy is invalid.");
    }
    return CircuitBreaker{clock, failureThreshold, openDuration};
}

CircuitBreaker::CircuitBreaker(CircuitBreaker&& other) noexcept
    : m_clock(other.m_clock), m_failureThreshold(other.m_failureThreshold),
      m_openDuration(other.m_openDuration), m_entries(std::move(other.m_entries))
{
}

bool CircuitBreaker::allow(const EndpointId& endpoint)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    Entry& entry = m_entries[endpoint];
    if (entry.state == CircuitState::Closed) return true;
    if (entry.state == CircuitState::Open) {
        if (m_clock->now() - entry.openedAt < m_openDuration) return false;
        entry.state = CircuitState::HalfOpen;
        entry.probeInFlight = false;
    }
    if (entry.probeInFlight) return false;
    entry.probeInFlight = true;
    return true;
}

void CircuitBreaker::recordSuccess(const EndpointId& endpoint)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    m_entries[endpoint] = Entry{};
}

void CircuitBreaker::recordFailure(const EndpointId& endpoint)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    Entry& entry = m_entries[endpoint];
    entry.probeInFlight = false;
    if (entry.state == CircuitState::HalfOpen || ++entry.failures >= m_failureThreshold) {
        entry.state = CircuitState::Open;
        entry.openedAt = m_clock->now();
    }
}

CircuitState CircuitBreaker::state(const EndpointId& endpoint) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    const auto found = m_entries.find(endpoint);
    return found == m_entries.end() ? CircuitState::Closed : found->second.state;
}

PolicyAccessController::PolicyAccessController(
    policy::PolicyEngine* policies,
    const organization::OrganizationRepository& organizations,
    const identity::core::IdentityRepository& identities,
    const organization::MembershipRepository& memberships)
    : m_policies(policies), m_organizations(&organizations), m_identities(&identities),
      m_memberships(&memberships)
{
}

policy::AuthorizationDecision PolicyAccessController::authorize(
    const session::AuthenticatedSession& authenticatedSession, const Route& route)
{
    auto request = policy::AuthorizationRequest::create(
        authenticatedSession, route.organization(), *m_organizations,
        *m_identities, *m_memberships, route.action(), route.resource());
    if (!request.has_value()) {
        return policy::AuthorizationDecision::indeterminate(
            std::string{"Trusted authorization context failed: "}
            + std::string{request.error().internalDetail()});
    }
    return policy::evaluateProtected(m_policies, request.value());
}

TrustedContextKey::TrustedContextKey(foundation::SecretString key)
    : m_key(std::move(key)) {}

foundation::Result<TrustedContextKey>
TrustedContextKey::create(foundation::SecretString key)
{
    if (key.expose().size() < 32U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A trusted-context key must contain at least 32 bytes.");
    }
    return TrustedContextKey{std::move(key)};
}

const foundation::SecretString& TrustedContextKey::secret() const noexcept
{ return m_key; }

TrustedContextSigner::TrustedContextSigner(
    const foundation::ClockSource& clock, TrustedContextKey key,
    foundation::Duration maximumAge)
    : m_clock(&clock), m_key(std::move(key)), m_maximumAge(maximumAge) {}

foundation::Result<TrustedContextSigner> TrustedContextSigner::create(
    const foundation::ClockSource& clock, TrustedContextKey key,
    foundation::Duration maximumAge)
{
    if (maximumAge <= foundation::Duration::zero()
        || maximumAge > std::chrono::minutes{5}) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The trusted-context freshness window is invalid.");
    }
    return TrustedContextSigner{clock, std::move(key), maximumAge};
}

foundation::Status TrustedContextSigner::seal(HttpRequest& request) const
{
    request.setHeader("x-openproof-context-issued-at",
        std::to_string(m_clock->now().time_since_epoch().count()));
    auto digest = security::hmacSha256(m_key.secret(), trustedContextPayload(request));
    if (!digest.has_value()) return foundation::fail(digest.error());
    request.setHeader("x-openproof-context-signature", foundation::toHex(digest.value()));
    return foundation::ok();
}

foundation::Status TrustedContextSigner::verify(const HttpRequest& request) const
{
    const auto issuedHeader = request.header("x-openproof-context-issued-at");
    const auto signature = request.header("x-openproof-context-signature");
    if (!issuedHeader.has_value() || !signature.has_value() || signature->size() != 64U) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The trusted gateway context is invalid.");
    }
    std::int64_t issuedCount{};
    const auto parsed = std::from_chars(issuedHeader->data(),
                                        issuedHeader->data() + issuedHeader->size(),
                                        issuedCount);
    if (parsed.ec != std::errc{} || parsed.ptr != issuedHeader->data() + issuedHeader->size()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The trusted gateway context is invalid.");
    }
    const foundation::Instant issued{foundation::Duration{issuedCount}};
    const foundation::Instant now = m_clock->now();
    if (issued > now + m_maximumAge || now > issued + m_maximumAge) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The trusted gateway context is stale.");
    }
    auto expected = security::hmacSha256(m_key.secret(), trustedContextPayload(request));
    auto supplied = foundation::fromHex(*signature);
    if (!expected.has_value() || !supplied.has_value()
        || supplied->size() != expected->size()
        || !security::constantTimeEquals(expected.value(), supplied.value())) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The trusted gateway context is invalid.");
    }
    return foundation::ok();
}

Gateway::Gateway(const Router& router, session::SessionService& sessions,
                 AccessController& access, TokenBucketRateLimiter& rateLimiter,
                 ServiceDiscovery& discovery, WeightedRoundRobin& loadBalancer,
                 CircuitBreaker& circuits, ProxyTransport& proxy,
                 TrustedContextSigner& contextSigner,
                 foundation::Duration upstreamTimeout)
    : m_router(&router), m_sessions(&sessions), m_access(&access),
      m_rateLimiter(&rateLimiter), m_discovery(&discovery),
      m_loadBalancer(&loadBalancer), m_circuits(&circuits), m_proxy(&proxy),
      m_contextSigner(&contextSigner),
      m_upstreamTimeout(upstreamTimeout)
{
}

HttpResponse Gateway::errorResponse(const foundation::Error& error,
                                    const HttpRequest& request) const
{
    HttpResponse response{foundation::errorHttpStatus(error.code()),
                          Headers{{"content-type", "application/json"}},
                          foundation::toClientJson(error, request.correlation().value())};
    secureResponse(response);
    return response;
}

HttpResponse Gateway::handle(HttpRequest request)
{
    const auto route = m_router->match(request.method(), request.path());
    if (!route.has_value()) {
        return errorResponse(foundation::Error{foundation::ErrorCode::NotFound}, request);
    }
    if (!m_rateLimiter->allow(request.remoteAddress())) {
        return errorResponse(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    stripTrustedIdentityHeaders(request);
    stripHopByHop(request);

    if (route->isProtected()) {
        auto credential = takeSessionCredential(request);
        if (!credential.has_value() || !credential->has_value()) {
            return errorResponse(
                credential.has_value()
                    ? foundation::Error{foundation::ErrorCode::AuthenticationRequired}
                    : credential.error(), request);
        }
        auto authenticated = m_sessions->authenticate(credential->value());
        if (!authenticated.has_value()) {
            return errorResponse(authenticated.error(), request);
        }
        if (!m_rateLimiter->allow(
                std::string{"identity:"} + authenticated->session().identity().value())) {
            return errorResponse(foundation::Error{foundation::ErrorCode::RateLimited}, request);
        }
        const policy::AuthorizationDecision decision =
            m_access->authorize(authenticated.value(), route.value());
        if (!decision.isPermitted()) {
            return errorResponse(foundation::Error{foundation::ErrorCode::PermissionDenied}, request);
        }
        request.setHeader("x-openproof-identity",
                          std::string{authenticated->session().identity().value()});
        request.setHeader("x-openproof-provider",
                          std::string{authenticated->session().provider().value()});
        request.setHeader("x-openproof-assurance",
                          std::string{identity::provider::assuranceLevelName(
                              authenticated->session().assurance())});
        request.setHeader("x-openproof-organization",
                          std::string{route->organization().value()});
    }
    request.setHeader("x-openproof-request-id",
                      std::string{request.correlation().value()});
    const foundation::Status sealed = m_contextSigner->seal(request);
    if (!sealed.has_value()) return errorResponse(sealed.error(), request);

    auto endpoints = m_discovery->resolve(route->service());
    if (!endpoints.has_value()) return errorResponse(endpoints.error(), request);
    std::vector<EndpointId> excluded;
    const std::size_t attempts = retryable(request.method())
        ? std::min<std::size_t>(2U, endpoints->size()) : 1U;
    foundation::Error lastFailure{foundation::ErrorCode::Unavailable};
    std::size_t sentAttempts = 0U;
    while (sentAttempts < attempts && excluded.size() < endpoints->size()) {
        auto endpoint = m_loadBalancer->choose(route->service(), endpoints.value(), excluded);
        if (!endpoint.has_value()) break;
        excluded.push_back(endpoint->id());
        if (!m_circuits->allow(endpoint->id())) {
            continue;
        }
        ++sentAttempts;
        auto response = m_proxy->send(endpoint.value(), request, m_upstreamTimeout);
        if (response.has_value()) {
            if (response->status() < 100 || response->status() > 599) {
                m_circuits->recordFailure(endpoint->id());
                return errorResponse(foundation::Error{foundation::ErrorCode::Unavailable},
                                     request);
            }
            if (response->status() >= 500) m_circuits->recordFailure(endpoint->id());
            else m_circuits->recordSuccess(endpoint->id());
            secureResponse(response.value());
            return std::move(response).value();
        }
        m_circuits->recordFailure(endpoint->id());
        lastFailure = response.error();
    }
    return errorResponse(lastFailure.code() == foundation::ErrorCode::Timeout
                             ? lastFailure
                             : foundation::Error{foundation::ErrorCode::Unavailable}, request);
}

}

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <latch>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// Suppress the duplicate thread-context variable instantiation before Asio
// creates any io_context types; the library owns its explicit definition.
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <boost/beast.hpp>

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.policy;
import openproof.session;

namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace beastHttp = beast::http;
namespace fnd = openproof::foundation;
namespace gw = openproof::gateway;
namespace httpAdapter = openproof::gateway::http;
namespace pol = openproof::policy;
namespace sess = openproof::session;
using Tcp = asio::ip::tcp;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

class AllowAccess final : public gw::AccessController {
public:
    [[nodiscard]] pol::AuthorizationDecision authorize(
        const sess::AuthenticatedSession&, const gw::Route&,
        const fnd::CorrelationId&) override
    { return pol::AuthorizationDecision::allow("test permit"); }
};

class TerminalProxy final : public gw::ProxyTransport {
public:
    [[nodiscard]] fnd::Result<gw::HttpResponse> send(
        const gw::Endpoint&, const gw::HttpRequest& request, fnd::Duration) override
    {
        gw::HttpResponse response{
            201, gw::Headers{{"content-type", "text/plain"}},
            std::string{"upstream:"} + std::string{request.path()}};
        response.addHeader("set-cookie", "first=one; Secure; HttpOnly");
        response.addHeader("set-cookie", "second=two; Secure; HttpOnly");
        return response;
    }
};

class WaitingHandler final : public gw::HttpHandler {
public:
    [[nodiscard]] gw::HttpResponse handle(gw::HttpRequest) override
    {
        const int active = m_active.fetch_add(1, std::memory_order_relaxed) + 1;
        int seen = m_peak.load(std::memory_order_relaxed);
        while (active > seen && !m_peak.compare_exchange_weak(seen, active,
                std::memory_order_relaxed)) {}
        std::this_thread::sleep_for(std::chrono::milliseconds{60});
        m_active.fetch_sub(1, std::memory_order_relaxed);
        return gw::HttpResponse{200, {}, "ok"};
    }
    [[nodiscard]] int peak() const noexcept { return m_peak.load(); }
private:
    std::atomic<int> m_active{0};
    std::atomic<int> m_peak{0};
};

class CountingFastHandler final : public gw::HttpHandler {
public:
    [[nodiscard]] gw::HttpResponse handle(gw::HttpRequest) override
    {
        received.fetch_add(1, std::memory_order_relaxed);
        return gw::HttpResponse{200, {}, "fast"};
    }
    std::atomic<int> received{0};
};

class DisabledCoroutineHandler final : public httpAdapter::CoroutineHttpHandler {
public:
    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }

    [[nodiscard]] gw::HttpResponse handle(gw::HttpRequest) override
    {
        synchronousCalls.fetch_add(1, std::memory_order_relaxed);
        return gw::HttpResponse{200, {}, "legacy-compatible"};
    }

    [[nodiscard]] asio::awaitable<gw::HttpResponse>
    handleAsync(gw::HttpRequest) override
    {
        asynchronousCalls.fetch_add(1, std::memory_order_relaxed);
        co_return gw::HttpResponse{503, {}, "should-not-execute"};
    }

    std::atomic<int> synchronousCalls{0};
    std::atomic<int> asynchronousCalls{0};
};

class CoroutineWaitingHandler final : public httpAdapter::CoroutineHttpHandler {
public:
    [[nodiscard]] gw::HttpResponse handle(gw::HttpRequest) override
    {
        // This route must never fall back to the synchronous handler.
        throw std::runtime_error{"synchronous fallback was used"};
    }

    [[nodiscard]] asio::awaitable<gw::HttpResponse>
    handleAsync(gw::HttpRequest) override
    {
        const int active = m_active.fetch_add(1, std::memory_order_relaxed) + 1;
        int peak = m_peak.load(std::memory_order_relaxed);
        while (active > peak && !m_peak.compare_exchange_weak(
            peak, active, std::memory_order_relaxed)) {}
        asio::steady_timer timer{co_await asio::this_coro::executor};
        timer.expires_after(std::chrono::milliseconds{125});
        co_await timer.async_wait(asio::use_awaitable);
        m_active.fetch_sub(1, std::memory_order_relaxed);
        co_return gw::HttpResponse{200, {}, "async"};
    }

    [[nodiscard]] int peak() const noexcept { return m_peak.load(); }
private:
    std::atomic<int> m_active{0};
    std::atomic<int> m_peak{0};
};

class DelegatingMetricsFacadeStub final : public gw::HttpHandler {
public:
    explicit DelegatingMetricsFacadeStub(gw::HttpHandler& fallback)
        : m_fallback(&fallback) {}
    [[nodiscard]] gw::HttpResponse handle(gw::HttpRequest request) override
    {
        return m_fallback->handle(std::move(request));
    }
private:
    gw::HttpHandler* m_fallback;
};

class MetricsFacadeStub final : public gw::HttpHandler {
public:
    [[nodiscard]] gw::HttpResponse handle(gw::HttpRequest request) override
    {
        if (request.path() != "/metrics") {
            throw std::runtime_error{"metrics facade handled a non-metrics route"};
        }
        const auto authorization = request.header("authorization");
        if (!authorization || *authorization != "Bearer test-only") {
            return gw::HttpResponse{401,
                gw::Headers{{"cache-control", "no-store"}}, ""};
        }
        return gw::HttpResponse{200,
            gw::Headers{{"content-type", "text/plain"}}, "counter 1"};
    }
};

class CoroutineProxyHandler final : public httpAdapter::CoroutineHttpHandler {
public:
    CoroutineProxyHandler(httpAdapter::BeastProxyTransport& proxy, gw::Endpoint endpoint)
        : m_proxy(&proxy), m_endpoint(std::move(endpoint)) {}

    [[nodiscard]] gw::HttpResponse handle(gw::HttpRequest) override
    {
        throw std::runtime_error{"synchronous proxy fallback was used"};
    }

    [[nodiscard]] asio::awaitable<gw::HttpResponse>
    handleAsync(gw::HttpRequest request) override
    {
        auto result = co_await m_proxy->sendAsync(
            m_endpoint, std::move(request), std::chrono::seconds{2});
        if (!result) {
            co_return gw::HttpResponse{502, {}, "upstream unavailable"};
        }
        co_return std::move(result).value();
    }

private:
    httpAdapter::BeastProxyTransport* m_proxy;
    gw::Endpoint m_endpoint;
};

class CoroutineThrowingHandler final : public httpAdapter::CoroutineHttpHandler {
public:
    [[nodiscard]] gw::HttpResponse handle(gw::HttpRequest) override
    {
        throw std::runtime_error{"wrong handler method"};
    }
    [[nodiscard]] asio::awaitable<gw::HttpResponse>
    handleAsync(gw::HttpRequest) override
    {
        asio::steady_timer timer{co_await asio::this_coro::executor};
        timer.expires_after(std::chrono::milliseconds{2});
        co_await timer.async_wait(asio::use_awaitable);
        throw std::runtime_error{"sensitive coroutine exception"};
    }
};

class ThrowingHandler final : public gw::HttpHandler {
public:
    [[nodiscard]] gw::HttpResponse handle(gw::HttpRequest) override
    {
        throw std::runtime_error{"provider error"};
    }
};

class ClientIpHandler final : public gw::HttpHandler {
public:
    [[nodiscard]] gw::HttpResponse handle(gw::HttpRequest request) override
    {
        const bool forwardingHeaderRemoved = !request.header("x-forwarded-for").has_value();
        return gw::HttpResponse{
            forwardingHeaderRemoved ? 200 : 500, {},
            std::string{request.remoteAddress()}};
    }
};

struct CoreFixture {
    CoreFixture()
        : clock(kNow), signer(gw::TrustedContextSigner::create(
              clock, gw::TrustedContextKey::create(fnd::SecretString{
                  "abcdef0123456789abcdef0123456789"}).value(),
              std::chrono::seconds{30}).value()),
          sessions(repository, clock,
              sess::SessionKey::create(fnd::SecretString{
                  "0123456789abcdef0123456789abcdef"}).value(),
              sess::SessionPolicy::create(std::chrono::hours{1},
                                          std::chrono::minutes{10}).value()),
          limiter(gw::TokenBucketRateLimiter::create(clock, 100.0, 100.0, 1000U).value()),
          circuits(gw::CircuitBreaker::create(clock, 2U, std::chrono::seconds{10}).value())
    {
    }
    fnd::ManualClockSource clock;
    gw::TrustedContextSigner signer;
    sess::InMemorySessionRepository repository;
    sess::SessionService sessions;
    AllowAccess access;
    gw::TokenBucketRateLimiter limiter;
    gw::StaticServiceDiscovery discovery;
    gw::WeightedRoundRobin balancer;
    gw::CircuitBreaker circuits;
};

[[nodiscard]] gw::Route route(gw::HttpMethod method = gw::HttpMethod::Get)
{
    return gw::Route::create(gw::RouteId{"route"}, method, "/api",
                             gw::ServiceId{"service"}, false, {}, {}, {}).value();
}

[[nodiscard]] httpAdapter::ServerConfig serverConfig(
    std::size_t bodyLimit = 1024U, std::size_t maximumConnections = 64U)
{
    return httpAdapter::ServerConfig::create(
        "127.0.0.1", 0U, 8192U, bodyLimit, std::chrono::seconds{2},
        std::chrono::seconds{2}, maximumConnections, 2U).value();
}

[[nodiscard]] beastHttp::response<beastHttp::string_body>
sendRequest(std::uint16_t port, beastHttp::verb method, std::string target,
            std::string body = {}, std::string largeHeader = {},
            std::string forwardedClientIp = {}, std::string bearerToken = {})
{
    asio::io_context context;
    Tcp::resolver resolver{context};
    beast::tcp_stream stream{context};
    stream.expires_after(std::chrono::seconds{3});
    stream.connect(resolver.resolve("127.0.0.1", std::to_string(port)));
    beastHttp::request<beastHttp::string_body> request{method, std::move(target), 11};
    request.set(beastHttp::field::host, "localhost");
    if (!bearerToken.empty()) request.set(beastHttp::field::authorization, bearerToken);
    if (!largeHeader.empty()) request.set("x-large", largeHeader);
    if (!forwardedClientIp.empty()) {
        request.set("x-forwarded-for", std::move(forwardedClientIp));
    }
    request.body() = std::move(body);
    request.prepare_payload();
    beastHttp::write(stream, request);
    beast::flat_buffer buffer;
    beastHttp::response<beastHttp::string_body> response;
    beastHttp::read(stream, buffer, response);
    return response;
}

TEST(BeastHttpIntegrationTest, BlockingHandlersDoNotOccupySocketEventLoop)
{
    WaitingHandler handler;
    httpAdapter::BeastHttpServer server{handler, serverConfig()};
    ASSERT_TRUE(server.start());
    std::atomic<int> success{0};
    std::vector<std::thread> clients;
    clients.reserve(12);
    for (int index = 0; index < 12; ++index) {
        clients.emplace_back([&] {
            try {
                const auto response = sendRequest(server.boundPort(),
                    beastHttp::verb::get, "/");
                if (response.result() == beastHttp::status::ok && response.body() == "ok") {
                    success.fetch_add(1);
                }
            } catch (...) {}
        });
    }
    for (auto& client : clients) client.join();
    EXPECT_EQ(success.load(), 12);
    EXPECT_GE(handler.peak(), 3);
    server.stop();
}

TEST(BeastHttpIntegrationTest, DisabledCoroutineCapabilityUsesOriginalWireHandler)
{
    DisabledCoroutineHandler handler;
    httpAdapter::BeastHttpServer server{handler, serverConfig()};
    ASSERT_TRUE(server.start());

    const auto response = sendRequest(
        server.boundPort(), beastHttp::verb::get, "/auth/web3/start");
    EXPECT_EQ(response.result(), beastHttp::status::ok);
    EXPECT_EQ(response.body(), "legacy-compatible");
    EXPECT_EQ(handler.synchronousCalls.load(std::memory_order_relaxed), 1);
    EXPECT_EQ(handler.asynchronousCalls.load(std::memory_order_relaxed), 0);
    server.stop();
}

TEST(BeastHttpIntegrationTest, DisabledCoroutineBehindMetricsKeepsLegacyDispatch)
{
    DisabledCoroutineHandler fallback;
    DelegatingMetricsFacadeStub metricsFacade{fallback};
    httpAdapter::CoroutineMetricsAdapter wrapper{
        metricsFacade, fallback, [](gw::HttpMethod, int, double) {}};
    EXPECT_FALSE(wrapper.nativeEnabled());
    httpAdapter::BeastHttpServer server{wrapper, serverConfig()};
    ASSERT_TRUE(server.start());

    const auto response = sendRequest(
        server.boundPort(), beastHttp::verb::get, "/auth/web3/start");
    EXPECT_EQ(response.result(), beastHttp::status::ok);
    EXPECT_EQ(response.body(), "legacy-compatible");
    EXPECT_EQ(fallback.synchronousCalls.load(std::memory_order_relaxed), 1);
    EXPECT_EQ(fallback.asynchronousCalls.load(std::memory_order_relaxed), 0);
    server.stop();
}

TEST(BeastHttpIntegrationTest, CoroutineHandlerSuspendsWithoutOccupyingPoolWorkers)
{
    CoroutineWaitingHandler handler;
    httpAdapter::BeastHttpServer server{handler, serverConfig()};
    ASSERT_TRUE(server.start());
    std::atomic<int> success{0};
    std::latch simultaneousStart{17};
    std::vector<std::thread> clients;
    clients.reserve(16);
    for (int index = 0; index < 16; ++index) {
        clients.emplace_back([&] {
            simultaneousStart.count_down();
            simultaneousStart.wait();
            try {
                const auto response = sendRequest(server.boundPort(),
                    beastHttp::verb::get, "/");
                if (response.result() == beastHttp::status::ok
                    && response.body() == "async") {
                    success.fetch_add(1, std::memory_order_relaxed);
                }
            } catch (...) {}
        });
    }
    simultaneousStart.count_down();
    simultaneousStart.wait();
    for (auto& client : clients) client.join();
    EXPECT_EQ(success.load(), 16);
    // The bounded worker pool has only 8 threads. A real suspension must
    // allow more than 8 outstanding handler coroutines simultaneously.
    EXPECT_GT(handler.peak(), 8);
    server.stop();
}

TEST(BeastHttpIntegrationTest, CoroutineMetricsWrapperKeepsGuardAndAsyncFallback)
{
    MetricsFacadeStub facade;
    CoroutineWaitingHandler asyncFallback;
    std::atomic<int> observations{0};
    std::atomic<int> lastStatus{0};
    httpAdapter::CoroutineMetricsAdapter handler{
        facade, asyncFallback,
        [&observations, &lastStatus](
            gw::HttpMethod method, int status, double duration) {
            if (method == gw::HttpMethod::Get && duration > 0.0) {
                lastStatus.store(status, std::memory_order_relaxed);
                observations.fetch_add(1, std::memory_order_relaxed);
            }
        }};
    httpAdapter::BeastHttpServer server{handler, serverConfig()};
    ASSERT_TRUE(server.start());

    const auto denied = sendRequest(
        server.boundPort(), beastHttp::verb::get, "/metrics");
    EXPECT_EQ(denied.result(), beastHttp::status::unauthorized);
    EXPECT_EQ(denied.at("cache-control"), "no-store");
    const auto allowed = sendRequest(
        server.boundPort(), beastHttp::verb::get, "/metrics",
        {}, {}, {}, "Bearer test-only");
    EXPECT_EQ(allowed.result(), beastHttp::status::ok);
    EXPECT_EQ(allowed.body(), "counter 1");

    const auto forwarded = sendRequest(
        server.boundPort(), beastHttp::verb::get, "/api/ping");
    EXPECT_EQ(forwarded.result(), beastHttp::status::ok);
    EXPECT_EQ(forwarded.body(), "async");
    EXPECT_EQ(observations.load(std::memory_order_relaxed), 1);
    EXPECT_EQ(lastStatus.load(std::memory_order_relaxed), 200);
    server.stop();
}

TEST(BeastHttpIntegrationTest, CoroutineMetricsCountsFailureAfterSuspension)
{
    MetricsFacadeStub facade;
    CoroutineThrowingHandler throwing;
    std::atomic<int> observations{0};
    std::atomic<int> failureStatus{0};
    httpAdapter::CoroutineMetricsAdapter handler{
        facade, throwing,
        [&observations, &failureStatus](
            gw::HttpMethod method, int status, double duration) {
            if (method == gw::HttpMethod::Get && duration > 0.0) {
                failureStatus.store(status, std::memory_order_relaxed);
                observations.fetch_add(1, std::memory_order_relaxed);
            }
        }};
    httpAdapter::BeastHttpServer server{handler, serverConfig()};
    ASSERT_TRUE(server.start());

    const auto response = sendRequest(
        server.boundPort(), beastHttp::verb::get, "/api/private");
    EXPECT_EQ(response.result(), beastHttp::status::internal_server_error);
    EXPECT_EQ(response.body().find("sensitive"), std::string::npos);
    EXPECT_EQ(observations.load(std::memory_order_relaxed), 1);
    EXPECT_EQ(failureStatus.load(std::memory_order_relaxed), 500);
    server.stop();
}

TEST(BeastHttpIntegrationTest, CoroutineMetricsObserverFailureDoesNotAlterHttpResponse)
{
    MetricsFacadeStub facade;
    CoroutineWaitingHandler asyncFallback;
    httpAdapter::CoroutineMetricsAdapter handler{
        facade, asyncFallback,
        [](gw::HttpMethod, int, double) {
            throw std::runtime_error{"metrics instrumentation failed"};
        }};
    httpAdapter::BeastHttpServer server{handler, serverConfig()};
    ASSERT_TRUE(server.start());
    const auto response = sendRequest(
        server.boundPort(), beastHttp::verb::get, "/api/health");
    EXPECT_EQ(response.result(), beastHttp::status::ok);
    EXPECT_EQ(response.body(), "async");
    server.stop();
}

TEST(BeastHttpIntegrationTest, NativeAsyncProxyPerformsRealTcpRoundTrip)
{
    WaitingHandler upstreamHandler;
    httpAdapter::BeastHttpServer upstreamServer{upstreamHandler, serverConfig()};
    ASSERT_TRUE(upstreamServer.start());

    auto proxy = httpAdapter::BeastProxyTransport::create(
        httpAdapter::ProxyConfig::create(8192U, 4096U).value());
    ASSERT_TRUE(proxy);
    CoroutineProxyHandler edgeHandler{
        *proxy.value(), gw::Endpoint::create(
            gw::EndpointId{"loopback-upstream"}, "127.0.0.1",
            upstreamServer.boundPort(), false, 1U).value()};
    httpAdapter::BeastHttpServer edgeServer{edgeHandler, serverConfig()};
    ASSERT_TRUE(edgeServer.start());

    const auto response = sendRequest(
        edgeServer.boundPort(), beastHttp::verb::get, "/api/items");
    EXPECT_EQ(response.result(), beastHttp::status::ok);
    EXPECT_EQ(response.body(), "ok");

    edgeServer.stop();
    upstreamServer.stop();
}

TEST(BeastHttpIntegrationTest, CoroutineExceptionIsRedactedAfterSuspension)
{
    CoroutineThrowingHandler handler;
    httpAdapter::BeastHttpServer server{handler, serverConfig()};
    ASSERT_TRUE(server.start());
    const auto response = sendRequest(server.boundPort(), beastHttp::verb::get, "/");
    EXPECT_EQ(response.result(), beastHttp::status::internal_server_error);
    EXPECT_EQ(response.body().find("sensitive"), std::string::npos);
    server.stop();
}

TEST(BeastHttpIntegrationTest, HandlerExceptionReturnsSafeInternalError)
{
    ThrowingHandler handler;
    httpAdapter::BeastHttpServer server{handler, serverConfig()};
    ASSERT_TRUE(server.start());
    const auto response = sendRequest(server.boundPort(), beastHttp::verb::get, "/");
    EXPECT_EQ(response.result(), beastHttp::status::internal_server_error);
    EXPECT_EQ(response.at("cache-control"), "no-store");
    EXPECT_EQ(response.at("x-content-type-options"), "nosniff");
    EXPECT_EQ(response.body().find("provider error"), std::string::npos);
    server.stop();
}

TEST(BeastHttpIntegrationTest, TrustedLoopbackProxySuppliesOneValidatedClientIp)
{
    ClientIpHandler handler;
    auto configuration = httpAdapter::ServerConfig::create(
        "127.0.0.1", 0U, 8192U, 1024U, std::chrono::seconds{2},
        std::chrono::seconds{2}, 64U, 2U, true);
    ASSERT_TRUE(configuration.has_value());
    httpAdapter::BeastHttpServer server{handler, std::move(configuration).value()};
    ASSERT_TRUE(server.start());

    const auto accepted = sendRequest(
        server.boundPort(), beastHttp::verb::get, "/", {}, {}, "203.0.113.42");
    EXPECT_EQ(accepted.result(), beastHttp::status::ok);
    EXPECT_EQ(accepted.body(), "203.0.113.42");

    const auto missing = sendRequest(server.boundPort(), beastHttp::verb::get, "/");
    EXPECT_EQ(missing.result(), beastHttp::status::bad_request);
    const auto chain = sendRequest(
        server.boundPort(), beastHttp::verb::get, "/", {}, {},
        "203.0.113.42, 127.0.0.1");
    EXPECT_EQ(chain.result(), beastHttp::status::bad_request);
    const auto malformed = sendRequest(
        server.boundPort(), beastHttp::verb::get, "/", {}, {}, "not-an-ip");
    EXPECT_EQ(malformed.result(), beastHttp::status::bad_request);
    server.stop();

    EXPECT_FALSE(httpAdapter::ServerConfig::create(
        "0.0.0.0", 8443U, 8192U, 1024U, std::chrono::seconds{2},
        std::chrono::seconds{2}, 64U, 2U, true).has_value());
}

asio::awaitable<void> collectAsyncProxyResponse(
    httpAdapter::BeastProxyTransport& transport,
    gw::Endpoint endpoint, gw::HttpRequest request, fnd::Duration timeout,
    std::optional<fnd::Result<gw::HttpResponse>>& result)
{
    result.emplace(co_await transport.sendAsync(
        std::move(endpoint), std::move(request), timeout));
}

TEST(BeastHttpIntegrationTest, NativeCoroutineProxyRoundTrip)
{
    ClientIpHandler handler;
    httpAdapter::BeastHttpServer upstream{handler, serverConfig()};
    ASSERT_TRUE(upstream.start());

    auto transport = httpAdapter::BeastProxyTransport::create(
        httpAdapter::ProxyConfig::create(8192U, 4096U).value());
    ASSERT_TRUE(transport.has_value());

    auto endpoint = gw::Endpoint::create(
        gw::EndpointId{"awaitable-upstream"}, "127.0.0.1",
        upstream.boundPort(), false, 1U);
    ASSERT_TRUE(endpoint.has_value());
    auto request = gw::HttpRequest::create(
        gw::HttpMethod::Get, "/native-coroutine", {}, {}, "127.0.0.1",
        fnd::CorrelationId{"coroutine-test-1"});
    ASSERT_TRUE(request.has_value());

    asio::io_context io;
    std::optional<fnd::Result<gw::HttpResponse>> result;
    auto future = asio::co_spawn(
        io, collectAsyncProxyResponse(
            *transport.value(), std::move(endpoint).value(),
            std::move(request).value(), std::chrono::seconds{2}, result),
        asio::use_future);
    io.run();
    future.get();
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->has_value());
    EXPECT_EQ(result->value().status(), 200);
    EXPECT_EQ(result->value().body(), "127.0.0.1");
    upstream.stop();
}

TEST(BeastHttpIntegrationTest, NativeCoroutineProxyEnforcesUpstreamDeadline)
{
    WaitingHandler handler;
    httpAdapter::BeastHttpServer upstream{handler, serverConfig()};
    ASSERT_TRUE(upstream.start());

    auto transport = httpAdapter::BeastProxyTransport::create(
        httpAdapter::ProxyConfig::create(8192U, 4096U).value());
    ASSERT_TRUE(transport.has_value());
    auto endpoint = gw::Endpoint::create(
        gw::EndpointId{"deadline-upstream"}, "127.0.0.1",
        upstream.boundPort(), false, 1U);
    ASSERT_TRUE(endpoint.has_value());
    auto request = gw::HttpRequest::create(
        gw::HttpMethod::Get, "/slow-response", {}, {}, "127.0.0.1",
        fnd::CorrelationId{"native-coroutine-timeout"});
    ASSERT_TRUE(request.has_value());

    asio::io_context io;
    std::optional<fnd::Result<gw::HttpResponse>> result;
    auto future = asio::co_spawn(
        io, collectAsyncProxyResponse(
            *transport.value(), std::move(endpoint).value(),
            std::move(request).value(), std::chrono::milliseconds{5}, result),
        asio::use_future);
    io.run();
    future.get();
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value());
    upstream.stop();
}

TEST(BeastHttpIntegrationTest, ListenerAndReverseProxyRoundTrip)
{
    CoreFixture upstreamCore;
    gw::Router upstreamRouter;
    ASSERT_TRUE(upstreamRouter.add(route()));
    ASSERT_TRUE(upstreamCore.discovery.set(gw::ServiceId{"service"}, {
        gw::Endpoint::create(gw::EndpointId{"terminal"}, "127.0.0.1", 1U,
                             false, 1U).value()}));
    TerminalProxy terminal;
    gw::Gateway upstreamGateway{
        upstreamRouter, upstreamCore.sessions, upstreamCore.access, upstreamCore.limiter,
        upstreamCore.discovery, upstreamCore.balancer, upstreamCore.circuits, terminal,
        upstreamCore.signer,
        std::chrono::seconds{1}};
    httpAdapter::BeastHttpServer upstreamServer{upstreamGateway, serverConfig()};
    ASSERT_TRUE(upstreamServer.start());
    ASSERT_NE(upstreamServer.boundPort(), 0U);

    CoreFixture edgeCore;
    gw::Router edgeRouter;
    ASSERT_TRUE(edgeRouter.add(route()));
    ASSERT_TRUE(edgeCore.discovery.set(gw::ServiceId{"service"}, {
        gw::Endpoint::create(gw::EndpointId{"upstream"}, "127.0.0.1",
                             upstreamServer.boundPort(), false, 1U).value()}));
    auto proxy = httpAdapter::BeastProxyTransport::create(
        httpAdapter::ProxyConfig::create(8192U, 4096U).value());
    ASSERT_TRUE(proxy);
    gw::Gateway edgeGateway{
        edgeRouter, edgeCore.sessions, edgeCore.access, edgeCore.limiter,
        edgeCore.discovery, edgeCore.balancer, edgeCore.circuits, *proxy.value(),
        edgeCore.signer,
        std::chrono::seconds{2}};
    // Exercise the real Gateway authorization and context-sealing stages,
    // then suspend for the actual upstream TCP I/O rather than calling send().
    httpAdapter::CoroutineGatewayAdapter asyncGateway{edgeGateway, *proxy.value()};
    httpAdapter::BeastHttpServer edgeServer{asyncGateway, serverConfig()};
    ASSERT_TRUE(edgeServer.start());

    const auto response = sendRequest(edgeServer.boundPort(), beastHttp::verb::get,
                                      "/api/items?limit=1");
    EXPECT_EQ(response.result(), beastHttp::status::created);
    EXPECT_EQ(response.body(), "upstream:/api/items");
    EXPECT_EQ(response.at("cache-control"), "no-store");
    EXPECT_EQ(response.at("x-content-type-options"), "nosniff");
    std::vector<std::string> cookies;
    for (const auto& field : response.base()) {
        if (field.name() == beastHttp::field::set_cookie) {
            cookies.emplace_back(field.value());
        }
    }
    EXPECT_EQ(cookies, (std::vector<std::string>{
        "first=one; Secure; HttpOnly", "second=two; Secure; HttpOnly"}));

    edgeServer.stop();
    upstreamServer.stop();
}

TEST(BeastHttpIntegrationTest, GatewayRetrySharesOneDeadlineAcrossRealTcpUpstreams)
{
    CoroutineWaitingHandler slowUpstream;
    CountingFastHandler fastUpstream;
    httpAdapter::BeastHttpServer slowServer{slowUpstream, serverConfig()};
    httpAdapter::BeastHttpServer fastServer{fastUpstream, serverConfig()};
    ASSERT_TRUE(slowServer.start());
    ASSERT_TRUE(fastServer.start());

    CoreFixture core;
    gw::Router router;
    ASSERT_TRUE(router.add(route()));
    // WeightedRoundRobin starts at slot zero: the slow upstream is always
    // selected first, and the next attempt would select the fast endpoint.
    ASSERT_TRUE(core.discovery.set(gw::ServiceId{"service"}, {
        gw::Endpoint::create(gw::EndpointId{"first-slow"}, "127.0.0.1",
                             slowServer.boundPort(), false, 1U).value(),
        gw::Endpoint::create(gw::EndpointId{"second-fast"}, "127.0.0.1",
                             fastServer.boundPort(), false, 1U).value()}));
    auto transport = httpAdapter::BeastProxyTransport::create(
        httpAdapter::ProxyConfig::create(8192U, 4096U).value());
    ASSERT_TRUE(transport);
    gw::Gateway gatewayCore{
        router, core.sessions, core.access, core.limiter,
        core.discovery, core.balancer, core.circuits, *transport.value(),
        core.signer, std::chrono::milliseconds{35}};
    httpAdapter::CoroutineGatewayAdapter asyncGateway{gatewayCore, *transport.value()};
    httpAdapter::BeastHttpServer edgeServer{asyncGateway, serverConfig()};
    ASSERT_TRUE(edgeServer.start());

    const auto response = sendRequest(
        edgeServer.boundPort(), beastHttp::verb::get, "/api/items");
    EXPECT_EQ(response.result(), beastHttp::status::gateway_timeout);
    EXPECT_EQ(fastUpstream.received.load(std::memory_order_relaxed), 0);
    edgeServer.stop();
    fastServer.stop();
    slowServer.stop();
}

TEST(BeastHttpIntegrationTest, GatewayAsyncProxyHandlesSlowTcpUpstreamsConcurrently)
{
    // Both hops perform actual HTTP/TCP I/O. The upstream deliberately
    // suspends for 125ms, proving the gateway's async forwarding does not
    // monopolize the eight bounded handler workers.
    CoroutineWaitingHandler upstreamHandler;
    httpAdapter::BeastHttpServer upstreamServer{upstreamHandler, serverConfig()};
    ASSERT_TRUE(upstreamServer.start());

    CoreFixture edgeCore;
    gw::Router router;
    ASSERT_TRUE(router.add(route()));
    ASSERT_TRUE(edgeCore.discovery.set(gw::ServiceId{"service"}, {
        gw::Endpoint::create(gw::EndpointId{"slow-upstream"}, "127.0.0.1",
                             upstreamServer.boundPort(), false, 1U).value()}));
    auto proxy = httpAdapter::BeastProxyTransport::create(
        httpAdapter::ProxyConfig::create(8192U, 4096U).value());
    ASSERT_TRUE(proxy);
    gw::Gateway gatewayCore{
        router, edgeCore.sessions, edgeCore.access, edgeCore.limiter,
        edgeCore.discovery, edgeCore.balancer, edgeCore.circuits,
        *proxy.value(), edgeCore.signer, std::chrono::seconds{2}};
    httpAdapter::CoroutineGatewayAdapter asyncGateway{gatewayCore, *proxy.value()};
    httpAdapter::BeastHttpServer edgeServer{asyncGateway, serverConfig()};
    ASSERT_TRUE(edgeServer.start());

    std::latch start{17};
    std::atomic<int> successes{0};
    std::vector<std::thread> clients;
    clients.reserve(16);
    for (int index = 0; index < 16; ++index) {
        clients.emplace_back([&] {
            start.count_down();
            start.wait();
            try {
                const auto response = sendRequest(
                    edgeServer.boundPort(), beastHttp::verb::get, "/api");
                if (response.result() == beastHttp::status::ok
                    && response.body() == "async") {
                    successes.fetch_add(1, std::memory_order_relaxed);
                }
            } catch (...) {}
        });
    }
    start.count_down();
    start.wait();
    for (auto& client : clients) client.join();
    EXPECT_EQ(successes.load(), 16);
    EXPECT_GT(upstreamHandler.peak(), 8);
    edgeServer.stop();
    upstreamServer.stop();
}

TEST(BeastHttpIntegrationTest, CoroutineGatewayStillRejectsMissingIdentity)
{
    CoreFixture core;
    gw::Router router;
    ASSERT_TRUE(router.add(gw::Route::create(
        gw::RouteId{"protected"}, gw::HttpMethod::Get, "/api",
        gw::ServiceId{"service"}, true,
        openproof::identity::core::OrganizationId{"organization"},
        pol::Action{"read"}, pol::Resource{"document"}).value()));
    ASSERT_TRUE(core.discovery.set(gw::ServiceId{"service"}, {
        gw::Endpoint::create(gw::EndpointId{"must-not-contact"}, "127.0.0.1",
                             1U, false, 1U).value()}));
    auto proxy = httpAdapter::BeastProxyTransport::create(
        httpAdapter::ProxyConfig::create(8192U, 4096U).value());
    ASSERT_TRUE(proxy);
    gw::Gateway gatewayCore{
        router, core.sessions, core.access, core.limiter,
        core.discovery, core.balancer, core.circuits, *proxy.value(),
        core.signer, std::chrono::seconds{1}};
    httpAdapter::CoroutineGatewayAdapter asyncGateway{gatewayCore, *proxy.value()};
    httpAdapter::BeastHttpServer server{asyncGateway, serverConfig()};
    ASSERT_TRUE(server.start());

    const auto response = sendRequest(
        server.boundPort(), beastHttp::verb::get, "/api/document");
    EXPECT_EQ(response.result(), beastHttp::status::unauthorized);
    EXPECT_EQ(response.at("cache-control"), "no-store");
    EXPECT_EQ(response.base().find("x-openproof-identity"), response.base().end());
    server.stop();
}

TEST(BeastHttpIntegrationTest, MetricsWrapperDoesNotBypassGatewayAuthorization)
{
    CoreFixture core;
    gw::Router router;
    ASSERT_TRUE(router.add(gw::Route::create(
        gw::RouteId{"protected-with-metrics"}, gw::HttpMethod::Get, "/api",
        gw::ServiceId{"service"}, true,
        openproof::identity::core::OrganizationId{"organization"},
        pol::Action{"read"}, pol::Resource{"document"}).value()));
    ASSERT_TRUE(core.discovery.set(gw::ServiceId{"service"}, {
        gw::Endpoint::create(gw::EndpointId{"never-contact"}, "127.0.0.1",
                             1U, false, 1U).value()}));
    auto proxy = httpAdapter::BeastProxyTransport::create(
        httpAdapter::ProxyConfig::create(8192U, 4096U).value());
    ASSERT_TRUE(proxy);
    gw::Gateway gatewayCore{
        router, core.sessions, core.access, core.limiter,
        core.discovery, core.balancer, core.circuits, *proxy.value(),
        core.signer, std::chrono::seconds{1}};
    httpAdapter::CoroutineGatewayAdapter asyncGateway{gatewayCore, *proxy.value()};
    MetricsFacadeStub facade;
    std::atomic<int> observedProtected{0};
    httpAdapter::CoroutineMetricsAdapter middleware{
        facade, asyncGateway,
        [&observedProtected](gw::HttpMethod, int status, double) {
            if (status == 401) {
                observedProtected.fetch_add(1, std::memory_order_relaxed);
            }
        }};
    httpAdapter::BeastHttpServer server{middleware, serverConfig()};
    ASSERT_TRUE(server.start());

    const auto protectedResponse = sendRequest(
        server.boundPort(), beastHttp::verb::get, "/api/document");
    EXPECT_EQ(protectedResponse.result(), beastHttp::status::unauthorized);
    EXPECT_EQ(protectedResponse.at("cache-control"), "no-store");
    EXPECT_EQ(protectedResponse.base().find("x-openproof-identity"),
              protectedResponse.base().end());
    EXPECT_EQ(observedProtected.load(std::memory_order_relaxed), 1);

    const auto deniedMetrics = sendRequest(
        server.boundPort(), beastHttp::verb::get, "/metrics");
    EXPECT_EQ(deniedMetrics.result(), beastHttp::status::unauthorized);
    const auto allowedMetrics = sendRequest(
        server.boundPort(), beastHttp::verb::get, "/metrics",
        {}, {}, {}, "Bearer test-only");
    EXPECT_EQ(allowedMetrics.result(), beastHttp::status::ok);
    EXPECT_EQ(observedProtected.load(std::memory_order_relaxed), 1);
    server.stop();
}

TEST(BeastHttpIntegrationTest, ParserEnforcesBodyAndHeaderLimits)
{
    CoreFixture core;
    gw::Router router;
    ASSERT_TRUE(router.add(route(gw::HttpMethod::Post)));
    ASSERT_TRUE(core.discovery.set(gw::ServiceId{"service"}, {
        gw::Endpoint::create(gw::EndpointId{"terminal"}, "127.0.0.1", 1U,
                             false, 1U).value()}));
    TerminalProxy terminal;
    gw::Gateway gateway{router, core.sessions, core.access, core.limiter,
                        core.discovery, core.balancer, core.circuits, terminal,
                        core.signer,
                        std::chrono::seconds{1}};
    httpAdapter::BeastHttpServer server{gateway, serverConfig(32U)};
    ASSERT_TRUE(server.start());

    const auto bodyRejected = sendRequest(server.boundPort(), beastHttp::verb::post,
                                          "/api", std::string(64U, 'x'));
    EXPECT_EQ(bodyRejected.result(), beastHttp::status::payload_too_large);
    const auto headerRejected = sendRequest(server.boundPort(), beastHttp::verb::post,
                                            "/api", "", std::string(9000U, 'h'));
    EXPECT_EQ(headerRejected.result(),
              beastHttp::status::request_header_fields_too_large);
    server.stop();
    EXPECT_FALSE(server.start().has_value());
}

TEST(BeastHttpIntegrationTest, ConnectionLimitIsAHardCeiling)
{
    CoreFixture core;
    gw::Router router;
    ASSERT_TRUE(router.add(route()));
    ASSERT_TRUE(core.discovery.set(gw::ServiceId{"service"}, {
        gw::Endpoint::create(gw::EndpointId{"terminal"}, "127.0.0.1", 1U,
                             false, 1U).value()}));
    TerminalProxy terminal;
    gw::Gateway gateway{router, core.sessions, core.access, core.limiter,
                        core.discovery, core.balancer, core.circuits, terminal,
                        core.signer, std::chrono::seconds{1}};
    httpAdapter::BeastHttpServer server{gateway, serverConfig(1024U, 1U)};
    ASSERT_TRUE(server.start());

    asio::io_context firstContext;
    Tcp::socket held{firstContext};
    held.connect({asio::ip::make_address("127.0.0.1"), server.boundPort()});
    std::this_thread::sleep_for(std::chrono::milliseconds{50});

    asio::io_context secondContext;
    beast::tcp_stream rejected{secondContext};
    rejected.expires_after(std::chrono::seconds{1});
    rejected.connect(Tcp::endpoint{asio::ip::make_address("127.0.0.1"),
                                   server.boundPort()});
    beastHttp::request<beastHttp::empty_body> request{
        beastHttp::verb::get, "/api", 11};
    request.set(beastHttp::field::host, "localhost");
    boost::system::error_code error;
    beastHttp::write(rejected, request, error);
    if (!error) {
        beast::flat_buffer buffer;
        beastHttp::response<beastHttp::string_body> response;
        beastHttp::read(rejected, buffer, response, error);
    }
    EXPECT_TRUE(error);
    boost::system::error_code ignored;
    held.close(ignored);
    server.stop();
}

}

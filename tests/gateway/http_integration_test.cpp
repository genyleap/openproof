#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/beast.hpp>

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
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
            std::string body = {}, std::string largeHeader = {})
{
    asio::io_context context;
    Tcp::resolver resolver{context};
    beast::tcp_stream stream{context};
    stream.expires_after(std::chrono::seconds{3});
    stream.connect(resolver.resolve("127.0.0.1", std::to_string(port)));
    beastHttp::request<beastHttp::string_body> request{method, std::move(target), 11};
    request.set(beastHttp::field::host, "localhost");
    if (!largeHeader.empty()) request.set("x-large", largeHeader);
    request.body() = std::move(body);
    request.prepare_payload();
    beastHttp::write(stream, request);
    beast::flat_buffer buffer;
    beastHttp::response<beastHttp::string_body> response;
    beastHttp::read(stream, buffer, response);
    return response;
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
    httpAdapter::BeastHttpServer edgeServer{edgeGateway, serverConfig()};
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

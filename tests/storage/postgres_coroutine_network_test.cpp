#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>

// The regular translation unit owns the thread-context storage required by
// Asio; this declaration avoids GCC 16 duplicate instantiations.
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <boost/beast.hpp>

#include "coroutine_session_listener.hpp"

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.session;

namespace {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace wire = beast::http;
namespace fnd = openproof::foundation;
namespace gw = openproof::gateway;
namespace gwHttp = openproof::gateway::http;
namespace pg = openproof::storage::postgres;
using namespace std::chrono_literals;

[[nodiscard]] wire::response<wire::string_body> send(
    std::uint16_t port, wire::verb method, std::string route,
    std::optional<std::string> bearer = std::nullopt,
    std::optional<std::string> cookie = std::nullopt)
{
    asio::io_context context;
    beast::tcp_stream stream{context};
    stream.expires_after(3s);
    asio::ip::tcp::resolver resolver{context};
    stream.connect(resolver.resolve("127.0.0.1", std::to_string(port)));
    wire::request<wire::string_body> request{method, std::move(route), 11};
    request.set(wire::field::host, "localhost");
    if (bearer) request.set(wire::field::authorization, *bearer);
    if (cookie) request.set(wire::field::cookie, *cookie);
    request.prepare_payload();
    wire::write(stream, request);
    beast::flat_buffer buffer;
    wire::response<wire::string_body> result;
    wire::read(stream, buffer, result);
    return result;
}

struct NativeFallback final : gwHttp::CoroutineHttpHandler {
    std::atomic<int>* observed;
    explicit NativeFallback(std::atomic<int>& counter) : observed(&counter) {}
    [[nodiscard]] gw::HttpResponse handle(gw::HttpRequest) override
    {
        return gw::HttpResponse{503, {}, ""};
    }
    [[nodiscard]] asio::awaitable<gw::HttpResponse>
    handleAsync(gw::HttpRequest) override
    {
        ++(*observed);
        co_return gw::HttpResponse{209, {}, "async-route"};
    }
};

struct Fixture {
    asio::io_context databaseIo;
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1770000000000}}};
    pg::CoroutinePostgresSessionRepository repo{
        databaseIo.get_executor(),
        fnd::SecretString{"openproof_invalid_connection_keyword=invalid"},
        1U, 100ms, 100ms, 100ms};
    pg::CoroutinePostgresSessionService service{
        repo, clock, fnd::SecretString{std::string(32, 'x')},
        openproof::session::SessionPolicy::create(8h, 30min).value()};
    gw::TokenBucketRateLimiter limiter{
        gw::TokenBucketRateLimiter::create(clock, 20.0, 20.0, 50U).value()};
    std::atomic<int> forwarded{0};
    NativeFallback fallback{forwarded};
    pg::CoroutineSessionListenerStack stack{service, limiter, fallback};
    gwHttp::BeastHttpServer listener{
        stack.handler(), gwHttp::ServerConfig::create(
            "127.0.0.1", 0U, 8192U, 4096U, 2s, 2s, 16U, 2U).value()};
    asio::executor_work_guard<asio::io_context::executor_type> keepAlive{
        asio::make_work_guard(databaseIo)};
    std::jthread dbWorker{[this] { databaseIo.run(); }};
    ~Fixture()
    {
        listener.stop();
        keepAlive.reset();
        databaseIo.stop();
    }
};

TEST(PostgresCoroutineNetworkTest, SocketRoutesThroughAwaitableForNonSession)
{
    Fixture f;
    ASSERT_TRUE(f.listener.start());
    const auto result = send(
        f.listener.boundPort(), wire::verb::get, "/other/api");
    EXPECT_EQ(result.result_int(), 209);
    EXPECT_EQ(result.body(), "async-route");
    EXPECT_EQ(f.forwarded.load(), 1);
}

TEST(PostgresCoroutineNetworkTest, RotationMissingBearerIsDeniedOverSocket)
{
    Fixture f;
    ASSERT_TRUE(f.listener.start());
    const auto result = send(
        f.listener.boundPort(), wire::verb::post, "/auth/session/rotate");
    EXPECT_EQ(result.result_int(), 401);
    EXPECT_EQ(result.base()[wire::field::www_authenticate], "Bearer");
    EXPECT_EQ(result.base()[wire::field::cache_control], "no-store");
    EXPECT_EQ(result.base().count(wire::field::set_cookie), 0U);
    EXPECT_EQ(f.forwarded.load(), 0);
}

TEST(PostgresCoroutineNetworkTest, AnonymousLogoutClearsCookieOverSocket)
{
    Fixture f;
    ASSERT_TRUE(f.listener.start());
    const auto result = send(
        f.listener.boundPort(), wire::verb::post, "/auth/logout");
    EXPECT_EQ(result.result_int(), 204);
    const auto cookie = result.base()[wire::field::set_cookie];
    const std::string_view cookieText{cookie.data(), cookie.size()};
    EXPECT_NE(cookieText.find("__Host-openproof-session="),
              std::string_view::npos);
    EXPECT_NE(cookieText.find("Max-Age=0"), std::string_view::npos);
}

TEST(PostgresCoroutineNetworkTest, DatabaseOutagePreservesCookieOverSocket)
{
    Fixture f;
    ASSERT_TRUE(f.listener.start());
    const auto rotate = send(
        f.listener.boundPort(), wire::verb::post, "/auth/session/rotate",
        std::string{"Bearer test-only-invalid-token"});
    EXPECT_EQ(rotate.result_int(), 503);
    EXPECT_EQ(rotate.base().count(wire::field::set_cookie), 0U);
    const auto logout = send(
        f.listener.boundPort(), wire::verb::post, "/auth/logout-all",
        std::string{"Bearer test-only-invalid-token"});
    EXPECT_EQ(logout.result_int(), 503);
    EXPECT_EQ(logout.base().count(wire::field::set_cookie), 0U);
}

TEST(PostgresCoroutineNetworkTest, AmbiguousCredentialsRejectedOverSocket)
{
    Fixture f;
    ASSERT_TRUE(f.listener.start());
    const auto result = send(
        f.listener.boundPort(), wire::verb::post, "/auth/session/rotate",
        std::string{"Bearer test-one"},
        std::string{"__Host-openproof-session=test-two"});
    EXPECT_EQ(result.result_int(), 401);
    EXPECT_EQ(result.base().count(wire::field::set_cookie), 0U);
}

TEST(PostgresCoroutineNetworkTest, SynchronousCompatibilityEntryFailsClosed)
{
    Fixture f;
    auto original = gw::HttpRequest::create(
        gw::HttpMethod::Post, "/auth/logout", {}, {}, "127.0.0.1",
        fnd::CorrelationId{"listener-sync-misuse"});
    ASSERT_TRUE(original);
    const auto denied = f.stack.handler().handle(std::move(original).value());
    EXPECT_EQ(denied.status(), 503);
    EXPECT_FALSE(denied.headers().contains("set-cookie"));
}

} // namespace

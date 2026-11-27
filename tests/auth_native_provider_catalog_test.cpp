#include "../src/gateway/asio_service_ids_extern.hpp"
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include <boost/asio/detail/call_stack.hpp>
#include "../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include "../src/authentication/http/coroutine_provider_catalog_http.hpp"

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;

namespace {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace wire = beast::http;
namespace gw = openproof::gateway;
namespace native = openproof::gateway::http;
namespace catalog = openproof::authentication::http;
namespace fnd = openproof::foundation;

constexpr std::string_view kCatalog =
    R"({"providers":["github","oidc"],"challenge_providers":["ldap","web3"]})";

class ReadyFallback final : public native::CoroutineHttpHandler {
public:
    [[nodiscard]] bool nativeEnabledFor(
        const gw::HttpRequest& request) const noexcept override
    {
        return request.method() == gw::HttpMethod::Post
            && request.path() == "/auth/web3/start";
    }
    [[nodiscard]] gw::HttpResponse handle(gw::HttpRequest) override
    {
        blocking.fetch_add(1);
        return gw::HttpResponse{500, {}, "synchronous"};
    }
    [[nodiscard]] asio::awaitable<gw::HttpResponse>
    handleAsync(gw::HttpRequest request) override
    {
        asynchronous.fetch_add(1);
        gotAuthorization = request.header("authorization") == "Bearer example";
        gotCookie = request.header("cookie") == "session=example";
        gotBody = request.body() == "credential";
        co_return gw::HttpResponse{202, {}, "native"};
    }
    std::atomic<int> blocking{0};
    std::atomic<int> asynchronous{0};
    bool gotAuthorization{};
    bool gotCookie{};
    bool gotBody{};
};

[[nodiscard]] gw::HttpRequest makeRequest(
    gw::HttpMethod method, std::string path)
{
    auto request = gw::HttpRequest::create(
        method, std::move(path), {}, {}, "127.0.0.1",
        fnd::CorrelationId{"native-catalog-regression"});
    if (!request) throw std::runtime_error{"invalid catalog test request"};
    return std::move(request).value();
}

asio::awaitable<void> collect(
    catalog::CoroutineProviderCatalogAdapter& adapter,
    gw::HttpRequest request, std::optional<gw::HttpResponse>& result)
{
    result.emplace(co_await adapter.handleAsync(std::move(request)));
    co_return;
}

[[nodiscard]] gw::HttpResponse call(
    catalog::CoroutineProviderCatalogAdapter& adapter,
    gw::HttpRequest request)
{
    asio::io_context io;
    std::optional<gw::HttpResponse> result;
    auto completion = asio::co_spawn(
        io, collect(adapter, std::move(request), result), asio::use_future);
    io.run();
    completion.get();
    if (!result) throw std::runtime_error{"no native catalog response"};
    return std::move(*result);
}

[[nodiscard]] native::ServerConfig testConfig()
{
    return native::ServerConfig::create(
        "127.0.0.1", 0U, 8192U, 8192U,
        std::chrono::seconds{2}, std::chrono::seconds{2}, 32U, 2U).value();
}

[[nodiscard]] wire::response<wire::string_body> requestOnLoopback(
    std::uint16_t port, wire::verb verb, std::string path,
    std::string authorization = {}, std::string cookie = {},
    std::string body = {})
{
    asio::io_context io;
    asio::ip::tcp::resolver resolver{io};
    beast::tcp_stream stream{io};
    stream.expires_after(std::chrono::seconds{3});
    stream.connect(resolver.resolve("127.0.0.1", std::to_string(port)));
    wire::request<wire::string_body> request{verb, std::move(path), 11};
    request.set(wire::field::host, "localhost");
    if (!authorization.empty()) request.set(wire::field::authorization, authorization);
    if (!cookie.empty()) request.set(wire::field::cookie, cookie);
    request.body() = std::move(body);
    request.prepare_payload();
    wire::write(stream, request);
    beast::flat_buffer buffer;
    wire::response<wire::string_body> response;
    wire::read(stream, buffer, response);
    return response;
}

TEST(NativeProviderCatalog, AnonymousAsyncResponseHasLegacyStructureAndHeaders)
{
    ReadyFallback fallback;
    catalog::CoroutineProviderCatalogAdapter adapter{
        fallback, std::string{kCatalog}};
    auto request = makeRequest(gw::HttpMethod::Get, "/auth/providers");
    ASSERT_TRUE(adapter.nativeEnabledFor(request));
    auto result = call(adapter, std::move(request));
    EXPECT_EQ(result.status(), 200);
    EXPECT_EQ(result.body(), kCatalog);
    EXPECT_EQ(result.headers().at("content-type"), "application/json");
    EXPECT_EQ(result.headers().at("cache-control"), "no-store");
    EXPECT_EQ(result.headers().at("pragma"), "no-cache");
    EXPECT_EQ(result.headers().at("x-content-type-options"), "nosniff");
    EXPECT_EQ(result.headers().at("referrer-policy"), "no-referrer");
    EXPECT_EQ(fallback.blocking.load(), 0);
    EXPECT_EQ(fallback.asynchronous.load(), 0);
}

TEST(NativeProviderCatalog, InvalidRouteAndSyncEntryFailClosed)
{
    ReadyFallback fallback;
    catalog::CoroutineProviderCatalogAdapter adapter{fallback, "{}"};
    EXPECT_FALSE(adapter.nativeEnabled());
    auto wrongVerb = makeRequest(gw::HttpMethod::Post, "/auth/providers");
    EXPECT_FALSE(adapter.nativeEnabledFor(wrongVerb));
    EXPECT_EQ(call(adapter, std::move(wrongVerb)).status(), 503);
    auto badPath = makeRequest(gw::HttpMethod::Get, "/auth/providers-other");
    EXPECT_FALSE(adapter.nativeEnabledFor(badPath));
    EXPECT_EQ(call(adapter, std::move(badPath)).status(), 503);
    EXPECT_EQ(adapter.handle(makeRequest(
        gw::HttpMethod::Get, "/auth/providers")).status(), 503);
    EXPECT_EQ(fallback.blocking.load(), 0);
    EXPECT_EQ(fallback.asynchronous.load(), 0);
}

TEST(NativeProviderCatalog, LoopbackListenerServesSnapshotWithoutFallback)
{
    ReadyFallback fallback;
    catalog::CoroutineProviderCatalogAdapter adapter{
        fallback, std::string{kCatalog}};
    native::BeastHttpServer server{adapter, testConfig()};
    ASSERT_TRUE(server.start());
    const auto response = requestOnLoopback(
        server.boundPort(), wire::verb::get, "/auth/providers",
        "Bearer unused", "session=unused", "ignored");
    EXPECT_EQ(response.result(), wire::status::ok);
    EXPECT_EQ(response.body(), kCatalog);
    EXPECT_EQ(response.at("content-type"), "application/json");
    EXPECT_EQ(response.at("cache-control"), "no-store");
    EXPECT_EQ(fallback.blocking.load(), 0);
    EXPECT_EQ(fallback.asynchronous.load(), 0);
    server.stop();
}

TEST(NativeProviderCatalog, NativeFallbackCredentialsSurviveSuspension)
{
    ReadyFallback fallback;
    catalog::CoroutineProviderCatalogAdapter adapter{fallback, "{}"};
    native::BeastHttpServer server{adapter, testConfig()};
    ASSERT_TRUE(server.start());
    const auto denied = requestOnLoopback(
        server.boundPort(), wire::verb::post, "/auth/providers", {},
        {}, "credential");
    EXPECT_EQ(denied.result(), wire::status::service_unavailable);
    const auto delegated = requestOnLoopback(
        server.boundPort(), wire::verb::post, "/auth/web3/start",
        "Bearer example", "session=example", "credential");
    EXPECT_EQ(delegated.result(), wire::status::accepted);
    EXPECT_EQ(delegated.body(), "native");
    EXPECT_EQ(fallback.asynchronous.load(), 1);
    EXPECT_EQ(fallback.blocking.load(), 0);
    EXPECT_TRUE(fallback.gotAuthorization);
    EXPECT_TRUE(fallback.gotCookie);
    EXPECT_TRUE(fallback.gotBody);
    server.stop();
}
} // namespace

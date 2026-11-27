#include "../src/gateway/asio_service_ids_extern.hpp"
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/asio/detail/call_stack.hpp>
#include "../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include "../src/oauth/http/coroutine_discovery_http.hpp"

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;

namespace {

namespace asio = boost::asio;
namespace fnd = openproof::foundation;
namespace gw = openproof::gateway;
namespace native = openproof::gateway::http;
namespace oidc = openproof::oauth::http;

class NativeFallback final : public native::CoroutineHttpHandler {
public:
    [[nodiscard]] bool nativeEnabledFor(
        const gw::HttpRequest& request) const noexcept override
    {
        return request.method() == gw::HttpMethod::Post
            && request.path() == "/auth/web3/start";
    }

    [[nodiscard]] gw::HttpResponse handle(gw::HttpRequest) override
    {
        blockingCalls.fetch_add(1);
        return gw::HttpResponse{500, {}, "blocking fallback called"};
    }

    [[nodiscard]] asio::awaitable<gw::HttpResponse>
    handleAsync(gw::HttpRequest request) override
    {
        nativeCalls.fetch_add(1);
        sawAuth = request.header("authorization") == "Bearer sample";
        sawCookie = request.header("cookie") == "session=sample";
        sawBody = request.body() == "native-credentials";
        co_return gw::HttpResponse{202, {}, "delegated"};
    }

    std::atomic<int> blockingCalls{0};
    std::atomic<int> nativeCalls{0};
    bool sawAuth{};
    bool sawCookie{};
    bool sawBody{};
};

[[nodiscard]] gw::HttpRequest makeRequest(
    gw::HttpMethod method, std::string path,
    gw::Headers headers = {}, std::string body = {})
{
    std::vector<std::pair<std::string, std::string>> fields;
    for (const auto& [name, value] : headers)
        fields.emplace_back(name, value);
    auto result = gw::HttpRequest::create(
        method, std::move(path), std::move(fields), std::move(body),
        "127.0.0.1", fnd::CorrelationId{"native-oidc-regression"});
    if (!result) throw std::runtime_error{"Invalid test HTTP request"};
    return std::move(result).value();
}

asio::awaitable<void> collectResponse(
    oidc::CoroutineOidcDiscoveryAdapter& adapter,
    gw::HttpRequest request,
    std::optional<gw::HttpResponse>& output)
{
    output.emplace(co_await adapter.handleAsync(std::move(request)));
    co_return;
}

[[nodiscard]] gw::HttpResponse callAsync(
    oidc::CoroutineOidcDiscoveryAdapter& adapter,
    gw::HttpRequest request)
{
    asio::io_context context;
    std::optional<gw::HttpResponse> output;
    auto future = asio::co_spawn(
        context, collectResponse(adapter, std::move(request), output),
        asio::use_future);
    context.run();
    future.get();
    if (!output) throw std::runtime_error{"Native handler returned no response"};
    return std::move(*output);
}

TEST(NativeOidcDiscoveryTest, GetDocumentsReturnPublicJsonWithLegacyHeaders)
{
    NativeFallback fallback;
    oidc::CoroutineOidcDiscoveryAdapter handler{
        fallback, R"({"issuer":"https://test.invalid"})",
        R"({"keys":[{"kid":"key-1"}]})"};

    for (const auto& [path, expected] : std::vector<std::pair<std::string, std::string>>{
            {"/.well-known/openid-configuration", R"({"issuer":"https://test.invalid"})"},
            {"/.well-known/jwks.json", R"({"keys":[{"kid":"key-1"}]})"}}) {
        auto request = makeRequest(
            gw::HttpMethod::Get, path,
            {{"authorization", "Bearer should-not-matter"},
             {"cookie", "session=should-not-matter"}},
            "body should not leak");
        ASSERT_TRUE(handler.nativeEnabledFor(request));
        auto response = callAsync(handler, std::move(request));
        EXPECT_EQ(response.status(), 200);
        EXPECT_EQ(response.body(), expected);
        EXPECT_EQ(response.headers().at("content-type"), "application/json");
        EXPECT_EQ(response.headers().at("cache-control"), "no-store");
        EXPECT_EQ(response.headers().at("access-control-allow-origin"), "*");
        EXPECT_EQ(response.headers().at("x-content-type-options"), "nosniff");
    }
    EXPECT_EQ(fallback.blockingCalls.load(), 0);
    EXPECT_EQ(fallback.nativeCalls.load(), 0);
}

TEST(NativeOidcDiscoveryTest, OptionsPreflightIsEmptyAndNeverDelegated)
{
    NativeFallback fallback;
    oidc::CoroutineOidcDiscoveryAdapter handler{fallback, "{}", "{}"};
    auto request = makeRequest(
        gw::HttpMethod::Options, "/.well-known/jwks.json");
    ASSERT_TRUE(handler.nativeEnabledFor(request));
    const auto response = callAsync(handler, std::move(request));
    EXPECT_EQ(response.status(), 204);
    EXPECT_TRUE(response.body().empty());
    EXPECT_EQ(response.headers().at("access-control-allow-origin"), "*");
    EXPECT_EQ(fallback.nativeCalls.load(), 0);
    EXPECT_EQ(fallback.blockingCalls.load(), 0);
}

TEST(NativeOidcDiscoveryTest, UnsupportedMethodCannotCallCompatibilityHandler)
{
    NativeFallback fallback;
    oidc::CoroutineOidcDiscoveryAdapter handler{fallback, "{}", "{}"};
    auto request = makeRequest(
        gw::HttpMethod::Post, "/.well-known/jwks.json");
    EXPECT_FALSE(handler.nativeEnabledFor(request));
    const auto response = callAsync(handler, std::move(request));
    EXPECT_EQ(response.status(), 503);
    EXPECT_EQ(fallback.nativeCalls.load(), 0);
    EXPECT_EQ(fallback.blockingCalls.load(), 0);
}

TEST(NativeOidcDiscoveryTest, NativeProviderFallbackKeepsOwnedCredentials)
{
    NativeFallback fallback;
    oidc::CoroutineOidcDiscoveryAdapter handler{fallback, "{}", "{}"};
    auto request = makeRequest(
        gw::HttpMethod::Post, "/auth/web3/start",
        {{"authorization", "Bearer sample"},
         {"cookie", "session=sample"}}, "native-credentials");
    ASSERT_TRUE(handler.nativeEnabledFor(request));
    const auto response = callAsync(handler, std::move(request));
    EXPECT_EQ(response.status(), 202);
    EXPECT_EQ(response.body(), "delegated");
    EXPECT_EQ(fallback.nativeCalls.load(), 1);
    EXPECT_EQ(fallback.blockingCalls.load(), 0);
    EXPECT_TRUE(fallback.sawAuth);
    EXPECT_TRUE(fallback.sawCookie);
    EXPECT_TRUE(fallback.sawBody);
}

TEST(NativeOidcDiscoveryTest, LegacySynchronousEntryNeverDelegates)
{
    NativeFallback fallback;
    oidc::CoroutineOidcDiscoveryAdapter handler{fallback, "{}", "{}"};
    const auto response = handler.handle(
        makeRequest(gw::HttpMethod::Get, "/.well-known/jwks.json"));
    EXPECT_EQ(response.status(), 503);
    EXPECT_EQ(fallback.blockingCalls.load(), 0);
}

namespace beast = boost::beast;
namespace beastHttp = boost::beast::http;
using Tcp = asio::ip::tcp;

[[nodiscard]] native::ServerConfig isolatedServerConfig()
{
    return native::ServerConfig::create(
        "127.0.0.1", 0U, 8192U, 16384U,
        std::chrono::seconds{2}, std::chrono::seconds{2}, 64U, 2U).value();
}

[[nodiscard]] beastHttp::response<beastHttp::string_body> sendWire(
    std::uint16_t port, beastHttp::verb method, std::string target,
    std::string bearer = {}, std::string cookie = {}, std::string body = {})
{
    asio::io_context io;
    Tcp::resolver resolver{io};
    beast::tcp_stream stream{io};
    stream.expires_after(std::chrono::seconds{3});
    stream.connect(resolver.resolve("127.0.0.1", std::to_string(port)));
    beastHttp::request<beastHttp::string_body> request{method, std::move(target), 11};
    request.set(beastHttp::field::host, "localhost");
    if (!bearer.empty()) request.set(beastHttp::field::authorization, bearer);
    if (!cookie.empty()) request.set(beastHttp::field::cookie, cookie);
    request.body() = std::move(body);
    request.prepare_payload();
    beastHttp::write(stream, request);
    beast::flat_buffer buffer;
    beastHttp::response<beastHttp::string_body> response;
    beastHttp::read(stream, buffer, response);
    return response;
}

TEST(NativeOidcDiscoveryTest, ListenerServesPublicEndpointsOnPrivateLoopback)
{
    NativeFallback fallback;
    oidc::CoroutineOidcDiscoveryAdapter handler{
        fallback, R"({"issuer":"https://test.invalid"})", R"({"keys":[]})"};
    native::BeastHttpServer server{handler, isolatedServerConfig()};
    ASSERT_TRUE(server.start());
    const auto discovery = sendWire(
        server.boundPort(), beastHttp::verb::get,
        "/.well-known/openid-configuration");
    const auto keys = sendWire(
        server.boundPort(), beastHttp::verb::get, "/.well-known/jwks.json");
    const auto options = sendWire(
        server.boundPort(), beastHttp::verb::options, "/.well-known/jwks.json");
    EXPECT_EQ(discovery.result(), beastHttp::status::ok);
    EXPECT_EQ(discovery.body(), R"({"issuer":"https://test.invalid"})");
    EXPECT_EQ(discovery.at("content-type"), "application/json");
    EXPECT_EQ(discovery.at("cache-control"), "no-store");
    EXPECT_EQ(keys.result(), beastHttp::status::ok);
    EXPECT_EQ(keys.body(), R"({"keys":[]})");
    EXPECT_EQ(options.result(), beastHttp::status::no_content);
    EXPECT_TRUE(options.body().empty());
    EXPECT_EQ(fallback.nativeCalls.load(), 0);
    EXPECT_EQ(fallback.blockingCalls.load(), 0);
    server.stop();
}

TEST(NativeOidcDiscoveryTest, ListenerOnlyDelegatesNativeProviderExactRoute)
{
    NativeFallback fallback;
    oidc::CoroutineOidcDiscoveryAdapter handler{fallback, "{}", "{}"};
    native::BeastHttpServer server{handler, isolatedServerConfig()};
    ASSERT_TRUE(server.start());
    const auto denied = sendWire(
        server.boundPort(), beastHttp::verb::post,
        "/.well-known/jwks.json", "Bearer denied", {}, "secret");
    EXPECT_EQ(denied.result(), beastHttp::status::service_unavailable);
    const auto delegated = sendWire(
        server.boundPort(), beastHttp::verb::post, "/auth/web3/start",
        "Bearer sample", "session=sample", "native-credentials");
    EXPECT_EQ(delegated.result(), beastHttp::status::accepted);
    EXPECT_EQ(delegated.body(), "delegated");
    EXPECT_EQ(fallback.nativeCalls.load(), 1);
    EXPECT_EQ(fallback.blockingCalls.load(), 0);
    EXPECT_TRUE(fallback.sawAuth);
    EXPECT_TRUE(fallback.sawCookie);
    EXPECT_TRUE(fallback.sawBody);
    server.stop();
}

} // namespace

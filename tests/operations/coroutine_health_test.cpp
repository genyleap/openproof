#include <gtest/gtest.h>
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <optional>
#include <string>
#include <utility>
#include "../../src/operations/http/coroutine_health_http.hpp"

namespace {
namespace asio=boost::asio;
namespace fnd=openproof::foundation;
namespace gw=openproof::gateway;
namespace ops=openproof::operations::http;

class Fallback final : public gw::http::CoroutineHttpHandler {
public:
    int syncCalls{},asyncCalls{};
    bool nativeEnabledFor(const gw::HttpRequest& r) const noexcept override {return r.path()=="/other";}
    gw::HttpResponse handle(gw::HttpRequest) override {++syncCalls;return {500,{},"sync"};}
    asio::awaitable<gw::HttpResponse> handleAsync(gw::HttpRequest r) override {
        ++asyncCalls;
        EXPECT_EQ(r.body(),"preserved");
        co_return gw::HttpResponse{202,{},"native"};
    }
};

gw::HttpRequest request(std::string path,gw::HttpMethod method=gw::HttpMethod::Get) {
    return gw::HttpRequest::create(method,std::move(path),{}, "preserved","127.0.0.1",
        fnd::CorrelationId{"health-fixture"}).value();
}

gw::HttpResponse run(ops::CoroutineHealthAdapter& api,gw::HttpRequest r) {
    asio::io_context io;
    // co_spawn's exception path requires a default-constructible result.
    // HttpResponse intentionally has no default constructor.
    std::optional<gw::HttpResponse> response;
    auto collect=[&]()->asio::awaitable<void> {
        response.emplace(co_await api.handleAsync(std::move(r)));
    };
    auto task=asio::co_spawn(io,collect(),asio::use_future);
    io.run();
    task.get();
    return std::move(response).value();
}

TEST(NativeHealthTest, ReadinessAwaitsDependencyAndLivenessNeverTouchesStorage)
{
    Fallback fallback;
    int calls=0;
    bool available=true;
    ops::CoroutineHealthAdapter api{fallback,[&]()->asio::awaitable<fnd::Status>{
        ++calls;
        co_await asio::post(asio::use_awaitable);
        co_return available?fnd::ok():fnd::fail(fnd::ErrorCode::Unavailable);
    }};
    EXPECT_TRUE(api.nativeEnabledFor(request("/health/ready")));
    EXPECT_EQ(run(api,request("/health/live")).status(),200);
    EXPECT_EQ(calls,0);
    EXPECT_EQ(run(api,request("/health/ready")).status(),200);
    available=false;
    const auto denied=run(api,request("/health/ready"));
    EXPECT_EQ(denied.status(),503);
    EXPECT_EQ(denied.body(),R"({"status":"unavailable"})");
    EXPECT_EQ(denied.headers().at("cache-control"),"no-store");
    EXPECT_EQ(run(api,request("/health/live")).status(),200);
    EXPECT_EQ(calls,2);
    EXPECT_EQ(api.handle(request("/health/ready")).status(),503);
    EXPECT_EQ(run(api,request("/health/ready",gw::HttpMethod::Post)).status(),405);
    EXPECT_EQ(calls,2);
    EXPECT_EQ(run(api,request("/other")).status(),202);
    EXPECT_EQ(run(api,request("/unknown")).status(),503);
    EXPECT_EQ(fallback.syncCalls,0);
    EXPECT_EQ(fallback.asyncCalls,1);
}
TEST(NativeHealthTest, MissingProbeFailsClosed)
{
    Fallback fallback;
    ops::CoroutineHealthAdapter api{fallback,{}};
    EXPECT_EQ(run(api,request("/health/live")).status(),200);
    EXPECT_EQ(run(api,request("/health/ready")).status(),503);
    EXPECT_EQ(fallback.syncCalls,0);
}
}

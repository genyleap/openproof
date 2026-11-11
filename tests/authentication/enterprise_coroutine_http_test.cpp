#include <gtest/gtest.h>

#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <utility>

import openproof.authentication;
import openproof.authentication.enterprise.http;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.session;

namespace {
namespace asio = boost::asio;
namespace auth = openproof::authentication;
namespace authHttp = openproof::authentication::http;
namespace foundation = openproof::foundation;
namespace gw = openproof::gateway;
namespace identity = openproof::identity::core;
namespace provider = openproof::identity::provider;
namespace session = openproof::session;

class Fallback final : public gw::HttpHandler {
public:
    unsigned calls{};
    gw::HttpResponse handle(gw::HttpRequest) override {
        ++calls;
        return gw::HttpResponse{418, {}, "unexpected-compatibility"};
    }
};

gw::HttpRequest request(std::string route)
{
    return gw::HttpRequest::create(
        gw::HttpMethod::Post, std::move(route),
        {{"content-type", "application/json"}},
        R"({"username":"alice"})", "127.0.0.1",
        foundation::CorrelationId{"native-ldap-boundary"}).value();
}

// Boost.Asio co_spawn must construct a default result on its exception
// path. HttpResponse is not default-constructible; the optional envelope
// preserves its status/body without constructing a fake successful response.
asio::awaitable<std::optional<gw::HttpResponse>> dispatch(
    authHttp::EnterpriseAuthenticationHttpApi& api, gw::HttpRequest input)
{
    co_return std::optional<gw::HttpResponse>{
        co_await api.handleAsync(std::move(input))};
}

TEST(NativeEnterpriseLdapHttpTest, MissingNativeSessionIssuerCannotStartOrRedeemProof)
{
    foundation::ManualClockSource clock{
        foundation::Instant{std::chrono::milliseconds{1'790'000'000'000LL}}};
    provider::ProviderRegistry providers;
    provider::InMemoryAuthenticationTransactionStore transactions;
    identity::InMemoryExternalIdentityDirectory identities;
    auth::ProviderTrustPolicy trust;
    auth::AuthenticationService authentication{
        providers, transactions, identities, clock, std::move(trust),
        std::chrono::minutes{5}};
    session::InMemorySessionRepository repository;
    session::SessionService sessions{
        repository, clock,
        session::SessionKey::create(
            foundation::SecretString{std::string(32U, 'K')}).value(),
        session::SessionPolicy::create(std::chrono::hours{8},
                                      std::chrono::minutes{30}).value()};
    auto limiter = gw::TokenBucketRateLimiter::create(
        clock, 100.0, 100.0, 256U).value();
    Fallback fallback;
    authHttp::EnterpriseAuthenticationHttpApi api{
        authentication, sessions, limiter, fallback};

    EXPECT_FALSE(api.nativeEnabled());
    EXPECT_FALSE(api.nativeEnabledFor(request("/auth/ldap/start")));
    EXPECT_FALSE(api.nativeEnabledFor(request("/auth/ldap/complete")));
    const auto syncStart = api.handle(request("/auth/ldap/start"));
    EXPECT_EQ(syncStart.status(), 503);
    EXPECT_EQ(syncStart.headers().at("cache-control"), "no-store");
    EXPECT_EQ(api.handle(request("/auth/ldap/complete")).status(), 503);

    for (auto route : {"/auth/ldap/start", "/auth/ldap/complete",
                       "/auth/ldap/future-route", "/unrelated"}) {
        asio::io_context io;
        auto result = asio::co_spawn(
            io, dispatch(api, request(route)), asio::use_future);
        io.run();
        auto response = result.get();
        ASSERT_TRUE(response);
        EXPECT_EQ(response->status(), 503) << route;
        EXPECT_EQ(response->headers().at("cache-control"), "no-store");
    }
    EXPECT_EQ(fallback.calls, 0U);
    EXPECT_EQ(repository.size(), 0U);
}
} // namespace

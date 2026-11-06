#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/json.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "coroutine_session_http.hpp"

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.session;
import openproof.security;

namespace {
namespace asio = boost::asio;
namespace json = boost::json;
namespace fnd = openproof::foundation;
namespace gw = openproof::gateway;
namespace http = openproof::account::http;
namespace sess = openproof::session;
namespace idp = openproof::identity::provider;
namespace core = openproof::identity::core;
namespace sec = openproof::security;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

class LegacyHandler final : public gw::HttpHandler {
public:
    int invoked{};
    gw::HttpResponse handle(gw::HttpRequest) override
    {
        ++invoked;
        return gw::HttpResponse{299, {}, "legacy"};
    }
};

class NativeFallback final : public gw::http::CoroutineHttpHandler {
public:
    int invoked{};
    [[nodiscard]] bool nativeEnabled() const noexcept override { return true; }
    [[nodiscard]] bool nativeEnabledFor(
        const gw::HttpRequest& request) const noexcept override
    {
        return request.path() == "/other/api";
    }
    gw::HttpResponse handle(gw::HttpRequest) override
    {
        return gw::HttpResponse{299, {}, "fallback-legacy"};
    }
    asio::awaitable<gw::HttpResponse> handleAsync(gw::HttpRequest) override
    {
        ++invoked;
        co_return gw::HttpResponse{209, {}, "fallback-native"};
    }
};

[[nodiscard]] sess::Session validSession(
    std::string id, std::string identity = "identity-current")
{
    return sess::Session::create(
        sess::SessionId{std::move(id)},
        core::IdentityId{std::move(identity)}, idp::ProviderId{"local"},
        idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{idp::AuthenticationFactor::Knowledge, false},
        kNow, sess::TokenDigest{
            sec::sha256("test-not-a-real-token-digest").value()},
        kNow, std::chrono::hours{8}, std::chrono::minutes{30}).value();
}

asio::awaitable<std::optional<gw::HttpResponse>> dispatch(
    http::CoroutineAccountSessionAdapter& api, gw::HttpRequest request)
{
    co_return std::optional<gw::HttpResponse>{
        co_await api.handleAsync(std::move(request))};
}

[[nodiscard]] gw::HttpRequest request(
    gw::HttpMethod method, std::string path, std::string token = {},
    std::string body = {})
{
    std::vector<std::pair<std::string, std::string>> headers;
    if (!token.empty()) headers.emplace_back("authorization", "Bearer " + token);
    if (!body.empty()) headers.emplace_back("content-type", "application/json");
    return gw::HttpRequest::create(method, std::move(path),
        std::move(headers), std::move(body), "127.0.0.1",
        fnd::CorrelationId{"account-coroutine-test"}).value();
}

struct Fixture final {
    Fixture()
        : limiter(gw::TokenBucketRateLimiter::create(
            clock, 1000.0, 1000.0, 1000U).value()),
          api(legacy, fallback, limiter,
              [this](fnd::SecretString token)
                  -> asio::awaitable<fnd::Result<sess::Session>> {
                  ++authenticationCalls;
                  if (token.expose() != "valid-token") {
                      co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
                  }
                  co_return validSession("current");
              },
              [this](core::IdentityId identity)
                  -> asio::awaitable<fnd::Result<std::vector<sess::Session>>> {
                  ++listCalls;
                  if (identity.value() != "identity-current") {
                      co_return fnd::fail(fnd::ErrorCode::PermissionDenied);
                  }
                  if (includeForeignSession) {
                      co_return std::vector<sess::Session>{
                          validSession("current"),
                          validSession("foreign-session-internal", "identity-foreign")};
                  }
                  co_return std::vector<sess::Session>{
                      validSession("current"), validSession("other")};
              },
              [this](core::IdentityId identity, sess::SessionId id)
                  -> asio::awaitable<fnd::Status> {
                  ++revokeCalls;
                  lastIdentity = std::string{identity.value()};
                  lastTarget = std::string{id.value()};
                  co_return fnd::ok();
              })
    {
    }

    gw::HttpResponse run(gw::HttpRequest input)
    {
        asio::io_context io;
        auto future = asio::co_spawn(io, dispatch(api, std::move(input)),
                                     asio::use_future);
        io.run();
        return std::move(future.get()).value();
    }

    fnd::ManualClockSource clock{kNow};
    LegacyHandler legacy;
    NativeFallback fallback;
    gw::TokenBucketRateLimiter limiter;
    int authenticationCalls{};
    int listCalls{};
    bool includeForeignSession{};
    int revokeCalls{};
    std::string lastIdentity;
    std::string lastTarget;
    http::CoroutineAccountSessionAdapter api;
};

TEST(AccountCoroutineSessionHttpTest, RequestSpecificCapabilityAndNativeFallback)
{
    Fixture f;
    EXPECT_FALSE(f.api.nativeEnabled());
    EXPECT_TRUE(f.api.nativeEnabledFor(
        request(gw::HttpMethod::Get, "/account/sessions")));
    EXPECT_TRUE(f.api.nativeEnabledFor(
        request(gw::HttpMethod::Post, "/account/sessions/revoke")));
    EXPECT_FALSE(f.api.nativeEnabledFor(
        request(gw::HttpMethod::Post, "/account/sessions")));
    EXPECT_FALSE(f.api.nativeEnabledFor(
        request(gw::HttpMethod::Get, "/account/profile")));
    EXPECT_TRUE(f.api.nativeEnabledFor(
        request(gw::HttpMethod::Get, "/other/api")));

    const auto response = f.run(request(gw::HttpMethod::Get, "/other/api"));
    EXPECT_EQ(response.status(), 209);
    EXPECT_EQ(f.fallback.invoked, 1);
    EXPECT_EQ(f.legacy.invoked, 0);
    const auto unavailable = f.run(
        request(gw::HttpMethod::Get, "/account/profile"));
    EXPECT_EQ(unavailable.status(), 503);
    EXPECT_EQ(unavailable.headers().at("cache-control"), "no-store");
    EXPECT_EQ(f.legacy.invoked, 0);
}

TEST(AccountCoroutineSessionHttpTest, ListNativeSessionsPreservesExistingJson)
{
    Fixture f;
    const auto response = f.run(
        request(gw::HttpMethod::Get, "/account/sessions", "valid-token"));
    ASSERT_EQ(response.status(), 200) << response.body();
    const auto document = json::parse(response.body()).as_object();
    const auto& values = document.at("sessions").as_array();
    ASSERT_EQ(values.size(), 2U);
    EXPECT_TRUE(values[0].as_object().at("current").as_bool());
    EXPECT_FALSE(values[1].as_object().at("current").as_bool());
    EXPECT_EQ(values[0].as_object().at("provider").as_string(), "local");
    EXPECT_EQ(f.authenticationCalls, 1);
    EXPECT_EQ(f.listCalls, 1);
    EXPECT_EQ(f.legacy.invoked, 0);
    EXPECT_EQ(response.headers().at("cache-control"), "no-store");
    EXPECT_EQ(response.body().find("valid-token"), std::string::npos);
}

TEST(AccountCoroutineSessionHttpTest, ForeignIdentityRowsFailClosedBeforeSerialization)
{
    Fixture f;
    f.includeForeignSession = true;
    const auto response = f.run(request(
        gw::HttpMethod::Get, "/account/sessions", "valid-token"));
    EXPECT_EQ(response.status(), 503);
    EXPECT_EQ(response.body().find("foreign-session-internal"), std::string::npos);
    EXPECT_EQ(response.body().find("identity-foreign"), std::string::npos);
    EXPECT_EQ(response.headers().at("cache-control"), "no-store");
    EXPECT_EQ(f.listCalls, 1);
    EXPECT_EQ(f.legacy.invoked, 0);
}

TEST(AccountCoroutineSessionHttpTest, MissingAndInvalidBearerNeverEnumerate)
{
    Fixture f;
    EXPECT_EQ(f.run(request(
        gw::HttpMethod::Get, "/account/sessions")).status(), 401);
    EXPECT_EQ(f.authenticationCalls, 0);
    const auto denied = f.run(request(
        gw::HttpMethod::Get, "/account/sessions", "invalid-token"));
    EXPECT_EQ(denied.status(), 401);
    EXPECT_EQ(f.listCalls, 0);
}

TEST(AccountCoroutineSessionHttpTest, RevokeRejectsCurrentAndMalformedRequests)
{
    Fixture f;
    for (const std::string& body : {
        R"({"session_id":"current"})",
        R"({"session_id":"other","unrecognized":true})",
        R"({"session_id":""})"}) {
        const auto response = f.run(request(gw::HttpMethod::Post,
            "/account/sessions/revoke", "valid-token", body));
        EXPECT_TRUE(response.status() == 412 || response.status() == 400);
    }
    EXPECT_EQ(f.revokeCalls, 0);

    const auto response = f.run(request(gw::HttpMethod::Post,
        "/account/sessions/revoke", "valid-token",
        R"({"session_id":"other"})"));
    EXPECT_EQ(response.status(), 200);
    EXPECT_EQ(f.lastIdentity, "identity-current");
    EXPECT_EQ(f.lastTarget, "other");
    EXPECT_EQ(f.revokeCalls, 1);
    EXPECT_EQ(f.legacy.invoked, 0);
}

} // namespace

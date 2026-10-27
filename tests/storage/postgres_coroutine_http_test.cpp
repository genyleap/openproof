#include <gtest/gtest.h>
#include <boost/asio.hpp>

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "coroutine_session_http.hpp"

import openproof.foundation;
import openproof.gateway;
import openproof.session;

namespace {
namespace asio = boost::asio;
namespace fnd = openproof::foundation;
namespace gw = openproof::gateway;
namespace pg = openproof::storage::postgres;
using namespace std::chrono_literals;

struct TestFixture {
    asio::io_context io;
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1770000000000}}};
    pg::CoroutinePostgresSessionRepository repository{
        io.get_executor(),
        fnd::SecretString{"openproof_invalid_connection_keyword=invalid"},
        1U, 100ms, 100ms, 100ms};
    pg::CoroutinePostgresSessionService service{
        repository, clock, fnd::SecretString{std::string(32, 'Q')},
        openproof::session::SessionPolicy::create(8h, 30min).value()};
    gw::TokenBucketRateLimiter limiter{
        gw::TokenBucketRateLimiter::create(clock, 50.0, 50.0, 100U).value()};
    int fallbackCalls{};
    pg::CoroutineSessionHttpHandler handler{
        service, limiter,
        [this](gw::HttpRequest) -> asio::awaitable<gw::HttpResponse> {
            ++fallbackCalls;
            co_return gw::HttpResponse{209, {}, "async-fallback"};
        }};

    [[nodiscard]] gw::HttpResponse run(
        gw::HttpMethod method, std::string path,
        std::vector<std::pair<std::string, std::string>> headers = {})
    {
        auto request = gw::HttpRequest::create(
            method, std::move(path), std::move(headers), {}, "127.0.0.1",
            fnd::CorrelationId{"isolated-coroutine-http-test"});
        if (!request) throw std::runtime_error{"Could not create test request"};
        std::optional<gw::HttpResponse> output;
        auto call = [&]() -> asio::awaitable<void> {
            output.emplace(co_await handler.handleAsync(
                std::move(request).value()));
        };
        io.restart();
        auto completion = asio::co_spawn(io, call(), asio::use_future);
        io.run();
        completion.get();
        if (!output) throw std::runtime_error{"Async HTTP dispatch failed"};
        return std::move(*output);
    }
};

TEST(PostgresCoroutineHttpTest, RotationWithoutCredentialIsUnauthorized)
{
    TestFixture fixture;
    const auto result = fixture.run(
        gw::HttpMethod::Post, "/auth/session/rotate");
    EXPECT_EQ(result.status(), 401);
    EXPECT_EQ(result.headers().at("www-authenticate"), "Bearer");
    EXPECT_EQ(result.headers().at("cache-control"), "no-store");
    EXPECT_FALSE(result.headers().contains("set-cookie"));
    EXPECT_EQ(fixture.fallbackCalls, 0);
}

TEST(PostgresCoroutineHttpTest, AnonymousLogoutClearsOnlySessionCookie)
{
    TestFixture fixture;
    const auto result = fixture.run(gw::HttpMethod::Post, "/auth/logout");
    EXPECT_EQ(result.status(), 204);
    EXPECT_EQ(result.headers().at("cache-control"), "no-store");
    const auto& cookie = result.headers().at("set-cookie");
    EXPECT_NE(cookie.find("__Host-openproof-session="), std::string::npos);
    EXPECT_NE(cookie.find("Max-Age=0"), std::string::npos);
    EXPECT_NE(cookie.find("HttpOnly"), std::string::npos);
    EXPECT_NE(cookie.find("Secure"), std::string::npos);
    EXPECT_NE(cookie.find("SameSite=Strict"), std::string::npos);
}

TEST(PostgresCoroutineHttpTest, DatabaseOutageCannotRotateOrLogout)
{
    TestFixture fixture;
    const auto rotate = fixture.run(
        gw::HttpMethod::Post, "/auth/session/rotate",
        {{"authorization", "Bearer not-a-real-test-credential"}});
    EXPECT_EQ(rotate.status(), 503);
    EXPECT_FALSE(rotate.headers().contains("set-cookie"));
    const auto logout = fixture.run(
        gw::HttpMethod::Post, "/auth/logout-all",
        {{"authorization", "Bearer not-a-real-test-credential"}});
    EXPECT_EQ(logout.status(), 503);
    EXPECT_FALSE(logout.headers().contains("set-cookie"));
}

TEST(PostgresCoroutineHttpTest, SimultaneousBearerAndCookieAreDenied)
{
    TestFixture fixture;
    const auto response = fixture.run(
        gw::HttpMethod::Post, "/auth/session/rotate",
        {{"authorization", "Bearer test-credential"},
         {"cookie", "__Host-openproof-session=test-cookie"}});
    EXPECT_EQ(response.status(), 401);
    EXPECT_FALSE(response.headers().contains("set-cookie"));
}

TEST(PostgresCoroutineHttpTest, WrongMethodCannotMutateSession)
{
    TestFixture fixture;
    const auto response = fixture.run(
        gw::HttpMethod::Get, "/auth/logout");
    EXPECT_EQ(response.status(), 404);
    EXPECT_FALSE(response.headers().contains("set-cookie"));
}

TEST(PostgresCoroutineHttpTest, RateLimitDeniesSessionMutationBeforeDatabase)
{
    TestFixture fixture;
    ASSERT_TRUE(fixture.limiter.allow("auth-ip:127.0.0.1", 50.0));
    const auto response = fixture.run(
        gw::HttpMethod::Post, "/auth/logout");
    EXPECT_EQ(response.status(), 429);
    EXPECT_FALSE(response.headers().contains("set-cookie"));
}

TEST(PostgresCoroutineHttpTest, DuplicateSessionCookiesAreDenied)
{
    TestFixture fixture;
    const auto response = fixture.run(
        gw::HttpMethod::Post, "/auth/session/rotate",
        {{"cookie", "__Host-openproof-session=first;"
                    " __Host-openproof-session=second"}});
    EXPECT_EQ(response.status(), 401);
    EXPECT_FALSE(response.headers().contains("set-cookie"));
}

TEST(PostgresCoroutineHttpTest, OtherPathsUseCoroutineFallback)
{
    TestFixture fixture;
    const auto response = fixture.run(
        gw::HttpMethod::Get, "/other/api");
    EXPECT_EQ(response.status(), 209);
    EXPECT_EQ(response.body(), "async-fallback");
    EXPECT_EQ(fixture.fallbackCalls, 1);
}

} // namespace

#include <gtest/gtest.h>
#include <boost/asio/detail/call_stack.hpp>
#include "../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include "../src/oauth/http/coroutine_consent_http.hpp"

import openproof.client;
import openproof.consent;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.security;
import openproof.session;

namespace {
namespace asio = boost::asio;
namespace fnd = openproof::foundation;
namespace gw = openproof::gateway;
namespace http = openproof::oauth::http;
namespace core = openproof::identity::core;
namespace idp = openproof::identity::provider;
namespace sess = openproof::session;
namespace cons = openproof::consent;
namespace client = openproof::client;
using namespace std::chrono_literals;
constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

class Fallback final : public gw::http::CoroutineHttpHandler {
public:
    bool nativeEnabledFor(const gw::HttpRequest& request) const noexcept override {
        return request.path() == "/other";
    }
    gw::HttpResponse handle(gw::HttpRequest) override {
        ++syncCalls;
        return {500, {}, "sync"};
    }
    asio::awaitable<gw::HttpResponse> handleAsync(gw::HttpRequest request) override {
        ++asyncCalls;
        EXPECT_EQ(request.body(), "preserved");
        EXPECT_EQ(request.header("authorization"), "Bearer other-token");
        co_return gw::HttpResponse{202, {}, "native"};
    }
    int syncCalls{}, asyncCalls{};
};

gw::HttpRequest request(gw::HttpMethod method, std::string path,
                        std::string cookie = {}, std::string body = {},
                        std::string type = "application/x-www-form-urlencoded",
                        std::string bearer = {})
{
    std::vector<std::pair<std::string, std::string>> headers;
    if (!cookie.empty()) headers.emplace_back("cookie", std::move(cookie));
    if (!body.empty()) headers.emplace_back("content-type", std::move(type));
    if (!bearer.empty()) headers.emplace_back("authorization", "Bearer " + bearer);
    return gw::HttpRequest::create(method, std::move(path), std::move(headers),
        std::move(body), "127.0.0.1", fnd::CorrelationId{"native-consent-test"}).value();
}

struct Fixture {
    fnd::ManualClockSource clock{kNow};
    Fallback fallback;
    gw::TokenBucketRateLimiter limiter;
    http::CoroutineConsentAdapter api;
    int authenticationCalls{}, listCalls{}, revokeCalls{};
    bool foreign{}, unavailable{};
    std::string revokedId;
    explicit Fixture(double burst = 1000.0)
        : limiter(gw::TokenBucketRateLimiter::create(clock, burst, 1000.0, 1000U).value()),
          api(fallback, limiter, clock,
            [this](fnd::SecretString token) -> asio::awaitable<fnd::Result<sess::Session>> {
                ++authenticationCalls;
                if (token.expose() != "valid-token")
                    co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
                co_return sess::Session::create(sess::SessionId{"current"}, core::IdentityId{"owner"},
                    idp::ProviderId{"local"}, idp::AssuranceLevel::Ial1,
                    idp::AuthenticationStrength{idp::AuthenticationFactor::Knowledge, false},
                    kNow, sess::TokenDigest{openproof::security::sha256("fixture").value()},
                    kNow, 8h, 30min);
            },
            [this](core::IdentityId owner) -> asio::awaitable<fnd::Result<std::vector<cons::ConsentGrant>>> {
                ++listCalls;
                if (unavailable) co_return fnd::fail(fnd::ErrorCode::Unavailable);
                std::vector<cons::ConsentGrant> values;
                values.push_back(cons::ConsentGrant::create(cons::ConsentId{"grant-1"},
                    foreign ? core::IdentityId{"foreign-owner"} : owner, client::ClientId{"client"},
                    "urn:fixture", {"write", "read"}, kNow, kNow + 1h).value());
                co_return values;
            },
            [this](cons::ConsentId id, core::IdentityId owner, fnd::Instant now)
                -> asio::awaitable<fnd::Status> {
                ++revokeCalls;
                EXPECT_EQ(owner.value(), "owner");
                EXPECT_EQ(now, kNow);
                revokedId = std::string{id.value()};
                if (unavailable) co_return fnd::fail(fnd::ErrorCode::Unavailable);
                co_return fnd::ok();
            }) {}
    gw::HttpResponse run(gw::HttpRequest input) {
        asio::io_context io;
        std::optional<gw::HttpResponse> result;
        auto collect = [&]() -> asio::awaitable<void> {
            result.emplace(co_await api.handleAsync(std::move(input)));
        };
        auto completion = asio::co_spawn(io, collect(), asio::use_future);
        io.run();
        completion.get();
        return std::move(result).value();
    }
};

constexpr std::string_view sessionCookie = "__Host-openproof-session=valid-token";
constexpr std::string_view csrfCookies =
    "__Host-openproof-session=valid-token; __Host-openproof-consent-csrf=proof";

TEST(NativeConsentHttpTest, CookieOnlyListingAndCsrfResponse)
{
    Fixture f;
    auto missing = f.run(request(gw::HttpMethod::Get, "/oauth/consents", {}, {}, {}, "valid-token"));
    EXPECT_EQ(missing.status(), 401);
    EXPECT_EQ(f.authenticationCalls, 0);
    auto duplicate = f.run(request(gw::HttpMethod::Get, "/oauth/consents",
        std::string{sessionCookie} + "; __Host-openproof-session=valid-token"));
    EXPECT_EQ(duplicate.status(), 401);
    auto result = f.run(request(gw::HttpMethod::Get, "/oauth/consents?ignored=secret",
        std::string{sessionCookie}, "ignored", "text/plain"));
    ASSERT_EQ(result.status(), 200);
    EXPECT_EQ(result.headers().at("cache-control"), "no-store");
    EXPECT_FALSE(result.headers().contains("access-control-allow-origin"));
    const auto cookie = result.headers().at("set-cookie");
    EXPECT_TRUE(cookie.starts_with("__Host-openproof-consent-csrf="));
    EXPECT_TRUE(cookie.ends_with("; Path=/; Max-Age=600; Secure; HttpOnly; SameSite=Lax"));
    const auto begin = cookie.find('=') + 1U;
    const auto end = cookie.find(';', begin);
    const auto csrf = cookie.substr(begin, end - begin);
    EXPECT_FALSE(csrf.empty());
    EXPECT_TRUE(result.body().find("\"csrf\":\"" + csrf + "\"") != std::string_view::npos);
    EXPECT_TRUE(result.body().find("\"scope\":\"read write\"") != std::string_view::npos);
    EXPECT_TRUE(result.body().find("\"active\":true") != std::string_view::npos);
    EXPECT_EQ(f.listCalls, 1);
    f.foreign = true;
    auto denied = f.run(request(gw::HttpMethod::Get, "/oauth/consents", std::string{sessionCookie}));
    EXPECT_EQ(denied.status(), 503);
    EXPECT_EQ(denied.body().find("foreign-owner"), std::string_view::npos);
    EXPECT_FALSE(denied.headers().contains("set-cookie"));
}

TEST(NativeConsentHttpTest, MutationRequiresUniqueMatchingCsrfAndExactRoute)
{
    Fixture f;
    for (const auto& body : {"consent_id=grant-1&csrf=wrong",
            "consent_id=grant-1&csrf=proof&csrf=proof",
            "consent_id=grant-1&csrf=%00", "consent_id=grant-1"}) {
        EXPECT_NE(f.run(request(gw::HttpMethod::Post, "/oauth/consents/revoke",
            std::string{csrfCookies}, body)).status(), 204);
    }
    EXPECT_EQ(f.revokeCalls, 0);
    EXPECT_NE(f.run(request(gw::HttpMethod::Post, "/oauth/consents/revoke",
        std::string{csrfCookies}, "consent_id=grant-1&csrf=proof",
        "application/x-www-form-urlencoded-invalid")).status(), 204);
    EXPECT_EQ(f.revokeCalls, 0);
    auto valid = f.run(request(gw::HttpMethod::Post, "/oauth/consents/revoke",
        std::string{csrfCookies}, "consent_id=grant%2D1&csrf=proof"));
    EXPECT_EQ(valid.status(), 204);
    EXPECT_TRUE(valid.body().empty());
    EXPECT_EQ(valid.headers().at("set-cookie"),
        "__Host-openproof-consent-csrf=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax");
    EXPECT_EQ(f.revokedId, "grant-1");
    EXPECT_EQ(f.revokeCalls, 1);
    EXPECT_EQ(f.run(request(gw::HttpMethod::Get, "/oauth/consents/revoke",
        std::string{csrfCookies})).status(), 503);
    EXPECT_EQ(f.api.handle(request(gw::HttpMethod::Get, "/oauth/consents",
        std::string{sessionCookie})).status(), 503);
    EXPECT_EQ(f.run(request(gw::HttpMethod::Post, "/other", {}, "preserved",
        "text/plain", "other-token")).status(), 202);
    EXPECT_EQ(f.fallback.syncCalls, 0);
    EXPECT_EQ(f.fallback.asyncCalls, 1);
    EXPECT_EQ(f.revokeCalls, 1);
}

TEST(NativeConsentHttpTest, RateLimitAndStorageFailureNeverReportSuccess)
{
    Fixture f{1.0};
    f.unavailable = true;
    auto unavailable = f.run(request(gw::HttpMethod::Post, "/oauth/consents/revoke",
        std::string{csrfCookies}, "consent_id=grant-1&csrf=proof"));
    EXPECT_EQ(unavailable.status(), 503);
    EXPECT_FALSE(unavailable.headers().contains("set-cookie"));
    EXPECT_EQ(f.run(request(gw::HttpMethod::Get, "/oauth/consents",
        std::string{sessionCookie})).status(), 429);
    EXPECT_EQ(f.authenticationCalls, 1);
    EXPECT_EQ(f.revokeCalls, 1);
    EXPECT_EQ(f.listCalls, 0);

    // Both consent routes share the legacy OAuth IP bucket. Once it refills,
    // storage failure must still fail closed rather than report success.
    f.clock.advance(1ms);
    EXPECT_EQ(f.run(request(gw::HttpMethod::Get, "/oauth/consents",
        std::string{sessionCookie})).status(), 503);
    EXPECT_EQ(f.authenticationCalls, 2);
    EXPECT_EQ(f.revokeCalls, 1);
    EXPECT_EQ(f.listCalls, 1);
}
} // namespace

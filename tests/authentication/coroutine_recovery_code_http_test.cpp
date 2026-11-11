#include <gtest/gtest.h>

#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <boost/json.hpp>

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "coroutine_recovery_code_http.hpp"

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
namespace idp = openproof::identity::provider;
namespace core = openproof::identity::core;
namespace sess = openproof::session;
namespace sec = openproof::security;
namespace auth = openproof::authentication::http;
namespace cred = openproof::credentials;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

class FakeRecoveryStore final : public cred::CoroutineRecoveryCodeRepository {
public:
    unsigned int replaced{};
    unsigned int consumed{};
    bool failReplace{};
    bool failRevoke{};
    std::vector<cred::RecoveryCodeDigest> stored;

    asio::awaitable<fnd::Status> replaceAsync(
        core::IdentityId identity,
        std::vector<cred::RecoveryCodeDigest> digests) override
    {
        ++replaced;
        if (identity.empty() || (digests.empty() ? failRevoke : failReplace)) {
            co_return fnd::fail(fnd::ErrorCode::Unavailable);
        }
        stored = std::move(digests);
        co_return fnd::ok();
    }

    asio::awaitable<fnd::Status> consumeAsync(
        core::IdentityId, cred::RecoveryCodeDigest) override
    {
        ++consumed;
        co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
    }

    asio::awaitable<fnd::Result<std::size_t>> remainingAsync(
        core::IdentityId) override
    {
        co_return stored.size();
    }
};

class NativeFallback final : public gw::http::CoroutineHttpHandler {
public:
    unsigned int asyncCalls{};
    unsigned int syncCalls{};
    bool enabled{true};

    bool nativeEnabled() const noexcept override { return false; }
    bool nativeEnabledFor(const gw::HttpRequest& request) const noexcept override
    {
        return enabled && request.path() == "/other/api";
    }
    gw::HttpResponse handle(gw::HttpRequest) override
    {
        ++syncCalls;
        return gw::HttpResponse{200, {}, "wrong-synchronous-fallback"};
    }
    asio::awaitable<gw::HttpResponse> handleAsync(gw::HttpRequest) override
    {
        ++asyncCalls;
        co_return gw::HttpResponse{209, {}, "native-fallback"};
    }
};

[[nodiscard]] sess::Session currentSession(bool highAssurance)
{
    return sess::Session::create(
        sess::SessionId{"recovery-session"},
        core::IdentityId{"identity-current"},
        idp::ProviderId{"local"},
        highAssurance ? idp::AssuranceLevel::Ial2
                      : idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{
            idp::AuthenticationFactor::Knowledge
                | idp::AuthenticationFactor::Possession, false},
        kNow, sess::TokenDigest{sec::sha256("recovery-test-cookie").value()},
        kNow, std::chrono::hours{8}, std::chrono::minutes{30}).value();
}

[[nodiscard]] gw::HttpRequest request(
    gw::HttpMethod method, std::string path, std::string bearer = {})
{
    std::vector<std::pair<std::string, std::string>> headers;
    if (!bearer.empty()) {
        headers.emplace_back("authorization", "Bearer " + bearer);
    }
    return gw::HttpRequest::create(method, std::move(path),
        std::move(headers), {}, "127.0.0.1",
        fnd::CorrelationId{"recovery-http-test"}).value();
}

asio::awaitable<gw::HttpResponse> dispatch(
    auth::CoroutineRecoveryCodeHttpAdapter& adapter,
    gw::HttpRequest input)
{
    co_return co_await adapter.handleAsync(std::move(input));
}

struct Fixture final {
    fnd::ManualClockSource clock{kNow};
    gw::TokenBucketRateLimiter limiter{
        gw::TokenBucketRateLimiter::create(clock, 100.0, 100.0, 256U).value()};
    FakeRecoveryStore store;
    cred::CoroutineRecoveryCodeService service{
        std::move(cred::CoroutineRecoveryCodeService::create(
            store, fnd::SecretString{std::string(32U, 'P')})).value()};
    NativeFallback fallback;
    unsigned int authCalls{};
    unsigned int eligibleCalls{};
    bool strongAssurance{true};
    bool eligible{true};
    bool eligibleOnlyInitially{};
    bool eligibilityUnavailable{};
    bool eligibilityUnavailableAfterFirst{};

    auth::CoroutineRecoveryCodeHttpAdapter adapter{
        fallback, limiter, service,
        [this](fnd::SecretString bearer)
            -> asio::awaitable<fnd::Result<sess::Session>> {
            ++authCalls;
            if (bearer.expose() != "valid-token") {
                co_return fnd::fail(fnd::ErrorCode::AuthenticationRequired);
            }
            auto executor = co_await asio::this_coro::executor;
            co_await asio::post(executor, asio::use_awaitable);
            co_return currentSession(strongAssurance);
        },
        [this](core::IdentityId identity)
            -> asio::awaitable<fnd::Result<bool>> {
            ++eligibleCalls;
            if (identity.value() != "identity-current") {
                co_return fnd::fail(fnd::ErrorCode::PermissionDenied);
            }
            auto executor = co_await asio::this_coro::executor;
            co_await asio::post(executor, asio::use_awaitable);
            if (eligibilityUnavailable
                || (eligibilityUnavailableAfterFirst && eligibleCalls > 1U)) {
                co_return fnd::fail(fnd::ErrorCode::Unavailable);
            }
            co_return eligible && !(eligibleOnlyInitially && eligibleCalls > 1U);
        }
    };

    [[nodiscard]] gw::HttpResponse run(gw::HttpRequest input)
    {
        asio::io_context io;
        auto future = asio::co_spawn(
            io, dispatch(adapter, std::move(input)), asio::use_future);
        io.run();
        return future.get();
    }
};

TEST(CoroutineRecoveryHttpTest, OnlyOneAuthorizedRouteIsNative)
{
    Fixture fixture;
    EXPECT_FALSE(fixture.adapter.nativeEnabled());
    EXPECT_TRUE(fixture.adapter.nativeEnabledFor(request(
        gw::HttpMethod::Post, "/auth/recovery-codes")));
    EXPECT_FALSE(fixture.adapter.nativeEnabledFor(request(
        gw::HttpMethod::Get, "/auth/recovery-codes")));
    EXPECT_FALSE(fixture.adapter.nativeEnabledFor(request(
        gw::HttpMethod::Post, "/auth/logout")));
    EXPECT_TRUE(fixture.adapter.nativeEnabledFor(request(
        gw::HttpMethod::Get, "/other/api")));

    const auto route = fixture.run(request(gw::HttpMethod::Get, "/other/api"));
    EXPECT_EQ(route.status(), 209);
    EXPECT_EQ(fixture.fallback.asyncCalls, 1U);
    EXPECT_EQ(fixture.fallback.syncCalls, 0U);
    const auto notNative = fixture.run(request(
        gw::HttpMethod::Post, "/auth/logout"));
    EXPECT_EQ(notNative.status(), 503);
    EXPECT_EQ(fixture.authCalls, 0U);
    const auto direct = fixture.adapter.handle(request(
        gw::HttpMethod::Post, "/auth/recovery-codes"));
    EXPECT_EQ(direct.status(), 503);
    EXPECT_EQ(fixture.store.replaced, 0U);
}

TEST(CoroutineRecoveryHttpTest, WeakOrMissingSessionNeverIssuesCode)
{
    Fixture fixture;
    EXPECT_EQ(fixture.run(request(
        gw::HttpMethod::Post, "/auth/recovery-codes")).status(), 401);
    EXPECT_EQ(fixture.authCalls, 0U);
    EXPECT_EQ(fixture.run(request(
        gw::HttpMethod::Post, "/auth/recovery-codes", "wrong")).status(), 401);
    fixture.strongAssurance = false;
    EXPECT_EQ(fixture.run(request(
        gw::HttpMethod::Post, "/auth/recovery-codes", "valid-token")).status(), 403);
    EXPECT_EQ(fixture.eligibleCalls, 0U);
    EXPECT_EQ(fixture.store.replaced, 0U);
}

TEST(CoroutineRecoveryHttpTest, NativeIssueReturnsTenCodesOnlyAfterPersistence)
{
    Fixture fixture;
    const auto result = fixture.run(request(
        gw::HttpMethod::Post, "/auth/recovery-codes", "valid-token"));
    ASSERT_EQ(result.status(), 201) << result.body();
    ASSERT_EQ(result.headers().at("cache-control"), "no-store");
    EXPECT_EQ(result.headers().at("x-content-type-options"), "nosniff");
    auto document = json::parse(result.body());
    const auto& response = document.as_object().at("codes").as_array();
    ASSERT_EQ(response.size(), 10U);
    EXPECT_EQ(fixture.store.stored.size(), 10U);
    EXPECT_EQ(fixture.store.replaced, 1U);
    EXPECT_EQ(fixture.eligibleCalls, 2U);
    for (std::size_t i=0; i<response.size(); ++i) {
        const auto text = response[i].as_string();
        const auto hashed = sec::hmacSha256(
            fnd::SecretString{std::string(32U, 'P')},
            std::string_view{text.data(), text.size()});
        ASSERT_TRUE(hashed);
        EXPECT_EQ(hashed.value(), fixture.store.stored[i]);
    }
    EXPECT_EQ(fixture.fallback.syncCalls, 0U);
}

TEST(CoroutineRecoveryHttpTest, MissingTotpStopsBeforeAnyPersistence)
{
    Fixture fixture;
    fixture.eligible = false;
    const auto result = fixture.run(request(
        gw::HttpMethod::Post, "/auth/recovery-codes", "valid-token"));
    EXPECT_EQ(result.status(), 412);
    EXPECT_EQ(fixture.store.replaced, 0U);
    EXPECT_EQ(fixture.eligibleCalls, 1U);
    EXPECT_EQ(result.headers().at("cache-control"), "no-store");
}

TEST(CoroutineRecoveryHttpTest, RevokedTotpDuringIssueBurnsAllCodes)
{
    Fixture fixture;
    fixture.eligibleOnlyInitially = true;
    const auto result = fixture.run(request(
        gw::HttpMethod::Post, "/auth/recovery-codes", "valid-token"));
    EXPECT_EQ(result.status(), 412);
    EXPECT_EQ(fixture.store.replaced, 2U);
    EXPECT_TRUE(fixture.store.stored.empty());
    EXPECT_EQ(fixture.eligibleCalls, 2U);
    EXPECT_EQ(result.body().find("codes"), std::string::npos);
}

TEST(CoroutineRecoveryHttpTest, FailedEligibilityRecheckCannotLeakPlaintext)
{
    Fixture fixture;
    fixture.eligibilityUnavailableAfterFirst = true;
    fixture.store.failRevoke = true;
    const auto result = fixture.run(request(
        gw::HttpMethod::Post, "/auth/recovery-codes", "valid-token"));
    EXPECT_EQ(result.status(), 503);
    EXPECT_EQ(fixture.store.replaced, 2U);
    EXPECT_EQ(result.headers().at("cache-control"), "no-store");
    EXPECT_EQ(result.body().find("codes"), std::string::npos);
}

TEST(CoroutineRecoveryHttpTest, PersistenceAndEligibilityErrorsFailClosed)
{
    Fixture noEligibility;
    noEligibility.eligibilityUnavailable = true;
    EXPECT_EQ(noEligibility.run(request(
        gw::HttpMethod::Post, "/auth/recovery-codes", "valid-token")).status(), 503);
    EXPECT_EQ(noEligibility.store.replaced, 0U);

    Fixture noStore;
    noStore.store.failReplace = true;
    EXPECT_EQ(noStore.run(request(
        gw::HttpMethod::Post, "/auth/recovery-codes", "valid-token")).status(), 503);
    EXPECT_EQ(noStore.eligibleCalls, 1U);
    EXPECT_TRUE(noStore.store.stored.empty());
}
} // namespace

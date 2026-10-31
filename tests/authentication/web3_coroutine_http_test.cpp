#include <gtest/gtest.h>
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <vector>

import openproof.authentication;
import openproof.authentication.web3.http;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.session;

namespace {
namespace asio = boost::asio;
namespace auth = openproof::authentication;
namespace http = openproof::authentication::http;
namespace fnd = openproof::foundation;
namespace gateway = openproof::gateway;
namespace idp = openproof::identity::provider;
namespace identity = openproof::identity::core;
namespace sess = openproof::session;

struct BlockingFallback final : gateway::HttpHandler {
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest) override {
        ++calls;
        return gateway::HttpResponse{200, {}, "unexpected fallback"};
    }
    int calls{};
};

// A native wallet provider whose legacy methods are deliberately unusable.
class NativeWalletProvider final : public idp::AuthenticationProvider,
                                   public idp::CoroutineAuthenticationProvider {
public:
    [[nodiscard]] idp::ProviderId id() const override {
        return idp::ProviderId{"ethereum-wallet"};
    }
    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override {
        return idp::InteractionModel::ChallengeResponse;
    }
    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override {
        return idp::AssuranceLevel::Ial1;
    }
    [[nodiscard]] fnd::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest&) override {
        ++blockingCalls;
        return fnd::fail(fnd::ErrorCode::Unavailable);
    }
    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse&) override {
        ++blockingCalls;
        return fnd::fail(fnd::ErrorCode::Unavailable);
    }
    [[nodiscard]] asio::awaitable<fnd::Result<idp::AuthenticationChallenge>>
    beginAuthenticationAsync(idp::AuthenticationRequest request) override {
        ++nativeCalls;
        co_await asio::post(asio::use_awaitable);
        if (request.provider() != id())
            co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        idp::AuthenticationChallenge challenge{
            idp::ChallengeId{"native-http-challenge"},
            fnd::Instant{std::chrono::milliseconds{1770000300000LL}}};
        challenge.setParameter("message", "SIWE test challenge");
        co_return challenge;
    }
    [[nodiscard]] asio::awaitable<fnd::Result<idp::AuthenticationOutcome>>
    completeAuthenticationAsync(idp::AuthenticationResponse response) override {
        ++nativeCalls;
        co_await asio::post(asio::use_awaitable);
        const auto message = response.parameters().find("message");
        const auto signature = response.parameters().find("signature");
        if (message == response.parameters().end()
            || signature == response.parameters().end()
            || message->second.expose() != "SIWE test challenge"
            || signature->second.expose() != "test-signed-proof") {
            co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        }
        co_return idp::AuthenticationOutcome::create(
            idp::ProviderId{"ethereum-wallet"}, idp::ExternalSubject{"wallet-user"},
            idp::VerifiedClaims{}, idp::AssuranceLevel::Ial1,
            idp::AuthenticationStrength{
                idp::AuthenticationFactor::Possession, true},
            idp::ProviderEvidence{},
            fnd::Instant{std::chrono::milliseconds{1770000000000LL}});
    }
    int blockingCalls{};
    int nativeCalls{};
};

// The coroutine coordinator must reject a registered provider that only
// implements synchronous verification, without ever calling its methods.
class LegacyOnlyWalletProvider final : public idp::AuthenticationProvider {
public:
    [[nodiscard]] idp::ProviderId id() const override {
        return idp::ProviderId{"ethereum-wallet"};
    }
    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override {
        return idp::InteractionModel::ChallengeResponse;
    }
    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override {
        return idp::AssuranceLevel::Ial1;
    }
    [[nodiscard]] fnd::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest&) override {
        ++blockingCalls;
        return fnd::fail(fnd::ErrorCode::Unavailable);
    }
    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse&) override {
        ++blockingCalls;
        return fnd::fail(fnd::ErrorCode::Unavailable);
    }
    int blockingCalls{};
};

struct Fixture {
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1770000000000LL}}};
    idp::ProviderRegistry providers;
    idp::InMemoryAuthenticationTransactionStore transactions;
    identity::InMemoryExternalIdentityDirectory identities;
    auth::ProviderTrustPolicy policy = [] {
        auth::ProviderTrustPolicy trust;
        static_cast<void>(trust.trust(
            idp::ProviderId{"ethereum-wallet"}, idp::AssuranceLevel::Ial1));
        return trust;
    }();
    sess::InMemorySessionRepository sessionsRepository;
    sess::SessionService sessions{
        sessionsRepository, clock,
        sess::SessionKey::create(
            fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value(),
        sess::SessionPolicy::create(std::chrono::hours{8},
                                    std::chrono::minutes{30}).value()};
    gateway::TokenBucketRateLimiter limiter =
        gateway::TokenBucketRateLimiter::create(clock, 1000.0, 1000.0, 1000U).value();
    BlockingFallback fallback;
    auth::AuthenticationService authentication{
        providers, transactions, identities, clock, std::move(policy),
        std::chrono::minutes{5}};
    http::Web3AuthenticationHttpApi api{
        authentication, providers, sessions, limiter, fallback};
};

[[nodiscard]] gateway::HttpRequest request(
    std::string path, std::string body = {})
{
    std::vector<std::pair<std::string, std::string>> headers;
    if (!body.empty()) headers.emplace_back("content-type", "application/json");
    return gateway::HttpRequest::create(
        gateway::HttpMethod::Post, std::move(path), std::move(headers),
        std::move(body), "127.0.0.1", fnd::CorrelationId{"async-http-test"}).value();
}

asio::awaitable<void> check(
    gateway::http::CoroutineHttpHandler& handler,
    gateway::HttpRequest input, int& status)
{
    auto reply = co_await handler.handleAsync(std::move(input));
    status = reply.status();
}

[[nodiscard]] int execute(Fixture& fixture, gateway::HttpRequest request)
{
    asio::io_context io;
    int status = 0;
    gateway::http::CoroutineHttpHandler& native = fixture.api;
    auto future = asio::co_spawn(
        io, check(native, std::move(request), status), asio::use_future);
    io.run();
    EXPECT_NO_THROW(future.get());
    return status;
}

TEST(Web3HttpCoroutineTest, UnsupportedHandoffDoesNotFallBackToBlockingStorage)
{
    Fixture fixture;
    EXPECT_EQ(execute(fixture, request(
        "/auth/web3/handoff", R"({"provider":"ethereum-wallet"})")), 503);
    EXPECT_EQ(execute(fixture, request(
        "/account/connections/web3/handoff", R"({"provider":"ethereum-wallet"})")), 503);
    EXPECT_EQ(fixture.fallback.calls, 0);
}

TEST(Web3HttpCoroutineTest, MissingJsonIsRejectedBeforeProviderOrDatabase)
{
    Fixture fixture;
    EXPECT_EQ(execute(fixture, request("/auth/web3/start")), 400);
    EXPECT_EQ(execute(fixture, request("/auth/web3/complete")), 400);
    EXPECT_EQ(fixture.fallback.calls, 0);
}

TEST(Web3HttpCoroutineTest, UnknownProviderIsRejectedWithoutBlockingFallback)
{
    Fixture fixture;
    EXPECT_EQ(execute(fixture, request(
        "/auth/web3/start",
        R"({"provider":"ethereum-wallet","address":"0x1111111111111111111111111111111111111111","chain_id":"1"})")),
        404);
    EXPECT_EQ(fixture.fallback.calls, 0);
}

TEST(Web3HttpCoroutineTest, JsonMimeLookalikeRejectedByBothHttpEntryPoints)
{
    Fixture fixture;
    auto malformed = [] {
        return gateway::HttpRequest::create(
            gateway::HttpMethod::Post, "/auth/web3/start",
            {{"content-type", "application/jsonp"}},
            R"({"provider":"ethereum-wallet","address":"0x1111111111111111111111111111111111111111","chain_id":"1"})",
            "127.0.0.1", fnd::CorrelationId{"mime-test"}).value();
    };
    EXPECT_EQ(execute(fixture, malformed()), 400);
    EXPECT_EQ(fixture.api.handle(malformed()).status(), 400);
    EXPECT_EQ(fixture.fallback.calls, 0);
}

TEST(Web3HttpCoroutineTest, JsonMimeParametersRemainSupported)
{
    Fixture fixture;
    auto withParameters = [] {
        return gateway::HttpRequest::create(
            gateway::HttpMethod::Post, "/auth/web3/start",
            {{"content-type", "application/json; charset=utf-8"}},
            R"({"provider":"ethereum-wallet","address":"0x1111111111111111111111111111111111111111","chain_id":"1"})",
            "127.0.0.1", fnd::CorrelationId{"mime-parameter-test"}).value();
    };
    // The provider is unregistered; 404 proves MIME validation succeeded.
    EXPECT_EQ(execute(fixture, withParameters()), 404);
    EXPECT_EQ(fixture.api.handle(withParameters()).status(), 404);
    EXPECT_EQ(fixture.fallback.calls, 0);
}

TEST(Web3HttpCoroutineTest, MalformedOptionalHandoffCannotDowngradeAuthFlow)
{
    Fixture fixture;
    EXPECT_EQ(execute(fixture, request(
        "/auth/web3/start",
        R"({"provider":"ethereum-wallet","address":"0x1111111111111111111111111111111111111111","chain_id":"1","handoff_ticket":17})")), 400);
    EXPECT_EQ(fixture.api.handle(request(
        "/auth/web3/start",
        R"({"provider":"ethereum-wallet","address":"0x1111111111111111111111111111111111111111","chain_id":"1","handoff_ticket":17})")).status(), 400);
    EXPECT_EQ(fixture.fallback.calls, 0);
}

TEST(Web3HttpCoroutineTest, MalformedOptionalWalletSelectorsAreRejected)
{
    Fixture fixture;
    EXPECT_EQ(execute(fixture, request(
        "/auth/web3/start",
        R"({"provider":"farcaster","address":null})")), 400);
    EXPECT_EQ(execute(fixture, request(
        "/auth/web3/start",
        R"({"provider":"farcaster","fid":42})")), 400);
    EXPECT_EQ(fixture.fallback.calls, 0);
}

TEST(Web3HttpCoroutineTest, RegisteredLegacyProviderNeverRunsOnAsyncDispatch)
{
    Fixture fixture;
    auto owned = std::make_unique<LegacyOnlyWalletProvider>();
    auto* legacy = owned.get();
    ASSERT_TRUE(fixture.providers.registerProvider(std::move(owned)));
    EXPECT_EQ(execute(fixture, request(
        "/auth/web3/start",
        R"({"provider":"ethereum-wallet","address":"0x1111111111111111111111111111111111111111","chain_id":"1"})")),
        401);
    EXPECT_EQ(legacy->blockingCalls, 0);
    EXPECT_EQ(fixture.transactions.size(), 0U);
    EXPECT_EQ(fixture.fallback.calls, 0);
}

TEST(Web3HttpCoroutineTest, UnmatchedRouteCannotInvokeSynchronousFallback)
{
    Fixture fixture;
    EXPECT_EQ(execute(fixture, request("/some-other-app")), 503);
    EXPECT_EQ(fixture.fallback.calls, 0);
}

asio::awaitable<void> collectNativeResponse(
    gateway::http::CoroutineHttpHandler& handler,
    gateway::HttpRequest input, int& status, bool& hasCookies)
{
    auto result = co_await handler.handleAsync(std::move(input));
    status = result.status();
    hasCookies = result.headers().contains("set-cookie")
        || !result.repeatedHeaders().empty();
}

TEST(Web3HttpCoroutineTest, WalletChallengeUsesProviderCoroutineAndAtomicTransactionStore)
{
    Fixture fixture;
    auto owned = std::make_unique<NativeWalletProvider>();
    auto* provider = owned.get();
    ASSERT_TRUE(fixture.providers.registerProvider(std::move(owned)));
    int status = 0;
    bool hasCookies = false;
    asio::io_context io;
    gateway::http::CoroutineHttpHandler& handler = fixture.api;
    auto future = asio::co_spawn(io,
        collectNativeResponse(
            handler, request("/auth/web3/start",
                R"({"provider":"ethereum-wallet","address":"0x1111111111111111111111111111111111111111","chain_id":"1"})"),
            status, hasCookies),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_EQ(status, 200);
    EXPECT_TRUE(hasCookies);
    EXPECT_EQ(fixture.transactions.size(), 1U);
    EXPECT_EQ(provider->nativeCalls, 1);
    EXPECT_EQ(provider->blockingCalls, 0);
    EXPECT_EQ(fixture.fallback.calls, 0);
}

asio::awaitable<void> positiveWalletFlow(
    gateway::http::CoroutineHttpHandler& handler, int& startStatus,
    int& completionStatus, bool& hasSession)
{
    const auto started = co_await handler.handleAsync(request(
        "/auth/web3/start",
        R"({"provider":"ethereum-wallet","address":"0x1111111111111111111111111111111111111111","chain_id":"1"})"));
    startStatus = started.status();
    if (startStatus != 200) co_return;
    std::string cookieHeader;
    const auto collect = [&](std::string_view name, std::string_view value) {
        if (name != "set-cookie") return;
        const auto end = value.find(';');
        if (!cookieHeader.empty()) cookieHeader.append("; ");
        cookieHeader.append(value.substr(0U, end));
    };
    for (const auto& [name, value] : started.headers())
        collect(name, value);
    for (const auto& [name, value] : started.repeatedHeaders())
        collect(name, value);

    std::vector<std::pair<std::string, std::string>> headers{
        {"content-type", "application/json"},
        {"cookie", std::move(cookieHeader)}};
    auto completed = gateway::HttpRequest::create(
        gateway::HttpMethod::Post, "/auth/web3/complete",
        std::move(headers),
        R"({"message":"SIWE test challenge","signature":"test-signed-proof"})",
        "127.0.0.1", fnd::CorrelationId{"async-http-completion"});
    if (!completed) co_return;
    const auto response = co_await handler.handleAsync(std::move(completed).value());
    completionStatus = response.status();
    for (const auto& [name, value] : response.repeatedHeaders()) {
        if (name == "set-cookie"
            && value.starts_with("__Host-openproof-session=")) hasSession = true;
    }
    for (const auto& [name, value] : response.headers()) {
        if (name == "set-cookie"
            && value.starts_with("__Host-openproof-session=")) hasSession = true;
    }
}

TEST(Web3HttpCoroutineTest, WalletChallengeToSessionGoesThroughNativeCoordinator)
{
    Fixture fixture;
    auto providerOwned = std::make_unique<NativeWalletProvider>();
    auto* provider = providerOwned.get();
    ASSERT_TRUE(fixture.providers.registerProvider(std::move(providerOwned)));
    auto link = identity::IdentityLink::request(
        identity::IdentityId{"wallet-canonical-identity"},
        identity::ExternalIdentityRef{
            idp::ProviderId{"ethereum-wallet"}, idp::ExternalSubject{"wallet-user"}},
        fnd::Instant{std::chrono::milliseconds{1770000000000LL}},
        std::chrono::minutes{5});
    ASSERT_TRUE(link);
    ASSERT_TRUE(link->requireVerification(
        fnd::Instant{std::chrono::milliseconds{1770000000000LL}}));
    ASSERT_TRUE(link->markVerified(
        fnd::Instant{std::chrono::milliseconds{1770000000000LL}}));
    ASSERT_TRUE(link->complete(
        fnd::Instant{std::chrono::milliseconds{1770000000000LL}}));
    ASSERT_TRUE(fixture.identities.attach(link.value()));
    int startStatus = 0, completionStatus = 0;
    bool hasSession = false;
    asio::io_context io;
    gateway::http::CoroutineHttpHandler& handler = fixture.api;
    auto future = asio::co_spawn(io,
        positiveWalletFlow(handler, startStatus, completionStatus, hasSession),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_EQ(startStatus, 200);
    EXPECT_EQ(completionStatus, 200);
    EXPECT_TRUE(hasSession);
    EXPECT_EQ(provider->nativeCalls, 2);
    EXPECT_EQ(provider->blockingCalls, 0);
    EXPECT_EQ(fixture.transactions.size(), 1U);
    EXPECT_EQ(fixture.fallback.calls, 0);
}

} // namespace

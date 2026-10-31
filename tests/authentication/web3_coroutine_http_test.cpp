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

// Disabled native support must remain disabled through middleware chaining.
// Its synchronous API is not safe to run on an Asio reactor either.
struct DisabledNativeFallback final : gateway::http::CoroutineHttpHandler {
    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest) override {
        ++blockingCalls;
        return gateway::HttpResponse{200, {}, "blocking-path"};
    }
    [[nodiscard]] asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest) override {
        ++nativeCalls;
        co_return gateway::HttpResponse{200, {}, "disabled-native-path"};
    }
    int blockingCalls{};
    int nativeCalls{};
};

struct EnabledNativeFallback final : gateway::http::CoroutineHttpHandler {
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest) override {
        ++blockingCalls;
        return gateway::HttpResponse{500, {}, "unexpected"};
    }
    [[nodiscard]] asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest) override {
        co_await asio::post(asio::use_awaitable);
        ++nativeCalls;
        co_return gateway::HttpResponse{202, {}, "native"};
    }
    int blockingCalls{};
    int nativeCalls{};
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

// Test-only adapter: its repository is explicitly in-memory, and has no
// network/disk I/O. Production must inject a native PostgreSQL issuer instead.
class InMemoryCoroutineSessionIssuer final : public sess::CoroutineSessionIssuer {
public:
    explicit InMemoryCoroutineSessionIssuer(sess::SessionService& service)
        : m_service(&service) {}

    [[nodiscard]] asio::awaitable<fnd::Result<sess::CoroutineIssuedSession>>
    issueAsync(const auth::VerifiedAuthentication& verified,
               idp::ClientContext client) override
    {
        ++nativeCalls;
        co_await asio::post(asio::use_awaitable);
        if (rejectIssuance)
            co_return fnd::fail(fnd::ErrorCode::Unavailable);
        if (malformedGrant) {
            co_return sess::CoroutineIssuedSession{
                sess::SessionId{"forged-id"},
                fnd::SecretString{"unsafe;Injected=1"}};
        }
        auto issued = m_service->issue(verified, client);
        if (!issued) co_return fnd::fail(issued.error());
        co_return sess::CoroutineIssuedSession{
            issued->id(), issued->token().clone()};
    }

    int nativeCalls{};
    bool rejectIssuance{};
    bool malformedGrant{};
private:
    sess::SessionService* m_service;
};

// This explicit fixture implementation is allowed to access the memory
// repository only. Production must use a native, bounded database adapter.
class MemoryNativeCanonicalFinalizer final
    : public auth::CoroutineCanonicalIdentityFinalizer {
public:
    explicit MemoryNativeCanonicalFinalizer(
        identity::InMemoryExternalIdentityDirectory& directory)
        : m_directory(&directory) {}

    [[nodiscard]] asio::awaitable<fnd::Result<identity::IdentityId>>
    finishLoginAsync(const idp::AuthenticationOutcome& outcome,
                     fnd::Instant) override
    {
        ++nativeCalls;
        co_await asio::post(asio::use_awaitable);
        identity::ExternalIdentityRef external{outcome.provider(), outcome.subject()};
        auto owner = m_directory->ownerOf(external);
        if (!owner) co_return fnd::fail(owner.error());
        if (!owner->has_value())
            co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        auto updated = m_directory->updatePresentation(external);
        if (!updated) co_return fnd::fail(updated.error());
        co_return owner->value();
    }

    int nativeCalls{};
private:
    identity::InMemoryExternalIdentityDirectory* m_directory;
};

struct Fixture {
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1770000000000LL}}};
    idp::ProviderRegistry providers;
    idp::InMemoryAuthenticationTransactionStore transactions;
    identity::InMemoryExternalIdentityDirectory identities;
    MemoryNativeCanonicalFinalizer nativeCanonical{identities};
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
    InMemoryCoroutineSessionIssuer nativeSessions{sessions};
    gateway::TokenBucketRateLimiter limiter =
        gateway::TokenBucketRateLimiter::create(clock, 1000.0, 1000.0, 1000U).value();
    BlockingFallback fallback;
    auth::AuthenticationService authentication{
        providers, transactions, identities, clock, std::move(policy),
        std::chrono::minutes{5}, nullptr, {}, nullptr, &nativeCanonical};
    http::Web3AuthenticationHttpApi api{
        authentication, providers, sessions, limiter, fallback,
        nullptr, &nativeSessions};
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

TEST(Web3HttpCoroutineTest, MissingNativeCanonicalCompletionDisablesListener)
{
    Fixture fixture;
    auth::ProviderTrustPolicy trust;
    ASSERT_TRUE(trust.trust(
        idp::ProviderId{"ethereum-wallet"}, idp::AssuranceLevel::Ial1));
    auth::AuthenticationService unconfigured{
        fixture.providers, fixture.transactions, fixture.identities,
        fixture.clock, std::move(trust), std::chrono::minutes{5}};
    http::Web3AuthenticationHttpApi disabled{
        unconfigured, fixture.providers, fixture.sessions,
        fixture.limiter, fixture.fallback, nullptr, &fixture.nativeSessions};
    EXPECT_FALSE(disabled.nativeEnabled());
    int status = 0;
    asio::io_context io;
    auto future = asio::co_spawn(
        io, check(disabled, request(
            "/auth/web3/start",
            R"({"provider":"ethereum-wallet","address":"0x1111111111111111111111111111111111111111","chain_id":"1"})"),
            status), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_EQ(status, 503);
    EXPECT_EQ(fixture.transactions.size(), 0U);
    EXPECT_EQ(fixture.nativeSessions.nativeCalls, 0);
    EXPECT_EQ(fixture.fallback.calls, 0);
}

TEST(Web3HttpCoroutineTest, NativeStartRequiresAsyncSessionIssuerBeforeStartingProof)
{
    Fixture fixture;
    http::Web3AuthenticationHttpApi withoutNativeSessions{
        fixture.authentication, fixture.providers, fixture.sessions,
        fixture.limiter, fixture.fallback};
    // On the actual Beast listener, this instance must dispatch through the
    // unchanged synchronous handler instead of selecting native HTTP.
    EXPECT_FALSE(withoutNativeSessions.nativeEnabled());
    EXPECT_TRUE(fixture.api.nativeEnabled());
    auto owned = std::make_unique<NativeWalletProvider>();
    auto* provider = owned.get();
    ASSERT_TRUE(fixture.providers.registerProvider(std::move(owned)));
    int status = 0;
    asio::io_context io;
    auto future = asio::co_spawn(
        io, check(withoutNativeSessions, request(
            "/auth/web3/start",
            R"({"provider":"ethereum-wallet","address":"0x1111111111111111111111111111111111111111","chain_id":"1"})"),
            status), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_EQ(status, 503);
    EXPECT_EQ(provider->nativeCalls, 0);
    EXPECT_EQ(provider->blockingCalls, 0);
    EXPECT_EQ(fixture.transactions.size(), 0U);
    EXPECT_EQ(fixture.nativeSessions.nativeCalls, 0);
}

TEST(Web3HttpCoroutineTest, ConnectionHandoffRejectsBeforeSyncSessionLookup)
{
    Fixture fixture;
    EXPECT_EQ(execute(fixture, request(
        "/account/connections/web3/start",
        R"({"provider":"ethereum-wallet","address":"0x1111111111111111111111111111111111111111","chain_id":"1"})")), 503);
    EXPECT_EQ(execute(fixture, request(
        "/account/connections/web3/complete",
        R"({"message":"proof","signature":"signed"})")), 503);
    EXPECT_EQ(fixture.nativeSessions.nativeCalls, 0);
    EXPECT_EQ(fixture.transactions.size(), 0U);
    EXPECT_EQ(fixture.fallback.calls, 0);
}

TEST(Web3HttpCoroutineTest, DisabledNativeFallbackCannotBypassCapabilityGuard)
{
    Fixture fixture;
    DisabledNativeFallback disabled;
    http::Web3AuthenticationHttpApi chained{
        fixture.authentication, fixture.providers, fixture.sessions,
        fixture.limiter, disabled, nullptr, &fixture.nativeSessions};
    int status = 0;
    asio::io_context io;
    auto future = asio::co_spawn(io,
        check(chained, request("/some-other-app"), status), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_EQ(status, 503);
    EXPECT_EQ(disabled.nativeCalls, 0);
    EXPECT_EQ(disabled.blockingCalls, 0);
}

TEST(Web3HttpCoroutineTest, EnabledNativeFallbackReceivesUnmatchedRoute)
{
    Fixture fixture;
    EnabledNativeFallback enabled;
    http::Web3AuthenticationHttpApi chained{
        fixture.authentication, fixture.providers, fixture.sessions,
        fixture.limiter, enabled, nullptr, &fixture.nativeSessions};
    int status = 0;
    asio::io_context io;
    auto future = asio::co_spawn(io,
        check(chained, request("/some-other-app"), status), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_EQ(status, 202);
    EXPECT_EQ(enabled.nativeCalls, 1);
    EXPECT_EQ(enabled.blockingCalls, 0);
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

void attachWalletIdentity(Fixture& fixture)
{
    const auto now = fnd::Instant{std::chrono::milliseconds{1770000000000LL}};
    auto link = identity::IdentityLink::request(
        identity::IdentityId{"wallet-canonical-identity"},
        identity::ExternalIdentityRef{
            idp::ProviderId{"ethereum-wallet"}, idp::ExternalSubject{"wallet-user"}},
        now, std::chrono::minutes{5});
    ASSERT_TRUE(link);
    ASSERT_TRUE(link->requireVerification(now));
    ASSERT_TRUE(link->markVerified(now));
    ASSERT_TRUE(link->complete(now));
    ASSERT_TRUE(fixture.identities.attach(link.value()));
}

TEST(Web3HttpCoroutineTest, UnlinkedVerifiedWalletCannotIssueSession)
{
    Fixture fixture;
    // No canonical identity was linked to this provider subject. Even a valid
    // native wallet signature must not create an authenticated session.
    ASSERT_TRUE(fixture.providers.registerProvider(
        std::make_unique<NativeWalletProvider>()));
    int startStatus = 0, completionStatus = 0;
    bool hasSession = false;
    asio::io_context io;
    auto future = asio::co_spawn(io,
        positiveWalletFlow(
            fixture.api, startStatus, completionStatus, hasSession),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_EQ(startStatus, 200);
    EXPECT_EQ(completionStatus, 401);
    EXPECT_FALSE(hasSession);
    EXPECT_EQ(fixture.nativeCanonical.nativeCalls, 1);
    EXPECT_EQ(fixture.nativeSessions.nativeCalls, 0);
    EXPECT_EQ(fixture.sessionsRepository.size(), 0U);
}

TEST(Web3HttpCoroutineTest, NativeSessionStorageFailureNeverIssuesCookie)
{
    Fixture fixture;
    fixture.nativeSessions.rejectIssuance = true;
    auto owned = std::make_unique<NativeWalletProvider>();
    ASSERT_TRUE(fixture.providers.registerProvider(std::move(owned)));
    attachWalletIdentity(fixture);
    int startStatus = 0, completionStatus = 0;
    bool hasSession = false;
    asio::io_context io;
    auto future = asio::co_spawn(io,
        positiveWalletFlow(fixture.api, startStatus, completionStatus, hasSession),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_EQ(startStatus, 200);
    EXPECT_EQ(completionStatus, 503);
    EXPECT_FALSE(hasSession);
    EXPECT_EQ(fixture.nativeSessions.nativeCalls, 1);
    EXPECT_EQ(fixture.sessionsRepository.size(), 0U);
    EXPECT_EQ(fixture.fallback.calls, 0);
}

TEST(Web3HttpCoroutineTest, MalformedNativeIssuerGrantCannotInjectSessionCookie)
{
    Fixture fixture;
    fixture.nativeSessions.malformedGrant = true;
    ASSERT_TRUE(fixture.providers.registerProvider(
        std::make_unique<NativeWalletProvider>()));
    attachWalletIdentity(fixture);
    int startStatus = 0, completionStatus = 0;
    bool hasSession = false;
    asio::io_context io;
    auto future = asio::co_spawn(io,
        positiveWalletFlow(fixture.api, startStatus, completionStatus, hasSession),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_EQ(startStatus, 200);
    EXPECT_EQ(completionStatus, 500);
    EXPECT_FALSE(hasSession);
    EXPECT_EQ(fixture.nativeSessions.nativeCalls, 1);
    EXPECT_EQ(fixture.sessionsRepository.size(), 0U);
}

TEST(Web3HttpCoroutineTest, NativeHandoffStartFailsBeforeCreatingTransaction)
{
    Fixture fixture;
    auto owned = std::make_unique<NativeWalletProvider>();
    auto* provider = owned.get();
    ASSERT_TRUE(fixture.providers.registerProvider(std::move(owned)));
    EXPECT_EQ(execute(fixture, request(
        "/auth/web3/start",
        R"({"provider":"ethereum-wallet","address":"0x1111111111111111111111111111111111111111","chain_id":"1","handoff_ticket":"test.ticket"})")), 503);
    EXPECT_EQ(fixture.transactions.size(), 0U);
    EXPECT_EQ(provider->nativeCalls, 0);
}

TEST(Web3HttpCoroutineTest, NativeProfileWriteFailsBeforeReadingCredentials)
{
    Fixture fixture;
    EXPECT_EQ(execute(fixture, request(
        "/auth/web3/complete",
        R"({"message":"test","signature":"sig","display_name":"Example"})")), 503);
    EXPECT_EQ(fixture.nativeSessions.nativeCalls, 0);
    EXPECT_EQ(fixture.transactions.size(), 0U);
}

TEST(Web3HttpCoroutineTest, WalletChallengeToSessionGoesThroughNativeCoordinator)
{
    Fixture fixture;
    auto providerOwned = std::make_unique<NativeWalletProvider>();
    auto* provider = providerOwned.get();
    ASSERT_TRUE(fixture.providers.registerProvider(std::move(providerOwned)));
    attachWalletIdentity(fixture);
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
    EXPECT_EQ(fixture.nativeSessions.nativeCalls, 1);
    EXPECT_EQ(fixture.sessionsRepository.size(), 1U);
    EXPECT_EQ(fixture.transactions.size(), 1U);
    EXPECT_EQ(fixture.fallback.calls, 0);
}

} // namespace

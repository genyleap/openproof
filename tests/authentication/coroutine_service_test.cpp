#include <gtest/gtest.h>
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <utility>

import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.security;

namespace {
namespace asio = boost::asio;
namespace auth = openproof::authentication;
namespace fnd = openproof::foundation;
namespace ids = openproof::identity::core;
namespace idp = openproof::identity::provider;
namespace security = openproof::security;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1770000000000LL}};
constexpr fnd::Duration kLifetime{std::chrono::minutes{5}};

[[nodiscard]] idp::BindingDigest binding(std::string_view text)
{
    auto digest = security::sha256(text);
    EXPECT_TRUE(digest);
    return digest.value_or(idp::BindingDigest{});
}

class ProofProvider : public idp::AuthenticationProvider {
public:
    [[nodiscard]] idp::ProviderId id() const override { return idp::ProviderId{"async-test"}; }
    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override
    { return idp::InteractionModel::Redirect; }
    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override
    { return idp::AssuranceLevel::Ial2; }
    [[nodiscard]] fnd::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest&) override
    {
        ++syncCalls;
        return idp::AuthenticationChallenge{idp::ChallengeId{"server-challenge"},
                                            kNow + kLifetime};
    }
    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse&) override
    {
        ++syncCalls;
        return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
    }
    int syncCalls{};
};

class NativeProofProvider final : public ProofProvider,
                                  public idp::CoroutineAuthenticationProvider {
public:
    [[nodiscard]] asio::awaitable<fnd::Result<idp::AuthenticationChallenge>>
    beginAuthenticationAsync(idp::AuthenticationRequest request) override
    {
        ++nativeBeginCalls;
        co_await asio::post(asio::use_awaitable);
        if (request.provider() != id()) co_return fnd::fail(fnd::ErrorCode::InvalidArgument);
        co_return idp::AuthenticationChallenge{
            idp::ChallengeId{"server-challenge"}, kNow + kLifetime};
    }

    [[nodiscard]] asio::awaitable<fnd::Result<idp::AuthenticationOutcome>>
    completeAuthenticationAsync(idp::AuthenticationResponse response) override
    {
        ++nativeCompleteCalls;
        co_await asio::post(asio::use_awaitable);
        if (response.parameters().find("proof") == response.parameters().end()) {
            co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        }
        co_return idp::AuthenticationOutcome::create(
            idp::ProviderId{forgedProvider ? "forged" : "async-test"},
            idp::ExternalSubject{"verified-subject"}, idp::VerifiedClaims{},
            idp::AssuranceLevel::Ial2,
            idp::AuthenticationStrength{idp::AuthenticationFactor::Possession, false},
            idp::ProviderEvidence{}, kNow);
    }

    bool forgedProvider{};
    int nativeBeginCalls{};
    int nativeCompleteCalls{};
};

struct Fixture {
    explicit Fixture(bool native = true, bool trusted = true)
        : clock(kNow)
    {
        if (native) {
            auto owned = std::make_unique<NativeProofProvider>();
            coroutineProvider = owned.get();
            EXPECT_TRUE(providers.registerProvider(std::move(owned)));
        } else {
            auto owned = std::make_unique<ProofProvider>();
            synchronousProvider = owned.get();
            EXPECT_TRUE(providers.registerProvider(std::move(owned)));
        }
        if (trusted) {
            EXPECT_TRUE(policy.trust(idp::ProviderId{"async-test"}, idp::AssuranceLevel::Ial2));
        }

        auto link = ids::IdentityLink::request(
            ids::IdentityId{"canonical-identity"},
            ids::ExternalIdentityRef{
                idp::ProviderId{"async-test"}, idp::ExternalSubject{"verified-subject"}},
            kNow, kLifetime);
        EXPECT_TRUE(link);
        if (!link) return;
        EXPECT_TRUE(link->requireVerification(kNow));
        EXPECT_TRUE(link->markVerified(kNow));
        EXPECT_TRUE(link->complete(kNow));
        EXPECT_TRUE(identities.attach(link.value()));
    }

    [[nodiscard]] auth::AuthenticationService service()
    {
        return auth::AuthenticationService{
            providers, transactions, identities, clock, std::move(policy), kLifetime};
    }

    [[nodiscard]] idp::AuthenticationRequest request()
    {
        return idp::AuthenticationRequest{idp::ProviderId{"async-test"}, idp::ClientContext{}};
    }

    idp::ProviderRegistry providers;
    idp::InMemoryAuthenticationTransactionStore transactions;
    ids::InMemoryExternalIdentityDirectory identities;
    fnd::ManualClockSource clock;
    auth::ProviderTrustPolicy policy;
    NativeProofProvider* coroutineProvider{};
    ProofProvider* synchronousProvider{};
};

[[nodiscard]] idp::AuthenticationResponse proof(std::string challenge)
{
    idp::AuthenticationResponse response{
        idp::ChallengeId{std::move(challenge)}, idp::ClientContext{}};
    response.setParameter("proof", idp::CredentialValue{"valid"});
    return response;
}

asio::awaitable<void> successfulFlow(auth::AuthenticationService& service,
                                     Fixture& fixture, bool& passed)
{
    const auto bound = binding("my-pinned-client");
    auto started = co_await service.beginAsync(
        fixture.request(), bound, fnd::CorrelationId{"native-test"});
    if (!started) co_return;
    auto id = idp::TransactionId{std::string{started->transactionId().value()}};
    auto token = started->continuationToken().clone();
    auto challenge = std::string{started->challenge().id().value()};
    auto verified = co_await service.completeAsync(
        id, token.clone(), bound, proof(challenge));
    if (!verified) co_return;
    auto replay = co_await service.completeAsync(
        std::move(id), std::move(token), bound, proof(challenge));
    passed = verified->identity() == ids::IdentityId{"canonical-identity"}
        && !replay
        && fixture.coroutineProvider->nativeBeginCalls == 1
        && fixture.coroutineProvider->nativeCompleteCalls == 1
        && fixture.coroutineProvider->syncCalls == 0;
}

TEST(TrustedAuthenticationCoroutineTest, VerifiesNativeProofAndConsumesTransactionOnce)
{
    Fixture fixture;
    auto service = fixture.service();
    bool passed = false;
    asio::io_context io;
    auto future = asio::co_spawn(io, successfulFlow(service, fixture, passed), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(passed);
}

asio::awaitable<void> noFallback(
    auth::AuthenticationService& service, Fixture& fixture, bool& denied)
{
    auto result = co_await service.beginAsync(
        fixture.request(), binding("pinned"), fnd::CorrelationId{"no-fallback"});
    denied = !result && fixture.synchronousProvider->syncCalls == 0;
}

TEST(TrustedAuthenticationCoroutineTest, SynchronousProviderIsNeverDispatchedOnReactor)
{
    Fixture fixture{false};
    auto service = fixture.service();
    bool denied = false;
    asio::io_context io;
    auto future = asio::co_spawn(io, noFallback(service, fixture, denied), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(denied);
}

asio::awaitable<void> wrongPurpose(
    auth::AuthenticationService& service, Fixture& fixture, bool& denied)
{
    const auto bound = binding("pinned");
    auto started = co_await service.beginConnectionAsync(
        fixture.request(), bound, fnd::CorrelationId{"connection-only"},
        ids::IdentityId{"canonical-identity"});
    if (!started) co_return;
    auto completed = co_await service.completeAsync(
        idp::TransactionId{std::string{started->transactionId().value()}},
        started->continuationToken().clone(), bound,
        proof(std::string{started->challenge().id().value()}));
    denied = !completed && fixture.coroutineProvider->nativeCompleteCalls == 1;
}

TEST(TrustedAuthenticationCoroutineTest, ConnectionTransactionCannotBecomeLoginSession)
{
    Fixture fixture;
    auto service = fixture.service();
    bool denied = false;
    asio::io_context io;
    auto future = asio::co_spawn(io, wrongPurpose(service, fixture, denied), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(denied);
}

asio::awaitable<void> untrustedRejected(
    auth::AuthenticationService& service, Fixture& fixture, bool& denied)
{
    auto result = co_await service.beginAsync(
        fixture.request(), binding("pinned"), fnd::CorrelationId{"untrusted"});
    denied = !result && fixture.coroutineProvider->nativeBeginCalls == 0;
}

TEST(TrustedAuthenticationCoroutineTest, UntrustedProviderRejectedBeforeItsCodeRuns)
{
    Fixture fixture{true, false};
    auto service = fixture.service();
    bool denied = false;
    asio::io_context io;
    auto future = asio::co_spawn(io, untrustedRejected(service, fixture, denied),
                                 asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(denied);
}

asio::awaitable<void> forgedOutcome(
    auth::AuthenticationService& service, Fixture& fixture, bool& denied)
{
    auto bound = binding("pinned");
    auto started = co_await service.beginAsync(
        fixture.request(), bound, fnd::CorrelationId{"forged-outcome"});
    if (!started) co_return;
    auto completed = co_await service.completeAsync(
        idp::TransactionId{std::string{started->transactionId().value()}},
        started->continuationToken().clone(), bound,
        proof(std::string{started->challenge().id().value()}));
    denied = !completed && fixture.coroutineProvider->syncCalls == 0;
}

TEST(TrustedAuthenticationCoroutineTest, ForgedOutcomeProviderCannotBeAccepted)
{
    Fixture fixture;
    fixture.coroutineProvider->forgedProvider = true;
    auto service = fixture.service();
    bool denied = false;
    asio::io_context io;
    auto future = asio::co_spawn(io, forgedOutcome(service, fixture, denied),
                                 asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(denied);
}

asio::awaitable<void> nativeConnection(
    auth::AuthenticationService& service, Fixture& fixture, bool& accepted)
{
    const auto bound = binding("linked-client");
    auto started = co_await service.beginConnectionAsync(
        fixture.request(), bound, fnd::CorrelationId{"link-native"},
        ids::IdentityId{"canonical-identity"});
    if (!started) co_return;
    auto id = idp::TransactionId{std::string{started->transactionId().value()}};
    auto token = started->continuationToken().clone();
    auto challenge = std::string{started->challenge().id().value()};
    auto linked = co_await service.completeConnectionAsync(
        id, token.clone(), bound, proof(challenge));
    auto replay = co_await service.completeConnectionAsync(
        std::move(id), std::move(token), bound, proof(challenge));
    accepted = linked
        && linked->providerId() == idp::ProviderId{"async-test"}
        && linked->subject() == idp::ExternalSubject{"verified-subject"}
        && !replay && fixture.coroutineProvider->nativeCompleteCalls == 1
        && fixture.coroutineProvider->syncCalls == 0;
}

TEST(TrustedAuthenticationCoroutineTest, NativeConnectionBindsCanonicalIdentityAndPreventsReplay)
{
    Fixture fixture;
    auto service = fixture.service();
    bool accepted = false;
    asio::io_context io;
    auto future = asio::co_spawn(
        io, nativeConnection(service, fixture, accepted), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(accepted);
}

asio::awaitable<void> loginIsNotConnection(
    auth::AuthenticationService& service, Fixture& fixture, bool& denied)
{
    const auto bound = binding("login-only");
    auto started = co_await service.beginAsync(
        fixture.request(), bound, fnd::CorrelationId{"no-link-upgrade"});
    if (!started) co_return;
    auto connected = co_await service.completeConnectionAsync(
        idp::TransactionId{std::string{started->transactionId().value()}},
        started->continuationToken().clone(), bound,
        proof(std::string{started->challenge().id().value()}));
    denied = !connected && fixture.coroutineProvider->nativeCompleteCalls == 1;
}

TEST(TrustedAuthenticationCoroutineTest, LoginTransactionCannotBecomeConnection)
{
    Fixture fixture;
    auto service = fixture.service();
    bool denied = false;
    asio::io_context io;
    auto future = asio::co_spawn(
        io, loginIsNotConnection(service, fixture, denied), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(denied);
}

asio::awaitable<void> wrongChallengeBurnsTransaction(
    auth::AuthenticationService& service, Fixture& fixture, bool& denied)
{
    const auto bound = binding("challenge-bound");
    auto started = co_await service.beginAsync(
        fixture.request(), bound, fnd::CorrelationId{"invalid-challenge"});
    if (!started) co_return;
    auto token = started->continuationToken().clone();
    auto id = idp::TransactionId{std::string{started->transactionId().value()}};
    auto invalid = co_await service.completeAsync(
        id, token.clone(), bound, proof("wrong-challenge"));
    auto valid = co_await service.completeAsync(
        std::move(id), std::move(token), bound,
        proof(std::string{started->challenge().id().value()}));
    denied = !invalid && !valid
        && fixture.coroutineProvider->nativeCompleteCalls == 0;
}

TEST(TrustedAuthenticationCoroutineTest, IncorrectChallengeBurnsTransactionBeforeProviderIo)
{
    Fixture fixture;
    auto service = fixture.service();
    bool denied = false;
    asio::io_context io;
    auto future = asio::co_spawn(
        io, wrongChallengeBurnsTransaction(service, fixture, denied),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(denied);
}
} // namespace

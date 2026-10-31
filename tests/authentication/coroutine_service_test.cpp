#include <gtest/gtest.h>
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>

#include <chrono>
#include <memory>
#include <optional>
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

// Test-only implementation: the directory is memory-backed and guarded by
// its own short critical section. Never use this adapter with PostgreSQL.
class MemoryNativeCanonicalFinalizer final
    : public auth::CoroutineCanonicalIdentityFinalizer {
public:
    explicit MemoryNativeCanonicalFinalizer(
        ids::InMemoryExternalIdentityDirectory& directory)
        : m_directory(&directory) {}

    [[nodiscard]] asio::awaitable<fnd::Result<ids::IdentityId>>
    finishLoginAsync(const idp::AuthenticationOutcome& outcome,
                     fnd::Instant) override
    {
        ++calls;
        co_await asio::post(asio::use_awaitable);
        ids::ExternalIdentityRef external{outcome.provider(), outcome.subject()};
        auto owner = m_directory->ownerOf(external);
        if (!owner) co_return fnd::fail(owner.error());
        if (!owner->has_value())
            co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        auto updated = m_directory->updatePresentation(external);
        if (!updated) co_return fnd::fail(updated.error());
        co_return owner->value();
    }

    int calls{};
private:
    ids::InMemoryExternalIdentityDirectory* m_directory;
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
            providers, transactions, identities, clock, std::move(policy),
            kLifetime, nullptr, {}, nullptr, &nativeCanonical};
    }

    [[nodiscard]] idp::AuthenticationRequest request()
    {
        return idp::AuthenticationRequest{idp::ProviderId{"async-test"}, idp::ClientContext{}};
    }

    idp::ProviderRegistry providers;
    idp::InMemoryAuthenticationTransactionStore transactions;
    ids::InMemoryExternalIdentityDirectory identities;
    MemoryNativeCanonicalFinalizer nativeCanonical{identities};
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

// Convert move-only non-default-constructible domain results into
// awaitable<void> completion flags so Boost.Asio co_spawn never needs to
// default-construct std::expected<AuthenticationStart/VerifiedAuthentication>.
asio::awaitable<void> startRacingTransaction(
    auth::AuthenticationService& service, idp::AuthenticationRequest request,
    idp::BindingDigest bound, fnd::CorrelationId correlation,
    std::optional<fnd::Result<auth::AuthenticationStart>>& destination)
{
    destination.emplace(co_await service.beginAsync(
        std::move(request), bound, std::move(correlation)));
}

asio::awaitable<void> completeRacingTransaction(
    auth::AuthenticationService& service, idp::TransactionId id,
    fnd::SecretString continuation, idp::BindingDigest bound,
    std::string challenge, bool& accepted)
{
    auto completed = co_await service.completeAsync(
        std::move(id), std::move(continuation), bound, proof(std::move(challenge)));
    accepted = completed.has_value();
}

TEST(TrustedAuthenticationCoroutineTest, ConcurrentCompletionsVerifyOnlyOnce)
{
    Fixture fixture;
    auto service = fixture.service();
    const auto bound = binding("two-racing-handlers");
    asio::io_context io;
    std::optional<fnd::Result<auth::AuthenticationStart>> startResult;
    auto startedFuture = asio::co_spawn(
        io, startRacingTransaction(service, fixture.request(), bound,
             fnd::CorrelationId{"race-test"}, startResult),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(startedFuture.get());
    ASSERT_TRUE(startResult.has_value());
    auto started = std::move(*startResult);
    ASSERT_TRUE(started);

    const auto id = idp::TransactionId{
        std::string{started->transactionId().value()}};
    const auto challenge = std::string{started->challenge().id().value()};

    bool firstAccepted = false, secondAccepted = false;
    io.restart();
    auto first = asio::co_spawn(io,
        completeRacingTransaction(
            service, id, started->continuationToken().clone(), bound,
            challenge, firstAccepted), asio::use_future);
    auto second = asio::co_spawn(io,
        completeRacingTransaction(
            service, id, started->continuationToken().clone(), bound,
            challenge, secondAccepted), asio::use_future);
    io.run();
    ASSERT_NO_THROW(first.get());
    ASSERT_NO_THROW(second.get());

    EXPECT_NE(firstAccepted, secondAccepted);
    EXPECT_EQ(fixture.coroutineProvider->nativeCompleteCalls, 1);
    EXPECT_EQ(fixture.coroutineProvider->syncCalls, 0);
}

// A forged callback is consumed before any provider coroutine suspends,
// so a correct callback cannot redeem the same continuation afterward.
TEST(TrustedAuthenticationCoroutineTest, ConcurrentForgedCallbackNeverDuplicatesVerification)
{
    Fixture fixture;
    auto service = fixture.service();
    const auto bound = binding("forged-racing-handler");
    asio::io_context io;
    std::optional<fnd::Result<auth::AuthenticationStart>> startResult;
    auto startedFuture = asio::co_spawn(
        io, startRacingTransaction(service, fixture.request(), bound,
             fnd::CorrelationId{"forged-race"}, startResult),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(startedFuture.get());
    ASSERT_TRUE(startResult.has_value());
    auto started = std::move(*startResult);
    ASSERT_TRUE(started);

    const auto id = idp::TransactionId{
        std::string{started->transactionId().value()}};
    const auto challenge = std::string{started->challenge().id().value()};
    bool forgedAccepted = false, validAccepted = false;
    io.restart();
    auto forged = asio::co_spawn(io,
        completeRacingTransaction(
            service, id, started->continuationToken().clone(), bound,
            "attacker-replaced-challenge", forgedAccepted), asio::use_future);
    auto valid = asio::co_spawn(io,
        completeRacingTransaction(
            service, id, started->continuationToken().clone(), bound,
            challenge, validAccepted), asio::use_future);
    io.run();
    ASSERT_NO_THROW(forged.get());
    ASSERT_NO_THROW(valid.get());

    EXPECT_FALSE(forgedAccepted);
    EXPECT_LE(fixture.coroutineProvider->nativeCompleteCalls, 1);
    EXPECT_EQ(fixture.coroutineProvider->nativeCompleteCalls,
              validAccepted ? 1 : 0);
    EXPECT_EQ(fixture.coroutineProvider->syncCalls, 0);
}

class LegacyOnlyTransactionStore final : public idp::AuthenticationTransactionStore {
public:
    [[nodiscard]] fnd::Status begin(idp::AuthenticationTransaction) override
    { ++blockingCalls; return fnd::ok(); }

    [[nodiscard]] fnd::Result<idp::AuthenticationTransaction>
    consume(const idp::TransactionId&, const fnd::SecretString&,
            const idp::BindingDigest&, fnd::Instant) override
    {
        ++blockingCalls;
        return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
    }

    [[nodiscard]] fnd::Result<std::optional<idp::AuthenticationTransaction>>
    find(const idp::TransactionId&) const override
    { return std::optional<idp::AuthenticationTransaction>{}; }

    [[nodiscard]] std::size_t purgeExpired(fnd::Instant) override { return 0U; }
    [[nodiscard]] std::size_t size() const override { return 0U; }
    int blockingCalls{};
};

asio::awaitable<void> missingNativeStore(
    auth::AuthenticationService& service, bool& rejected)
{
    auto started = co_await service.beginAsync(
        idp::AuthenticationRequest{idp::ProviderId{"async-test"}, idp::ClientContext{}},
        binding("must-not-fall-back"), fnd::CorrelationId{"legacy-store-rejection"});
    rejected = !started && started.error().code() == fnd::ErrorCode::Unavailable;
}

TEST(TrustedAuthenticationCoroutineTest, BlockingTransactionStoreCannotRunOnReactor)
{
    idp::ProviderRegistry providers;
    auto owned = std::make_unique<NativeProofProvider>();
    auto* native = owned.get();
    ASSERT_TRUE(providers.registerProvider(std::move(owned)));
    LegacyOnlyTransactionStore legacy;
    ids::InMemoryExternalIdentityDirectory identities;
    fnd::ManualClockSource clock{kNow};
    auth::ProviderTrustPolicy policy;
    ASSERT_TRUE(policy.trust(idp::ProviderId{"async-test"}, idp::AssuranceLevel::Ial2));
    auth::AuthenticationService service{
        providers, legacy, identities, clock, std::move(policy), kLifetime};
    bool rejected = false;
    asio::io_context io;
    auto future = asio::co_spawn(
        io, missingNativeStore(service, rejected), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(rejected);
    EXPECT_EQ(legacy.blockingCalls, 0);
    EXPECT_EQ(native->nativeBeginCalls, 0);
    EXPECT_EQ(native->syncCalls, 0);
}
TEST(TrustedAuthenticationCoroutineTest, MissingNativeCanonicalRefusesBeforeProofRedemption)
{
    Fixture fixture;
    // A trusted service creates a legitimate, unconsumed transaction.
    // An unconfigured service must reject completion without burning it.
    auto configured = fixture.service();
    auth::ProviderTrustPolicy trust;
    ASSERT_TRUE(trust.trust(
        idp::ProviderId{"async-test"}, idp::AssuranceLevel::Ial2));
    auth::AuthenticationService disabled{
        fixture.providers, fixture.transactions, fixture.identities,
        fixture.clock, std::move(trust), kLifetime};
    EXPECT_FALSE(disabled.nativeCanonicalCompletionEnabled());
    EXPECT_TRUE(configured.nativeCanonicalCompletionEnabled());
    int deniedStart = 0, deniedCompletion = 0, canStillComplete = 0;
    asio::io_context io;
    auto check = [&]() -> asio::awaitable<void> {
        auto start = co_await disabled.beginAsync(
            fixture.request(), binding("pinned"),
            fnd::CorrelationId{"canonical-guard"});
        deniedStart = !start
            && start.error().code() == fnd::ErrorCode::Unavailable;
        auto validStart = co_await configured.beginAsync(
            fixture.request(), binding("pinned"),
            fnd::CorrelationId{"proof-must-survive"});
        if (!validStart) co_return;
        const auto challenge = std::string{validStart->challenge().id().value()};
        const auto transactionId = std::string{validStart->transactionId().value()};
        auto complete = co_await disabled.completeAsync(
            idp::TransactionId{transactionId},
            validStart->continuationToken().clone(), binding("pinned"),
            proof(challenge));
        deniedCompletion = !complete
            && complete.error().code() == fnd::ErrorCode::Unavailable;
        auto validCompletion = co_await configured.completeAsync(
            idp::TransactionId{transactionId},
            validStart->continuationToken().clone(), binding("pinned"),
            proof(challenge));
        canStillComplete = validCompletion.has_value();
    };
    // Coroutine lambda is only used as a test harness, with its closure
    // alive for the entire co_spawn execution.
    auto operation = check();
    auto future = asio::co_spawn(io, std::move(operation), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(deniedStart);
    EXPECT_TRUE(deniedCompletion);
    EXPECT_TRUE(canStillComplete);
    EXPECT_EQ(fixture.transactions.size(), 1U);
    EXPECT_EQ(fixture.coroutineProvider->nativeBeginCalls, 1);
    EXPECT_EQ(fixture.coroutineProvider->nativeCompleteCalls, 1);
    EXPECT_EQ(fixture.nativeCanonical.calls, 1);
}

} // namespace

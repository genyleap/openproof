#include <gtest/gtest.h>
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include "../../src/authentication/http/coroutine_federated_start_http.hpp"
#include "../../src/authentication/http/coroutine_federated_callback_http.hpp"

import openproof.authentication;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.security;
import openproof.session;

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
        idp::AuthenticationChallenge challenge{
            idp::ChallengeId{"server-challenge"}, kNow + kLifetime};
        challenge.setParameter("authorization_url", authorizationUrl);
        co_return challenge;
    }

    [[nodiscard]] asio::awaitable<fnd::Result<idp::AuthenticationOutcome>>
    completeAuthenticationAsync(idp::AuthenticationResponse response) override
    {
        ++nativeCompleteCalls;
        co_await asio::post(asio::use_awaitable);
        const auto& fields = response.parameters();
        const bool proof = fields.contains("proof");
        const bool oauth2 = fields.contains("code") && fields.contains("state")
            && fields.at("code").expose() == "valid-code"
            && fields.at("state").expose() == "matching-state";
        if (!proof && !oauth2) {
            co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        }
        co_return idp::AuthenticationOutcome::create(
            idp::ProviderId{forgedProvider ? "forged" : "async-test"},
            idp::ExternalSubject{externalSubject}, idp::VerifiedClaims{},
            idp::AssuranceLevel::Ial2,
            idp::AuthenticationStrength{idp::AuthenticationFactor::Possession, false},
            idp::ProviderEvidence{}, kNow);
    }

    // Allow a single native provider instance to verify different wallet-like
    // subjects in the same process. Existing links must stay usable when the
    // operator disallows first-time identity creation.
    std::string authorizationUrl{"https://example.test/authorize"};
    std::string externalSubject{"verified-subject"};
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

    [[nodiscard]] bool nativeConnectionsEnabled() const noexcept override {
        return true;
    }

    [[nodiscard]] asio::awaitable<fnd::Status>
    authorizeConnectionTargetAsync(ids::IdentityId target) override
    {
        co_await asio::post(asio::use_awaitable);
        if (target.empty()) co_return fnd::fail(fnd::ErrorCode::InvalidArgument);
        // No lifecycle repository exists in this test fixture. Production
        // implementations must validate the active tenant-scoped aggregate.
        co_return fnd::ok();
    }

    [[nodiscard]] asio::awaitable<fnd::Result<ids::ExternalIdentityRef>>
    finishConnectionAsync(const idp::AuthenticationOutcome& outcome,
                          ids::IdentityId target, fnd::Instant now) override
    {
        co_await asio::post(asio::use_awaitable);
        ids::ExternalIdentityRef external{outcome.provider(), outcome.subject()};
        auto current = m_directory->ownerOf(external);
        if (!current) co_return fnd::fail(current.error());
        if (current->has_value() && current->value() != target)
            co_return fnd::fail(fnd::ErrorCode::Conflict);
        if (!current->has_value()) {
            auto link = ids::IdentityLink::request(
                target, external, now, std::chrono::minutes{5});
            if (!link) co_return fnd::fail(link.error());
            auto required = link->requireVerification(now);
            if (!required) co_return fnd::fail(required.error());
            auto verified = link->markVerified(now);
            if (!verified) co_return fnd::fail(verified.error());
            auto completed = link->complete(now);
            if (!completed) co_return fnd::fail(completed.error());
            auto attached = m_directory->attach(link.value());
            if (!attached) co_return fnd::fail(attached.error());
        }
        auto updated = m_directory->updatePresentation(external);
        if (!updated) co_return fnd::fail(updated.error());
        co_return external;
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

// Regression for the RC7 wallet onboarding switch. Native verification must
// authenticate an explicitly linked subject and reject a verified but
// unlinked subject without creating any canonical identity. No sync provider
// method may be called on the coroutine reactor.
asio::awaitable<void> optOutKeepsLinkedAndRejectsUnknown(
    auth::AuthenticationService& service, Fixture& fixture,
    bool& linkedAllowed, bool& unknownRefused)
{
    const auto existingBinding = binding("opt-out-linked-wallet");
    auto existing = co_await service.beginAsync(
        fixture.request(), existingBinding,
        fnd::CorrelationId{"opt-out-existing-native"});
    if (!existing) co_return;
    auto verified = co_await service.completeAsync(
        idp::TransactionId{std::string{existing->transactionId().value()}},
        existing->continuationToken().clone(), existingBinding,
        proof(std::string{existing->challenge().id().value()}));
    linkedAllowed = verified
        && verified->identity() == ids::IdentityId{"canonical-identity"};

    fixture.coroutineProvider->externalSubject = "unlinked-native-wallet";
    const auto freshBinding = binding("opt-out-unknown-wallet");
    auto newAttempt = co_await service.beginAsync(
        fixture.request(), freshBinding,
        fnd::CorrelationId{"opt-out-new-native"});
    if (!newAttempt) co_return;
    auto refused = co_await service.completeAsync(
        idp::TransactionId{std::string{newAttempt->transactionId().value()}},
        newAttempt->continuationToken().clone(), freshBinding,
        proof(std::string{newAttempt->challenge().id().value()}));
    auto owner = fixture.identities.ownerOf(ids::ExternalIdentityRef{
        idp::ProviderId{"async-test"},
        idp::ExternalSubject{"unlinked-native-wallet"}});
    unknownRefused = !refused
        && refused.error().code() == fnd::ErrorCode::AuthenticationFailed
        && owner && !owner->has_value()
        && fixture.coroutineProvider->nativeBeginCalls == 2
        && fixture.coroutineProvider->nativeCompleteCalls == 2
        && fixture.coroutineProvider->syncCalls == 0
        && fixture.nativeCanonical.calls == 2;
}

TEST(TrustedAuthenticationCoroutineTest,
     WalletSelfProvisioningOptOutRetainsLinkedNativeLoginAndDeniesUnlinked)
{
    Fixture fixture;
    const auto provider = idp::ProviderId{"async-test"};
    // Default to the operator's explicit no-self-provision policy; the
    // provider is trusted to verify proof, NOT to register unknown identities.
    ASSERT_FALSE(fixture.policy.maySelfProvision(provider));
    auto service = fixture.service();
    bool linkedAllowed = false;
    bool unknownRefused = false;
    asio::io_context io;
    auto future = asio::co_spawn(
        io, optOutKeepsLinkedAndRejectsUnknown(
            service, fixture, linkedAllowed, unknownRefused), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(linkedAllowed);
    EXPECT_TRUE(unknownRefused);
}

// Disabling automatic wallet identity creation must NOT disable the explicit
// owner-authorized link ceremony. After a verified new wallet has been bound to
// an existing canonical identity, a normal native login can reuse that link.
asio::awaitable<void> optOutAllowsExplicitNativeWalletLink(
    auth::AuthenticationService& service, Fixture& fixture, bool& accepted)
{
    const idp::ExternalSubject unknown{"new-linkable-wallet"};
    const ids::ExternalIdentityRef external{idp::ProviderId{"async-test"}, unknown};
    auto before = fixture.identities.ownerOf(external);
    if (!before || before->has_value()) co_return;

    const auto connectionBinding = binding("opt-out-explicit-link");
    auto connection = co_await service.beginConnectionAsync(
        fixture.request(), connectionBinding,
        fnd::CorrelationId{"opt-out-link-native"},
        ids::IdentityId{"canonical-identity"});
    if (!connection) co_return;
    auto linked = co_await service.completeConnectionAsync(
        idp::TransactionId{std::string{connection->transactionId().value()}},
        connection->continuationToken().clone(), connectionBinding,
        proof(std::string{connection->challenge().id().value()}));
    if (!linked || linked->subject() != unknown) co_return;
    auto owner = fixture.identities.ownerOf(external);
    if (!owner || !owner->has_value()
        || owner->value() != ids::IdentityId{"canonical-identity"}) {
        co_return;
    }

    const auto loginBinding = binding("opt-out-login-after-link");
    auto started = co_await service.beginAsync(
        fixture.request(), loginBinding,
        fnd::CorrelationId{"opt-out-after-link"});
    if (!started) co_return;
    auto loggedIn = co_await service.completeAsync(
        idp::TransactionId{std::string{started->transactionId().value()}},
        started->continuationToken().clone(), loginBinding,
        proof(std::string{started->challenge().id().value()}));
    accepted = loggedIn
        && loggedIn->identity() == ids::IdentityId{"canonical-identity"}
        && fixture.coroutineProvider->nativeBeginCalls == 2
        && fixture.coroutineProvider->nativeCompleteCalls == 2
        && fixture.coroutineProvider->syncCalls == 0;
}

TEST(TrustedAuthenticationCoroutineTest,
     WalletSelfProvisioningOptOutStillAllowsVerifiedExplicitNativeLink)
{
    Fixture fixture;
    ASSERT_FALSE(fixture.policy.maySelfProvision(
        idp::ProviderId{"async-test"}));
    fixture.coroutineProvider->externalSubject = "new-linkable-wallet";
    auto service = fixture.service();
    bool accepted = false;
    asio::io_context io;
    auto future = asio::co_spawn(
        io, optOutAllowsExplicitNativeWalletLink(service, fixture, accepted),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(accepted);
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
TEST(TrustedAuthenticationCoroutineTest, MissingNativeConnectionFinalizerPreservesProof)
{
    Fixture fixture;
    auto configured = fixture.service();
    auth::ProviderTrustPolicy trust;
    ASSERT_TRUE(trust.trust(
        idp::ProviderId{"async-test"}, idp::AssuranceLevel::Ial2));
    auth::AuthenticationService disabled{
        fixture.providers, fixture.transactions, fixture.identities,
        fixture.clock, std::move(trust), kLifetime};
    EXPECT_TRUE(configured.nativeConnectionCompletionEnabled());
    EXPECT_FALSE(disabled.nativeConnectionCompletionEnabled());
    bool startDenied = false, completionDenied = false, stillRedeemable = false;
    asio::io_context io;
    auto check = [&]() -> asio::awaitable<void> {
        auto rejected = co_await disabled.beginConnectionAsync(
            fixture.request(), binding("pinned"),
            fnd::CorrelationId{"native-connection-disabled"},
            ids::IdentityId{"canonical-identity"});
        startDenied = !rejected
            && rejected.error().code() == fnd::ErrorCode::Unavailable;
        auto started = co_await configured.beginConnectionAsync(
            fixture.request(), binding("pinned"),
            fnd::CorrelationId{"native-connection-enabled"},
            ids::IdentityId{"canonical-identity"});
        if (!started) co_return;
        const auto id = std::string{started->transactionId().value()};
        const auto challenge = std::string{started->challenge().id().value()};
        auto refused = co_await disabled.completeConnectionAsync(
            idp::TransactionId{id}, started->continuationToken().clone(),
            binding("pinned"), proof(challenge));
        completionDenied = !refused
            && refused.error().code() == fnd::ErrorCode::Unavailable;
        auto completed = co_await configured.completeConnectionAsync(
            idp::TransactionId{id}, started->continuationToken().clone(),
            binding("pinned"), proof(challenge));
        stillRedeemable = completed
            && completed->subject() == idp::ExternalSubject{"verified-subject"};
    };
    auto operation = check();
    auto future = asio::co_spawn(io, std::move(operation), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(startDenied);
    EXPECT_TRUE(completionDenied);
    EXPECT_TRUE(stillRedeemable);
    EXPECT_EQ(fixture.coroutineProvider->nativeBeginCalls, 1);
    EXPECT_EQ(fixture.coroutineProvider->nativeCompleteCalls, 1);
    EXPECT_EQ(fixture.coroutineProvider->syncCalls, 0);
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

class FederatedNoFallback final : public openproof::gateway::http::CoroutineHttpHandler {
public:
    [[nodiscard]] bool nativeEnabledFor(
        const openproof::gateway::HttpRequest&) const noexcept override { return false; }
    [[nodiscard]] openproof::gateway::HttpResponse
    handle(openproof::gateway::HttpRequest) override
    {
        ++syncCalls;
        return openproof::gateway::HttpResponse{500, {}, {}};
    }
    [[nodiscard]] asio::awaitable<openproof::gateway::HttpResponse>
    handleAsync(openproof::gateway::HttpRequest) override
    {
        ++asyncCalls;
        co_return openproof::gateway::HttpResponse{500, {}, {}};
    }
    int syncCalls{};
    int asyncCalls{};
};

[[nodiscard]] openproof::gateway::HttpRequest makeFederatedStart(std::string target)
{
    auto request = openproof::gateway::HttpRequest::create(
        openproof::gateway::HttpMethod::Get, std::move(target), {}, {},
        "127.0.0.1", fnd::CorrelationId{"native-federated-start-test"});
    EXPECT_TRUE(request);
    return std::move(request).value();
}

// Boost.Asio's use_future co_spawn completion requires a default-constructible
// T. HttpResponse deliberately has no default constructor, so deliver it via
// an owned optional and an awaitable<void> instead.
asio::awaitable<void> collectFederatedResponse(
    auth::http::CoroutineFederatedStartAdapter& adapter,
    openproof::gateway::HttpRequest request,
    std::optional<openproof::gateway::HttpResponse>& result)
{
    result.emplace(co_await adapter.handleAsync(std::move(request)));
    co_return;
}

[[nodiscard]] openproof::gateway::HttpResponse invokeFederated(
    auth::http::CoroutineFederatedStartAdapter& adapter,
    openproof::gateway::HttpRequest request)
{
    asio::io_context io;
    std::optional<openproof::gateway::HttpResponse> result;
    auto completion = asio::co_spawn(
        io, collectFederatedResponse(adapter, std::move(request), result),
        asio::use_future);
    io.run();
    completion.get();
    if (!result) throw std::runtime_error{"missing federated HTTP response"};
    return std::move(*result);
}

TEST(TrustedAuthenticationCoroutineTest, FederatedStartUsesNativeProviderNoSyncFallback)
{
    Fixture fixture;
    auto service = fixture.service();
    auto limiter = openproof::gateway::TokenBucketRateLimiter::create(
        fixture.clock, 100.0, 100.0, 100U);
    ASSERT_TRUE(limiter);
    FederatedNoFallback fallback;
    auth::http::CoroutineFederatedStartAdapter adapter{
        service, fixture.providers, limiter.value(), fallback};
    auto request = makeFederatedStart(
        "/auth/federated/start?provider=async-test&return_to=%2Faccount");
    EXPECT_TRUE(adapter.nativeEnabledFor(request));
    EXPECT_FALSE(adapter.nativeEnabled());
    auto response = invokeFederated(adapter, std::move(request));
    EXPECT_EQ(response.status(), 302);
    EXPECT_EQ(response.headers().at("location"), "https://example.test/authorize");
    EXPECT_EQ(response.headers().at("cache-control"), "no-store");
    ASSERT_TRUE(response.headers().contains("set-cookie"));
    EXPECT_EQ(response.repeatedHeaders().size(), 4U);
    EXPECT_EQ(fixture.coroutineProvider->nativeBeginCalls, 1);
    EXPECT_EQ(fixture.coroutineProvider->syncCalls, 0);
    EXPECT_EQ(fallback.syncCalls, 0);
    EXPECT_EQ(fallback.asyncCalls, 0);
}

TEST(TrustedAuthenticationCoroutineTest, FederatedStartRejectsInvalidQueryAndLegacyProvider)
{
    Fixture fixture{false};
    auto service = fixture.service();
    auto limiter = openproof::gateway::TokenBucketRateLimiter::create(
        fixture.clock, 100.0, 100.0, 100U);
    ASSERT_TRUE(limiter);
    FederatedNoFallback fallback;
    auth::http::CoroutineFederatedStartAdapter adapter{
        service, fixture.providers, limiter.value(), fallback};
    EXPECT_EQ(adapter.handle(makeFederatedStart(
        "/auth/federated/start?provider=async-test")).status(), 503);
    for (const auto bad : {
            "/auth/federated/start?provider=async-test&provider=async-test",
            "/auth/federated/start?provider=async-test&return_to=%2F%2Fevil.test",
            "/auth/federated/start?provider=async-test&return_to=%ZZ",
            "/auth/federated/start?provider=async-test"}) {
        auto response = invokeFederated(adapter, makeFederatedStart(bad));
        EXPECT_GE(response.status(), 400);
    }
    EXPECT_EQ(fixture.synchronousProvider->syncCalls, 0);
    EXPECT_EQ(fallback.syncCalls, 0);
    EXPECT_EQ(fallback.asyncCalls, 0);
}

// The native service must reject untrusted or malformed provider redirects
// before writing any authentication transaction (including in PostgreSQL).
// A mere "https://" prefix is insufficient to protect the Location header.
TEST(TrustedAuthenticationCoroutineTest, FederatedStartUnsafeRedirectDoesNotPersistTransaction)
{
    Fixture fixture;
    auto service = fixture.service();
    auto limiter = openproof::gateway::TokenBucketRateLimiter::create(
        fixture.clock, 100.0, 100.0, 100U);
    ASSERT_TRUE(limiter);
    FederatedNoFallback fallback;
    auth::http::CoroutineFederatedStartAdapter adapter{
        service, fixture.providers, limiter.value(), fallback};

    for (const std::string_view invalid : {
            std::string_view{"https://example.test/authorize\\r\\nset-cookie: compromised=1"},
            std::string_view{"https://trusted.test@attacker.test/authorize"},
            std::string_view{"https://example.test/authorize#fragment"},
            std::string_view{"https://example.test/authorize with space"},
            std::string_view{"https://example.test/authorize\\backslash"},
            std::string_view{"https:///missing-authority"},
            std::string_view{"https://example.test%0d.invalid/authorize"},
            std::string_view{"http://example.test/authorize"},
            std::string_view{""}}) {
        fixture.coroutineProvider->authorizationUrl = invalid;
        auto response = invokeFederated(adapter, makeFederatedStart(
            "/auth/federated/start?provider=async-test&return_to=%2Faccount"));
        EXPECT_GE(response.status(), 400) << invalid;
        EXPECT_FALSE(response.headers().contains("location"));
        EXPECT_FALSE(response.headers().contains("authorization"));
        EXPECT_EQ(fixture.transactions.size(), 0U)
            << "Bad provider response must not persist a one-time transaction";
    }
    EXPECT_EQ(fixture.coroutineProvider->syncCalls, 0);
    EXPECT_EQ(fallback.syncCalls, 0);
    EXPECT_EQ(fallback.asyncCalls, 0);

    fixture.coroutineProvider->authorizationUrl =
        "https://example.test/authorize?state=valid%2B123";
    auto good = invokeFederated(adapter, makeFederatedStart(
        "/auth/federated/start?provider=async-test"));
    EXPECT_EQ(good.status(), 302);
    EXPECT_EQ(good.headers().at("location"),
              "https://example.test/authorize?state=valid%2B123");
    EXPECT_EQ(fixture.transactions.size(), 1U);
}

TEST(TrustedAuthenticationCoroutineTest, FederatedStartRealHttpLoopbackPreservesRedirectAndBoundState)
{
    namespace beast = boost::beast;
    namespace wire = beast::http;
    Fixture fixture;
    auto service = fixture.service();
    auto limiter = openproof::gateway::TokenBucketRateLimiter::create(
        fixture.clock, 100.0, 100.0, 100U);
    ASSERT_TRUE(limiter);
    FederatedNoFallback fallback;
    auth::http::CoroutineFederatedStartAdapter adapter{
        service, fixture.providers, limiter.value(), fallback};
    auto config = openproof::gateway::http::ServerConfig::create(
        "127.0.0.1", 0U, 8192U, 8192U, std::chrono::seconds{2},
        std::chrono::seconds{2}, 32U, 2U);
    ASSERT_TRUE(config);
    openproof::gateway::http::BeastHttpServer server{
        adapter, std::move(config).value()};
    ASSERT_TRUE(server.start());

    asio::io_context io;
    beast::tcp_stream stream{io};
    stream.expires_after(std::chrono::seconds{3});
    asio::ip::tcp::resolver resolver{io};
    stream.connect(resolver.resolve(
        "127.0.0.1", std::to_string(server.boundPort())));
    wire::request<wire::string_body> request{
        wire::verb::get,
        "/auth/federated/start?provider=async-test&return_to=%2Faccount", 11};
    request.set(wire::field::host, "localhost");
    wire::write(stream, request);
    beast::flat_buffer buffer;
    wire::response<wire::string_body> response;
    wire::read(stream, buffer, response);

    EXPECT_EQ(response.result(), wire::status::found);
    EXPECT_EQ(response.at(wire::field::location), "https://example.test/authorize");
    EXPECT_EQ(response.at(wire::field::cache_control), "no-store");
    int cookieCount = 0;
    for (const auto& field : response) {
        if (field.name() == wire::field::set_cookie) ++cookieCount;
    }
    EXPECT_EQ(cookieCount, 5);
    EXPECT_EQ(fixture.coroutineProvider->nativeBeginCalls, 1);
    EXPECT_EQ(fixture.coroutineProvider->syncCalls, 0);
    EXPECT_EQ(fallback.syncCalls, 0);
    EXPECT_EQ(fallback.asyncCalls, 0);
    server.stop();
}

// Test-only native session issuer: verifies that callback really suspends on
// a native issuer, never touching the synchronous SessionService.
class FederatedNativeSessionIssuer final
    : public openproof::session::CoroutineReplacingSessionIssuer {
public:
    [[nodiscard]] asio::awaitable<fnd::Result<openproof::session::CoroutineIssuedSession>>
    issueAsync(const auth::VerifiedAuthentication& verification,
               idp::ClientContext client) override
    {
        co_return co_await issueReplacingAsync(
            verification, std::move(client), std::nullopt);
    }

    [[nodiscard]] asio::awaitable<fnd::Result<openproof::session::CoroutineIssuedSession>>
    issueReplacingAsync(
        const auth::VerifiedAuthentication& verification,
        idp::ClientContext,
        std::optional<fnd::SecretString> previousToken) override
    {
        ++calls;
        sawPrevious = previousToken && previousToken->expose() == "prior-session";
        co_await asio::post(asio::use_awaitable);
        if (verification.identity() != ids::IdentityId{"canonical-identity"})
            co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        co_return openproof::session::CoroutineIssuedSession{
            openproof::session::SessionId{"test-session-1"},
            fnd::SecretString{"new-session-1"}};
    }

    int calls{};
    bool sawPrevious{};
};

[[nodiscard]] std::string federatedCookies(
    const openproof::gateway::HttpResponse& response)
{
    std::string result;
    const auto append = [&result](std::string_view field) {
        const auto semi = field.find(';');
        if (!result.empty()) result.append("; ");
        result.append(field.substr(0U, semi));
    };
    const auto first = response.headers().find("set-cookie");
    if (first != response.headers().end()) append(first->second);
    for (const auto& [name, value] : response.repeatedHeaders())
        if (name == "set-cookie") append(value);
    return result;
}

[[nodiscard]] openproof::gateway::HttpRequest makeFederatedCallback(
    std::string target, std::string cookieHeader)
{
    auto request = openproof::gateway::HttpRequest::create(
        openproof::gateway::HttpMethod::Get, std::move(target),
        {{"cookie", std::move(cookieHeader)}}, {},
        "127.0.0.1", fnd::CorrelationId{"native-federated-callback-test"});
    EXPECT_TRUE(request);
    return std::move(request).value();
}

asio::awaitable<void> collectCallbackResponse(
    auth::http::CoroutineFederatedCallbackAdapter& adapter,
    openproof::gateway::HttpRequest request,
    std::optional<openproof::gateway::HttpResponse>& result)
{
    result.emplace(co_await adapter.handleAsync(std::move(request)));
    co_return;
}

[[nodiscard]] openproof::gateway::HttpResponse invokeCallback(
    auth::http::CoroutineFederatedCallbackAdapter& adapter,
    openproof::gateway::HttpRequest request)
{
    asio::io_context io;
    std::optional<openproof::gateway::HttpResponse> result;
    auto completed = asio::co_spawn(io,
        collectCallbackResponse(adapter, std::move(request), result),
        asio::use_future);
    io.run();
    completed.get();
    if (!result) throw std::runtime_error{"missing native callback HTTP response"};
    return std::move(*result);
}

TEST(TrustedAuthenticationCoroutineTest, FederatedCallbackConsumesProofAndIssuesNativeSessionOnce)
{
    Fixture fixture;
    auto service = fixture.service();
    auto limiter = openproof::gateway::TokenBucketRateLimiter::create(
        fixture.clock, 100.0, 100.0, 100U);
    ASSERT_TRUE(limiter);
    FederatedNoFallback fallback;
    auth::http::CoroutineFederatedStartAdapter start{
        service, fixture.providers, limiter.value(), fallback};
    FederatedNativeSessionIssuer issuer;
    auth::http::CoroutineFederatedCallbackAdapter callback{
        service, issuer, fallback};

    auto started = invokeFederated(start, makeFederatedStart(
        "/auth/federated/start?provider=async-test&return_to=%2Faccount"));
    ASSERT_EQ(started.status(), 302);
    auto cookies = federatedCookies(started);
    ASSERT_FALSE(cookies.empty());
    auto first = makeFederatedCallback(
        "/auth/federated/callback?code=valid-code&state=matching-state",
        cookies + "; __Host-openproof-session=prior-session");
    EXPECT_TRUE(callback.nativeEnabledFor(first));
    EXPECT_FALSE(callback.nativeEnabled());
    auto response = invokeCallback(callback, std::move(first));
    EXPECT_EQ(response.status(), 302);
    EXPECT_EQ(response.headers().at("location"), "/account");
    const auto newCookie = federatedCookies(response);
    EXPECT_NE(newCookie.find("__Host-openproof-session=new-session-1"),
              std::string::npos);
    EXPECT_EQ(issuer.calls, 1);
    EXPECT_TRUE(issuer.sawPrevious);
    EXPECT_EQ(fixture.coroutineProvider->nativeCompleteCalls, 1);
    EXPECT_EQ(fixture.coroutineProvider->syncCalls, 0);
    EXPECT_EQ(fallback.syncCalls, 0);
    EXPECT_EQ(fallback.asyncCalls, 0);
    // The in-memory store retains a Consumed tombstone for replay detection.
    EXPECT_EQ(fixture.transactions.size(), 1U);

    // A one-time transaction cannot mint a second session from replay.
    auto replay = invokeCallback(callback, makeFederatedCallback(
        "/auth/federated/callback?code=valid-code&state=matching-state", cookies));
    EXPECT_GE(replay.status(), 400);
    EXPECT_EQ(issuer.calls, 1);
    EXPECT_EQ(fixture.coroutineProvider->nativeCompleteCalls, 1);
}

TEST(TrustedAuthenticationCoroutineTest, FederatedCallbackRejectsMalformedAndMissingState)
{
    Fixture fixture;
    auto service = fixture.service();
    FederatedNoFallback fallback;
    FederatedNativeSessionIssuer issuer;
    auth::http::CoroutineFederatedCallbackAdapter callback{
        service, issuer, fallback};
    EXPECT_EQ(callback.handle(makeFederatedCallback(
        "/auth/federated/callback?code=valid-code&state=matching-state",
        "cookie-name=cookie-value")).status(), 503);
    for (const auto target : {
        "/auth/federated/callback?code=valid-code&state=matching-state",
        "/auth/federated/callback?code=valid-code&code=again&state=matching-state",
        "/auth/federated/callback?code=valid-code&state=matching-state&oauth_token=ambiguous",
        "/auth/federated/callback?code=valid-code&state=matching-state&SAMLResponse=ambiguous",
        "/auth/federated/callback?code=valid-code&state=%ZZ",
        "/auth/federated/callback?code=valid-code"}) {
        auto response = invokeCallback(
            callback, makeFederatedCallback(target, "cookie-name=cookie-value"));
        EXPECT_GE(response.status(), 400);
    }
    EXPECT_EQ(issuer.calls, 0);
    EXPECT_EQ(fixture.coroutineProvider->syncCalls, 0);
    EXPECT_EQ(fixture.coroutineProvider->nativeCompleteCalls, 0);
    EXPECT_EQ(fallback.syncCalls, 0);
    EXPECT_EQ(fallback.asyncCalls, 0);
}

TEST(TrustedAuthenticationCoroutineTest, FederatedCallbackRealHttpLoopbackIssuesSession)
{
    namespace beast = boost::beast;
    namespace wire = beast::http;
    Fixture fixture;
    auto service = fixture.service();
    auto limiter = openproof::gateway::TokenBucketRateLimiter::create(
        fixture.clock, 100.0, 100.0, 100U);
    ASSERT_TRUE(limiter);
    FederatedNoFallback fallback;
    auth::http::CoroutineFederatedStartAdapter start{
        service, fixture.providers, limiter.value(), fallback};
    FederatedNativeSessionIssuer issuer;
    auth::http::CoroutineFederatedCallbackAdapter callback{
        service, issuer, start};
    auto config = openproof::gateway::http::ServerConfig::create(
        "127.0.0.1", 0U, 8192U, 8192U, std::chrono::seconds{2},
        std::chrono::seconds{2}, 32U, 2U);
    ASSERT_TRUE(config);
    openproof::gateway::http::BeastHttpServer server{
        callback, std::move(config).value()};
    ASSERT_TRUE(server.start());

    const auto exchange = [&server](
        std::string target, std::optional<std::string> cookies)
        -> wire::response<wire::string_body> {
        asio::io_context io;
        beast::tcp_stream stream{io};
        stream.expires_after(std::chrono::seconds{3});
        asio::ip::tcp::resolver resolver{io};
        stream.connect(resolver.resolve(
            "127.0.0.1", std::to_string(server.boundPort())));
        wire::request<wire::string_body> request{
            wire::verb::get, std::move(target), 11};
        request.set(wire::field::host, "localhost");
        if (cookies) request.set(wire::field::cookie, *cookies);
        wire::write(stream, request);
        beast::flat_buffer buffer;
        wire::response<wire::string_body> response;
        wire::read(stream, buffer, response);
        return response;
    };

    auto authorization = exchange(
        "/auth/federated/start?provider=async-test&return_to=%2Faccount",
        std::nullopt);
    EXPECT_EQ(authorization.result(), wire::status::found);
    EXPECT_EQ(authorization.at(wire::field::location),
              "https://example.test/authorize");
    std::string cookies;
    std::size_t count = 0U;
    for (const auto& field : authorization) {
        if (field.name() != wire::field::set_cookie) continue;
        ++count;
        const std::string value{
            field.value().data(), field.value().size()};
        if (!cookies.empty()) cookies.append("; ");
        cookies.append(value.substr(0U, value.find(';')));
    }
    EXPECT_EQ(count, 5U);
    ASSERT_FALSE(cookies.empty());

    auto finished = exchange(
        "/auth/federated/callback?code=valid-code&state=matching-state",
        cookies);
    EXPECT_EQ(finished.result(), wire::status::found);
    EXPECT_EQ(finished.at(wire::field::location), "/account");
    bool foundSession = false;
    for (const auto& field : finished) {
        if (field.name() == wire::field::set_cookie
            && field.value().starts_with(
                "__Host-openproof-session=new-session-1")) {
            foundSession = true;
        }
    }
    EXPECT_TRUE(foundSession);
    EXPECT_EQ(issuer.calls, 1);
    EXPECT_EQ(fixture.coroutineProvider->nativeBeginCalls, 1);
    EXPECT_EQ(fixture.coroutineProvider->nativeCompleteCalls, 1);
    EXPECT_EQ(fixture.coroutineProvider->syncCalls, 0);
    EXPECT_EQ(fallback.syncCalls, 0);
    EXPECT_EQ(fallback.asyncCalls, 0);

    auto replay = exchange(
        "/auth/federated/callback?code=valid-code&state=matching-state",
        cookies);
    EXPECT_GE(replay.result_int(), 400);
    EXPECT_EQ(issuer.calls, 1);
    server.stop();
}

} // namespace

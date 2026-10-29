#include <gtest/gtest.h>
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <utility>

import openproof.foundation;
import openproof.identity.provider;
import openproof.provider.web3;

namespace {
namespace asio = boost::asio;
namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace web3 = openproof::provider::web3;

constexpr auto kNow = fnd::Instant{std::chrono::milliseconds{1770000000000LL}};
constexpr std::string_view kAddress{"0x1111111111111111111111111111111111111111"};

[[nodiscard]] web3::FarcasterProviderConfig config()
{
    auto result = web3::FarcasterProviderConfig::create(
        "login.openproof.test", "https://login.openproof.test/farcaster",
        10U, "https://rpc.openproof.test",
        "0x00000000fc6c5f01fc30151999387bb99a9f489b",
        fnd::SecretString{std::string(48U, 'f')},
        std::chrono::minutes{5}, {}, {},
        "0x00000000fc1237824fb747abde0ff18990e59b7e");
    EXPECT_TRUE(result);
    return std::move(result).value();
}

class NativeTestVerifier final : public web3::FarcasterChainVerifier,
                                 public web3::CoroutineFarcasterChainVerifier {
public:
    [[nodiscard]] fnd::Result<bool> chainMatches() override
    { ++blockingCalls; return fnd::fail(fnd::ErrorCode::Unavailable); }

    [[nodiscard]] fnd::Result<bool> verifySignature(
        std::string_view, std::string_view, std::string_view) override
    { ++blockingCalls; return fnd::fail(fnd::ErrorCode::Unavailable); }

    [[nodiscard]] fnd::Result<std::optional<web3::FarcasterSignerKind>>
    authorizeSigner(std::uint64_t, std::string_view) override
    { ++blockingCalls; return fnd::fail(fnd::ErrorCode::Unavailable); }

    [[nodiscard]] asio::awaitable<fnd::Result<bool>>
    chainMatchesAsync(std::chrono::steady_clock::time_point) override
    {
        ++chainCalls;
        co_await asio::post(asio::use_awaitable);
        co_return true;
    }

    [[nodiscard]] asio::awaitable<fnd::Result<bool>>
    verifySignatureAsync(std::string_view, std::string_view, std::string_view,
                         std::chrono::steady_clock::time_point) override
    {
        ++signatureCalls;
        co_await asio::post(asio::use_awaitable);
        co_return signatureValid;
    }

    [[nodiscard]] asio::awaitable<
        fnd::Result<std::optional<web3::FarcasterSignerKind>>>
    authorizeSignerAsync(std::uint64_t fid, std::string_view address,
                         std::chrono::steady_clock::time_point) override
    {
        ++authorizationCalls;
        co_await asio::post(asio::use_awaitable);
        if (fid != 6841U || address != kAddress)
            co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        co_return authorized
            ? std::optional<web3::FarcasterSignerKind>{
                web3::FarcasterSignerKind::Custody}
            : std::optional<web3::FarcasterSignerKind>{};
    }

    bool signatureValid{true};
    bool authorized{true};
    int blockingCalls{};
    int chainCalls{};
    int authorizationCalls{};
    int signatureCalls{};
};

class BlockingTestVerifier final : public web3::FarcasterChainVerifier {
public:
    [[nodiscard]] fnd::Result<bool> chainMatches() override
    { ++calls; return true; }
    [[nodiscard]] fnd::Result<bool> verifySignature(
        std::string_view, std::string_view, std::string_view) override
    { ++calls; return true; }
    [[nodiscard]] fnd::Result<std::optional<web3::FarcasterSignerKind>>
    authorizeSigner(std::uint64_t, std::string_view) override
    { ++calls; return std::optional<web3::FarcasterSignerKind>{}; }
    int calls{};
};

[[nodiscard]] idp::AuthenticationRequest request()
{
    idp::AuthenticationRequest value{
        idp::ProviderId{"farcaster"}, idp::ClientContext{}};
    value.setParameter("address", std::string{kAddress});
    value.setParameter("fid", "6841");
    return value;
}

asio::awaitable<void> directNativeFlow(
    web3::FarcasterAuthenticationProvider& provider,
    NativeTestVerifier& verifier, bool& success)
{
    auto started = co_await provider.beginAuthenticationAsync(request());
    if (!started) co_return;
    const auto found = started->parameters().find("message");
    if (found == started->parameters().end()) co_return;
    idp::AuthenticationResponse response{
        started->id(), idp::ClientContext{}};
    response.setParameter(
        "message", idp::CredentialValue{std::string{found->second}});
    response.setParameter("signature", idp::CredentialValue{"0x0102"});
    auto completed = co_await provider.completeAuthenticationAsync(std::move(response));
    success = completed
        && completed->subject() == idp::ExternalSubject{"6841"}
        && verifier.blockingCalls == 0
        && verifier.chainCalls == 1
        && verifier.signatureCalls == 1
        && verifier.authorizationCalls == 2;
}

TEST(FarcasterCoroutineTest, DirectCustodyAuthenticationIsEntirelyNonblocking)
{
    fnd::ManualClockSource clock{kNow};
    auto owned = std::make_unique<NativeTestVerifier>();
    auto* verifier = owned.get();
    web3::FarcasterAuthenticationProvider provider{
        config(), clock, std::move(owned)};
    bool success = false;
    asio::io_context io;
    auto future = asio::co_spawn(
        io, directNativeFlow(provider, *verifier, success), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(success);
}

asio::awaitable<void> noBlockingFallback(
    web3::FarcasterAuthenticationProvider& provider, bool& denied)
{
    auto started = co_await provider.beginAuthenticationAsync(request());
    denied = !started && started.error().code() == fnd::ErrorCode::Unavailable;
}

TEST(FarcasterCoroutineTest, InjectedBlockingVerifierIsNeverRunOnReactor)
{
    fnd::ManualClockSource clock{kNow};
    auto owned = std::make_unique<BlockingTestVerifier>();
    auto* verifier = owned.get();
    web3::FarcasterAuthenticationProvider provider{config(), clock, std::move(owned)};
    bool denied = false;
    asio::io_context io;
    auto future = asio::co_spawn(
        io, noBlockingFallback(provider, denied), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(denied);
    EXPECT_EQ(verifier->calls, 0);
}

asio::awaitable<void> revokedAfterChallenge(
    web3::FarcasterAuthenticationProvider& provider,
    NativeTestVerifier& verifier, bool& rejected)
{
    auto started = co_await provider.beginAuthenticationAsync(request());
    if (!started) co_return;
    const auto found = started->parameters().find("message");
    if (found == started->parameters().end()) co_return;
    verifier.authorized = false;
    idp::AuthenticationResponse response{started->id(), idp::ClientContext{}};
    response.setParameter(
        "message", idp::CredentialValue{std::string{found->second}});
    response.setParameter("signature", idp::CredentialValue{"0x0102"});
    auto outcome = co_await provider.completeAuthenticationAsync(std::move(response));
    rejected = !outcome
        && outcome.error().code() == fnd::ErrorCode::AuthenticationFailed
        && verifier.blockingCalls == 0
        && verifier.authorizationCalls == 2;
}

TEST(FarcasterCoroutineTest, RevokedSignerIsRejectedDuringNativeProofCompletion)
{
    fnd::ManualClockSource clock{kNow};
    auto owned = std::make_unique<NativeTestVerifier>();
    auto* verifier = owned.get();
    web3::FarcasterAuthenticationProvider provider{
        config(), clock, std::move(owned)};
    bool rejected = false;
    asio::io_context io;
    auto future = asio::co_spawn(
        io, revokedAfterChallenge(provider, *verifier, rejected), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(rejected);
}
} // namespace

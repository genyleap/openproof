#include <gtest/gtest.h>
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>

#include <chrono>
#include <map>
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

[[nodiscard]] web3::WalletProviderConfig config()
{
    auto result = web3::WalletProviderConfig::create(
        "login.openproof.test", "https://login.openproof.test/wallet",
        std::map<std::uint64_t, std::string>{},
        fnd::SecretString{std::string(48U, 'w')}, std::chrono::minutes{5});
    EXPECT_TRUE(result);
    return std::move(result).value();
}

asio::awaitable<void> badProvider(
    idp::CoroutineAuthenticationProvider& native, bool& rejected)
{
    auto result = co_await native.beginAuthenticationAsync(
        idp::AuthenticationRequest{idp::ProviderId{"other"}, idp::ClientContext{}});
    rejected = !result && result.error().code() == fnd::ErrorCode::InvalidArgument;
}

TEST(WalletCoroutineTest, WrongProviderFailsBeforeOutboundIo)
{
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1770000000000LL}}};
    web3::WalletAuthenticationProvider provider{config(), clock};
    idp::AuthenticationProvider& base = provider;
    auto* native = dynamic_cast<idp::CoroutineAuthenticationProvider*>(&base);
    ASSERT_NE(native, nullptr);
    bool rejected = false;
    asio::io_context io;
    auto future = asio::co_spawn(io, badProvider(*native, rejected), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(rejected);
}

asio::awaitable<void> incompleteCallback(
    idp::CoroutineAuthenticationProvider& native, bool& rejected)
{
    idp::AuthenticationResponse response{
        idp::ChallengeId{"siwe_invalid"}, idp::ClientContext{}};
    response.setParameter("message", idp::CredentialValue{"not a SIWE message"});
    auto result = co_await native.completeAuthenticationAsync(std::move(response));
    rejected = !result && result.error().code() == fnd::ErrorCode::AuthenticationFailed;
}

TEST(WalletCoroutineTest, IncompleteWalletCallbackFailsWithoutRpc)
{
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1770000000000LL}}};
    web3::WalletAuthenticationProvider provider{config(), clock};
    idp::CoroutineAuthenticationProvider& native = provider;
    bool rejected = false;
    asio::io_context io;
    auto future = asio::co_spawn(io, incompleteCallback(native, rejected), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(rejected);
}

asio::awaitable<void> forgedSignatureNoRpc(
    web3::WalletAuthenticationProvider& provider, bool& rejected)
{
    idp::AuthenticationRequest request{
        idp::ProviderId{"ethereum-wallet"}, idp::ClientContext{}};
    request.setParameter("address", "0x1111111111111111111111111111111111111111");
    request.setParameter("chain_id", "8453");
    auto started = co_await provider.beginAuthenticationAsync(std::move(request));
    if (!started) co_return;
    const auto it = started->parameters().find("message");
    if (it == started->parameters().end()) co_return;
    idp::AuthenticationResponse response{started->id(), idp::ClientContext{}};
    response.setParameter("message", idp::CredentialValue{std::string{it->second}});
    response.setParameter("signature", idp::CredentialValue{"0x0102"});
    auto completed = co_await provider.completeAuthenticationAsync(std::move(response));
    rejected = !completed && completed.error().code() == fnd::ErrorCode::AuthenticationFailed;
}

TEST(WalletCoroutineTest, ForgedSmartWalletProofFailsWithoutConfiguredRpc)
{
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1770000000000LL}}};
    web3::WalletAuthenticationProvider provider{config(), clock};
    bool rejected = false;
    asio::io_context io;
    auto future = asio::co_spawn(
        io, forgedSignatureNoRpc(provider, rejected), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(rejected);
}
} // namespace

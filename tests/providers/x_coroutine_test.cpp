#include <gtest/gtest.h>
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>

#include <chrono>
#include <future>
#include <string>
#include <utility>

import openproof.foundation;
import openproof.identity.provider;
import openproof.provider.x;

namespace {
namespace asio = boost::asio;
namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace xProvider = openproof::provider::x;

[[nodiscard]] auto config()
{
    return xProvider::XProviderConfig::create(
        "x-api-key", fnd::SecretString{std::string(40U, 's')},
        "https://identity.example.test/oauth/callback",
        fnd::SecretString{std::string(32U, 'k')},
        std::chrono::minutes{5});
}

asio::awaitable<void> checkInvalidStart(
    xProvider::XAuthenticationProvider& provider, bool& rejected)
{
    auto result = co_await provider.beginAuthenticationAsync(
        idp::AuthenticationRequest{
            idp::ProviderId{"unrelated-provider"}, idp::ClientContext{}});
    rejected = !result && result.error().code() == fnd::ErrorCode::InvalidArgument;
}

asio::awaitable<void> checkInvalidCompletion(
    xProvider::XAuthenticationProvider& provider,
    idp::AuthenticationResponse response, bool& rejected)
{
    auto result = co_await provider.completeAuthenticationAsync(std::move(response));
    rejected = !result && result.error().code() == fnd::ErrorCode::AuthenticationFailed;
}

TEST(XCoroutineProviderTest, IncorrectProviderRejectedBeforeTokenExchange)
{
    auto configuration = config();
    ASSERT_TRUE(configuration);
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1770000000000}}};
    xProvider::XAuthenticationProvider provider{std::move(configuration).value(), clock};
    bool rejected = false;
    asio::io_context io;
    auto result = asio::co_spawn(io, checkInvalidStart(provider, rejected), asio::use_future);
    io.run();
    ASSERT_NO_THROW(result.get());
    EXPECT_TRUE(rejected);
}

void rejectCallback(bool includeVerifier)
{
    auto configuration = config();
    ASSERT_TRUE(configuration);
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1770000000000}}};
    xProvider::XAuthenticationProvider provider{std::move(configuration).value(), clock};
    idp::AuthenticationResponse response{
        idp::ChallengeId{"xo1_invalid-envelope"}, idp::ClientContext{}};
    response.setParameter("oauth_token", idp::CredentialValue{"request-token"});
    if (includeVerifier)
        response.setParameter("oauth_verifier", idp::CredentialValue{"verifier"});
    bool rejected = false;
    asio::io_context io;
    auto result = asio::co_spawn(
        io, checkInvalidCompletion(provider, std::move(response), rejected),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(result.get());
    EXPECT_TRUE(rejected);
}

TEST(XCoroutineProviderTest, IncompleteCallbackRejectedBeforeOutboundRequest)
{
    rejectCallback(false);
}

TEST(XCoroutineProviderTest, ForgedChallengeEnvelopeRejectedBeforeOutboundRequest)
{
    rejectCallback(true);
}
} // namespace

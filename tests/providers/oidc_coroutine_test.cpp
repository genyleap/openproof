#include <gtest/gtest.h>
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>

#include <chrono>
#include <future>
#include <string>
#include <utility>
#include <vector>

import openproof.foundation;
import openproof.identity.provider;
import openproof.provider.oidc;

namespace {
namespace asio = boost::asio;
namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace oidc = openproof::provider::oidc;

[[nodiscard]] auto configuration()
{
    return oidc::OidcProviderConfig::create(
        idp::ProviderId{"test-oidc"}, "https://issuer.example.test",
        "isolated-client", fnd::SecretString{std::string(32U, 's')},
        "https://identity.example.test/oauth/callback",
        std::vector<std::string>{"openid", "profile"},
        fnd::SecretString{std::string(32U, 'k')},
        std::chrono::minutes{5});
}

asio::awaitable<void> invalidCompletion(
    oidc::OidcAuthenticationProvider& provider,
    idp::AuthenticationResponse response, bool& rejected)
{
    const auto result = co_await provider.completeAuthenticationAsync(
        std::move(response));
    rejected = !result
        && result.error().code() == fnd::ErrorCode::AuthenticationFailed;
}

asio::awaitable<void> wrongProviderRequest(
    oidc::OidcAuthenticationProvider& provider, bool& rejected)
{
    const auto result = co_await provider.beginAuthenticationAsync(
        idp::AuthenticationRequest{
            idp::ProviderId{"not-this-provider"}, idp::ClientContext{}});
    rejected = !result
        && result.error().code() == fnd::ErrorCode::InvalidArgument;
}

void verifyInvalidCallback(bool codeProvided, bool stateProvided)
{
    auto configured = configuration();
    ASSERT_TRUE(configured);
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1770000000000}}};
    oidc::OidcAuthenticationProvider provider{
        std::move(configured).value(), clock};
    idp::AuthenticationResponse response{
        idp::ChallengeId{"opc_only-local-test"}, idp::ClientContext{}};
    if (codeProvided) {
        response.setParameter("code", idp::CredentialValue{"test-only-code"});
    }
    if (stateProvided) {
        response.setParameter("state", idp::CredentialValue{"invalid-binding"});
    }
    bool rejected = false;
    asio::io_context io;
    auto future = asio::co_spawn(io,
        invalidCompletion(provider, std::move(response), rejected),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(rejected);
}

TEST(OidcCoroutineProviderTest, InvalidProviderRejectedBeforeDiscoveryNetwork)
{
    auto configured = configuration();
    ASSERT_TRUE(configured);
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1770000000000}}};
    oidc::OidcAuthenticationProvider provider{
        std::move(configured).value(), clock};
    asio::io_context io;
    bool rejected = false;
    auto future = asio::co_spawn(io,
        wrongProviderRequest(provider, rejected), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(rejected);
}

TEST(OidcCoroutineProviderTest, MissingCodeRejectedBeforeNetwork)
{
    verifyInvalidCallback(false, true);
}

TEST(OidcCoroutineProviderTest, MissingStateRejectedBeforeNetwork)
{
    verifyInvalidCallback(true, false);
}

TEST(OidcCoroutineProviderTest, InvalidStateRejectedBeforeNetwork)
{
    verifyInvalidCallback(true, true);
}
} // namespace

#include "../../src/gateway/asio_service_ids_extern.hpp"
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
import openproof.provider.github;

namespace {
namespace asio = boost::asio;
namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace github = openproof::provider::github;

asio::awaitable<void> checkCallback(
    github::GitHubAuthenticationProvider& provider,
    idp::AuthenticationResponse callback, bool& denied)
{
    auto result = co_await provider.completeAuthenticationAsync(std::move(callback));
    denied = !result
        && result.error().code() == fnd::ErrorCode::AuthenticationFailed;
}

void verifyRejectedCallback(bool includeCode, bool includeState)
{
    auto configuration = github::GitHubProviderConfig::create(
        "coroutine-test-id", fnd::SecretString{std::string(32, 's')},
        "https://identity.example.test/oauth/callback",
        fnd::SecretString{std::string(32, 'k')},
        std::chrono::minutes{5});
    ASSERT_TRUE(configuration);

    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1770000000000}}};
    github::GitHubAuthenticationProvider provider{
        std::move(configuration).value(), clock};
    idp::AuthenticationResponse callback{
        idp::ChallengeId{"ghc_coroutine_test_only"}, idp::ClientContext{}};
    if (includeCode) {
        callback.setParameter("code", idp::CredentialValue{"test-only-code"});
    }
    if (includeState) {
        callback.setParameter("state", idp::CredentialValue{"wrong-state"});
    }

    asio::io_context io;
    bool denied = false;
    auto completed = asio::co_spawn(
        io, checkCallback(provider, std::move(callback), denied),
        asio::use_future);
    io.run();
    ASSERT_NO_THROW(completed.get());
    EXPECT_TRUE(denied);
}

TEST(GitHubCoroutineProviderTest, SynchronousCompletionFailsClosedWithoutOutboundIo)
{
    auto configuration=github::GitHubProviderConfig::create(
        "coroutine-test-id",fnd::SecretString{std::string(32,'s')},
        "https://identity.example.test/oauth/callback",
        fnd::SecretString{std::string(32,'k')},std::chrono::minutes{5});
    ASSERT_TRUE(configuration);
    fnd::ManualClockSource clock{fnd::Instant{std::chrono::milliseconds{1770000000000}}};
    github::GitHubAuthenticationProvider provider{std::move(configuration).value(),clock};
    auto challenge=provider.beginAuthentication(
        idp::AuthenticationRequest{idp::ProviderId{"github"},idp::ClientContext{}});
    ASSERT_TRUE(challenge);
    idp::AuthenticationResponse proof{challenge->id(),idp::ClientContext{}};
    proof.setParameter("code",idp::CredentialValue{"fixture-code"});
    // Valid challenge/state still cannot admit any synchronous exchange.
    const auto& url=challenge->parameters().at("authorization_url");
    auto start=url.find("state=");
    ASSERT_NE(start,std::string::npos);
    start+=6U;
    const auto end=url.find('&',start);
    proof.setParameter("state",idp::CredentialValue{url.substr(start,end-start)});
    auto denied=provider.completeAuthentication(proof);
    ASSERT_FALSE(denied);
    EXPECT_EQ(denied.error().code(),fnd::ErrorCode::Unavailable);
}

TEST(GitHubCoroutineProviderTest, MissingCodeIsRejectedBeforeOutboundIo)
{
    verifyRejectedCallback(false, true);
}

TEST(GitHubCoroutineProviderTest, InvalidStateIsRejectedBeforeOutboundIo)
{
    verifyRejectedCallback(true, true);
}

TEST(GitHubCoroutineProviderTest, MissingStateIsRejectedBeforeOutboundIo)
{
    verifyRejectedCallback(true, false);
}
} // namespace

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <utility>

import openproof.foundation;
import openproof.identity.provider;
import openproof.provider.github;

namespace {

namespace fnd = openproof::foundation;
namespace github = openproof::provider::github;
namespace idp = openproof::identity::provider;

[[nodiscard]] fnd::SecretString derivationKey()
{
    return fnd::SecretString{std::string(32U, 'k')};
}

[[nodiscard]] fnd::Result<github::GitHubProviderConfig> configuration(
    std::string callback)
{
    return github::GitHubProviderConfig::create(
        "client-id", fnd::SecretString{std::string(32U, 's')},
        std::move(callback), derivationKey(), std::chrono::minutes{5});
}

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'790'000'000'000LL}};

[[nodiscard]] github::GitHubProviderConfig validConfiguration()
{
    return configuration(
        "https://identity.example.test/auth/federated/callback?provider=github").value();
}

TEST(GitHubProviderConfigTest, AcceptsValidatedHttpsCallback)
{
    auto configured = configuration(
        "https://identity.example.test:443/auth/federated/callback?provider=github");

    ASSERT_TRUE(configured) << configured.error().internalDetail();
    EXPECT_EQ(configured->callbackUri(),
              "https://identity.example.test:443/auth/federated/callback?provider=github");
}

TEST(GitHubProviderConfigTest, RejectsMalformedHttpsCallbackAuthoritiesAndTargets)
{
    for (const std::string callback : {
             "http://identity.example.test/auth/federated/callback",
             "https:///auth/federated/callback",
             "https://user@identity.example.test/auth/federated/callback",
             "https://identity.example.test:0/auth/federated/callback",
             "https://identity.example.test:70000/auth/federated/callback",
             "https://identity.example.test:/auth/federated/callback",
             "https://identity example.test/auth/federated/callback",
             "https://identity.example.test/auth/federated/callback with-space",
             "https://identity.example.test/auth/federated/callback\nnext",
             "https://identity.example.test/auth/federated/callback#fragment",
             "https://identity.example.test\\auth/federated/callback"}) {
        auto configured = configuration(callback);
        EXPECT_FALSE(configured) << callback;
    }
}

TEST(GitHubAuthenticationProviderTest, ChallengeIsSingleUseAndProviderBound)
{
    fnd::ManualClockSource clock{kNow};
    github::GitHubAuthenticationProvider provider{validConfiguration(), clock, {}};

    idp::AuthenticationRequest wrong{idp::ProviderId{"oidc"}, idp::ClientContext{}};
    EXPECT_FALSE(provider.beginAuthentication(wrong));

    idp::AuthenticationRequest request{idp::ProviderId{"github"}, idp::ClientContext{}};
    auto challenge = provider.beginAuthentication(request);
    ASSERT_TRUE(challenge);
    idp::AuthenticationResponse completion{challenge->id(), idp::ClientContext{}};

    auto first = provider.completeAuthentication(completion);
    ASSERT_FALSE(first);
    EXPECT_NE(first.error().internalDetail().find("incomplete"), std::string::npos);

    auto replay = provider.completeAuthentication(completion);
    ASSERT_FALSE(replay);
    EXPECT_NE(replay.error().internalDetail().find("already used"), std::string::npos);
}

TEST(GitHubAuthenticationProviderTest, ExpiredChallengeIsConsumedBeforeCallbackParsing)
{
    fnd::ManualClockSource clock{kNow};
    github::GitHubAuthenticationProvider provider{validConfiguration(), clock, {}};
    idp::AuthenticationRequest request{idp::ProviderId{"github"}, idp::ClientContext{}};
    auto challenge = provider.beginAuthentication(request);
    ASSERT_TRUE(challenge);
    clock.advance(std::chrono::minutes{5});

    idp::AuthenticationResponse completion{challenge->id(), idp::ClientContext{}};
    auto expired = provider.completeAuthentication(completion);
    ASSERT_FALSE(expired);
    EXPECT_NE(expired.error().internalDetail().find("challenge expired"), std::string::npos);
}

} // namespace

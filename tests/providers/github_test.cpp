#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <utility>

import openproof.foundation;
import openproof.provider.github;

namespace {

namespace fnd = openproof::foundation;
namespace github = openproof::provider::github;

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

} // namespace

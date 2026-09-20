#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <string_view>
#include <utility>

#include <boost/json.hpp>

#include "../../src/providers/github/response_validation.hpp"

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

TEST(GitHubResponseValidationTest, BoundsCredentialsAndPresentationClaims)
{
    namespace detail = openproof::provider::github::detail;

    EXPECT_TRUE(detail::validBearerCredential("gho_token-value_123"));
    EXPECT_TRUE(detail::validBearerCredential("opaque.token+/value=="));
    EXPECT_FALSE(detail::validBearerCredential("opaque=token"));
    EXPECT_FALSE(detail::validBearerCredential("token;parameter"));
    EXPECT_FALSE(detail::validBearerCredential("token with space"));
    EXPECT_FALSE(detail::validBearerCredential("token\nheader"));
    EXPECT_FALSE(detail::validBearerCredential(
        std::string(detail::kAccessTokenMaximum + 1U, 'a')));

    EXPECT_TRUE(detail::validScopeResponse(""));
    EXPECT_TRUE(detail::validScopeResponse("read:user,user:email"));
    EXPECT_TRUE(detail::validScopeResponse("read:user user:email"));
    EXPECT_FALSE(detail::validScopeResponse("user:email\nrepo"));
    EXPECT_TRUE(detail::hasEmailScope("user:email"));
    EXPECT_TRUE(detail::hasEmailScope("read:user,user"));
    EXPECT_TRUE(detail::hasEmailScope("repo user:email"));
    EXPECT_FALSE(detail::hasEmailScope(""));
    EXPECT_FALSE(detail::hasEmailScope("read:user"));
    EXPECT_FALSE(detail::hasEmailScope("repo,gist"));

    EXPECT_TRUE(detail::safeProfileText(
        std::string(detail::kPreferredUsernameMaximum, 'u'),
        detail::kPreferredUsernameMaximum));
    EXPECT_FALSE(detail::safeProfileText(
        std::string(detail::kPreferredUsernameMaximum + 1U, 'u'),
        detail::kPreferredUsernameMaximum));
}

TEST(GitHubResponseValidationTest, UsesOnlyOnePlausibleVerifiedPrimaryEmail)
{
    namespace json = boost::json;
    using openproof::provider::github::detail::uniqueVerifiedPrimaryEmail;

    json::array emails{
        json::object{{"email", "secondary@example.test"},
                     {"verified", true}, {"primary", false}},
        json::object{{"email", "primary@example.test"},
                     {"verified", true}, {"primary", true}}};

    auto selected = uniqueVerifiedPrimaryEmail(emails);
    ASSERT_TRUE(selected);
    EXPECT_EQ(*selected, "primary@example.test");

    emails.emplace_back(json::object{
        {"email", "other@example.test"}, {"verified", true}, {"primary", true}});
    EXPECT_FALSE(uniqueVerifiedPrimaryEmail(emails));

    json::array malformed{
        json::object{{"email", "not an email"}, {"verified", true}, {"primary", true}}};
    EXPECT_FALSE(uniqueVerifiedPrimaryEmail(malformed));

    json::array noVerifiedPrimary{
        json::object{{"email", "primary@example.test"},
                     {"verified", false}, {"primary", true}}};
    EXPECT_FALSE(uniqueVerifiedPrimaryEmail(noVerifiedPrimary));
}

} // namespace

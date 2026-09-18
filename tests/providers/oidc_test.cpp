#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <vector>

import openproof.foundation;
import openproof.identity.provider;
import openproof.provider.oidc;

namespace {

namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace oidc = openproof::provider::oidc;

[[nodiscard]] fnd::Result<oidc::OidcProviderConfig> configuration(
    std::string clientId, std::string clientSecret,
    oidc::OidcClientAuthenticationMethod authentication)
{
    return oidc::OidcProviderConfig::create(
        idp::ProviderId{"telegram"}, "https://oauth.telegram.org",
        std::move(clientId), fnd::SecretString{std::move(clientSecret)},
        "https://identity.example.test/auth/federated/callback",
        std::vector<std::string>{"openid", "profile"},
        fnd::SecretString{std::string(32U, 'k')}, std::chrono::minutes{5},
        authentication);
}

TEST(OidcProviderConfigTest, PreservesExplicitBasicTokenAuthentication)
{
    auto configured = configuration(
        "123456789", "telegram-client-secret",
        oidc::OidcClientAuthenticationMethod::ClientSecretBasic);

    ASSERT_TRUE(configured) << configured.error().internalDetail();
    EXPECT_EQ(configured->clientAuthentication(),
              oidc::OidcClientAuthenticationMethod::ClientSecretBasic);
}

TEST(OidcProviderConfigTest, BasicCredentialsRejectAmbiguousColonEncoding)
{
    auto colonInId = configuration(
        "123:456", "secret",
        oidc::OidcClientAuthenticationMethod::ClientSecretBasic);
    auto colonInSecret = configuration(
        "123456", "secret:value",
        oidc::OidcClientAuthenticationMethod::ClientSecretBasic);

    EXPECT_FALSE(colonInId);
    EXPECT_FALSE(colonInSecret);
}

TEST(OidcProviderConfigTest, PostAuthenticationRemainsTheCompatibilityDefault)
{
    auto configured = oidc::OidcProviderConfig::create(
        idp::ProviderId{"linkedin"}, "https://www.linkedin.com/oauth",
        "client-id", fnd::SecretString{"client-secret"},
        "https://identity.example.test/auth/federated/callback",
        std::vector<std::string>{"openid", "profile", "email"},
        fnd::SecretString{std::string(32U, 'k')}, std::chrono::minutes{5});

    ASSERT_TRUE(configured) << configured.error().internalDetail();
    EXPECT_EQ(configured->clientAuthentication(),
              oidc::OidcClientAuthenticationMethod::ClientSecretPost);
}

}

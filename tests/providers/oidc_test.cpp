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

TEST(OidcProviderConfigTest, BasicCredentialsAllowFormEncodableSeparators)
{
    std::string clientSecret(16U, 's');
    clientSecret.push_back(':');
    clientSecret.append(16U, 'x');
    clientSecret.push_back(' ');
    clientSecret.push_back('+');
    const std::string expectedSecret = clientSecret;
    auto configured = configuration(
        "123:456", std::move(clientSecret),
        oidc::OidcClientAuthenticationMethod::ClientSecretBasic);

    ASSERT_TRUE(configured) << configured.error().internalDetail();
    EXPECT_EQ(configured->clientId(), "123:456");
    EXPECT_EQ(configured->clientSecret().expose(), expectedSecret);
    EXPECT_EQ(configured->clientAuthentication(),
              oidc::OidcClientAuthenticationMethod::ClientSecretBasic);
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
    EXPECT_EQ(configured->authorizationResponseMode(),
              oidc::OidcAuthorizationResponseMode::Query);
}

TEST(OidcProviderConfigTest, PreservesFormPostAuthorizationResponseMode)
{
    auto configured = oidc::OidcProviderConfig::create(
        idp::ProviderId{"apple"}, "https://appleid.apple.com",
        "com.example.web", fnd::SecretString{"signed-client-secret-jwt"},
        "https://identity.example.test/auth/federated/callback",
        std::vector<std::string>{"name", "email"},
        fnd::SecretString{std::string(32U, 'k')}, std::chrono::minutes{5},
        oidc::OidcClientAuthenticationMethod::ClientSecretPost,
        oidc::OidcAuthorizationResponseMode::FormPost);

    ASSERT_TRUE(configured) << configured.error().internalDetail();
    EXPECT_EQ(configured->authorizationResponseMode(),
              oidc::OidcAuthorizationResponseMode::FormPost);
}

TEST(OidcProviderConfigTest, MicrosoftCanUseFormPostWithPostClientAuthentication)
{
    auto configured = oidc::OidcProviderConfig::create(
        idp::ProviderId{"microsoft"},
        "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
        "00000000-aaaa-bbbb-cccc-111111111111",
        fnd::SecretString{std::string(32U, 's')},
        "https://identity.example.test/auth/federated/callback",
        std::vector<std::string>{"openid", "profile", "email"},
        fnd::SecretString{std::string(32U, 'k')}, std::chrono::minutes{5},
        oidc::OidcClientAuthenticationMethod::ClientSecretPost,
        oidc::OidcAuthorizationResponseMode::FormPost);

    ASSERT_TRUE(configured) << configured.error().internalDetail();
    EXPECT_EQ(configured->clientAuthentication(),
              oidc::OidcClientAuthenticationMethod::ClientSecretPost);
    EXPECT_EQ(configured->authorizationResponseMode(),
              oidc::OidcAuthorizationResponseMode::FormPost);
}

}

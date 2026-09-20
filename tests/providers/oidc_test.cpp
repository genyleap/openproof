#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <vector>

#include "../../src/providers/oidc/profile_claims.hpp"

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

TEST(OidcProfileClaimTest, PrefersStandardNameOverComponents)
{
    const auto value = openproof::provider::oidc::detail::displayName(
        std::string_view{"Ada Byron"}, std::string_view{"Ignored"},
        std::string_view{"Name"});

    ASSERT_TRUE(value);
    EXPECT_EQ(*value, "Ada Byron");
}

TEST(OidcProfileClaimTest, JoinsGivenAndFamilyNameWhenNameIsUnavailable)
{
    const auto both = openproof::provider::oidc::detail::displayName(
        std::nullopt, std::string_view{"Ada"}, std::string_view{"Lovelace"});
    const auto familyOnly = openproof::provider::oidc::detail::displayName(
        std::nullopt, std::nullopt, std::string_view{"Lovelace"});

    ASSERT_TRUE(both);
    EXPECT_EQ(*both, "Ada Lovelace");
    ASSERT_TRUE(familyOnly);
    EXPECT_EQ(*familyOnly, "Lovelace");
}

TEST(OidcProfileClaimTest, IgnoresUnsafeNameComponents)
{
    const auto recovered = openproof::provider::oidc::detail::displayName(
        std::string_view{"Unsafe\nName"}, std::string_view{"Ada"},
        std::string_view{"Lovelace"});
    const auto rejected = openproof::provider::oidc::detail::displayName(
        std::nullopt, std::string_view{"Unsafe\rGiven"},
        std::string_view{"Unsafe\nFamily"});

    ASSERT_TRUE(recovered);
    EXPECT_EQ(*recovered, "Ada Lovelace");
    EXPECT_FALSE(rejected);
}

TEST(OidcProfileClaimTest, EnforcesPlatformDisplayNameLimit)
{
    const std::string tooLongName(257U, 'n');
    const std::string tooLongGiven(200U, 'g');
    const std::string tooLongFamily(100U, 'f');

    const auto recovered = openproof::provider::oidc::detail::displayName(
        std::string_view{tooLongName}, std::string_view{"Ada"},
        std::string_view{"Lovelace"});
    const auto rejected = openproof::provider::oidc::detail::displayName(
        std::nullopt, std::string_view{tooLongGiven},
        std::string_view{tooLongFamily});

    ASSERT_TRUE(recovered);
    EXPECT_EQ(*recovered, "Ada Lovelace");
    EXPECT_FALSE(rejected);
}

TEST(OidcProfileClaimTest, EnforcesPreferredUsernamePlatformLimit)
{
    using openproof::provider::oidc::detail::kPreferredUsernameMaximum;
    using openproof::provider::oidc::detail::safeProfileText;

    const std::string accepted(kPreferredUsernameMaximum, 'u');
    const std::string rejected(kPreferredUsernameMaximum + 1U, 'u');
    EXPECT_TRUE(safeProfileText(accepted, kPreferredUsernameMaximum));
    EXPECT_FALSE(safeProfileText(rejected, kPreferredUsernameMaximum));
}

TEST(OidcProfileClaimTest, ValidatesHttpsPictureUrlStructure)
{
    using openproof::provider::oidc::detail::validHttpsProfileUrl;

    EXPECT_TRUE(validHttpsProfileUrl(
        "https://images.example.test:443/avatar/42?variant=large"));
    for (const std::string value : {
             "http://images.example.test/avatar.png",
             "https:///avatar.png",
             "https://user@images.example.test/avatar.png",
             "https://images.example.test:0/avatar.png",
             "https://images.example.test:70000/avatar.png",
             "https://images.example.test:/avatar.png",
             "https://images.example.test/avatar.png#fragment",
             "https://images.example.test\\\\avatar.png",
             "https://images.example.test/avatar image.png"}) {
        EXPECT_FALSE(validHttpsProfileUrl(value)) << value;
    }
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

TEST(OidcAuthenticationProviderTest, UnknownChallengeFailsBeforeCallbackOrNetworkWork)
{
    auto config = configuration(
        "123456789", "telegram-client-secret",
        oidc::OidcClientAuthenticationMethod::ClientSecretBasic);
    ASSERT_TRUE(config);
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1'790'000'000'000LL}}};
    oidc::OidcAuthenticationProvider provider{std::move(config).value(), clock};
    idp::AuthenticationResponse completion{
        idp::ChallengeId{"opc_unknown"}, idp::ClientContext{}};

    auto outcome = provider.completeAuthentication(completion);

    ASSERT_FALSE(outcome);
    EXPECT_EQ(outcome.error().code(), fnd::ErrorCode::AuthenticationFailed);
    EXPECT_NE(outcome.error().internalDetail().find("unknown or already used"),
              std::string::npos);
}

}

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <utility>

import openproof.foundation;
import openproof.identity.provider;
import openproof.provider.x;

namespace {

namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace xProvider = openproof::provider::x;

[[nodiscard]] fnd::SecretString derivationKey()
{
    return fnd::SecretString{std::string(32U, 'k')};
}

[[nodiscard]] fnd::Result<xProvider::XProviderConfig> configuration(
    std::string callback)
{
    return xProvider::XProviderConfig::create(
        "x-api-key", fnd::SecretString{std::string(40U, 's')},
        std::move(callback), derivationKey(), std::chrono::minutes{5});
}

TEST(XProviderConfigTest, AcceptsValidatedHttpsCallback)
{
    auto configured = configuration(
        "https://identity.example.test/auth/federated/callback");

    ASSERT_TRUE(configured) << configured.error().internalDetail();
    EXPECT_EQ(configured->apiKey(), "x-api-key");
    EXPECT_EQ(configured->callbackUri(),
              "https://identity.example.test/auth/federated/callback");
}

TEST(XProviderConfigTest, RejectsInvalidCallbackAndNon256BitDerivationKey)
{
    auto insecure = configuration(
        "http://identity.example.test/auth/federated/callback");
    EXPECT_FALSE(insecure);

    auto weak = xProvider::XProviderConfig::create(
        "x-api-key", fnd::SecretString{std::string(40U, 's')},
        "https://identity.example.test/auth/federated/callback",
        fnd::SecretString{std::string(31U, 'k')},
        std::chrono::minutes{5});
    EXPECT_FALSE(weak);

    auto oversized = xProvider::XProviderConfig::create(
        "x-api-key", fnd::SecretString{std::string(40U, 's')},
        "https://identity.example.test/auth/federated/callback",
        fnd::SecretString{std::string(33U, 'k')},
        std::chrono::minutes{5});
    EXPECT_FALSE(oversized);
}

TEST(XAuthenticationProviderTest, RejectsWrongProviderBeforeNetwork)
{
    auto configured = configuration(
        "https://identity.example.test/auth/federated/callback");
    ASSERT_TRUE(configured);
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1'790'000'000'000LL}}};
    xProvider::XAuthenticationProvider provider{
        std::move(configured).value(), clock};
    idp::AuthenticationRequest request{
        idp::ProviderId{"github"}, idp::ClientContext{}};

    auto challenge = provider.beginAuthentication(request);

    ASSERT_FALSE(challenge);
    EXPECT_EQ(challenge.error().code(), fnd::ErrorCode::InvalidArgument);
}

TEST(XAuthenticationProviderTest, RejectsIncompleteOauth1CallbackBeforeNetwork)
{
    auto configured = configuration(
        "https://identity.example.test/auth/federated/callback");
    ASSERT_TRUE(configured);
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1'790'000'000'000LL}}};
    xProvider::XAuthenticationProvider provider{
        std::move(configured).value(), clock};
    idp::AuthenticationResponse response{
        idp::ChallengeId{"xo1_invalid"}, idp::ClientContext{}};
    response.setParameter(
        "oauth_token", idp::CredentialValue{"request-token"});

    auto outcome = provider.completeAuthentication(response);

    ASSERT_FALSE(outcome);
    EXPECT_EQ(outcome.error().code(), fnd::ErrorCode::AuthenticationFailed);
}

} // namespace

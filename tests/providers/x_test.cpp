#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <string_view>
#include <utility>

#include "../../src/providers/x/response_validation.hpp"

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
        "x-client-id", fnd::SecretString{std::string(32U, 's')},
        std::move(callback), derivationKey(), std::chrono::minutes{5});
}

TEST(XProviderConfigTest, AcceptsValidatedHttpsCallback)
{
    auto configured = configuration(
        "https://identity.example.test/auth/federated/callback");

    ASSERT_TRUE(configured) << configured.error().internalDetail();
    EXPECT_EQ(configured->clientId(), "x-client-id");
    EXPECT_EQ(configured->callbackUri(),
              "https://identity.example.test/auth/federated/callback");
}

TEST(XProviderConfigTest, RejectsInvalidCallbackAndWeakDerivationKey)
{
    auto insecure = configuration(
        "http://identity.example.test/auth/federated/callback");
    EXPECT_FALSE(insecure);

    auto weak = xProvider::XProviderConfig::create(
        "x-client-id", fnd::SecretString{std::string(32U, 's')},
        "https://identity.example.test/auth/federated/callback",
        fnd::SecretString{"short"}, std::chrono::minutes{5});
    EXPECT_FALSE(weak);
}

TEST(XResponseValidationTest, ValidatesTokensScopesAndProfileText)
{
    namespace detail = openproof::provider::x::detail;

    EXPECT_TRUE(detail::validBearerCredential("opaque-token_123"));
    EXPECT_FALSE(detail::validBearerCredential("token with space"));
    EXPECT_FALSE(detail::validBearerCredential("token\nheader"));

    EXPECT_TRUE(detail::validScopeResponse("users.read tweet.read"));
    EXPECT_TRUE(detail::hasScope("users.read tweet.read", "users.read"));
    EXPECT_TRUE(detail::hasScope("tweet.read users.read", "users.read"));
    EXPECT_FALSE(detail::hasScope("tweet.read", "users.read"));
    EXPECT_FALSE(detail::validScopeResponse("users.read\ntweet.read"));

    EXPECT_TRUE(detail::safeProfileText("genyleap", detail::kPreferredUsernameMaximum));
    EXPECT_FALSE(detail::safeProfileText(
        std::string(detail::kPreferredUsernameMaximum + 1U, 'u'),
        detail::kPreferredUsernameMaximum));
}

TEST(XAuthenticationProviderTest, CreatesS256PkceAuthorizationUrl)
{
    auto configured = configuration(
        "https://identity.example.test/auth/federated/callback");
    ASSERT_TRUE(configured) << configured.error().internalDetail();

    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1'790'000'000'000LL}}};
    xProvider::XAuthenticationProvider provider{
        std::move(configured).value(), clock};
    idp::AuthenticationRequest request{
        idp::ProviderId{"x"}, idp::ClientContext{}};

    auto challenge = provider.beginAuthentication(request);

    ASSERT_TRUE(challenge) << challenge.error().internalDetail();
    const auto found = challenge->parameters().find("authorization_url");
    ASSERT_NE(found, challenge->parameters().end());
    const std::string_view url{found->second};
    EXPECT_TRUE(url.starts_with("https://x.com/i/oauth2/authorize?"));
    EXPECT_NE(url.find("response_type=code"), std::string_view::npos);
    EXPECT_NE(url.find("scope=users.read%20tweet.read"), std::string_view::npos);
    EXPECT_NE(url.find("code_challenge_method=S256"), std::string_view::npos);
    EXPECT_EQ(url.find("offline.access"), std::string_view::npos);
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

} // namespace

#include <gtest/gtest.h>

#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <boost/json.hpp>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/params.h>

#include "../../src/providers/oidc/id_token_validation.hpp"
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

TEST(OidcIdTokenValidationTest, RejectsMismatchedAuthorizedPartyEvenForSingleAudience)
{
    using openproof::provider::oidc::detail::authorizedPartyMatches;

    EXPECT_TRUE(authorizedPartyMatches(std::nullopt, "client-id"));
    EXPECT_TRUE(authorizedPartyMatches(
        std::optional<std::string_view>{"client-id"}, "client-id"));
    EXPECT_FALSE(authorizedPartyMatches(
        std::optional<std::string_view>{"another-client"}, "client-id"));
}

TEST(OidcIdTokenValidationTest, HonorsJwkSignatureUseAndVerificationOperations)
{
    namespace json = boost::json;
    using openproof::provider::oidc::detail::jwkPermitsRs256Verification;

    json::object key{
        {"kid", "signing-key"},
        {"kty", "RSA"},
        {"alg", "RS256"},
        {"n", "modulus"},
        {"e", "AQAB"}};
    EXPECT_TRUE(jwkPermitsRs256Verification(key, "signing-key"));

    key["use"] = "sig";
    key["key_ops"] = json::array{"verify"};
    EXPECT_TRUE(jwkPermitsRs256Verification(key, "signing-key"));

    auto encryptionKey = key;
    encryptionKey["use"] = "enc";
    EXPECT_FALSE(jwkPermitsRs256Verification(encryptionKey, "signing-key"));

    auto nonVerifyingKey = key;
    nonVerifyingKey["key_ops"] = json::array{"encrypt"};
    EXPECT_FALSE(jwkPermitsRs256Verification(nonVerifyingKey, "signing-key"));

    auto duplicateOperations = key;
    duplicateOperations["key_ops"] = json::array{"verify", "verify"};
    EXPECT_FALSE(jwkPermitsRs256Verification(duplicateOperations, "signing-key"));

    auto malformedOperations = key;
    malformedOperations["key_ops"] = "verify";
    EXPECT_FALSE(jwkPermitsRs256Verification(malformedOperations, "signing-key"));

    auto wrongAlgorithm = key;
    wrongAlgorithm["alg"] = "RS512";
    EXPECT_FALSE(jwkPermitsRs256Verification(wrongAlgorithm, "signing-key"));

    EXPECT_FALSE(jwkPermitsRs256Verification(key, "another-key"));
}

[[nodiscard]] std::string generatedP256PrivateKey()
{
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (context == nullptr || EVP_PKEY_keygen_init(context) != 1) {
        if (context != nullptr) EVP_PKEY_CTX_free(context);
        return {};
    }
    std::string curve{"prime256v1"};
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(
            const_cast<char*>(OSSL_PKEY_PARAM_GROUP_NAME), curve.data(), 0U),
        OSSL_PARAM_construct_end()};
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_CTX_set_params(context, parameters) != 1
        || EVP_PKEY_generate(context, &key) != 1) {
        EVP_PKEY_CTX_free(context);
        if (key != nullptr) EVP_PKEY_free(key);
        return {};
    }
    EVP_PKEY_CTX_free(context);
    BIO* output = BIO_new(BIO_s_mem());
    if (output == nullptr
        || PEM_write_bio_PrivateKey(output, key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        if (output != nullptr) BIO_free(output);
        EVP_PKEY_free(key);
        return {};
    }
    BUF_MEM* buffer = nullptr;
    BIO_get_mem_ptr(output, &buffer);
    std::string pem;
    if (buffer != nullptr && buffer->data != nullptr && buffer->length != 0U) {
        pem.assign(buffer->data, buffer->length);
    }
    BIO_free(output);
    EVP_PKEY_free(key);
    return pem;
}

TEST(OidcProviderConfigTest, BuildsAppleEs256ClientSecretWithExpectedClaims)
{
    const fnd::Instant now{std::chrono::milliseconds{1'790'000'000'000LL}};
    const std::string pem = generatedP256PrivateKey();
    ASSERT_FALSE(pem.empty());
    auto configured = oidc::OidcProviderConfig::createApple(
        idp::ProviderId{"apple"}, "https://appleid.apple.com",
        "com.example.web", "TEAM123ABC", "KEY123ABCD", fnd::SecretString{pem},
        "https://identity.example.test/auth/federated/callback",
        std::vector<std::string>{"name", "email"},
        fnd::SecretString{std::string(32U, 'k')}, std::chrono::minutes{5});
    ASSERT_TRUE(configured) << configured.error().internalDetail();
    auto secret = configured->clientSecretAt(now);
    ASSERT_TRUE(secret) << secret.error().internalDetail();
    auto laterSecret = configured->clientSecretAt(now + std::chrono::hours{1});
    ASSERT_TRUE(laterSecret) << laterSecret.error().internalDetail();
    const std::string_view jwt = secret->expose();
    const auto firstDot = jwt.find('.');
    const auto secondDot = jwt.find('.', firstDot + 1U);
    ASSERT_NE(firstDot, std::string_view::npos);
    ASSERT_NE(secondDot, std::string_view::npos);
    auto headerBytes = fnd::fromBase64Url(jwt.substr(0U, firstDot));
    auto payloadBytes = fnd::fromBase64Url(
        jwt.substr(firstDot + 1U, secondDot - firstDot - 1U));
    ASSERT_TRUE(headerBytes);
    ASSERT_TRUE(payloadBytes);
    const std::string header{
        reinterpret_cast<const char*>(headerBytes->data()), headerBytes->size()};
    const std::string payload{
        reinterpret_cast<const char*>(payloadBytes->data()), payloadBytes->size()};
    EXPECT_NE(header.find(R"("alg":"ES256")"), std::string::npos);
    EXPECT_NE(header.find(R"("kid":"KEY123ABCD")"), std::string::npos);
    EXPECT_NE(payload.find(R"("iss":"TEAM123ABC")"), std::string::npos);
    EXPECT_NE(payload.find(R"("sub":"com.example.web")"), std::string::npos);
    EXPECT_NE(payload.find(R"("aud":"https://appleid.apple.com")"), std::string::npos);
    auto signature = fnd::fromBase64Url(jwt.substr(secondDot + 1U));
    ASSERT_TRUE(signature);
    EXPECT_EQ(signature->size(), 64U);
    EXPECT_NE(secret->expose(), laterSecret->expose());
}


TEST(OidcProviderConfigTest, RejectsInvalidAppleIdentifiersAndOverlongSecretLifetime)
{
    const std::string pem = generatedP256PrivateKey();
    ASSERT_FALSE(pem.empty());
    const fnd::Instant now{std::chrono::milliseconds{1'790'000'000'000LL}};
    EXPECT_FALSE(oidc::makeAppleClientSecret(
        "SHORT", "com.example.web", "KEY123ABCD", fnd::SecretString{pem}, now));
    EXPECT_FALSE(oidc::makeAppleClientSecret(
        "TEAM123ABC", "com.example.web", "SHORT", fnd::SecretString{pem}, now));
    EXPECT_FALSE(oidc::makeAppleClientSecret(
        "TEAM123ABC", "com.example.web", "KEY123ABCD", fnd::SecretString{pem}, now,
        std::chrono::seconds{15'777'001}));
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

TEST(OidcAuthenticationProviderTest, WrongProviderFailsBeforeDiscovery)
{
    auto config = configuration(
        "123456789", "telegram-client-secret",
        oidc::OidcClientAuthenticationMethod::ClientSecretBasic);
    ASSERT_TRUE(config);
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1'790'000'000'000LL}}};
    oidc::OidcAuthenticationProvider provider{std::move(config).value(), clock};
    idp::AuthenticationRequest request{
        idp::ProviderId{"github"}, idp::ClientContext{}};

    auto challenge = provider.beginAuthentication(request);

    ASSERT_FALSE(challenge);
    EXPECT_EQ(challenge.error().code(), fnd::ErrorCode::InvalidArgument);
}

}

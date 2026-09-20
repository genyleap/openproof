#include <gtest/gtest.h>

#include <chrono>
#include <optional>
#include <string>
#include <utility>

#include "../../src/providers/enterprise/presentation.hpp"

import openproof.foundation;
import openproof.identity.provider;
import openproof.provider.enterprise;

namespace {

namespace enterprise = openproof::provider::enterprise;
namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;

[[nodiscard]] fnd::SecretString derivationKey()
{
    return fnd::SecretString{std::string(32U, 'k')};
}

TEST(EnterprisePresentationClaimTest, AllowsSpacesAndUtf8WithinProfileLimit)
{
    using openproof::provider::enterprise::detail::safePresentationText;

    const std::string utf8Name = std::string{"Jos"} + "\xC3\xA9" + " Alvarez";
    EXPECT_TRUE(safePresentationText("Ada Lovelace"));
    EXPECT_TRUE(safePresentationText(utf8Name));
    EXPECT_TRUE(safePresentationText(std::string(256U, 'a')));
}

TEST(EnterprisePresentationClaimTest, RejectsControlCharactersAndOversizedValues)
{
    using openproof::provider::enterprise::detail::safePresentationText;

    EXPECT_FALSE(safePresentationText("Ada\nLovelace"));
    EXPECT_FALSE(safePresentationText(std::string(257U, 'a')));
    EXPECT_FALSE(safePresentationText(""));
}

TEST(EnterpriseSamlValidationTest, RequiresEveryAudienceRestrictionToPermitServiceProvider)
{
    using openproof::provider::enterprise::detail::samlAudienceRestrictionsPermit;

    const std::string expected{"https://sp.example.test/metadata"};
    EXPECT_TRUE(samlAudienceRestrictionsPermit(
        {{"https://other.example.test", expected},
         {expected, "https://partner.example.test"}},
        expected));
    EXPECT_FALSE(samlAudienceRestrictionsPermit(
        {{expected}, {"https://other.example.test"}},
        expected));
    EXPECT_FALSE(samlAudienceRestrictionsPermit(
        {{expected}, {}},
        expected));
    EXPECT_FALSE(samlAudienceRestrictionsPermit({}, expected));
}

TEST(EnterpriseSamlValidationTest, ValidatesEntityIssuerIdentityAndFormat)
{
    using openproof::provider::enterprise::detail::validSamlEntityIssuer;

    const std::string expected{"https://idp.example.test/entity"};
    EXPECT_TRUE(validSamlEntityIssuer(expected, std::nullopt, expected));
    EXPECT_TRUE(validSamlEntityIssuer(
        expected,
        std::optional<std::string>{
            "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"},
        expected));
    EXPECT_FALSE(validSamlEntityIssuer(
        "https://other.example.test/entity", std::nullopt, expected));
    EXPECT_FALSE(validSamlEntityIssuer(
        expected,
        std::optional<std::string>{
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"},
        expected));
}

TEST(EnterpriseLdapConfigTest, AcceptsCertificateVerifiedLdapsConfiguration)
{
    auto configured = enterprise::LdapProviderConfig::create(
        "ldaps://directory.example.test:636", "ou=people,dc=example,dc=test",
        "uid", "entryUUID", "cn", "mail", {}, {}, derivationKey(), {},
        std::chrono::minutes{5});

    ASSERT_TRUE(configured) << configured.error().internalDetail();
    EXPECT_EQ(configured->uri(), "ldaps://directory.example.test:636");
    EXPECT_EQ(configured->usernameAttribute(), "uid");
    EXPECT_EQ(configured->subjectAttribute(), "entryUUID");
}

TEST(EnterpriseLdapConfigTest, RejectsAmbiguousLdapsUrisAndMalformedBaseDns)
{
    const auto create = [](std::string uri, std::string baseDn) {
        return enterprise::LdapProviderConfig::create(
            std::move(uri), std::move(baseDn), "uid", "entryUUID", "cn", "mail",
            {}, {}, derivationKey(), {}, std::chrono::minutes{5});
    };

    EXPECT_TRUE(create("ldaps://directory.example.test:636",
                       "ou=people,dc=example,dc=test"));
    EXPECT_FALSE(create("ldaps:///", "dc=example,dc=test"));
    EXPECT_FALSE(create("ldaps://user@directory.example.test", "dc=example,dc=test"));
    EXPECT_FALSE(create("ldaps://directory.example.test:0", "dc=example,dc=test"));
    EXPECT_FALSE(create("ldaps://directory.example.test:70000", "dc=example,dc=test"));
    EXPECT_FALSE(create("ldaps://directory.example.test/path", "dc=example,dc=test"));
    EXPECT_FALSE(create("ldaps://directory.example.test ldap://fallback.example.test",
                        "dc=example,dc=test"));
    EXPECT_FALSE(create("ldaps://directory.example.test", "not-a-dn"));
    EXPECT_FALSE(create("ldaps://directory.example.test", "dc=example,"));
}

TEST(EnterpriseLdapConfigTest, RejectsPlaintextLdapAndHalfConfiguredServiceBind)
{
    auto plaintext = enterprise::LdapProviderConfig::create(
        "ldap://directory.example.test:389", "dc=example,dc=test",
        "uid", "entryUUID", "cn", "mail", {}, {}, derivationKey(), {},
        std::chrono::minutes{5});
    EXPECT_FALSE(plaintext);

    auto incompleteBind = enterprise::LdapProviderConfig::create(
        "ldaps://directory.example.test:636", "dc=example,dc=test",
        "uid", "entryUUID", "cn", "mail", "cn=reader,dc=example,dc=test", {},
        derivationKey(), {}, std::chrono::minutes{5});
    EXPECT_FALSE(incompleteBind);
}

TEST(EnterpriseSamlConfigTest, RejectsInsecureEndpointsBeforeTrustMaterialIsUsed)
{
    const std::string placeholderCertificate(128U, 'x');
    auto insecureAcs = enterprise::SamlProviderConfig::create(
        "https://sp.example.test/metadata", "http://sp.example.test/saml/acs",
        "https://idp.example.test/entity", "https://idp.example.test/sso",
        placeholderCertificate, derivationKey(), std::chrono::minutes{5},
        std::chrono::minutes{2});
    EXPECT_FALSE(insecureAcs);

    auto insecureSso = enterprise::SamlProviderConfig::create(
        "https://sp.example.test/metadata", "https://sp.example.test/saml/acs",
        "https://idp.example.test/entity", "http://idp.example.test/sso",
        placeholderCertificate, derivationKey(), std::chrono::minutes{5},
        std::chrono::minutes{2});
    EXPECT_FALSE(insecureSso);
}

TEST(EnterpriseSamlConfigTest, RejectsMalformedHttpsAuthoritiesAndTargets)
{
    const std::string placeholderCertificate(128U, 'x');
    const auto rejects = [&](std::string acs, std::string sso) {
        auto configured = enterprise::SamlProviderConfig::create(
            "https://sp.example.test/metadata", std::move(acs),
            "https://idp.example.test/entity", std::move(sso),
            placeholderCertificate, derivationKey(), std::chrono::minutes{5},
            std::chrono::minutes{2});
        EXPECT_FALSE(configured);
    };

    rejects("https:///saml/acs", "https://idp.example.test/sso");
    rejects("https://user@sp.example.test/saml/acs", "https://idp.example.test/sso");
    rejects("https://sp.example.test:70000/saml/acs", "https://idp.example.test/sso");
    rejects("https://sp.example.test/saml/acs#fragment", "https://idp.example.test/sso");
    rejects("https://sp.example.test/saml/acs with-space", "https://idp.example.test/sso");
    rejects("https://sp.example.test/saml/acs\nnext", "https://idp.example.test/sso");
    rejects("https://sp.example.test\\saml/acs", "https://idp.example.test/sso");
    rejects("https://sp.example.test/saml/acs", "https:///sso");
}

TEST(EnterpriseLdapAuthenticationTest, WrongProviderFailsBeforeDirectoryWork)
{
    auto config = enterprise::LdapProviderConfig::create(
        "ldaps://directory.example.test:636", "ou=people,dc=example,dc=test",
        "uid", "entryUUID", "cn", "mail", {}, {}, derivationKey(), {},
        std::chrono::minutes{5});
    ASSERT_TRUE(config);
    fnd::ManualClockSource clock{fnd::Instant{std::chrono::milliseconds{1'790'000'000'000LL}}};
    enterprise::LdapAuthenticationProvider provider{std::move(config).value(), clock};
    idp::AuthenticationRequest request{idp::ProviderId{"github"}, idp::ClientContext{}};
    request.setParameter("username", "alice");

    auto challenge = provider.beginAuthentication(request);

    ASSERT_FALSE(challenge);
    EXPECT_EQ(challenge.error().code(), fnd::ErrorCode::InvalidArgument);
}

} // namespace

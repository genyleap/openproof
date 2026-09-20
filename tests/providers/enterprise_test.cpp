#include <gtest/gtest.h>

#include <chrono>
#include <string>

import openproof.foundation;
import openproof.provider.enterprise;

namespace {

namespace enterprise = openproof::provider::enterprise;
namespace fnd = openproof::foundation;

[[nodiscard]] fnd::SecretString derivationKey()
{
    return fnd::SecretString{std::string(32U, 'k')};
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

} // namespace

#include <gtest/gtest.h>

#include <chrono>
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

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'790'000'000'000LL}};

constexpr std::string_view kTestSamlCertificate = R"PEM(-----BEGIN CERTIFICATE-----
MIIDHzCCAgegAwIBAgIUBJKj7JTCiPjZcBomcKCxohOWwfgwDQYJKoZIhvcNAQEL
BQAwHjEcMBoGA1UEAwwTb3BlbnByb29mLXRlc3Qtc2FtbDAgFw0yNjA5MjAwOTMw
MDRaGA8yMTI2MDgyNzA5MzAwNFowHjEcMBoGA1UEAwwTb3BlbnByb29mLXRlc3Qt
c2FtbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPy+InWShnjy4u9S
LAa1BeulmEBaTP3mJQeVFPVWx4S+X/Xl9BHvd2rd509zPxrAU8ajlRqchbY5fbUw
fY9vAuNooCqi+D4G7bxe0L4wDPJCyOtG6/Cl01vkjl/SxwokYrm371ZCz+H176Kh
bBfMYVJe12DkQ4UrF3ybIb6Szl6NsUqIJK2SD4eopG9WaZcNsSw5qAMepMXo9UkD
Bwt0Ne9hbGoNeQaJ3s/sTCcptfv9dx1cJXKLpQIeA5UMr5eYkXRXygN6um6wMeYY
8CMHYJL75eCzOBlPFCowTBwaT7Nner2MRK1nUInO/sWYJ+5JHFP0hDzvpTMeYzCJ
5puNIJ8CAwEAAaNTMFEwHQYDVR0OBBYEFHXoa7V+XzPoQr3fZl+xRCtd1mkbMB8G
A1UdIwQYMBaAFHXoa7V+XzPoQr3fZl+xRCtd1mkbMA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQELBQADggEBAB/diiPojz7mhKrENJLhZpYsib353+jxSX6Jqnm3
i39SFMb349Ck9s2ACLqDSaB/1xb6HMSdPbf+eF7Hh+X4B8DTf98+XfF/3lwJLXtE
DPbutLiNKbfHDcxSKxTjhAt7GJpfBbdXM+ntoBLdbqmoFV0+BRyMIZpbJPnpH+fA
TcRd8Xi5xuO89h6tVcZ/M4V/6lQnD9+q23nWv5rj8eoCRvEOw/vwlh+RAYiva/VD
KF9nzO9/dLHCUokl1v/CXCATO4jH/o7Io3CBN4vh0lsTMR3JOZdf8Ew9mzMy2VCT
zY2uu7puTA4+599VFzdWsRZEviMNAAEEbSjwjGfAMpM8/08=
-----END CERTIFICATE-----)PEM";

[[nodiscard]] enterprise::LdapProviderConfig ldapConfiguration()
{
    return enterprise::LdapProviderConfig::create(
        "ldaps://directory.example.test:636", "ou=people,dc=example,dc=test",
        "uid", "entryUUID", "cn", "mail", {}, {}, derivationKey(), {},
        std::chrono::minutes{5}).value();
}

[[nodiscard]] enterprise::SamlProviderConfig samlConfiguration()
{
    return enterprise::SamlProviderConfig::create(
        "https://sp.example.test/metadata", "https://sp.example.test/saml/acs",
        "https://idp.example.test/entity", "https://idp.example.test/sso",
        std::string{kTestSamlCertificate}, derivationKey(), std::chrono::minutes{5},
        std::chrono::minutes{2}).value();
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

TEST(EnterpriseLdapAuthenticationTest, ChallengeIsSingleUseAndProviderBound)
{
    fnd::ManualClockSource clock{kNow};
    enterprise::LdapAuthenticationProvider provider{ldapConfiguration(), clock};
    idp::AuthenticationRequest wrong{idp::ProviderId{"github"}, idp::ClientContext{}};
    wrong.setParameter("username", "alice");
    EXPECT_FALSE(provider.beginAuthentication(wrong));

    idp::AuthenticationRequest request{idp::ProviderId{"ldap"}, idp::ClientContext{}};
    request.setParameter("username", "alice");
    auto challenge = provider.beginAuthentication(request);
    ASSERT_TRUE(challenge);
    idp::AuthenticationResponse completion{challenge->id(), idp::ClientContext{}};

    auto first = provider.completeAuthentication(completion);
    ASSERT_FALSE(first);
    EXPECT_NE(first.error().internalDetail().find("incomplete"), std::string::npos);
    auto replay = provider.completeAuthentication(completion);
    ASSERT_FALSE(replay);
    EXPECT_NE(replay.error().internalDetail().find("already used"), std::string::npos);
}

TEST(EnterpriseLdapAuthenticationTest, ExpiredChallengeIsConsumedBeforeCredentials)
{
    fnd::ManualClockSource clock{kNow};
    enterprise::LdapAuthenticationProvider provider{ldapConfiguration(), clock};
    idp::AuthenticationRequest request{idp::ProviderId{"ldap"}, idp::ClientContext{}};
    request.setParameter("username", "alice");
    auto challenge = provider.beginAuthentication(request);
    ASSERT_TRUE(challenge);
    clock.advance(std::chrono::minutes{5});
    idp::AuthenticationResponse completion{challenge->id(), idp::ClientContext{}};
    auto expired = provider.completeAuthentication(completion);
    ASSERT_FALSE(expired);
    EXPECT_NE(expired.error().internalDetail().find("challenge expired"), std::string::npos);
}

TEST(EnterpriseSamlAuthenticationTest, ChallengeIsSingleUseAndProviderBound)
{
    fnd::ManualClockSource clock{kNow};
    enterprise::SamlAuthenticationProvider provider{samlConfiguration(), clock};
    idp::AuthenticationRequest wrong{idp::ProviderId{"github"}, idp::ClientContext{}};
    EXPECT_FALSE(provider.beginAuthentication(wrong));

    idp::AuthenticationRequest request{idp::ProviderId{"saml"}, idp::ClientContext{}};
    auto challenge = provider.beginAuthentication(request);
    ASSERT_TRUE(challenge);
    idp::AuthenticationResponse completion{challenge->id(), idp::ClientContext{}};
    auto first = provider.completeAuthentication(completion);
    ASSERT_FALSE(first);
    EXPECT_NE(first.error().internalDetail().find("incomplete"), std::string::npos);
    auto replay = provider.completeAuthentication(completion);
    ASSERT_FALSE(replay);
    EXPECT_NE(replay.error().internalDetail().find("already used"), std::string::npos);
}

TEST(EnterpriseSamlAuthenticationTest, ExpiredChallengeIsConsumedBeforeXmlParsing)
{
    fnd::ManualClockSource clock{kNow};
    enterprise::SamlAuthenticationProvider provider{samlConfiguration(), clock};
    idp::AuthenticationRequest request{idp::ProviderId{"saml"}, idp::ClientContext{}};
    auto challenge = provider.beginAuthentication(request);
    ASSERT_TRUE(challenge);
    clock.advance(std::chrono::minutes{5});
    idp::AuthenticationResponse completion{challenge->id(), idp::ClientContext{}};
    auto expired = provider.completeAuthentication(completion);
    ASSERT_FALSE(expired);
    EXPECT_NE(expired.error().internalDetail().find("challenge expired"), std::string::npos);
}

} // namespace

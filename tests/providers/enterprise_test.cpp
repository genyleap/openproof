#include <gtest/gtest.h>
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <memory>
#include <future>


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

TEST(EnterpriseLdapConfigTest, InvalidCaPathCannotCreateAnOperationalProvider)
{
    auto config = enterprise::LdapProviderConfig::create(
        "ldaps://directory.example.invalid:636", "dc=example,dc=invalid",
        "uid", "entryUUID", "cn", "mail", {}, {}, derivationKey(),
        "/dev/null/openproof-invalid-ca.pem", std::chrono::minutes{5});
    ASSERT_TRUE(config);
    fnd::ManualClockSource clock{fnd::Instant{std::chrono::milliseconds{1770000000000LL}}};
    enterprise::LdapAuthenticationProvider provider{std::move(config).value(), clock};
    EXPECT_FALSE(provider.nativeTrustReady());
    idp::AuthenticationRequest request{idp::ProviderId{"ldap"}, idp::ClientContext{}};
    request.setParameter("username", "fixture-user");
    const auto denied = provider.beginAuthentication(request);
    ASSERT_FALSE(denied);
    EXPECT_EQ(denied.error().code(), fnd::ErrorCode::Unavailable);
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

TEST(EnterpriseSamlAuthenticationTest, NativeWorkerUsesExistingVerifierAndRejectsInvalidAssertion)
{
    namespace asio=boost::asio;
    std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key{
        EVP_PKEY_Q_keygen(nullptr,nullptr,"RSA",std::size_t{2048U}),EVP_PKEY_free};
    ASSERT_TRUE(key);
    std::unique_ptr<X509,decltype(&X509_free)> cert{X509_new(),X509_free};
    ASSERT_TRUE(cert);
    ASSERT_EQ(X509_set_version(cert.get(),2),1);
    ASSERT_EQ(ASN1_INTEGER_set(X509_get_serialNumber(cert.get()),1),1);
    ASSERT_NE(X509_gmtime_adj(X509_getm_notBefore(cert.get()),-60),nullptr);
    ASSERT_NE(X509_gmtime_adj(X509_getm_notAfter(cert.get()),3600),nullptr);
    ASSERT_EQ(X509_set_pubkey(cert.get(),key.get()),1);
    auto* name=X509_get_subject_name(cert.get());
    ASSERT_NE(name,nullptr);
    ASSERT_EQ(X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("SAML test IdP"),-1,-1,0),1);
    ASSERT_EQ(X509_set_issuer_name(cert.get(),name),1);
    ASSERT_GT(X509_sign(cert.get(),key.get(),EVP_sha256()),0);
    std::unique_ptr<BIO,decltype(&BIO_free)> pem{BIO_new(BIO_s_mem()),BIO_free};
    ASSERT_TRUE(pem);
    ASSERT_EQ(PEM_write_bio_X509(pem.get(),cert.get()),1);
    char* bytes=nullptr;
    const auto length=BIO_get_mem_data(pem.get(),&bytes);
    ASSERT_GT(length,0);
    auto config=enterprise::SamlProviderConfig::create(
        "https://sp.example.test/metadata","https://sp.example.test/saml/acs",
        "https://idp.example.test/entity","https://idp.example.test/sso",
        std::string{bytes,static_cast<std::size_t>(length)},derivationKey(),
        std::chrono::minutes{5},std::chrono::minutes{2});
    ASSERT_TRUE(config);
    fnd::SystemClockSource clock;
    enterprise::SamlAuthenticationProvider provider{std::move(config).value(),clock};
    EXPECT_EQ(provider.redirectProofKind(),idp::RedirectProofKind::SamlAssertion);
    asio::io_context io;
    auto run=[&]<class T>(asio::awaitable<T> task) {
        std::optional<T> result;
        auto capture=[](asio::awaitable<T> op,std::optional<T>& output)->asio::awaitable<void>{
            output.emplace(co_await std::move(op));
        };
        io.restart();
        auto completed=asio::co_spawn(io,capture(std::move(task),result),asio::use_future);
        io.run();
        completed.get();
        return std::move(result.value());
    };
    auto challenge=run(provider.beginAuthenticationAsync(
        idp::AuthenticationRequest{idp::ProviderId{"saml"},idp::ClientContext{}}));
    ASSERT_TRUE(challenge);
    const auto& url=challenge->parameters().at("authorization_url");
    const auto marker=url.find("&RelayState=");
    ASSERT_NE(marker,std::string::npos);
    const auto relay=url.substr(marker+12U);
    ASSERT_FALSE(relay.empty());
    // Correctly bound RelayState, base64 "not xml": reaches the original
    // XML verifier on the bounded worker instead of only a preflight denial.
    idp::AuthenticationResponse proof{challenge->id(),idp::ClientContext{}};
    proof.setParameter("SAMLResponse",idp::CredentialValue{"bm90IHhtbA=="});
    proof.setParameter("RelayState",idp::CredentialValue{relay});
    const auto sync=provider.completeAuthentication(proof);
    ASSERT_FALSE(sync);
    auto denied=run(provider.completeAuthenticationAsync(std::move(proof)));
    ASSERT_FALSE(denied);
    EXPECT_EQ(denied.error().code(),sync.error().code());
    EXPECT_EQ(denied.error().internalDetail(),sync.error().internalDetail());
    EXPECT_EQ(denied.error().internalDetail(),"The SAML XML document is invalid.");
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

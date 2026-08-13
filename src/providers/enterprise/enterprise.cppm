module;

#include <memory>
#include <string>
#include <string_view>

export module openproof.provider.enterprise;

import openproof.foundation;
import openproof.identity.provider;

export namespace openproof::provider::enterprise {

/** @brief Validated LDAPS search-then-bind authentication configuration. */
class LdapProviderConfig final {
public:
    [[nodiscard]] static foundation::Result<LdapProviderConfig> create(
        std::string uri, std::string baseDn, std::string usernameAttribute,
        std::string subjectAttribute, std::string displayNameAttribute,
        std::string emailAttribute, std::string serviceBindDn,
        foundation::SecretString serviceBindPassword, foundation::SecretString derivationKey,
        std::string caFile, foundation::Duration challengeLifetime);

    [[nodiscard]] std::string_view uri() const noexcept;
    [[nodiscard]] std::string_view baseDn() const noexcept;
    [[nodiscard]] std::string_view usernameAttribute() const noexcept;
    [[nodiscard]] std::string_view subjectAttribute() const noexcept;
    [[nodiscard]] std::string_view displayNameAttribute() const noexcept;
    [[nodiscard]] std::string_view emailAttribute() const noexcept;
    [[nodiscard]] std::string_view serviceBindDn() const noexcept;
    [[nodiscard]] const foundation::SecretString& serviceBindPassword() const noexcept;
    [[nodiscard]] const foundation::SecretString& derivationKey() const noexcept;
    [[nodiscard]] std::string_view caFile() const noexcept;
    [[nodiscard]] foundation::Duration challengeLifetime() const noexcept;

    LdapProviderConfig(const LdapProviderConfig&) = delete;
    LdapProviderConfig& operator=(const LdapProviderConfig&) = delete;
    LdapProviderConfig(LdapProviderConfig&&) noexcept = default;
    LdapProviderConfig& operator=(LdapProviderConfig&&) noexcept = default;

private:
    friend class LdapAuthenticationProvider;
    LdapProviderConfig(std::string uri, std::string baseDn, std::string usernameAttribute,
                       std::string subjectAttribute, std::string displayNameAttribute,
                       std::string emailAttribute, std::string serviceBindDn,
                       foundation::SecretString serviceBindPassword, foundation::SecretString derivationKey,
                       std::string caFile, foundation::Duration challengeLifetime);

    std::string m_uri;
    std::string m_baseDn;
    std::string m_usernameAttribute;
    std::string m_subjectAttribute;
    std::string m_displayNameAttribute;
    std::string m_emailAttribute;
    std::string m_serviceBindDn;
    foundation::SecretString m_serviceBindPassword;
    foundation::SecretString m_derivationKey;
    std::string m_caFile;
    foundation::Duration m_challengeLifetime{};
};

/** @brief Enterprise LDAP authentication over certificate-verified LDAPS. */
class LdapAuthenticationProvider final : public identity::provider::AuthenticationProvider {
public:
    LdapAuthenticationProvider(LdapProviderConfig config,
                               const foundation::ClockSource& clock);
    ~LdapAuthenticationProvider() override;

    [[nodiscard]] identity::provider::ProviderId id() const override;
    [[nodiscard]] identity::provider::InteractionModel interactionModel() const noexcept override;
    [[nodiscard]] identity::provider::AssuranceLevel maximumClaimableAssurance() const noexcept override;
    [[nodiscard]] foundation::Result<identity::provider::AuthenticationChallenge>
    beginAuthentication(const identity::provider::AuthenticationRequest& request) override;
    [[nodiscard]] foundation::Result<identity::provider::AuthenticationOutcome>
    completeAuthentication(const identity::provider::AuthenticationResponse& response) override;

private:
    class Implementation;
    std::unique_ptr<Implementation> m_implementation;
};

/** @brief Validated SAML 2.0 Web Browser SSO service-provider configuration. */
class SamlProviderConfig final {
public:
    [[nodiscard]] static foundation::Result<SamlProviderConfig> create(
        std::string spEntityId, std::string assertionConsumerServiceUri,
        std::string idpEntityId, std::string idpSsoUrl,
        std::string idpCertificatePem, foundation::SecretString derivationKey,
        foundation::Duration challengeLifetime, foundation::Duration clockSkew);

    SamlProviderConfig(const SamlProviderConfig&) = delete;
    SamlProviderConfig& operator=(const SamlProviderConfig&) = delete;
    SamlProviderConfig(SamlProviderConfig&&) noexcept = default;
    SamlProviderConfig& operator=(SamlProviderConfig&&) noexcept = default;

private:
    friend class SamlAuthenticationProvider;
    SamlProviderConfig(std::string spEntityId, std::string assertionConsumerServiceUri,
                       std::string idpEntityId, std::string idpSsoUrl,
                       std::string idpCertificatePem,
                       foundation::SecretString derivationKey,
                       foundation::Duration challengeLifetime,
                       foundation::Duration clockSkew);

    std::string m_spEntityId;
    std::string m_acsUri;
    std::string m_idpEntityId;
    std::string m_idpSsoUrl;
    std::string m_idpCertificatePem;
    foundation::SecretString m_derivationKey;
    foundation::Duration m_challengeLifetime{};
    foundation::Duration m_clockSkew{};
};

/** @brief SAML 2.0 Redirect/AuthnRequest + POST/XMLDSIG authentication provider. */
class SamlAuthenticationProvider final : public identity::provider::AuthenticationProvider {
public:
    SamlAuthenticationProvider(SamlProviderConfig config,
                               const foundation::ClockSource& clock);
    ~SamlAuthenticationProvider() override;

    [[nodiscard]] identity::provider::ProviderId id() const override;
    [[nodiscard]] identity::provider::InteractionModel interactionModel() const noexcept override;
    [[nodiscard]] identity::provider::AssuranceLevel maximumClaimableAssurance() const noexcept override;
    [[nodiscard]] foundation::Result<identity::provider::AuthenticationChallenge>
    beginAuthentication(const identity::provider::AuthenticationRequest& request) override;
    [[nodiscard]] foundation::Result<identity::provider::AuthenticationOutcome>
    completeAuthentication(const identity::provider::AuthenticationResponse& response) override;

private:
    class Implementation;
    std::unique_ptr<Implementation> m_implementation;
};

} // namespace openproof::provider::enterprise

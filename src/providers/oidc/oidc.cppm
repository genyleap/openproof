module;

#include <memory>
#include <string>
#include <string_view>
#include <vector>

export module openproof.provider.oidc;

import openproof.foundation;
import openproof.identity.provider;

export namespace openproof::provider::oidc {

/** @brief Client authentication used at the upstream token endpoint. */
enum class OidcClientAuthenticationMethod {
    ClientSecretPost,
    ClientSecretBasic,
};

/** @brief Validated configuration for an external OpenID Connect authentication provider. */
class OidcProviderConfig final {
public:
    [[nodiscard]] static foundation::Result<OidcProviderConfig> create(
        identity::provider::ProviderId providerId, std::string issuer,
        std::string clientId, foundation::SecretString clientSecret,
        std::string callbackUri, std::vector<std::string> scopes,
        foundation::SecretString derivationKey,
        foundation::Duration challengeLifetime,
        OidcClientAuthenticationMethod clientAuthentication =
            OidcClientAuthenticationMethod::ClientSecretPost);

    OidcProviderConfig(const OidcProviderConfig&) = delete;
    OidcProviderConfig& operator=(const OidcProviderConfig&) = delete;
    OidcProviderConfig(OidcProviderConfig&&) noexcept = default;
    OidcProviderConfig& operator=(OidcProviderConfig&&) noexcept = default;

    [[nodiscard]] const identity::provider::ProviderId& providerId() const noexcept;
    [[nodiscard]] std::string_view issuer() const noexcept;
    [[nodiscard]] std::string_view clientId() const noexcept;
    [[nodiscard]] const foundation::SecretString& clientSecret() const noexcept;
    [[nodiscard]] std::string_view callbackUri() const noexcept;
    [[nodiscard]] const std::vector<std::string>& scopes() const noexcept;
    [[nodiscard]] const foundation::SecretString& derivationKey() const noexcept;
    [[nodiscard]] foundation::Duration challengeLifetime() const noexcept;
    [[nodiscard]] OidcClientAuthenticationMethod clientAuthentication() const noexcept;

private:
    friend class OidcAuthenticationProvider;
    OidcProviderConfig(identity::provider::ProviderId providerId, std::string issuer,
                       std::string clientId, foundation::SecretString clientSecret,
                       std::string callbackUri, std::vector<std::string> scopes,
                       foundation::SecretString derivationKey,
                       foundation::Duration challengeLifetime,
                       OidcClientAuthenticationMethod clientAuthentication);

    identity::provider::ProviderId m_providerId;
    std::string m_issuer;
    std::string m_clientId;
    foundation::SecretString m_clientSecret;
    std::string m_callbackUri;
    std::vector<std::string> m_scopes;
    foundation::SecretString m_derivationKey;
    foundation::Duration m_challengeLifetime{};
    OidcClientAuthenticationMethod m_clientAuthentication{
        OidcClientAuthenticationMethod::ClientSecretPost};
};

/**
 * @brief Discovery-driven OIDC Authorization Code provider with PKCE and nonce validation.
 *
 * Discovery metadata, token responses and JWKS are fetched over verified TLS. ID Tokens are
 * accepted only after RS256 signature, issuer, audience, expiry, issued-at and nonce checks.
 */
class OidcAuthenticationProvider final : public identity::provider::AuthenticationProvider {
public:
    OidcAuthenticationProvider(OidcProviderConfig config,
                               const foundation::ClockSource& clock,
                               std::string caFile = {});
    ~OidcAuthenticationProvider() override;

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

} // namespace openproof::provider::oidc

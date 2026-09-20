module;

#include <chrono>
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

/** @brief Browser response transport expected from the upstream authorization endpoint. */
enum class OidcAuthorizationResponseMode {
    Query,
    FormPost,
};

/** @brief Proof Key for Code Exchange policy for the upstream authorization code flow. */
enum class OidcPkceMode {
    S256,
    Disabled,
};

/**
 * Builds a Sign in with Apple OAuth client secret using the required ES256 JWT.
 * The default lifetime is one hour because a fresh credential is generated for
 * every token exchange; callers may request a longer value within Apple's limit.
 */
[[nodiscard]] foundation::Result<foundation::SecretString> makeAppleClientSecret(
    std::string teamId, std::string clientId, std::string keyId,
    foundation::SecretString privateKeyPem, foundation::Instant now,
    foundation::Duration lifetime = std::chrono::hours{1});

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
            OidcClientAuthenticationMethod::ClientSecretPost,
        OidcAuthorizationResponseMode authorizationResponseMode =
            OidcAuthorizationResponseMode::Query,
        OidcPkceMode pkceMode = OidcPkceMode::S256);

    [[nodiscard]] static foundation::Result<OidcProviderConfig> createApple(
        identity::provider::ProviderId providerId, std::string issuer,
        std::string clientId, std::string teamId, std::string keyId,
        foundation::SecretString privateKeyPem, std::string callbackUri,
        std::vector<std::string> scopes, foundation::SecretString derivationKey,
        foundation::Duration challengeLifetime);

    OidcProviderConfig(const OidcProviderConfig&) = delete;
    OidcProviderConfig& operator=(const OidcProviderConfig&) = delete;
    OidcProviderConfig(OidcProviderConfig&&) noexcept = default;
    OidcProviderConfig& operator=(OidcProviderConfig&&) noexcept = default;

    [[nodiscard]] const identity::provider::ProviderId& providerId() const noexcept;
    [[nodiscard]] std::string_view issuer() const noexcept;
    [[nodiscard]] std::string_view clientId() const noexcept;
    [[nodiscard]] const foundation::SecretString& clientSecret() const noexcept;
    [[nodiscard]] foundation::Result<foundation::SecretString>
    clientSecretAt(foundation::Instant now) const;
    [[nodiscard]] std::string_view callbackUri() const noexcept;
    [[nodiscard]] const std::vector<std::string>& scopes() const noexcept;
    [[nodiscard]] const foundation::SecretString& derivationKey() const noexcept;
    [[nodiscard]] foundation::Duration challengeLifetime() const noexcept;
    [[nodiscard]] OidcClientAuthenticationMethod clientAuthentication() const noexcept;
    [[nodiscard]] OidcAuthorizationResponseMode authorizationResponseMode() const noexcept;
    [[nodiscard]] OidcPkceMode pkceMode() const noexcept;

private:
    friend class OidcAuthenticationProvider;
    OidcProviderConfig(identity::provider::ProviderId providerId, std::string issuer,
                       std::string clientId, foundation::SecretString clientSecret,
                       std::string callbackUri, std::vector<std::string> scopes,
                       foundation::SecretString derivationKey,
                       foundation::Duration challengeLifetime,
                       OidcClientAuthenticationMethod clientAuthentication,
                       OidcAuthorizationResponseMode authorizationResponseMode,
                       OidcPkceMode pkceMode);

    identity::provider::ProviderId m_providerId;
    std::string m_issuer;
    std::string m_clientId;
    foundation::SecretString m_clientSecret;
    bool m_dynamicAppleClientSecret{false};
    std::string m_appleTeamId;
    std::string m_appleKeyId;
    foundation::SecretString m_applePrivateKey;
    std::string m_callbackUri;
    std::vector<std::string> m_scopes;
    foundation::SecretString m_derivationKey;
    foundation::Duration m_challengeLifetime{};
    OidcClientAuthenticationMethod m_clientAuthentication{
        OidcClientAuthenticationMethod::ClientSecretPost};
    OidcAuthorizationResponseMode m_authorizationResponseMode{
        OidcAuthorizationResponseMode::Query};
    OidcPkceMode m_pkceMode{OidcPkceMode::S256};
};

/**
 * @brief Discovery-driven OIDC Authorization Code provider with nonce validation and configurable PKCE.
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

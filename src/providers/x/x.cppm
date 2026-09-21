module;

#include <memory>
#include <string>
#include <string_view>

export module openproof.provider.x;

import openproof.foundation;
import openproof.identity.provider;

export namespace openproof::provider::x {

/** @brief Validated X OAuth 1.0a three-legged browser-login configuration. */
class XProviderConfig final {
public:
    [[nodiscard]] static foundation::Result<XProviderConfig> create(
        std::string apiKey, foundation::SecretString apiSecret,
        std::string callbackUri, foundation::SecretString derivationKey,
        foundation::Duration challengeLifetime);

    XProviderConfig(const XProviderConfig&) = delete;
    XProviderConfig& operator=(const XProviderConfig&) = delete;
    XProviderConfig(XProviderConfig&&) noexcept = default;
    XProviderConfig& operator=(XProviderConfig&&) noexcept = default;

    [[nodiscard]] std::string_view apiKey() const noexcept;
    [[nodiscard]] const foundation::SecretString& apiSecret() const noexcept;
    [[nodiscard]] std::string_view callbackUri() const noexcept;
    [[nodiscard]] const foundation::SecretString& derivationKey() const noexcept;
    [[nodiscard]] foundation::Duration challengeLifetime() const noexcept;

private:
    XProviderConfig(std::string apiKey, foundation::SecretString apiSecret,
                    std::string callbackUri, foundation::SecretString derivationKey,
                    foundation::Duration challengeLifetime);

    std::string m_apiKey;
    foundation::SecretString m_apiSecret;
    std::string m_callbackUri;
    foundation::SecretString m_derivationKey;
    foundation::Duration m_challengeLifetime{};
};

/**
 * @brief X OAuth 1.0a three-legged identity provider.
 *
 * The provider intentionally stops at oauth/access_token. That response itself
 * supplies the stable X user id and screen name, so OpenProof does not call a
 * profile/user lookup endpoint just to establish identity.
 */
class XAuthenticationProvider final : public identity::provider::AuthenticationProvider {
public:
    XAuthenticationProvider(XProviderConfig config,
                            const foundation::ClockSource& clock,
                            std::string caFile = {});
    ~XAuthenticationProvider() override;

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

} // namespace openproof::provider::x

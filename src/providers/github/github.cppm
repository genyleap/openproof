module;

#include <memory>
#include <string>
#include <string_view>

export module openproof.provider.github;

import openproof.foundation;
import openproof.identity.provider;

export namespace openproof::provider::github {

/** @brief Validated GitHub OAuth browser-login configuration. */
class GitHubProviderConfig final {
public:
    [[nodiscard]] static foundation::Result<GitHubProviderConfig> create(
        std::string clientId, foundation::SecretString clientSecret,
        std::string callbackUri, foundation::SecretString derivationKey,
        foundation::Duration challengeLifetime);

    GitHubProviderConfig(const GitHubProviderConfig&) = delete;
    GitHubProviderConfig& operator=(const GitHubProviderConfig&) = delete;
    GitHubProviderConfig(GitHubProviderConfig&&) noexcept = default;
    GitHubProviderConfig& operator=(GitHubProviderConfig&&) noexcept = default;

    [[nodiscard]] std::string_view clientId() const noexcept;
    [[nodiscard]] const foundation::SecretString& clientSecret() const noexcept;
    [[nodiscard]] std::string_view callbackUri() const noexcept;
    [[nodiscard]] const foundation::SecretString& derivationKey() const noexcept;
    [[nodiscard]] foundation::Duration challengeLifetime() const noexcept;

private:
    GitHubProviderConfig(std::string clientId, foundation::SecretString clientSecret,
                         std::string callbackUri, foundation::SecretString derivationKey,
                         foundation::Duration challengeLifetime);

    std::string m_clientId;
    foundation::SecretString m_clientSecret;
    std::string m_callbackUri;
    foundation::SecretString m_derivationKey;
    foundation::Duration m_challengeLifetime{};
};

/** @brief GitHub OAuth Authorization Code + PKCE identity provider. */
class GitHubAuthenticationProvider final : public identity::provider::AuthenticationProvider {
public:
    GitHubAuthenticationProvider(GitHubProviderConfig config,
                                 const foundation::ClockSource& clock,
                                 std::string caFile = {});
    ~GitHubAuthenticationProvider() override;

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

} // namespace openproof::provider::github

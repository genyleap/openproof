module;

#include <string>
#include <string_view>
#include <vector>

export module openproof.examples.tegra.identity;

import openproof.foundation;
import openproof.sdk;

export namespace openproof::examples::tegra {

/**
 * @brief Minimal identity adapter demonstrating how Tegra consumes OpenProof.
 *
 * Tegra owns its product data. Authentication, PKCE, state validation and
 * OpenID user lookup are delegated to OpenProof through the SDK.
 */
class IdentityAdapter final {
public:
    /** @brief Creates a Tegra adapter for one registered public OAuth client. */
    [[nodiscard]] static foundation::Result<IdentityAdapter>
    create(std::string issuer, std::string clientId, std::string redirectUri);

    /** @brief Starts the central OpenProof login transaction. */
    [[nodiscard]] foundation::Result<sdk::AuthorizationSession> beginLogin() const;

    /** @brief Builds the token exchange after Tegra receives its callback. */
    [[nodiscard]] foundation::Result<sdk::HttpRequest>
    completeLogin(std::string_view authorizationCode,
                  const sdk::AuthorizationSession& session,
                  std::string_view returnedState,
                  std::string_view returnedIssuer) const;

    /** @brief Builds the OpenID UserInfo request for the authenticated user. */
    [[nodiscard]] foundation::Result<sdk::HttpRequest>
    userInfo(const foundation::SecretString& accessToken) const;

private:
    explicit IdentityAdapter(sdk::IdentityClient client);
    sdk::IdentityClient m_client;
};

}

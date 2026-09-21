module;

#include <string>
#include <string_view>
#include <vector>

export module openproof.examples.reference.identity;

import openproof.foundation;
import openproof.sdk;

export namespace openproof::examples::reference {

/**
 * @brief Minimal adapter showing how an application consumes OpenProof.
 *
 * The application owns its product data. Authentication, PKCE, state validation,
 * token exchange and OpenID user lookup remain delegated to OpenProof.
 */
class IdentityAdapter final {
public:
    /** @brief Creates an adapter for one registered public OAuth client. */
    [[nodiscard]] static foundation::Result<IdentityAdapter>
    create(std::string issuer, std::string clientId, std::string redirectUri);

    /** @brief Starts an Authorization Code + PKCE login transaction. */
    [[nodiscard]] foundation::Result<sdk::AuthorizationSession> beginLogin() const;

    /** @brief Builds the token exchange after the application receives its callback. */
    [[nodiscard]] foundation::Result<sdk::HttpRequest>
    completeLogin(std::string_view authorizationCode,
                  const sdk::AuthorizationSession& session,
                  std::string_view returnedState,
                  std::string_view returnedIssuer) const;

    /** @brief Builds the OpenID UserInfo request for an authenticated user. */
    [[nodiscard]] foundation::Result<sdk::HttpRequest>
    userInfo(const foundation::SecretString& accessToken) const;

private:
    explicit IdentityAdapter(sdk::IdentityClient client);
    sdk::IdentityClient m_client;
};

}

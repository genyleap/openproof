module;

#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.examples.tegra.identity;

namespace openproof::examples::tegra {

IdentityAdapter::IdentityAdapter(sdk::IdentityClient client)
    : m_client(std::move(client))
{
}

foundation::Result<IdentityAdapter> IdentityAdapter::create(
    std::string issuer, std::string clientId, std::string redirectUri)
{
    auto config = sdk::ClientConfig::create(
        std::move(issuer), std::move(clientId), std::move(redirectUri),
        std::vector<std::string>{"openid", "profile", "email"});
    if (!config) {
        return foundation::fail(config.error());
    }
    return IdentityAdapter{sdk::IdentityClient{std::move(config).value()}};
}

foundation::Result<sdk::AuthorizationSession> IdentityAdapter::beginLogin() const
{
    return m_client.beginLogin();
}

foundation::Result<sdk::HttpRequest> IdentityAdapter::completeLogin(
    std::string_view authorizationCode,
    const sdk::AuthorizationSession& session,
    std::string_view returnedState, std::string_view returnedIssuer) const
{
    return m_client.authorizationCodeRequest(
        authorizationCode, session, returnedState, returnedIssuer);
}

foundation::Result<sdk::HttpRequest>
IdentityAdapter::userInfo(const foundation::SecretString& accessToken) const
{
    return m_client.userInfoRequest(accessToken);
}

}

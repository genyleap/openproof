module;

#include <string>
#include <string_view>
#include <vector>

export module openproof.sdk;

import openproof.foundation;

export namespace openproof::sdk {

/** @brief Public-client configuration for Authorization Code + PKCE. */
class ClientConfig final {
public:
    ClientConfig(const ClientConfig& other);
    ClientConfig(ClientConfig&& other);
    ClientConfig& operator=(const ClientConfig& other);
    ClientConfig& operator=(ClientConfig&& other);
    ~ClientConfig();

    [[nodiscard]] static foundation::Result<ClientConfig>
    create(std::string issuer, std::string clientId, std::string redirectUri,
           std::vector<std::string> scopes);
    [[nodiscard]] std::string_view issuer() const noexcept;
    [[nodiscard]] std::string_view clientId() const noexcept;
    [[nodiscard]] std::string_view redirectUri() const noexcept;
    [[nodiscard]] const std::vector<std::string>& scopes() const noexcept;
private:
    ClientConfig(std::string issuer, std::string clientId, std::string redirectUri,
                 std::vector<std::string> scopes);
    std::string m_issuer;
    std::string m_clientId;
    std::string m_redirectUri;
    std::vector<std::string> m_scopes;
};

/** @brief Move-only browser/native authorization transaction. */
class AuthorizationSession final {
public:
    AuthorizationSession(const AuthorizationSession&) = delete;
    AuthorizationSession& operator=(const AuthorizationSession&) = delete;
    AuthorizationSession(AuthorizationSession&& other) noexcept;
    AuthorizationSession& operator=(AuthorizationSession&& other) noexcept;
    ~AuthorizationSession();
    [[nodiscard]] std::string_view authorizationUrl() const noexcept;
    [[nodiscard]] const foundation::SecretString& codeVerifier() const noexcept;
    [[nodiscard]] const foundation::SecretString& state() const noexcept;
    [[nodiscard]] std::string_view nonce() const noexcept;
private:
    friend class IdentityClient;
    AuthorizationSession(std::string authorizationUrl,
                         foundation::SecretString codeVerifier,
                         foundation::SecretString state, std::string nonce);
    std::string m_authorizationUrl;
    foundation::SecretString m_codeVerifier;
    foundation::SecretString m_state;
    std::string m_nonce;
};

/**
 * @brief Transport-neutral request description with explicit secret ownership.
 *
 * Token request bodies and bearer credentials are move-only secrets so an SDK
 * consumer cannot accidentally log or copy them while adapting to its HTTP
 * stack.
 */
struct HttpRequest final {
    HttpRequest(const HttpRequest&) = delete;
    HttpRequest& operator=(const HttpRequest&) = delete;
    HttpRequest(HttpRequest&& other) noexcept;
    HttpRequest& operator=(HttpRequest&& other) noexcept;
    ~HttpRequest();

    HttpRequest(std::string method, std::string url, std::string contentType,
                foundation::SecretString body, std::string authorizationScheme,
                foundation::SecretString authorizationCredential);

    std::string method;
    std::string url;
    std::string contentType;
    foundation::SecretString body;
    std::string authorizationScheme;
    foundation::SecretString authorizationCredential;
};

/** @brief Protocol helper shared by desktop, mobile and server-side products. */
class IdentityClient final {
public:
    explicit IdentityClient(ClientConfig config);
    [[nodiscard]] foundation::Result<AuthorizationSession>
    beginLogin() const;
    [[nodiscard]] foundation::Result<HttpRequest>
    authorizationCodeRequest(std::string_view code,
                             const AuthorizationSession& session,
                             std::string_view returnedState,
                             std::string_view returnedIssuer) const;
    [[nodiscard]] foundation::Result<HttpRequest>
    refreshRequest(const foundation::SecretString& refreshToken) const;
    [[nodiscard]] foundation::Result<HttpRequest>
    userInfoRequest(const foundation::SecretString& accessToken) const;
private:
    ClientConfig m_config;
};

}

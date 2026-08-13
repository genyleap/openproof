module;

#include <optional>
#include <string>
#include <vector>

export module openproof.client:service;

import openproof.application;
import openproof.foundation;
import openproof.security;
import :model;
import :repository;

export namespace openproof::client {

class ClientSecretKey final {
public:
    ~ClientSecretKey();
    [[nodiscard]] static foundation::Result<ClientSecretKey>
    create(foundation::SecretString key);
    ClientSecretKey(const ClientSecretKey&) = delete;
    ClientSecretKey& operator=(const ClientSecretKey&) = delete;
    ClientSecretKey(ClientSecretKey&& other) noexcept;
    ClientSecretKey& operator=(ClientSecretKey&& other) noexcept;
private:
    friend class ClientManager;
    explicit ClientSecretKey(foundation::SecretString key);
    foundation::SecretString m_key;
};

class ClientRegistration final {
public:
    ~ClientRegistration();
    ClientRegistration(const ClientRegistration&) = delete;
    ClientRegistration& operator=(const ClientRegistration&) = delete;
    ClientRegistration(ClientRegistration&& other) noexcept;
    ClientRegistration& operator=(ClientRegistration&& other) noexcept;

    [[nodiscard]] const Client& client() const noexcept;
    [[nodiscard]] const std::optional<foundation::SecretString>& secret() const noexcept;
private:
    friend class ClientManager;
    ClientRegistration(Client client, std::optional<foundation::SecretString> secret);
    Client m_client;
    std::optional<foundation::SecretString> m_secret;
};

class ClientManager final {
public:
    ClientManager(ClientRepository& clients,
                  application::ApplicationRepository& applications,
                  const foundation::ClockSource& clock, ClientSecretKey secretKey);

    [[nodiscard]] foundation::Result<ClientRegistration>
    registerClient(const application::ApplicationId& applicationId,
                   std::string displayName, ClientKind kind,
                   std::vector<std::string> redirectUris,
                   std::vector<std::string> scopes);

    [[nodiscard]] foundation::Result<foundation::SecretString>
    rotateSecret(const ClientId& id);
    [[nodiscard]] foundation::Result<Client> suspend(const ClientId& id);
    [[nodiscard]] foundation::Result<Client> activate(const ClientId& id);
    [[nodiscard]] foundation::Result<Client> revoke(const ClientId& id);

    [[nodiscard]] foundation::Result<Client>
    authenticate(const ClientId& id,
                 const std::optional<foundation::SecretString>& presentedSecret) const;

    [[nodiscard]] foundation::Result<Client> requireActive(const ClientId& id) const;

private:
    [[nodiscard]] foundation::Result<Client> require(const ClientId& id) const;
    [[nodiscard]] foundation::Result<ClientSecretDigest>
    digest(const foundation::SecretString& secret) const;

    ClientRepository* m_clients;
    application::ApplicationRepository* m_applications;
    const foundation::ClockSource* m_clock;
    ClientSecretKey m_secretKey;
};

}

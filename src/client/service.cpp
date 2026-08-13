module;

#include <optional>
#include <string>
#include <utility>
#include <vector>

module openproof.client;

namespace openproof::client {

ClientSecretKey::ClientSecretKey(ClientSecretKey&& other) noexcept
    : m_key(std::move(other.m_key))
{
}
ClientSecretKey& ClientSecretKey::operator=(ClientSecretKey&& other) noexcept
{
    if (this != &other) m_key = std::move(other.m_key);
    return *this;
}
ClientSecretKey::~ClientSecretKey() {}

ClientRegistration::ClientRegistration(ClientRegistration&& other) noexcept
    : m_client(std::move(other.m_client))
    , m_secret(std::move(other.m_secret))
{
}
ClientRegistration& ClientRegistration::operator=(ClientRegistration&& other) noexcept
{
    if (this != &other) {
        m_client = std::move(other.m_client);
        m_secret = std::move(other.m_secret);
    }
    return *this;
}
ClientRegistration::~ClientRegistration() {}

ClientSecretKey::ClientSecretKey(foundation::SecretString key)
    : m_key(std::move(key))
{
}

foundation::Result<ClientSecretKey> ClientSecretKey::create(foundation::SecretString key)
{
    if (key.expose().size() < 32U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A client-secret key must contain at least 32 bytes.");
    }
    return ClientSecretKey{std::move(key)};
}

ClientRegistration::ClientRegistration(
    Client client, std::optional<foundation::SecretString> secret)
    : m_client(std::move(client)), m_secret(std::move(secret))
{
}

const Client& ClientRegistration::client() const noexcept { return m_client; }
const std::optional<foundation::SecretString>& ClientRegistration::secret() const noexcept
{ return m_secret; }

ClientManager::ClientManager(ClientRepository& clients,
                             application::ApplicationRepository& applications,
                             const foundation::ClockSource& clock,
                             ClientSecretKey secretKey)
    : m_clients(&clients)
    , m_applications(&applications)
    , m_clock(&clock)
    , m_secretKey(std::move(secretKey))
{
}

foundation::Result<ClientSecretDigest>
ClientManager::digest(const foundation::SecretString& secret) const
{
    if (secret.empty()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    }
    auto digest = security::hmacSha256(m_secretKey.m_key, secret.expose());
    if (!digest) return foundation::fail(digest.error());
    return ClientSecretDigest{digest.value()};
}

foundation::Result<ClientRegistration> ClientManager::registerClient(
    const application::ApplicationId& applicationId, std::string displayName,
    ClientKind kind, std::vector<std::string> redirectUris,
    std::vector<std::string> scopes)
{
    auto application = m_applications->findById(applicationId);
    if (!application) return foundation::fail(application.error());
    if (!application->has_value() || !application->value().permitsAuthorization()) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The application is unavailable for client registration.");
    }

    std::vector<RedirectUri> parsedRedirects;
    parsedRedirects.reserve(redirectUris.size());
    for (std::string& value : redirectUris) {
        auto parsed = RedirectUri::create(std::move(value), kind);
        if (!parsed) return foundation::fail(parsed.error());
        parsedRedirects.push_back(std::move(parsed).value());
    }
    std::vector<Scope> parsedScopes;
    parsedScopes.reserve(scopes.size());
    for (std::string& value : scopes) {
        auto parsed = Scope::create(std::move(value));
        if (!parsed) return foundation::fail(parsed.error());
        parsedScopes.push_back(std::move(parsed).value());
    }

    auto randomId = security::randomTokenBase64Url(24U);
    if (!randomId) return foundation::fail(randomId.error());
    ClientId id{"opc_" + randomId.value()};

    std::optional<foundation::SecretString> plaintext;
    std::optional<ClientSecretDigest> secretDigest;
    if (!clientIsPublic(kind)) {
        auto generated = security::randomTokenBase64Url(32U);
        if (!generated) return foundation::fail(generated.error());
        plaintext.emplace("ops_" + std::move(generated).value());
        auto calculated = digest(plaintext.value());
        if (!calculated) return foundation::fail(calculated.error());
        secretDigest = calculated.value();
    }

    auto client = Client::create(
        id, applicationId, std::move(displayName), kind,
        std::move(parsedRedirects), std::move(parsedScopes),
        secretDigest, m_clock->now());
    if (!client) return foundation::fail(client.error());
    auto stored = m_clients->add(client.value());
    if (!stored) return foundation::fail(stored.error());
    return ClientRegistration{std::move(client).value(), std::move(plaintext)};
}

foundation::Result<foundation::SecretString>
ClientManager::rotateSecret(const ClientId& id)
{
    auto found = m_clients->findById(id);
    if (!found) return foundation::fail(found.error());
    if (!found->has_value()) return foundation::fail(foundation::ErrorCode::NotFound);
    Client client = found->value();
    if (client.isPublic()) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "Public clients do not have client secrets.");
    }
    auto generated = security::randomTokenBase64Url(32U);
    if (!generated) return foundation::fail(generated.error());
    foundation::SecretString secret{"ops_" + std::move(generated).value()};
    auto calculated = digest(secret);
    if (!calculated) return foundation::fail(calculated.error());
    auto changed = client.replaceSecret(calculated.value(), m_clock->now());
    if (!changed) return foundation::fail(changed.error());
    auto saved = m_clients->save(client);
    if (!saved) return foundation::fail(saved.error());
    return secret;
}


foundation::Result<Client> ClientManager::require(const ClientId& id) const
{
    auto found = m_clients->findById(id);
    if (!found) return foundation::fail(found.error());
    if (!found->has_value()) return foundation::fail(foundation::ErrorCode::NotFound);
    return found->value();
}

foundation::Result<Client> ClientManager::suspend(const ClientId& id)
{
    auto value = require(id);
    if (!value) return foundation::fail(value.error());
    auto changed = value->suspend(m_clock->now());
    if (!changed) return foundation::fail(changed.error());
    auto saved = m_clients->save(value.value());
    if (!saved) return foundation::fail(saved.error());
    return value;
}

foundation::Result<Client> ClientManager::activate(const ClientId& id)
{
    auto value = require(id);
    if (!value) return foundation::fail(value.error());
    auto changed = value->activate(m_clock->now());
    if (!changed) return foundation::fail(changed.error());
    auto saved = m_clients->save(value.value());
    if (!saved) return foundation::fail(saved.error());
    return value;
}

foundation::Result<Client> ClientManager::revoke(const ClientId& id)
{
    auto value = require(id);
    if (!value) return foundation::fail(value.error());
    auto changed = value->revoke(m_clock->now());
    if (!changed) return foundation::fail(changed.error());
    auto saved = m_clients->save(value.value());
    if (!saved) return foundation::fail(saved.error());
    return value;
}

foundation::Result<Client> ClientManager::requireActive(const ClientId& id) const
{
    auto found = m_clients->findById(id);
    if (!found) return foundation::fail(found.error());
    if (!found->has_value() || !found->value().permitsAuthorization()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "Client authentication failed.");
    }
    auto application = m_applications->findById(found->value().applicationId());
    if (!application) return foundation::fail(application.error());
    if (!application->has_value() || !application->value().permitsAuthorization()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "Client authentication failed.");
    }
    return found->value();
}

foundation::Result<Client> ClientManager::authenticate(
    const ClientId& id,
    const std::optional<foundation::SecretString>& presentedSecret) const
{
    auto client = requireActive(id);
    if (!client) return foundation::fail(client.error());
    if (client->isPublic()) {
        if (presentedSecret.has_value()) {
            return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                    "Client authentication failed.");
        }
        return client;
    }
    if (!presentedSecret.has_value() || !client->secretDigest().has_value()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "Client authentication failed.");
    }
    auto calculated = digest(presentedSecret.value());
    if (!calculated
        || !security::constantTimeEquals(
            calculated->bytes(), client->secretDigest()->bytes())) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "Client authentication failed.");
    }
    return client;
}

}

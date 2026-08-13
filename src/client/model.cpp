module;

#include <array>

#include <chrono>
#include <algorithm>
#include <cctype>
#include <compare>
#include <memory>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.client;

namespace openproof::client {
namespace {

[[nodiscard]] bool validDisplayName(std::string_view value) noexcept
{
    if (value.empty() || value.size() > 120U) return false;
    return std::ranges::none_of(value, [](char symbol) {
        const auto byte = static_cast<unsigned char>(symbol);
        return byte < 0x20U || byte == 0x7FU;
    });
}

[[nodiscard]] bool allDigits(std::string_view value) noexcept
{
    return !value.empty() && std::ranges::all_of(value, [](char symbol) {
        return symbol >= '0' && symbol <= '9';
    });
}

[[nodiscard]] bool validPort(std::string_view value) noexcept
{
    if (!allDigits(value) || value.size() > 5U) return false;
    unsigned int port = 0U;
    for (char symbol : value) {
        port = (port * 10U) + static_cast<unsigned int>(symbol - '0');
    }
    return port > 0U && port <= 65535U;
}

struct Authority final {
    std::string_view host;
    std::optional<std::string_view> port;
};

[[nodiscard]] std::optional<Authority> authority(
    std::string_view uri, std::string_view scheme) noexcept
{
    if (!uri.starts_with(scheme)) return std::nullopt;
    const auto rest = uri.substr(scheme.size());
    const auto end = rest.find_first_of("/?");
    const auto value = rest.substr(0U, end);
    if (value.empty() || value.contains('@')) return std::nullopt;

    if (value.front() == '[') {
        const auto close = value.find(']');
        if (close == std::string_view::npos) return std::nullopt;
        const auto host = value.substr(0U, close + 1U);
        if (close + 1U == value.size()) return Authority{host, std::nullopt};
        if (value[close + 1U] != ':') return std::nullopt;
        const auto port = value.substr(close + 2U);
        if (!validPort(port)) return std::nullopt;
        return Authority{host, port};
    }

    const auto colon = value.rfind(':');
    if (colon == std::string_view::npos) return Authority{value, std::nullopt};
    const auto host = value.substr(0U, colon);
    const auto port = value.substr(colon + 1U);
    if (host.empty() || host.contains(':') || !validPort(port)) return std::nullopt;
    return Authority{host, port};
}

[[nodiscard]] bool validHttps(std::string_view uri) noexcept
{
    const auto parsed = authority(uri, "https://");
    return parsed.has_value() && !parsed->host.empty();
}

[[nodiscard]] bool loopbackHost(std::string_view host) noexcept
{
    return host == "127.0.0.1" || host == "[::1]";
}

[[nodiscard]] bool loopbackHttp(std::string_view uri) noexcept
{
    const auto parsed = authority(uri, "http://");
    return parsed.has_value() && parsed->port.has_value() && loopbackHost(parsed->host);
}

struct LoopbackRedirect final {
    std::string_view host;
    std::string_view pathAndQuery;
};

[[nodiscard]] std::optional<LoopbackRedirect>
parseLoopbackRedirect(std::string_view uri) noexcept
{
    constexpr std::string_view scheme{"http://"};
    const auto parsed = authority(uri, scheme);
    if (!parsed.has_value() || !parsed->port.has_value() || !loopbackHost(parsed->host)) {
        return std::nullopt;
    }
    const auto rest = uri.substr(scheme.size());
    const auto end = rest.find_first_of("/?");
    const std::string_view suffix = end == std::string_view::npos
        ? std::string_view{} : rest.substr(end);
    return LoopbackRedirect{parsed->host, suffix};
}

[[nodiscard]] bool sameNativeLoopbackRedirect(
    std::string_view registered, std::string_view presented) noexcept
{
    const auto expected = parseLoopbackRedirect(registered);
    const auto actual = parseLoopbackRedirect(presented);
    return expected.has_value() && actual.has_value()
        && expected->host == actual->host
        && expected->pathAndQuery == actual->pathAndQuery;
}

}

std::string_view clientKindName(ClientKind kind) noexcept
{
    switch (kind) {
    case ClientKind::Web: return "web";
    case ClientKind::Native: return "native";
    case ClientKind::Browser: return "browser";
    case ClientKind::Service: return "service";
    }
    return "web";
}

bool clientIsPublic(ClientKind kind) noexcept
{
    return kind == ClientKind::Native || kind == ClientKind::Browser;
}

std::string_view clientStatusName(ClientStatus status) noexcept
{
    switch (status) {
    case ClientStatus::Active: return "active";
    case ClientStatus::Suspended: return "suspended";
    case ClientStatus::Revoked: return "revoked";
    }
    return "revoked";
}

bool clientPermitsAuthorization(ClientStatus status) noexcept
{
    return status == ClientStatus::Active;
}

Scope::Scope(const Scope& other) : m_value(other.m_value) {}
Scope::Scope(Scope&& other) : m_value(std::move(other.m_value)) {}
Scope& Scope::operator=(const Scope& other)
{
    if (this != &other) m_value = other.m_value;
    return *this;
}
Scope& Scope::operator=(Scope&& other)
{
    if (this != &other) m_value = std::move(other.m_value);
    return *this;
}
Scope::~Scope() {}

RedirectUri::RedirectUri(const RedirectUri& other) : m_value(other.m_value) {}
RedirectUri::RedirectUri(RedirectUri&& other) : m_value(std::move(other.m_value)) {}
RedirectUri& RedirectUri::operator=(const RedirectUri& other)
{
    if (this != &other) m_value = other.m_value;
    return *this;
}
RedirectUri& RedirectUri::operator=(RedirectUri&& other)
{
    if (this != &other) m_value = std::move(other.m_value);
    return *this;
}
RedirectUri::~RedirectUri() {}

Scope::Scope(std::string value) : m_value(std::move(value)) {}

foundation::Result<Scope> Scope::create(std::string value)
{
    if (value.empty() || value.size() > 128U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The OAuth scope is invalid.");
    }
    for (char symbol : value) {
        const auto byte = static_cast<unsigned char>(symbol);
        if (!(byte == 0x21U || (byte >= 0x23U && byte <= 0x5BU)
              || (byte >= 0x5DU && byte <= 0x7EU))) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The OAuth scope is invalid.");
        }
    }
    return Scope{std::move(value)};
}

std::string_view Scope::value() const noexcept { return m_value; }

RedirectUri::RedirectUri(std::string value) : m_value(std::move(value)) {}

foundation::Result<RedirectUri> RedirectUri::create(std::string value,
                                                     ClientKind clientKind)
{
    if (value.empty() || value.size() > 2048U || value.contains('#')
        || value.contains('\\')
        || std::ranges::any_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte <= 0x20U || byte == 0x7FU;
           })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The redirect URI is invalid.");
    }
    const bool https = validHttps(value);
    const bool nativeLoopback = clientKind == ClientKind::Native && loopbackHttp(value);
    if (!https && !nativeLoopback) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Redirect URIs require HTTPS except native loopback callbacks.");
    }
    if (clientKind == ClientKind::Service) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Service clients do not use redirect URIs.");
    }
    return RedirectUri{std::move(value)};
}

std::string_view RedirectUri::value() const noexcept { return m_value; }

struct Client::State final {
    ClientId id;
    application::ApplicationId applicationId;
    std::string displayName;
    ClientKind kind{ClientKind::Web};
    ClientStatus status{ClientStatus::Active};
    std::vector<RedirectUri> redirectUris;
    std::vector<Scope> scopes;
    std::optional<ClientSecretDigest> secretDigest;
    foundation::Instant createdAt{};
    foundation::Instant updatedAt{};
};

Client::Client(ClientId id, application::ApplicationId applicationId,
               std::string displayName, ClientKind kind,
               std::vector<RedirectUri> redirectUris, std::vector<Scope> scopes,
               std::optional<ClientSecretDigest> secretDigest,
               foundation::Instant createdAt)
    : m_state(std::make_shared<State>(State{
          .id = std::move(id),
          .applicationId = std::move(applicationId),
          .displayName = std::move(displayName),
          .kind = kind,
          .status = ClientStatus::Active,
          .redirectUris = std::move(redirectUris),
          .scopes = std::move(scopes),
          .secretDigest = std::move(secretDigest),
          .createdAt = createdAt,
          .updatedAt = createdAt}))
{
}

void Client::detach()
{
    if (!m_state.unique()) {
        m_state = std::make_shared<State>(*m_state);
    }
}

foundation::Result<Client> Client::create(
    ClientId id, application::ApplicationId applicationId,
    std::string displayName, ClientKind kind,
    std::vector<RedirectUri> redirectUris, std::vector<Scope> scopes,
    std::optional<ClientSecretDigest> secretDigest,
    foundation::Instant createdAt)
{
    if (id.empty() || applicationId.empty() || !validDisplayName(displayName)
        || scopes.empty() || scopes.size() > 64U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The client registration is invalid.");
    }
    if (kind == ClientKind::Service) {
        if (!redirectUris.empty() || !secretDigest.has_value()) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "A service client requires a secret and no redirect URI.");
        }
    } else if (redirectUris.empty() || redirectUris.size() > 32U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The client redirect registration is invalid.");
    }
    if (clientIsPublic(kind) && secretDigest.has_value()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Public clients must not rely on a client secret.");
    }
    if (!clientIsPublic(kind) && !secretDigest.has_value()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Confidential clients require a client secret.");
    }

    std::ranges::sort(redirectUris);
    if (std::ranges::adjacent_find(redirectUris) != redirectUris.end()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Redirect URIs must be unique.");
    }
    std::ranges::sort(scopes);
    if (std::ranges::adjacent_find(scopes) != scopes.end()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Client scopes must be unique.");
    }
    return Client{std::move(id), std::move(applicationId), std::move(displayName),
                  kind, std::move(redirectUris), std::move(scopes),
                  std::move(secretDigest), createdAt};
}

foundation::Result<Client> Client::restore(
    ClientId id, application::ApplicationId applicationId,
    std::string displayName, ClientKind kind, ClientStatus status,
    std::vector<RedirectUri> redirectUris, std::vector<Scope> scopes,
    std::optional<ClientSecretDigest> secretDigest,
    foundation::Instant createdAt, foundation::Instant updatedAt)
{
    auto restored = create(std::move(id), std::move(applicationId),
                           std::move(displayName), kind, std::move(redirectUris),
                           std::move(scopes), std::move(secretDigest), createdAt);
    if (!restored) return foundation::fail(restored.error());
    if (updatedAt < createdAt) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "Stored client timestamps are invalid.");
    }
    restored->m_state->status = status;
    restored->m_state->updatedAt = updatedAt;
    return restored;
}

const ClientId& Client::id() const noexcept { return m_state->id; }
const application::ApplicationId& Client::applicationId() const noexcept
{ return m_state->applicationId; }
std::string_view Client::displayName() const noexcept { return m_state->displayName; }
ClientKind Client::kind() const noexcept { return m_state->kind; }
ClientStatus Client::status() const noexcept { return m_state->status; }
bool Client::isPublic() const noexcept { return clientIsPublic(m_state->kind); }
bool Client::permitsAuthorization() const noexcept
{ return clientPermitsAuthorization(m_state->status); }
const std::vector<RedirectUri>& Client::redirectUris() const noexcept
{ return m_state->redirectUris; }
const std::vector<Scope>& Client::scopes() const noexcept { return m_state->scopes; }
const std::optional<ClientSecretDigest>& Client::secretDigest() const noexcept
{ return m_state->secretDigest; }
foundation::Instant Client::createdAt() const noexcept { return m_state->createdAt; }
foundation::Instant Client::updatedAt() const noexcept { return m_state->updatedAt; }

bool Client::permitsRedirect(std::string_view redirectUri) const noexcept
{
    return std::ranges::any_of(m_state->redirectUris, [&](const RedirectUri& item) {
        if (item.value() == redirectUri) return true;
        return m_state->kind == ClientKind::Native
            && sameNativeLoopbackRedirect(item.value(), redirectUri);
    });
}

bool Client::permitsScope(std::string_view scope) const noexcept
{
    return std::ranges::any_of(m_state->scopes, [scope](const Scope& item) {
        return item.value() == scope;
    });
}

bool Client::permitsScopes(const std::vector<Scope>& requested) const noexcept
{
    return std::ranges::all_of(requested, [this](const Scope& scope) {
        return permitsScope(scope.value());
    });
}

foundation::Status Client::suspend(foundation::Instant now)
{
    detach();
    if (m_state->status != ClientStatus::Active || now < m_state->updatedAt) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The client cannot be suspended.");
    }
    m_state->status = ClientStatus::Suspended;
    m_state->updatedAt = now;
    return foundation::ok();
}

foundation::Status Client::activate(foundation::Instant now)
{
    detach();
    if (m_state->status != ClientStatus::Suspended || now < m_state->updatedAt) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The client cannot be activated.");
    }
    m_state->status = ClientStatus::Active;
    m_state->updatedAt = now;
    return foundation::ok();
}

foundation::Status Client::revoke(foundation::Instant now)
{
    detach();
    if (m_state->status == ClientStatus::Revoked || now < m_state->updatedAt) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The client cannot be revoked.");
    }
    m_state->status = ClientStatus::Revoked;
    m_state->updatedAt = now;
    return foundation::ok();
}

foundation::Status Client::replaceSecret(ClientSecretDigest digest,
                                         foundation::Instant now)
{
    detach();
    if (isPublic() || m_state->status == ClientStatus::Revoked || now < m_state->updatedAt) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The client secret cannot be replaced.");
    }
    m_state->secretDigest = std::move(digest);
    m_state->updatedAt = now;
    return foundation::ok();
}

}

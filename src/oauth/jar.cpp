module;

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

module openproof.oauth;

#ifndef OPENPROOF_OAUTH_MODULE_ABI_REV
#error "OPENPROOF_OAUTH_MODULE_ABI_REV must be defined by the openproof_oauth target."
#endif

static_assert(OPENPROOF_OAUTH_MODULE_ABI_REV == 3,
              "The OAuth JAR implementation and build graph are out of sync.");

namespace openproof::oauth {

namespace {

struct ClientRequestSigningKeyState final {
    ClientRequestSigningKeyState(
        openproof::client::ClientId clientIdValue, std::string keyIdValue,
        std::string publicKeyPemValue, openproof::foundation::Instant updatedAtValue)
        : clientId(std::move(clientIdValue)),
          keyId(std::move(keyIdValue)),
          publicKeyPem(std::move(publicKeyPemValue)),
          updatedAt(updatedAtValue)
    {
    }

    openproof::client::ClientId clientId;
    std::string keyId;
    std::string publicKeyPem;
    openproof::foundation::Instant updatedAt{};
};

[[nodiscard]] const ClientRequestSigningKeyState& keyState(
    const std::shared_ptr<const void>& state) noexcept
{
    return *static_cast<const ClientRequestSigningKeyState*>(state.get());
}

} // namespace

ClientRequestSigningKey::ClientRequestSigningKey(std::shared_ptr<const void> state) noexcept
    : m_state(std::move(state))
{
}

foundation::Result<ClientRequestSigningKey> ClientRequestSigningKey::create(
    client::ClientId clientId, std::string keyId, std::string publicKeyPem,
    foundation::Instant updatedAt)
{
    if (clientId.empty() || keyId.empty() || keyId.size() > 128U
        || publicKeyPem.empty() || publicKeyPem.size() > 16U * 1024U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The JAR signing key registration is invalid.");
    }

    std::shared_ptr<const void> state = std::make_shared<ClientRequestSigningKeyState>(
        std::move(clientId), std::move(keyId), std::move(publicKeyPem), updatedAt);
    ClientRequestSigningKey value{std::move(state)};
    return foundation::Result<ClientRequestSigningKey>{std::move(value)};
}

const client::ClientId& ClientRequestSigningKey::clientId() const noexcept
{
    return keyState(m_state).clientId;
}

std::string_view ClientRequestSigningKey::keyId() const noexcept
{
    return keyState(m_state).keyId;
}

std::string_view ClientRequestSigningKey::publicKeyPem() const noexcept
{
    return keyState(m_state).publicKeyPem;
}

foundation::Instant ClientRequestSigningKey::updatedAt() const noexcept
{
    return keyState(m_state).updatedAt;
}

JarService::JarService(ClientRequestSigningKeyStore& keys, JarReplayStore& replays,
                       const foundation::ClockSource& clock)
    : m_keys(&keys), m_replays(&replays), m_clock(&clock) {}
foundation::Status JarService::registerKey(
    const client::ClientId& clientId, std::string keyId, std::string publicKeyPem)
{
    auto verifiedKey = security::validateRs256PublicKey(publicKeyPem);
    if (!verifiedKey) {
        return foundation::fail(verifiedKey.error());
    }

    auto key = ClientRequestSigningKey::create(
        clientId, std::move(keyId), std::move(publicKeyPem), m_clock->now());
    if (!key) {
        return foundation::fail(key.error());
    }
    return m_keys->save(std::move(key).value());
}
foundation::Status JarService::removeKey(const client::ClientId& clientId)
{
    return m_keys->remove(clientId);
}
foundation::Result<ClientRequestSigningKey> JarService::key(
    const client::ClientId& clientId) const
{
    auto found = m_keys->find(clientId);
    if (!found) {
        return foundation::fail(found.error());
    }
    if (!found->has_value()) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The OAuth client has no registered JAR signing key.");
    }
    return foundation::Result<ClientRequestSigningKey>{std::move(found->value())};
}
foundation::Result<security::VerifiedCompactJws> JarService::verify(
    const client::ClientId& clientId, std::string_view compactJwt) const
{
    auto registered = key(clientId);
    if (!registered) {
        return foundation::fail(registered.error());
    }
    return security::verifyRs256Jwt(registered->publicKeyPem(), compactJwt);
}
foundation::Status JarService::consumeReplay(
    const client::ClientId& clientId, std::string_view jwtId,
    foundation::Instant issuedAt, foundation::Instant expiresAt)
{
    const auto now = m_clock->now();
    constexpr auto clockSkew = std::chrono::seconds{60};
    constexpr auto maximumLifetime = std::chrono::minutes{10};
    if (jwtId.empty() || jwtId.size() > 256U || expiresAt <= now
        || issuedAt > now + clockSkew || issuedAt < now - maximumLifetime
        || expiresAt > issuedAt + maximumLifetime) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The JAR temporal or replay claims are invalid.");
    }
    return m_replays->consume(clientId, jwtId, expiresAt, now);
}

}

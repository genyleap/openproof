module;

#include <memory>
#include <optional>
#include <string>
#include <string_view>

export module openproof.oauth:jar;

import openproof.client;
import openproof.foundation;
import openproof.security;

#ifndef OPENPROOF_OAUTH_MODULE_ABI_REV
#error "OPENPROOF_OAUTH_MODULE_ABI_REV must be defined by the openproof_oauth target."
#endif

static_assert(OPENPROOF_OAUTH_MODULE_ABI_REV == 3,
              "The OAuth JAR module interface and build graph are out of sync.");

export namespace openproof::oauth {

/** @brief Pinned RS256 public key registered for OAuth JWT-secured authorization requests. */
class ClientRequestSigningKey final {
public:
    ClientRequestSigningKey(const ClientRequestSigningKey&) = default;
    ClientRequestSigningKey& operator=(const ClientRequestSigningKey&) = default;
    ClientRequestSigningKey(ClientRequestSigningKey&&) noexcept = default;
    ClientRequestSigningKey& operator=(ClientRequestSigningKey&&) noexcept = default;
    ~ClientRequestSigningKey() = default;

    [[nodiscard]] static foundation::Result<ClientRequestSigningKey> create(
        client::ClientId clientId, std::string keyId, std::string publicKeyPem,
        foundation::Instant updatedAt);
    [[nodiscard]] const client::ClientId& clientId() const noexcept;
    [[nodiscard]] std::string_view keyId() const noexcept;
    [[nodiscard]] std::string_view publicKeyPem() const noexcept;
    [[nodiscard]] foundation::Instant updatedAt() const noexcept;

private:
    explicit ClientRequestSigningKey(std::shared_ptr<const void> state) noexcept;

    std::shared_ptr<const void> m_state;
};

class ClientRequestSigningKeyStore {
public:
    ClientRequestSigningKeyStore(const ClientRequestSigningKeyStore&) = delete;
    ClientRequestSigningKeyStore& operator=(const ClientRequestSigningKeyStore&) = delete;
    virtual ~ClientRequestSigningKeyStore() = default;
    [[nodiscard]] virtual foundation::Status save(ClientRequestSigningKey key) = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<ClientRequestSigningKey>> find(
        const client::ClientId& clientId) const = 0;
    [[nodiscard]] virtual foundation::Status remove(const client::ClientId& clientId) = 0;
protected:
    ClientRequestSigningKeyStore() = default;
};

/** @brief Durable replay boundary for JWT authorization request jti values. */
class JarReplayStore {
public:
    JarReplayStore(const JarReplayStore&) = delete;
    JarReplayStore& operator=(const JarReplayStore&) = delete;
    virtual ~JarReplayStore() = default;
    [[nodiscard]] virtual foundation::Status consume(
        const client::ClientId& clientId, std::string_view jwtId,
        foundation::Instant expiresAt, foundation::Instant now) = 0;
protected:
    JarReplayStore() = default;
};

/** @brief Registered-key and replay orchestration for RFC 9101 request objects. */
class JarService final {
public:
    JarService(ClientRequestSigningKeyStore& keys, JarReplayStore& replays,
               const foundation::ClockSource& clock);
    [[nodiscard]] foundation::Status registerKey(
        const client::ClientId& clientId, std::string keyId, std::string publicKeyPem);
    [[nodiscard]] foundation::Status removeKey(const client::ClientId& clientId);
    [[nodiscard]] foundation::Result<ClientRequestSigningKey> key(
        const client::ClientId& clientId) const;
    [[nodiscard]] foundation::Result<security::VerifiedCompactJws> verify(
        const client::ClientId& clientId, std::string_view compactJwt) const;
    [[nodiscard]] foundation::Status consumeReplay(
        const client::ClientId& clientId, std::string_view jwtId,
        foundation::Instant issuedAt, foundation::Instant expiresAt);
private:
    ClientRequestSigningKeyStore* m_keys;
    JarReplayStore* m_replays;
    const foundation::ClockSource* m_clock;
};

}

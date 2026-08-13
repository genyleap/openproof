module;

#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.oauth:device;

import openproof.client;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.session;

export namespace openproof::oauth {

/** @brief Non-reversible fingerprint of a Device Authorization device code. */
class DeviceCodeDigest final {
public:
    explicit DeviceCodeDigest(std::array<std::byte, 32> value) noexcept;
    [[nodiscard]] const std::array<std::byte, 32>& bytes() const noexcept;
    friend bool operator==(const DeviceCodeDigest&, const DeviceCodeDigest&) noexcept = default;
private:
    std::array<std::byte, 32> m_value{};
};

/** @brief Non-reversible fingerprint of the human-entered device user code. */
class DeviceUserCodeDigest final {
public:
    explicit DeviceUserCodeDigest(std::array<std::byte, 32> value) noexcept;
    [[nodiscard]] const std::array<std::byte, 32>& bytes() const noexcept;
    friend bool operator==(const DeviceUserCodeDigest&, const DeviceUserCodeDigest&) noexcept = default;
private:
    std::array<std::byte, 32> m_value{};
};

enum class DeviceAuthorizationStatus {
    Pending,
    Approved,
    Denied,
    Consumed,
};

/** @brief Durable state for one RFC 8628 device authorization ceremony. */
class DeviceAuthorization final {
public:
    [[nodiscard]] static foundation::Result<DeviceAuthorization> create(
        DeviceCodeDigest deviceCode, DeviceUserCodeDigest userCode,
        client::ClientId clientId, std::vector<client::Scope> scopes,
        std::optional<std::string> resource, foundation::Instant issuedAt,
        foundation::Duration lifetime, foundation::Duration pollInterval);

    [[nodiscard]] static foundation::Result<DeviceAuthorization> restore(
        DeviceCodeDigest deviceCode, DeviceUserCodeDigest userCode,
        client::ClientId clientId, std::vector<client::Scope> scopes,
        std::optional<std::string> resource, foundation::Instant issuedAt,
        foundation::Instant expiresAt, foundation::Duration pollInterval,
        DeviceAuthorizationStatus status,
        std::optional<identity::core::IdentityId> identity,
        std::optional<identity::provider::ProviderId> provider,
        std::optional<identity::provider::AssuranceLevel> assurance,
        std::optional<identity::provider::AuthenticationStrength> strength,
        std::optional<foundation::Instant> authenticatedAt,
        std::optional<foundation::Instant> lastPollAt);

    [[nodiscard]] const DeviceCodeDigest& deviceCode() const noexcept;
    [[nodiscard]] const DeviceUserCodeDigest& userCode() const noexcept;
    [[nodiscard]] const client::ClientId& clientId() const noexcept;
    [[nodiscard]] const std::vector<client::Scope>& scopes() const noexcept;
    [[nodiscard]] const std::optional<std::string>& resource() const noexcept;
    [[nodiscard]] foundation::Instant issuedAt() const noexcept;
    [[nodiscard]] foundation::Instant expiresAt() const noexcept;
    [[nodiscard]] foundation::Duration pollInterval() const noexcept;
    [[nodiscard]] DeviceAuthorizationStatus status() const noexcept;
    [[nodiscard]] const std::optional<identity::core::IdentityId>& identity() const noexcept;
    [[nodiscard]] const std::optional<identity::provider::ProviderId>& provider() const noexcept;
    [[nodiscard]] const std::optional<identity::provider::AssuranceLevel>& assurance() const noexcept;
    [[nodiscard]] const std::optional<identity::provider::AuthenticationStrength>& strength() const noexcept;
    [[nodiscard]] const std::optional<foundation::Instant>& authenticatedAt() const noexcept;
    [[nodiscard]] const std::optional<foundation::Instant>& lastPollAt() const noexcept;
    [[nodiscard]] bool expiredAt(foundation::Instant now) const noexcept;

    [[nodiscard]] foundation::Status approve(
        const session::AuthenticatedSession& authenticated, foundation::Instant now);
    [[nodiscard]] foundation::Status deny(foundation::Instant now);
    [[nodiscard]] foundation::Status markPolled(foundation::Instant now);
    [[nodiscard]] foundation::Status slowDown(foundation::Instant now);
    [[nodiscard]] foundation::Status consume(foundation::Instant now);

private:
    struct State;
    explicit DeviceAuthorization(std::shared_ptr<State> state);
    void detach();
    std::shared_ptr<State> m_state;
};

enum class DevicePollDisposition {
    Pending,
    SlowDown,
    Denied,
    Expired,
    Approved,
};

/** @brief Atomic result of polling a device code. */
class DevicePollResult final {
public:
    DevicePollResult(DevicePollDisposition disposition,
                     std::optional<DeviceAuthorization> authorization,
                     foundation::Duration retryAfter);
    [[nodiscard]] DevicePollDisposition disposition() const noexcept;
    [[nodiscard]] const std::optional<DeviceAuthorization>& authorization() const noexcept;
    [[nodiscard]] foundation::Duration retryAfter() const noexcept;
private:
    DevicePollDisposition m_disposition{DevicePollDisposition::Pending};
    std::optional<DeviceAuthorization> m_authorization;
    foundation::Duration m_retryAfter{};
};

/** @brief Atomic persistence boundary for RFC 8628 device authorization. */
class DeviceAuthorizationStore {
public:
    DeviceAuthorizationStore(const DeviceAuthorizationStore&) = delete;
    DeviceAuthorizationStore& operator=(const DeviceAuthorizationStore&) = delete;
    virtual ~DeviceAuthorizationStore() = default;

    [[nodiscard]] virtual foundation::Status add(DeviceAuthorization authorization) = 0;
    [[nodiscard]] virtual foundation::Result<DeviceAuthorization> findByUserCode(
        const DeviceUserCodeDigest& userCode, foundation::Instant now) = 0;
    [[nodiscard]] virtual foundation::Result<DeviceAuthorization> approve(
        const DeviceUserCodeDigest& userCode,
        const session::AuthenticatedSession& authenticated,
        foundation::Instant now) = 0;
    [[nodiscard]] virtual foundation::Status deny(
        const DeviceUserCodeDigest& userCode, foundation::Instant now) = 0;
    [[nodiscard]] virtual foundation::Result<DevicePollResult> poll(
        const DeviceCodeDigest& deviceCode, const client::ClientId& expectedClient,
        foundation::Instant now) = 0;

protected:
    DeviceAuthorizationStore() = default;
};

/** @brief Thread-safe single-process Device Authorization store for tests. */
class InMemoryDeviceAuthorizationStore final : public DeviceAuthorizationStore {
public:
    InMemoryDeviceAuthorizationStore();
    ~InMemoryDeviceAuthorizationStore() override;
    [[nodiscard]] foundation::Status add(DeviceAuthorization authorization) override;
    [[nodiscard]] foundation::Result<DeviceAuthorization> findByUserCode(
        const DeviceUserCodeDigest& userCode, foundation::Instant now) override;
    [[nodiscard]] foundation::Result<DeviceAuthorization> approve(
        const DeviceUserCodeDigest& userCode,
        const session::AuthenticatedSession& authenticated,
        foundation::Instant now) override;
    [[nodiscard]] foundation::Status deny(
        const DeviceUserCodeDigest& userCode, foundation::Instant now) override;
    [[nodiscard]] foundation::Result<DevicePollResult> poll(
        const DeviceCodeDigest& deviceCode, const client::ClientId& expectedClient,
        foundation::Instant now) override;
private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

/** @brief HMAC key used to fingerprint raw device and user codes at rest. */
class DeviceAuthorizationKey final {
public:
    [[nodiscard]] static foundation::Result<DeviceAuthorizationKey> create(
        foundation::SecretString secret);
    DeviceAuthorizationKey(const DeviceAuthorizationKey&) = delete;
    DeviceAuthorizationKey& operator=(const DeviceAuthorizationKey&) = delete;
    DeviceAuthorizationKey(DeviceAuthorizationKey&&) noexcept = default;
    DeviceAuthorizationKey& operator=(DeviceAuthorizationKey&&) noexcept = default;
private:
    friend class DeviceAuthorizationService;
    explicit DeviceAuthorizationKey(foundation::SecretString secret);
    foundation::SecretString m_secret;
};

/** @brief Raw codes returned once to the device during authorization initiation. */
class DeviceAuthorizationGrant final {
public:
    DeviceAuthorizationGrant(const DeviceAuthorizationGrant&) = delete;
    DeviceAuthorizationGrant& operator=(const DeviceAuthorizationGrant&) = delete;
    DeviceAuthorizationGrant(DeviceAuthorizationGrant&&) noexcept = default;
    DeviceAuthorizationGrant& operator=(DeviceAuthorizationGrant&&) noexcept = default;
    ~DeviceAuthorizationGrant() = default;

    [[nodiscard]] const foundation::SecretString& deviceCode() const noexcept;
    [[nodiscard]] std::string_view userCode() const noexcept;
    [[nodiscard]] foundation::Duration expiresIn() const noexcept;
    [[nodiscard]] foundation::Duration interval() const noexcept;
private:
    friend class DeviceAuthorizationService;
    DeviceAuthorizationGrant(foundation::SecretString deviceCode, std::string userCode,
                             foundation::Duration expiresIn,
                             foundation::Duration interval);
    foundation::SecretString m_deviceCode;
    std::string m_userCode;
    foundation::Duration m_expiresIn{};
    foundation::Duration m_interval{};
};

/** @brief RFC 8628 orchestration with single-use codes and atomic polling. */
class DeviceAuthorizationService final {
public:
    DeviceAuthorizationService(DeviceAuthorizationStore& store,
                               client::ClientManager& clients,
                               const foundation::ClockSource& clock,
                               DeviceAuthorizationKey key,
                               foundation::Duration lifetime,
                               foundation::Duration pollInterval);

    [[nodiscard]] foundation::Result<DeviceAuthorizationGrant> begin(
        const client::ClientId& clientId, std::vector<client::Scope> scopes,
        std::optional<std::string> resource);
    [[nodiscard]] foundation::Result<DeviceAuthorization> find(
        std::string_view userCode);
    [[nodiscard]] foundation::Result<DeviceAuthorization> approve(
        std::string_view userCode,
        const session::AuthenticatedSession& authenticated);
    [[nodiscard]] foundation::Status deny(std::string_view userCode);
    [[nodiscard]] foundation::Result<DevicePollResult> poll(
        const foundation::SecretString& deviceCode, const client::ClientId& expectedClient);

private:
    [[nodiscard]] foundation::Result<DeviceCodeDigest> digestDevice(
        const foundation::SecretString& code) const;
    [[nodiscard]] foundation::Result<DeviceUserCodeDigest> digestUser(
        std::string_view code) const;
    [[nodiscard]] static foundation::Result<std::string> generateUserCode();

    DeviceAuthorizationStore* m_store;
    client::ClientManager* m_clients;
    const foundation::ClockSource* m_clock;
    DeviceAuthorizationKey m_key;
    foundation::Duration m_lifetime{};
    foundation::Duration m_pollInterval{};
};

}

module;

#include <optional>
#include <chrono>
#include <algorithm>
#include <array>
#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.oauth;

import openproof.security;

namespace openproof::oauth {
namespace {

[[nodiscard]] std::string digestKey(const std::array<std::byte, 32>& bytes)
{
    return foundation::toHex(bytes);
}

[[nodiscard]] foundation::Result<std::vector<client::Scope>> normalizeScopes(
    std::vector<client::Scope> scopes)
{
    if (scopes.empty() || scopes.size() > 256U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Device authorization requires scopes.");
    }
    std::ranges::sort(scopes, {}, [](const client::Scope& scope) {
        return scope.value();
    });
    if (std::adjacent_find(scopes.begin(), scopes.end(), [](const auto& left, const auto& right) {
            return left.value() == right.value();
        }) != scopes.end()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Device authorization scopes must be unique.");
    }
    return scopes;
}

}

DeviceCodeDigest::DeviceCodeDigest(std::array<std::byte, 32> value) noexcept
    : m_value(value)
{
}
const std::array<std::byte, 32>& DeviceCodeDigest::bytes() const noexcept { return m_value; }
DeviceUserCodeDigest::DeviceUserCodeDigest(std::array<std::byte, 32> value) noexcept
    : m_value(value)
{
}
const std::array<std::byte, 32>& DeviceUserCodeDigest::bytes() const noexcept { return m_value; }

struct DeviceAuthorization::State final {
    DeviceCodeDigest deviceCode;
    DeviceUserCodeDigest userCode;
    client::ClientId clientId;
    std::vector<client::Scope> scopes;
    std::optional<std::string> resource;
    foundation::Instant issuedAt{};
    foundation::Instant expiresAt{};
    foundation::Duration pollInterval{};
    DeviceAuthorizationStatus status{DeviceAuthorizationStatus::Pending};
    std::optional<identity::core::IdentityId> identity;
    std::optional<identity::provider::ProviderId> provider;
    std::optional<identity::provider::AssuranceLevel> assurance;
    std::optional<identity::provider::AuthenticationStrength> strength;
    std::optional<foundation::Instant> authenticatedAt;
    std::optional<foundation::Instant> lastPollAt;
};

DeviceAuthorization::DeviceAuthorization(std::shared_ptr<State> state)
    : m_state(std::move(state))
{
}
void DeviceAuthorization::detach()
{
    if (!m_state.unique()) m_state = std::make_shared<State>(*m_state);
}

foundation::Result<DeviceAuthorization> DeviceAuthorization::create(
    DeviceCodeDigest deviceCode, DeviceUserCodeDigest userCode,
    client::ClientId clientId, std::vector<client::Scope> scopes,
    std::optional<std::string> resource, foundation::Instant issuedAt,
    foundation::Duration lifetime, foundation::Duration pollInterval)
{
    if (lifetime <= foundation::Duration::zero()
        || pollInterval <= foundation::Duration::zero()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Device authorization timing policy is invalid.");
    }
    return restore(std::move(deviceCode), std::move(userCode), std::move(clientId),
                   std::move(scopes), std::move(resource), issuedAt,
                   issuedAt + lifetime, pollInterval, DeviceAuthorizationStatus::Pending,
                   std::nullopt, std::nullopt, std::nullopt, std::nullopt,
                   std::nullopt, std::nullopt);
}

foundation::Result<DeviceAuthorization> DeviceAuthorization::restore(
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
    std::optional<foundation::Instant> lastPollAt)
{
    auto normalized = normalizeScopes(std::move(scopes));
    const bool approvedClaims = identity.has_value() && provider.has_value()
        && assurance.has_value() && strength.has_value() && authenticatedAt.has_value();
    if (clientId.empty() || !normalized || expiresAt <= issuedAt
        || pollInterval <= foundation::Duration::zero()
        || (resource && (resource->empty() || resource->size() > 2048U))
        || ((status == DeviceAuthorizationStatus::Approved
             || status == DeviceAuthorizationStatus::Consumed) && !approvedClaims)
        || (status == DeviceAuthorizationStatus::Pending && approvedClaims)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The device authorization record is invalid.");
    }
    return DeviceAuthorization{std::make_shared<State>(State{
        std::move(deviceCode), std::move(userCode), std::move(clientId),
        std::move(normalized).value(), std::move(resource), issuedAt, expiresAt,
        pollInterval, status, std::move(identity), std::move(provider),
        assurance, std::move(strength), authenticatedAt, lastPollAt})};
}

const DeviceCodeDigest& DeviceAuthorization::deviceCode() const noexcept { return m_state->deviceCode; }
const DeviceUserCodeDigest& DeviceAuthorization::userCode() const noexcept { return m_state->userCode; }
const client::ClientId& DeviceAuthorization::clientId() const noexcept { return m_state->clientId; }
const std::vector<client::Scope>& DeviceAuthorization::scopes() const noexcept { return m_state->scopes; }
const std::optional<std::string>& DeviceAuthorization::resource() const noexcept { return m_state->resource; }
foundation::Instant DeviceAuthorization::issuedAt() const noexcept { return m_state->issuedAt; }
foundation::Instant DeviceAuthorization::expiresAt() const noexcept { return m_state->expiresAt; }
foundation::Duration DeviceAuthorization::pollInterval() const noexcept { return m_state->pollInterval; }
DeviceAuthorizationStatus DeviceAuthorization::status() const noexcept { return m_state->status; }
const std::optional<identity::core::IdentityId>& DeviceAuthorization::identity() const noexcept { return m_state->identity; }
const std::optional<identity::provider::ProviderId>& DeviceAuthorization::provider() const noexcept { return m_state->provider; }
const std::optional<identity::provider::AssuranceLevel>& DeviceAuthorization::assurance() const noexcept { return m_state->assurance; }
const std::optional<identity::provider::AuthenticationStrength>& DeviceAuthorization::strength() const noexcept { return m_state->strength; }
const std::optional<foundation::Instant>& DeviceAuthorization::authenticatedAt() const noexcept { return m_state->authenticatedAt; }
const std::optional<foundation::Instant>& DeviceAuthorization::lastPollAt() const noexcept { return m_state->lastPollAt; }
bool DeviceAuthorization::expiredAt(foundation::Instant now) const noexcept { return now >= m_state->expiresAt; }

foundation::Status DeviceAuthorization::approve(
    const session::AuthenticatedSession& authenticated, foundation::Instant now)
{
    if (m_state->status != DeviceAuthorizationStatus::Pending || expiredAt(now)) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The device authorization cannot be approved.");
    }
    detach();
    m_state->identity = authenticated.session().identity();
    m_state->provider = authenticated.session().provider();
    m_state->assurance = authenticated.session().assurance();
    m_state->strength = authenticated.session().strength();
    m_state->authenticatedAt = authenticated.session().authenticatedAt();
    m_state->status = DeviceAuthorizationStatus::Approved;
    return foundation::ok();
}

foundation::Status DeviceAuthorization::deny(foundation::Instant now)
{
    if (m_state->status != DeviceAuthorizationStatus::Pending || expiredAt(now)) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The device authorization cannot be denied.");
    }
    detach();
    m_state->status = DeviceAuthorizationStatus::Denied;
    return foundation::ok();
}

foundation::Status DeviceAuthorization::markPolled(foundation::Instant now)
{
    if (expiredAt(now) || m_state->status == DeviceAuthorizationStatus::Consumed) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition);
    }
    detach();
    m_state->lastPollAt = now;
    return foundation::ok();
}

foundation::Status DeviceAuthorization::slowDown(foundation::Instant now)
{
    if (expiredAt(now) || m_state->status == DeviceAuthorizationStatus::Consumed) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition);
    }
    detach();
    m_state->pollInterval += std::chrono::seconds{5};
    m_state->lastPollAt = now;
    return foundation::ok();
}

foundation::Status DeviceAuthorization::consume(foundation::Instant now)
{
    if (expiredAt(now) || m_state->status != DeviceAuthorizationStatus::Approved) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The device authorization cannot be consumed.");
    }
    detach();
    m_state->status = DeviceAuthorizationStatus::Consumed;
    m_state->lastPollAt = now;
    return foundation::ok();
}

DevicePollResult::DevicePollResult(
    DevicePollDisposition disposition, std::optional<DeviceAuthorization> authorization,
    foundation::Duration retryAfter)
    : m_disposition(disposition), m_authorization(std::move(authorization)),
      m_retryAfter(retryAfter)
{
}
DevicePollDisposition DevicePollResult::disposition() const noexcept { return m_disposition; }
const std::optional<DeviceAuthorization>& DevicePollResult::authorization() const noexcept { return m_authorization; }
foundation::Duration DevicePollResult::retryAfter() const noexcept { return m_retryAfter; }

struct InMemoryDeviceAuthorizationStore::Impl final {
    std::mutex mutex;
    std::map<std::string, DeviceAuthorization, std::less<>> byDevice;
    std::map<std::string, std::string, std::less<>> userToDevice;
};

InMemoryDeviceAuthorizationStore::InMemoryDeviceAuthorizationStore()
    : m_impl(std::make_unique<Impl>())
{
}
InMemoryDeviceAuthorizationStore::~InMemoryDeviceAuthorizationStore() = default;

foundation::Status InMemoryDeviceAuthorizationStore::add(DeviceAuthorization authorization)
{
    std::scoped_lock lock{m_impl->mutex};
    const auto device = digestKey(authorization.deviceCode().bytes());
    const auto user = digestKey(authorization.userCode().bytes());
    if (m_impl->byDevice.contains(device) || m_impl->userToDevice.contains(user)) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists);
    }
    m_impl->userToDevice.emplace(user, device);
    m_impl->byDevice.emplace(device, std::move(authorization));
    return foundation::ok();
}

foundation::Result<DeviceAuthorization> InMemoryDeviceAuthorizationStore::findByUserCode(
    const DeviceUserCodeDigest& userCode, foundation::Instant now)
{
    std::scoped_lock lock{m_impl->mutex};
    const auto mapping = m_impl->userToDevice.find(digestKey(userCode.bytes()));
    if (mapping == m_impl->userToDevice.end()) {
        return foundation::fail(foundation::ErrorCode::NotFound);
    }
    const auto found = m_impl->byDevice.find(mapping->second);
    if (found == m_impl->byDevice.end() || found->second.expiredAt(now)
        || found->second.status() != DeviceAuthorizationStatus::Pending) {
        return foundation::fail(foundation::ErrorCode::NotFound);
    }
    return found->second;
}

foundation::Result<DeviceAuthorization> InMemoryDeviceAuthorizationStore::approve(
    const DeviceUserCodeDigest& userCode,
    const session::AuthenticatedSession& authenticated,
    foundation::Instant now)
{
    std::scoped_lock lock{m_impl->mutex};
    const auto user = digestKey(userCode.bytes());
    const auto mapping = m_impl->userToDevice.find(user);
    if (mapping == m_impl->userToDevice.end()) {
        return foundation::fail(foundation::ErrorCode::NotFound);
    }
    auto found = m_impl->byDevice.find(mapping->second);
    if (found == m_impl->byDevice.end()) return foundation::fail(foundation::ErrorCode::NotFound);
    auto value = found->second;
    auto approved = value.approve(authenticated, now);
    if (!approved) return foundation::fail(approved.error());
    found->second = value;
    return value;
}

foundation::Status InMemoryDeviceAuthorizationStore::deny(
    const DeviceUserCodeDigest& userCode, foundation::Instant now)
{
    std::scoped_lock lock{m_impl->mutex};
    const auto mapping = m_impl->userToDevice.find(digestKey(userCode.bytes()));
    if (mapping == m_impl->userToDevice.end()) return foundation::fail(foundation::ErrorCode::NotFound);
    auto found = m_impl->byDevice.find(mapping->second);
    if (found == m_impl->byDevice.end()) return foundation::fail(foundation::ErrorCode::NotFound);
    auto value = found->second;
    auto denied = value.deny(now);
    if (!denied) return foundation::fail(denied.error());
    found->second = value;
    return foundation::ok();
}

foundation::Result<DevicePollResult> InMemoryDeviceAuthorizationStore::poll(
    const DeviceCodeDigest& deviceCode, const client::ClientId& expectedClient,
    foundation::Instant now)
{
    std::scoped_lock lock{m_impl->mutex};
    auto found = m_impl->byDevice.find(digestKey(deviceCode.bytes()));
    if (found == m_impl->byDevice.end()) return foundation::fail(foundation::ErrorCode::NotFound);
    auto value = found->second;
    if (value.clientId() != expectedClient) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The device code is not bound to this client.");
    }
    if (value.expiredAt(now)) {
        return DevicePollResult{DevicePollDisposition::Expired, std::nullopt, value.pollInterval()};
    }
    if (value.status() == DeviceAuthorizationStatus::Denied) {
        return DevicePollResult{DevicePollDisposition::Denied, std::nullopt, value.pollInterval()};
    }
    if (value.status() == DeviceAuthorizationStatus::Consumed) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The device code has already been consumed.");
    }
    if (value.lastPollAt() && now < *value.lastPollAt() + value.pollInterval()) {
        auto slowed = value.slowDown(now);
        if (!slowed) return foundation::fail(slowed.error());
        found->second = value;
        return DevicePollResult{DevicePollDisposition::SlowDown, std::nullopt,
                                value.pollInterval()};
    }
    if (value.status() == DeviceAuthorizationStatus::Approved) {
        auto consumed = value.consume(now);
        if (!consumed) return foundation::fail(consumed.error());
        found->second = value;
        return DevicePollResult{DevicePollDisposition::Approved, value, value.pollInterval()};
    }
    auto polled = value.markPolled(now);
    if (!polled) return foundation::fail(polled.error());
    found->second = value;
    return DevicePollResult{DevicePollDisposition::Pending, std::nullopt, value.pollInterval()};
}

DeviceAuthorizationKey::DeviceAuthorizationKey(foundation::SecretString secret)
    : m_secret(std::move(secret))
{
}
foundation::Result<DeviceAuthorizationKey> DeviceAuthorizationKey::create(
    foundation::SecretString secret)
{
    if (secret.expose().size() < 32U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A device authorization key requires at least 32 bytes.");
    }
    return DeviceAuthorizationKey{std::move(secret)};
}

DeviceAuthorizationGrant::DeviceAuthorizationGrant(
    foundation::SecretString deviceCode, std::string userCode,
    foundation::Duration expiresIn, foundation::Duration interval)
    : m_deviceCode(std::move(deviceCode)), m_userCode(std::move(userCode)),
      m_expiresIn(expiresIn), m_interval(interval)
{
}
const foundation::SecretString& DeviceAuthorizationGrant::deviceCode() const noexcept { return m_deviceCode; }
std::string_view DeviceAuthorizationGrant::userCode() const noexcept { return m_userCode; }
foundation::Duration DeviceAuthorizationGrant::expiresIn() const noexcept { return m_expiresIn; }
foundation::Duration DeviceAuthorizationGrant::interval() const noexcept { return m_interval; }

DeviceAuthorizationService::DeviceAuthorizationService(
    DeviceAuthorizationStore& store, client::ClientManager& clients,
    const foundation::ClockSource& clock, DeviceAuthorizationKey key,
    foundation::Duration lifetime, foundation::Duration pollInterval)
    : m_store(&store), m_clients(&clients), m_clock(&clock), m_key(std::move(key)),
      m_lifetime(lifetime), m_pollInterval(pollInterval)
{
    foundation::requireInvariant(m_lifetime > foundation::Duration::zero(),
                                 "device lifetime must be positive");
    foundation::requireInvariant(m_pollInterval >= std::chrono::seconds{1},
                                 "device poll interval must be at least one second");
}

foundation::Result<DeviceCodeDigest> DeviceAuthorizationService::digestDevice(
    const foundation::SecretString& code) const
{
    auto digest = security::hmacSha256(m_key.m_secret, code.expose());
    if (!digest) return foundation::fail(digest.error());
    return DeviceCodeDigest{digest.value()};
}

foundation::Result<DeviceUserCodeDigest> DeviceAuthorizationService::digestUser(
    std::string_view code) const
{
    auto digest = security::hmacSha256(m_key.m_secret, code);
    if (!digest) return foundation::fail(digest.error());
    return DeviceUserCodeDigest{digest.value()};
}

foundation::Result<std::string> DeviceAuthorizationService::generateUserCode()
{
    static constexpr std::string_view alphabet{"BCDFGHJKLMNPQRSTVWXYZ23456789"};
    auto random = security::randomBytes(8U);
    if (!random) return foundation::fail(random.error());
    std::string code;
    code.reserve(9U);
    for (std::size_t index = 0U; index < random->size(); ++index) {
        if (index == 4U) code.push_back('-');
        code.push_back(alphabet[std::to_integer<unsigned int>((*random)[index]) % alphabet.size()]);
    }
    return code;
}

foundation::Result<DeviceAuthorizationGrant> DeviceAuthorizationService::begin(
    const client::ClientId& clientId, std::vector<client::Scope> scopes,
    std::optional<std::string> resource)
{
    auto active = m_clients->requireActive(clientId);
    if (!active || !active->permitsScopes(scopes)) {
        return foundation::fail(foundation::ErrorCode::PermissionDenied,
                                "The client cannot request this device grant.");
    }
    auto deviceRandom = security::randomTokenBase64Url(32U);
    auto userCode = generateUserCode();
    if (!deviceRandom) return foundation::fail(deviceRandom.error());
    if (!userCode) return foundation::fail(userCode.error());
    foundation::SecretString deviceCode{"opd_" + deviceRandom.value()};
    auto deviceDigest = digestDevice(deviceCode);
    auto userDigest = digestUser(userCode.value());
    if (!deviceDigest) return foundation::fail(deviceDigest.error());
    if (!userDigest) return foundation::fail(userDigest.error());
    auto authorization = DeviceAuthorization::create(
        deviceDigest.value(), userDigest.value(), clientId, std::move(scopes),
        std::move(resource), m_clock->now(), m_lifetime, m_pollInterval);
    if (!authorization) return foundation::fail(authorization.error());
    auto stored = m_store->add(std::move(authorization).value());
    if (!stored) return foundation::fail(stored.error());
    return DeviceAuthorizationGrant{
        std::move(deviceCode), std::move(userCode).value(), m_lifetime, m_pollInterval};
}

foundation::Result<DeviceAuthorization> DeviceAuthorizationService::find(
    std::string_view userCode)
{
    auto digest = digestUser(userCode);
    if (!digest) return foundation::fail(digest.error());
    return m_store->findByUserCode(digest.value(), m_clock->now());
}

foundation::Result<DeviceAuthorization> DeviceAuthorizationService::approve(
    std::string_view userCode, const session::AuthenticatedSession& authenticated)
{
    auto digest = digestUser(userCode);
    if (!digest) return foundation::fail(digest.error());
    return m_store->approve(digest.value(), authenticated, m_clock->now());
}

foundation::Status DeviceAuthorizationService::deny(std::string_view userCode)
{
    auto digest = digestUser(userCode);
    if (!digest) return foundation::fail(digest.error());
    return m_store->deny(digest.value(), m_clock->now());
}

foundation::Result<DevicePollResult> DeviceAuthorizationService::poll(
    const foundation::SecretString& deviceCode, const client::ClientId& expectedClient)
{
    auto digest = digestDevice(deviceCode);
    if (!digest) return foundation::fail(digest.error());
    return m_store->poll(digest.value(), expectedClient, m_clock->now());
}

}

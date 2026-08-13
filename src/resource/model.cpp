module;

#include <algorithm>
#include <chrono>
#include <memory>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.resource;

namespace openproof::resource {
namespace {

[[nodiscard]] bool validAudience(std::string_view value) noexcept
{
    return !value.empty() && value.size() <= 2048U && !value.contains(' ')
        && !value.contains('\t') && !value.contains('\r') && !value.contains('\n');
}

[[nodiscard]] foundation::Result<std::vector<std::string>> normalizedScopes(
    std::vector<std::string> scopes)
{
    if (scopes.empty() || scopes.size() > 256U) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "A resource server must declare scopes.");
    }

    for (const auto& value : scopes) {
        auto parsed = client::Scope::create(value);
        if (!parsed) {
            return foundation::fail(parsed.error());
        }
    }

    std::ranges::sort(scopes);
    scopes.erase(std::unique(scopes.begin(), scopes.end()), scopes.end());
    return scopes;
}

[[nodiscard]] foundation::Result<std::vector<std::string>> normalizedAudiences(
    std::vector<std::string> audiences)
{
    if (audiences.empty() || audiences.size() > 64U
        || std::ranges::any_of(audiences, [](const auto& value) {
               return !validAudience(value);
           })) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "A service identity audience grant is invalid.");
    }

    std::ranges::sort(audiences);
    audiences.erase(std::unique(audiences.begin(), audiences.end()), audiences.end());
    return audiences;
}

} // namespace

struct ResourceServer::State final {
    ResourceId id;
    std::string audience;
    std::string displayName;
    std::vector<std::string> scopes;
    ResourceStatus status{ResourceStatus::Active};
    foundation::Instant createdAt{};
    foundation::Instant updatedAt{};
};

ResourceServer::ResourceServer(std::shared_ptr<State> state)
    : m_state(std::move(state))
{
}

void ResourceServer::detach()
{
    if (!m_state.unique()) {
        m_state = std::make_shared<State>(*m_state);
    }
}

foundation::Result<ResourceServer> ResourceServer::create(
    ResourceId id,
    std::string audience,
    std::string displayName,
    std::vector<std::string> scopes,
    foundation::Instant now)
{
    return restore(
        std::move(id),
        std::move(audience),
        std::move(displayName),
        std::move(scopes),
        ResourceStatus::Active,
        now,
        now);
}

foundation::Result<ResourceServer> ResourceServer::restore(
    ResourceId id,
    std::string audience,
    std::string displayName,
    std::vector<std::string> scopes,
    ResourceStatus status,
    foundation::Instant createdAt,
    foundation::Instant updatedAt)
{
    auto normalized = normalizedScopes(std::move(scopes));
    if (id.empty() || !validAudience(audience) || displayName.empty()
        || displayName.size() > 256U || !normalized || updatedAt < createdAt
        || static_cast<unsigned int>(status) > 2U) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "The resource-server registration is invalid.");
    }

    return ResourceServer{std::make_shared<State>(State{
        std::move(id),
        std::move(audience),
        std::move(displayName),
        std::move(normalized).value(),
        status,
        createdAt,
        updatedAt})};
}

const ResourceId& ResourceServer::id() const noexcept
{
    return m_state->id;
}

std::string_view ResourceServer::audience() const noexcept
{
    return m_state->audience;
}

std::string_view ResourceServer::displayName() const noexcept
{
    return m_state->displayName;
}

const std::vector<std::string>& ResourceServer::scopes() const noexcept
{
    return m_state->scopes;
}

ResourceStatus ResourceServer::status() const noexcept
{
    return m_state->status;
}

bool ResourceServer::active() const noexcept
{
    return m_state->status == ResourceStatus::Active;
}

bool ResourceServer::permitsScope(std::string_view scope) const noexcept
{
    return std::ranges::binary_search(m_state->scopes, std::string{scope});
}

bool ResourceServer::permitsScopes(const std::vector<std::string>& scopes) const noexcept
{
    return std::ranges::all_of(scopes, [&](const auto& value) {
        return permitsScope(value);
    });
}

foundation::Instant ResourceServer::createdAt() const noexcept
{
    return m_state->createdAt;
}

foundation::Instant ResourceServer::updatedAt() const noexcept
{
    return m_state->updatedAt;
}

foundation::Status ResourceServer::setStatus(
    ResourceStatus status,
    foundation::Instant now)
{
    if (m_state->status == ResourceStatus::Revoked && status != ResourceStatus::Revoked) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "A revoked resource server cannot be reactivated.");
    }

    detach();
    m_state->status = status;
    m_state->updatedAt = now;
    return foundation::ok();
}

struct ServiceIdentity::State final {
    identity::core::IdentityId identity;
    client::ClientId client;
    std::vector<std::string> audiences;
    std::vector<std::string> scopes;
    bool active{true};
    foundation::Instant createdAt{};
    foundation::Instant updatedAt{};
};

ServiceIdentity::ServiceIdentity(std::shared_ptr<State> state)
    : m_state(std::move(state))
{
}

void ServiceIdentity::detach()
{
    if (!m_state.unique()) {
        m_state = std::make_shared<State>(*m_state);
    }
}

foundation::Result<ServiceIdentity> ServiceIdentity::create(
    identity::core::IdentityId identity,
    client::ClientId clientId,
    std::vector<std::string> audiences,
    std::vector<std::string> scopes,
    foundation::Instant now)
{
    return restore(
        std::move(identity),
        std::move(clientId),
        std::move(audiences),
        std::move(scopes),
        true,
        now,
        now);
}

foundation::Result<ServiceIdentity> ServiceIdentity::restore(
    identity::core::IdentityId identity,
    client::ClientId clientId,
    std::vector<std::string> audiences,
    std::vector<std::string> scopes,
    bool active,
    foundation::Instant createdAt,
    foundation::Instant updatedAt)
{
    auto normalizedAudience = normalizedAudiences(std::move(audiences));
    auto normalizedScope = normalizedScopes(std::move(scopes));
    if (identity.empty() || clientId.empty() || !normalizedAudience || !normalizedScope
        || updatedAt < createdAt) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "The service identity registration is invalid.");
    }

    return ServiceIdentity{std::make_shared<State>(State{
        std::move(identity),
        std::move(clientId),
        std::move(normalizedAudience).value(),
        std::move(normalizedScope).value(),
        active,
        createdAt,
        updatedAt})};
}

const identity::core::IdentityId& ServiceIdentity::identity() const noexcept
{
    return m_state->identity;
}

const client::ClientId& ServiceIdentity::client() const noexcept
{
    return m_state->client;
}

const std::vector<std::string>& ServiceIdentity::audiences() const noexcept
{
    return m_state->audiences;
}

const std::vector<std::string>& ServiceIdentity::scopes() const noexcept
{
    return m_state->scopes;
}

bool ServiceIdentity::active() const noexcept
{
    return m_state->active;
}

bool ServiceIdentity::permitsAudience(std::string_view audience) const noexcept
{
    return std::ranges::binary_search(m_state->audiences, std::string{audience});
}

bool ServiceIdentity::permitsScopes(const std::vector<std::string>& scopes) const noexcept
{
    return std::ranges::all_of(scopes, [&](const auto& value) {
        return std::ranges::binary_search(m_state->scopes, value);
    });
}

foundation::Instant ServiceIdentity::createdAt() const noexcept
{
    return m_state->createdAt;
}

foundation::Instant ServiceIdentity::updatedAt() const noexcept
{
    return m_state->updatedAt;
}

foundation::Status ServiceIdentity::deactivate(foundation::Instant now)
{
    detach();
    m_state->active = false;
    m_state->updatedAt = now;
    return foundation::ok();
}

foundation::Status ServiceIdentity::activate(foundation::Instant now)
{
    detach();
    m_state->active = true;
    m_state->updatedAt = now;
    return foundation::ok();
}

} // namespace openproof::resource

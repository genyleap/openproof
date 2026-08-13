module;

#include <string_view>
#include <algorithm>
#include <chrono>
#include <memory>
#include <optional>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

module openproof.consent;

namespace openproof::consent {
namespace {

[[nodiscard]] foundation::Result<std::vector<std::string>> normalizeScopes(
    std::vector<std::string> scopes)
{
    if (scopes.empty() || scopes.size() > 256U) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "A consent grant must contain scopes.");
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

} // namespace

struct ConsentGrant::State final {
    ConsentId id;
    identity::core::IdentityId identity;
    client::ClientId client;
    std::string audience;
    std::vector<std::string> scopes;
    foundation::Instant grantedAt{};
    std::optional<foundation::Instant> expiresAt;
    std::optional<foundation::Instant> revokedAt;
};

ConsentGrant::ConsentGrant(std::shared_ptr<State> state)
    : m_state(std::move(state))
{
}

void ConsentGrant::detach()
{
    if (!m_state.unique()) {
        m_state = std::make_shared<State>(*m_state);
    }
}

foundation::Result<ConsentGrant> ConsentGrant::create(
    ConsentId id,
    identity::core::IdentityId identity,
    client::ClientId clientId,
    std::string audience,
    std::vector<std::string> scopes,
    foundation::Instant grantedAt,
    std::optional<foundation::Instant> expiresAt)
{
    return restore(
        std::move(id),
        std::move(identity),
        std::move(clientId),
        std::move(audience),
        std::move(scopes),
        grantedAt,
        expiresAt,
        std::nullopt);
}

foundation::Result<ConsentGrant> ConsentGrant::restore(
    ConsentId id,
    identity::core::IdentityId identity,
    client::ClientId clientId,
    std::string audience,
    std::vector<std::string> scopes,
    foundation::Instant grantedAt,
    std::optional<foundation::Instant> expiresAt,
    std::optional<foundation::Instant> revokedAt)
{
    auto normalized = normalizeScopes(std::move(scopes));
    const bool invalidExpiry = expiresAt.has_value() && *expiresAt <= grantedAt;
    const bool invalidRevocation = revokedAt.has_value() && *revokedAt < grantedAt;

    if (id.empty() || identity.empty() || clientId.empty() || audience.empty()
        || audience.size() > 2048U || !normalized || invalidExpiry || invalidRevocation) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "The consent grant is invalid.");
    }

    return ConsentGrant{std::make_shared<State>(State{
        std::move(id),
        std::move(identity),
        std::move(clientId),
        std::move(audience),
        std::move(normalized).value(),
        grantedAt,
        expiresAt,
        revokedAt})};
}

const ConsentId& ConsentGrant::id() const noexcept
{
    return m_state->id;
}

const identity::core::IdentityId& ConsentGrant::identity() const noexcept
{
    return m_state->identity;
}

const client::ClientId& ConsentGrant::client() const noexcept
{
    return m_state->client;
}

std::string_view ConsentGrant::audience() const noexcept
{
    return m_state->audience;
}

const std::vector<std::string>& ConsentGrant::scopes() const noexcept
{
    return m_state->scopes;
}

foundation::Instant ConsentGrant::grantedAt() const noexcept
{
    return m_state->grantedAt;
}

const std::optional<foundation::Instant>& ConsentGrant::expiresAt() const noexcept
{
    return m_state->expiresAt;
}

const std::optional<foundation::Instant>& ConsentGrant::revokedAt() const noexcept
{
    return m_state->revokedAt;
}

bool ConsentGrant::activeAt(foundation::Instant now) const noexcept
{
    return !m_state->revokedAt.has_value()
        && (!m_state->expiresAt.has_value() || now < *m_state->expiresAt);
}

bool ConsentGrant::covers(const std::vector<std::string>& scopes) const noexcept
{
    return std::ranges::all_of(scopes, [&](const auto& scope) {
        return std::ranges::binary_search(m_state->scopes, scope);
    });
}

void ConsentGrant::revoke(foundation::Instant now)
{
    detach();
    if (!m_state->revokedAt.has_value()) {
        m_state->revokedAt = now;
    }
}

} // namespace openproof::consent

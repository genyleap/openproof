module;

#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.consent;

import openproof.security;

namespace openproof::consent {

ConsentService::ConsentService(
    ConsentRepository& repository,
    const foundation::ClockSource& clock)
    : m_repository(&repository)
    , m_clock(&clock)
{
}

foundation::Result<bool> ConsentService::covers(
    const identity::core::IdentityId& identity,
    const client::ClientId& clientId,
    std::string_view audience,
    const std::vector<std::string>& scopes) const
{
    auto found = m_repository->findActive(identity, clientId, audience, m_clock->now());
    if (!found) {
        return foundation::fail(found.error());
    }

    return found->has_value() && found->value().covers(scopes);
}

foundation::Result<ConsentGrant> ConsentService::grant(
    const identity::core::IdentityId& identity,
    const client::ClientId& clientId,
    std::string audience,
    std::vector<std::string> scopes,
    std::optional<foundation::Duration> lifetime)
{
    if (lifetime.has_value() && *lifetime <= foundation::Duration::zero()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }

    auto random = security::randomTokenBase64Url(18U);
    if (!random) {
        return foundation::fail(random.error());
    }

    const auto now = m_clock->now();
    const auto expiresAt = lifetime.has_value()
        ? std::optional<foundation::Instant>{now + *lifetime}
        : std::nullopt;

    auto grant = ConsentGrant::create(
        ConsentId{"opcns_" + random.value()},
        identity,
        clientId,
        std::move(audience),
        std::move(scopes),
        now,
        expiresAt);
    if (!grant) {
        return foundation::fail(grant.error());
    }

    auto stored = m_repository->save(grant.value());
    if (!stored) {
        return foundation::fail(stored.error());
    }

    return grant;
}

foundation::Result<std::vector<ConsentGrant>> ConsentService::list(
    const identity::core::IdentityId& identity) const
{
    return m_repository->list(identity);
}

bool ConsentService::active(const ConsentGrant& grant) const noexcept
{
    return grant.activeAt(m_clock->now());
}

foundation::Status ConsentService::revoke(
    const ConsentId& id,
    const identity::core::IdentityId& identity)
{
    return m_repository->revoke(id, identity, m_clock->now());
}

} // namespace openproof::consent

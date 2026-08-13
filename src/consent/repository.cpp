module;

#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

module openproof.consent;

namespace openproof::consent {

struct InMemoryConsentRepository::Impl final {
    mutable std::mutex mutex;
    std::map<ConsentId, ConsentGrant> grants;
};

InMemoryConsentRepository::InMemoryConsentRepository()
    : m_impl(std::make_unique<Impl>())
{
}

InMemoryConsentRepository::~InMemoryConsentRepository() = default;

foundation::Status InMemoryConsentRepository::save(ConsentGrant grant)
{
    std::scoped_lock lock{m_impl->mutex};

    for (auto& [id, value] : m_impl->grants) {
        static_cast<void>(id);
        if (value.identity() == grant.identity() && value.client() == grant.client()
            && value.audience() == grant.audience()
            && value.activeAt(grant.grantedAt())) {
            value.revoke(grant.grantedAt());
        }
    }

    m_impl->grants.insert_or_assign(grant.id(), std::move(grant));
    return foundation::ok();
}

foundation::Result<std::optional<ConsentGrant>> InMemoryConsentRepository::findActive(
    const identity::core::IdentityId& identity,
    const client::ClientId& clientId,
    std::string_view audience,
    foundation::Instant now) const
{
    std::scoped_lock lock{m_impl->mutex};

    for (const auto& [id, value] : m_impl->grants) {
        static_cast<void>(id);
        if (value.identity() == identity && value.client() == clientId
            && value.audience() == audience && value.activeAt(now)) {
            return std::optional<ConsentGrant>{value};
        }
    }

    return std::optional<ConsentGrant>{};
}

foundation::Result<std::vector<ConsentGrant>> InMemoryConsentRepository::list(
    const identity::core::IdentityId& identity) const
{
    std::scoped_lock lock{m_impl->mutex};
    std::vector<ConsentGrant> grants;

    for (const auto& [id, value] : m_impl->grants) {
        static_cast<void>(id);
        if (value.identity() == identity) {
            grants.push_back(value);
        }
    }

    return grants;
}

foundation::Status InMemoryConsentRepository::revoke(
    const ConsentId& id,
    const identity::core::IdentityId& identity,
    foundation::Instant now)
{
    std::scoped_lock lock{m_impl->mutex};
    auto found = m_impl->grants.find(id);
    if (found == m_impl->grants.end()) {
        return foundation::fail(foundation::ErrorCode::NotFound);
    }
    if (found->second.identity() != identity) {
        return foundation::fail(foundation::ErrorCode::PermissionDenied);
    }

    found->second.revoke(now);
    return foundation::ok();
}

} // namespace openproof::consent

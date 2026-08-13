module;

#include <map>
#include <memory>
#include <mutex>
#include <optional>

module openproof.identity.profile;

namespace openproof::identity::profile {

struct InMemoryIdentityProfileRepository::Impl final {
    mutable std::mutex mutex;
    std::map<core::IdentityId, std::unique_ptr<IdentityProfile>> profiles;
};

InMemoryIdentityProfileRepository::InMemoryIdentityProfileRepository()
    : m_impl(std::make_unique<Impl>())
{
}

InMemoryIdentityProfileRepository::~InMemoryIdentityProfileRepository() = default;

foundation::Status InMemoryIdentityProfileRepository::save(
    const IdentityProfile& profile)
{
    std::scoped_lock lock{m_impl->mutex};
    m_impl->profiles.insert_or_assign(
        profile.identity(), std::make_unique<IdentityProfile>(profile));
    return foundation::ok();
}

foundation::Result<std::optional<IdentityProfile>>
InMemoryIdentityProfileRepository::find(const core::IdentityId& identity) const
{
    std::scoped_lock lock{m_impl->mutex};
    const auto found = m_impl->profiles.find(identity);
    if (found == m_impl->profiles.end()) return std::optional<IdentityProfile>{};
    return std::optional<IdentityProfile>{*found->second};
}

}

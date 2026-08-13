module;

#include <cstddef>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <utility>
#include <vector>

module openproof.identity.provider;

namespace openproof::identity::provider {

foundation::Status
ProviderRegistry::registerProvider(std::unique_ptr<AuthenticationProvider> provider)
{
    if (provider == nullptr) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A null authentication provider cannot be registered.");
    }

    ProviderId id = provider->id();
    if (id.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An authentication provider must have a non-empty identifier.");
    }

    const std::unique_lock<std::shared_mutex> guard{m_mutex};
    if (m_providers.contains(id)) {
        return foundation::fail(
            foundation::ErrorCode::AlreadyExists,
            "An authentication provider with that identifier is already registered.",
            "Duplicate provider registration was rejected rather than replacing the existing "
            "provider, because sessions and audit records already reference the identifier.");
    }

    m_providers.emplace(std::move(id), std::move(provider));

    // Ownership transferred, and the identifier is now resolvable. If either
    // failed, find() would return nullptr for a provider the caller believes is
    // registered, and authentication for it would fail closed with a confusing
    // error rather than a clear one.
    foundation::requireInvariant(provider == nullptr, "provider registry duplicate identifier");
    return foundation::ok();
}

AuthenticationProvider* ProviderRegistry::find(const ProviderId& id) const
{
    const std::shared_lock<std::shared_mutex> guard{m_mutex};
    const auto position = m_providers.find(id);
    if (position == m_providers.end()) {
        return nullptr;
    }
    return position->second.get();
}

bool ProviderRegistry::contains(const ProviderId& id) const
{
    const std::shared_lock<std::shared_mutex> guard{m_mutex};
    return m_providers.contains(id);
}

std::vector<ProviderId> ProviderRegistry::ids() const
{
    const std::shared_lock<std::shared_mutex> guard{m_mutex};
    std::vector<ProviderId> out;
    out.reserve(m_providers.size());
    for (const auto& entry : m_providers) {
        out.push_back(entry.first);
    }
    return out;
}

std::size_t ProviderRegistry::size() const
{
    const std::shared_lock<std::shared_mutex> guard{m_mutex};
    return m_providers.size();
}

}

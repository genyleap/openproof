module;

#include <cstddef>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

module openproof.identity.core;

namespace openproof::identity::core {

foundation::Status InMemoryIdentityRepository::add(const OrganizationId& organization,
                                                   Identity identity)
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    const IdentityId key = identity.id();
    if (m_entries.contains(key)) {
        return foundation::fail(
            foundation::ErrorCode::AlreadyExists,
            "That identity already exists.",
            "Identity keys are globally unique across organizations; a duplicate was "
            "rejected rather than shadowing the existing record.");
    }

    m_entries.emplace(key, Owned{organization, std::move(identity)});
    return foundation::ok();
}

foundation::Result<std::optional<Identity>>
InMemoryIdentityRepository::findById(const OrganizationId& organization,
                                     const IdentityId& id) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    const auto position = m_entries.find(id);
    if (position == m_entries.end()) {
        return std::optional<Identity>{};
    }

    // The tenant check is part of the lookup, not a separate step a caller could
    // forget. A key owned by another organization is reported as absent, which
    // is what stops this interface from being usable as a cross-tenant probe.
    if (position->second.organization != organization) {
        return std::optional<Identity>{};
    }

    return std::optional<Identity>{position->second.identity};
}

foundation::Status InMemoryIdentityRepository::changeStatus(const OrganizationId& organization,
                                                            const IdentityId& id,
                                                            IdentityStatus status)
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    const auto position = m_entries.find(id);
    if (position == m_entries.end() || position->second.organization != organization) {
        // Same conflation as findById, for the same reason: a caller must not be
        // able to distinguish "no such identity" from "not yours".
        return foundation::fail(foundation::ErrorCode::NotFound);
    }

    return position->second.identity.changeStatus(status);
}

foundation::Result<std::vector<IdentityId>>
InMemoryIdentityRepository::idsOfKind(const OrganizationId& organization, SubjectKind kind) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    std::vector<IdentityId> out;
    for (const auto& [key, owned] : m_entries) {
        if (owned.organization == organization && owned.identity.kind() == kind) {
            out.push_back(key);
        }
    }
    return out;
}

foundation::Result<std::size_t>
InMemoryIdentityRepository::countIn(const OrganizationId& organization) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    std::size_t total = 0;
    for (const auto& [key, owned] : m_entries) {
        static_cast<void>(key);
        if (owned.organization == organization) {
            ++total;
        }
    }

    foundation::requireInvariant(total <= m_entries.size(), "identity repository count exceeds storage size");
    return total;
}

std::size_t InMemoryIdentityRepository::size() const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    return m_entries.size();
}

}

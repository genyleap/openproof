module;

#include <cstddef>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

module openproof.organization;

namespace openproof::organization {

foundation::Status InMemoryOrganizationRepository::add(Organization organization)
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    const OrganizationId key = organization.id();
    if (m_entries.contains(key)) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "That organization already exists.");
    }

    m_entries.emplace(key, std::move(organization));
    return foundation::ok();
}

foundation::Result<std::optional<Organization>>
InMemoryOrganizationRepository::findById(const OrganizationId& id) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    const auto position = m_entries.find(id);
    if (position == m_entries.end()) {
        return std::optional<Organization>{};
    }
    return std::optional<Organization>{position->second};
}

foundation::Status InMemoryOrganizationRepository::changeStatus(const OrganizationId& id,
                                                                OrganizationStatus status)
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    const auto position = m_entries.find(id);
    if (position == m_entries.end()) {
        return foundation::fail(foundation::ErrorCode::NotFound);
    }
    return position->second.changeStatus(status);
}

foundation::Result<std::size_t> InMemoryOrganizationRepository::count() const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    return m_entries.size();
}

foundation::Status InMemoryMembershipRepository::add(Membership membership)
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    const Key key{membership.organization(), membership.identity()};
    if (m_entries.contains(key)) {
        return foundation::fail(
            foundation::ErrorCode::AlreadyExists,
            "That identity is already a member of this organization.",
            "A second membership for the same pair would make the member's effective role "
            "set ambiguous.");
    }

    m_entries.emplace(key, std::move(membership));
    return foundation::ok();
}

foundation::Result<std::optional<Membership>>
InMemoryMembershipRepository::find(const OrganizationId& organization,
                                   const IdentityId& identity) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    const auto position = m_entries.find(Key{organization, identity});
    if (position == m_entries.end()) {
        return std::optional<Membership>{};
    }
    return std::optional<Membership>{position->second};
}

foundation::Status InMemoryMembershipRepository::save(const Membership& membership)
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    const Key key{membership.organization(), membership.identity()};
    const auto position = m_entries.find(key);
    if (position == m_entries.end()) {
        return foundation::fail(foundation::ErrorCode::NotFound,
                                "That membership was not found.");
    }

    position->second = membership;
    return foundation::ok();
}

foundation::Result<std::vector<IdentityId>>
InMemoryMembershipRepository::membersOf(const OrganizationId& organization) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    std::vector<IdentityId> out;
    for (const auto& [key, membership] : m_entries) {
        static_cast<void>(membership);
        if (key.first == organization) {
            out.push_back(key.second);
        }
    }
    return out;
}

foundation::Result<std::vector<OrganizationId>>
InMemoryMembershipRepository::organizationsOf(const IdentityId& identity) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    std::vector<OrganizationId> out;
    for (const auto& [key, membership] : m_entries) {
        static_cast<void>(membership);
        if (key.second == identity) {
            out.push_back(key.first);
        }
    }
    return out;
}

foundation::Result<std::size_t>
InMemoryMembershipRepository::countIn(const OrganizationId& organization) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    std::size_t total = 0;
    for (const auto& [key, membership] : m_entries) {
        static_cast<void>(membership);
        if (key.first == organization) {
            ++total;
        }
    }

    contract_assert(total <= m_entries.size());
    return total;
}

std::size_t InMemoryMembershipRepository::size() const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    return m_entries.size();
}

}

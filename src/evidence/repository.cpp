module;

#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

module openproof.evidence;

namespace openproof::evidence {

struct InMemoryEvidenceRepository::Impl final {
    mutable std::mutex mutex;
    std::map<EvidenceId, std::unique_ptr<Evidence>> evidence;
};

InMemoryEvidenceRepository::InMemoryEvidenceRepository()
    : m_impl(std::make_unique<Impl>())
{
}

InMemoryEvidenceRepository::~InMemoryEvidenceRepository() = default;

foundation::Status InMemoryEvidenceRepository::add(Evidence evidence)
{
    std::vector<Evidence> batch;
    batch.push_back(std::move(evidence));
    return addBatch(std::move(batch));
}

foundation::Status InMemoryEvidenceRepository::addBatch(std::vector<Evidence> evidence)
{
    std::scoped_lock lock{m_impl->mutex};
    for (const auto& item : evidence) {
        if (m_impl->evidence.contains(item.id())) {
            return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                    "The evidence already exists.");
        }
    }
    for (auto& item : evidence) {
        const EvidenceId id = item.id();
        m_impl->evidence.emplace(id, std::make_unique<Evidence>(std::move(item)));
    }
    return foundation::ok();
}

foundation::Status InMemoryEvidenceRepository::revoke(const EvidenceId& id)
{
    std::scoped_lock lock{m_impl->mutex};
    const auto found = m_impl->evidence.find(id);
    if (found == m_impl->evidence.end()) {
        return foundation::fail(foundation::ErrorCode::NotFound);
    }
    return found->second->revoke();
}

foundation::Result<std::optional<Evidence>>
InMemoryEvidenceRepository::find(const EvidenceId& id) const
{
    std::scoped_lock lock{m_impl->mutex};
    const auto found = m_impl->evidence.find(id);
    if (found == m_impl->evidence.end()) return std::optional<Evidence>{};
    return std::optional<Evidence>{*found->second};
}

foundation::Result<std::vector<Evidence>>
InMemoryEvidenceRepository::forIdentity(
    const identity::core::IdentityId& identity) const
{
    std::scoped_lock lock{m_impl->mutex};
    std::vector<Evidence> output;
    for (const auto& [id, item] : m_impl->evidence) {
        static_cast<void>(id);
        if (item->identity() == identity) output.push_back(*item);
    }
    return output;
}

} // namespace openproof::evidence

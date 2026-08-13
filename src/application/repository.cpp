module;

#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.application;

namespace openproof::application {
namespace {
[[nodiscard]] std::string tenantIdentifierKey(
    const identity::core::OrganizationId& owner, std::string_view identifier)
{
    std::string key{owner.value()};
    key.push_back('\0');
    key.append(identifier);
    return key;
}
}

struct InMemoryApplicationRepository::Impl final {
    mutable std::mutex mutex;
    std::map<ApplicationId, std::unique_ptr<Application>> applications;
    std::map<std::string, ApplicationId, std::less<>> identifiers;
};

InMemoryApplicationRepository::InMemoryApplicationRepository()
    : m_impl(std::make_unique<Impl>())
{
}

InMemoryApplicationRepository::~InMemoryApplicationRepository() = default;

foundation::Status InMemoryApplicationRepository::add(Application application)
{
    std::scoped_lock lock{m_impl->mutex};
    if (m_impl->applications.contains(application.id())
        || m_impl->identifiers.contains(
            tenantIdentifierKey(application.owner(), application.identifier()))) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The application already exists.");
    }
    const ApplicationId id = application.id();
    m_impl->identifiers.emplace(
        tenantIdentifierKey(application.owner(), application.identifier()), id);
    m_impl->applications.emplace(
        id, std::make_unique<Application>(std::move(application)));
    return foundation::ok();
}

foundation::Status InMemoryApplicationRepository::save(const Application& application)
{
    std::scoped_lock lock{m_impl->mutex};
    auto found = m_impl->applications.find(application.id());
    if (found == m_impl->applications.end()) {
        return foundation::fail(foundation::ErrorCode::NotFound);
    }
    if (found->second->identifier() != application.identifier()) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "An application identifier is immutable.");
    }
    found->second = std::make_unique<Application>(application);
    return foundation::ok();
}

foundation::Result<std::optional<Application>>
InMemoryApplicationRepository::findById(const ApplicationId& id) const
{
    std::scoped_lock lock{m_impl->mutex};
    const auto found = m_impl->applications.find(id);
    if (found == m_impl->applications.end()) return std::optional<Application>{};
    return std::optional<Application>{*found->second};
}

foundation::Result<std::optional<Application>>
InMemoryApplicationRepository::findByIdentifier(
    const identity::core::OrganizationId& owner, std::string_view identifier) const
{
    std::scoped_lock lock{m_impl->mutex};
    const auto byIdentifier = m_impl->identifiers.find(
        tenantIdentifierKey(owner, identifier));
    if (byIdentifier == m_impl->identifiers.end()) return std::optional<Application>{};
    const auto found = m_impl->applications.find(byIdentifier->second);
    if (found == m_impl->applications.end()) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "The application registry index is inconsistent.");
    }
    return std::optional<Application>{*found->second};
}

foundation::Result<std::vector<Application>> InMemoryApplicationRepository::list() const
{
    std::scoped_lock lock{m_impl->mutex};
    std::vector<Application> output;
    output.reserve(m_impl->applications.size());
    for (const auto& [id, application] : m_impl->applications) {
        static_cast<void>(id);
        output.push_back(*application);
    }
    return output;
}

}

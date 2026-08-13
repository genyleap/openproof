module;

#include <string>
#include <utility>

module openproof.application;

namespace openproof::application {

ApplicationRegistry::ApplicationRegistry(ApplicationRepository& repository,
                                         const foundation::ClockSource& clock)
    : m_repository(&repository), m_clock(&clock)
{
}

foundation::Result<Application> ApplicationRegistry::registerApplication(
    identity::core::OrganizationId owner, std::string identifier,
    std::string displayName, Environment environment)
{
    auto id = security::randomTokenBase64Url(24U);
    if (!id) return foundation::fail(id.error());
    auto application = Application::create(
        ApplicationId{std::move(id).value()}, std::move(owner), std::move(identifier),
        std::move(displayName), environment, m_clock->now());
    if (!application) return foundation::fail(application.error());
    auto stored = m_repository->add(application.value());
    if (!stored) return foundation::fail(stored.error());
    return application;
}

foundation::Result<Application> ApplicationRegistry::require(const ApplicationId& id) const
{
    auto found = m_repository->findById(id);
    if (!found) return foundation::fail(found.error());
    if (!found->has_value()) return foundation::fail(foundation::ErrorCode::NotFound);
    return found->value();
}

foundation::Result<Application> ApplicationRegistry::suspend(const ApplicationId& id)
{
    auto application = require(id);
    if (!application) return foundation::fail(application.error());
    auto changed = application->suspend(m_clock->now());
    if (!changed) return foundation::fail(changed.error());
    auto saved = m_repository->save(application.value());
    if (!saved) return foundation::fail(saved.error());
    return application;
}

foundation::Result<Application> ApplicationRegistry::activate(const ApplicationId& id)
{
    auto application = require(id);
    if (!application) return foundation::fail(application.error());
    auto changed = application->activate(m_clock->now());
    if (!changed) return foundation::fail(changed.error());
    auto saved = m_repository->save(application.value());
    if (!saved) return foundation::fail(saved.error());
    return application;
}

foundation::Result<Application> ApplicationRegistry::revoke(const ApplicationId& id)
{
    auto application = require(id);
    if (!application) return foundation::fail(application.error());
    auto changed = application->revoke(m_clock->now());
    if (!changed) return foundation::fail(changed.error());
    auto saved = m_repository->save(application.value());
    if (!saved) return foundation::fail(saved.error());
    return application;
}

}

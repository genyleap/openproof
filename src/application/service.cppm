module;

#include <string>

export module openproof.application:service;

import openproof.foundation;
import openproof.identity.core;
import openproof.security;
import :model;
import :repository;

export namespace openproof::application {

class ApplicationRegistry final {
public:
    ApplicationRegistry(ApplicationRepository& repository,
                        const foundation::ClockSource& clock);

    [[nodiscard]] foundation::Result<Application>
    registerApplication(identity::core::OrganizationId owner,
                        std::string identifier, std::string displayName,
                        Environment environment);
    [[nodiscard]] foundation::Result<Application>
    suspend(const ApplicationId& id);
    [[nodiscard]] foundation::Result<Application>
    activate(const ApplicationId& id);
    [[nodiscard]] foundation::Result<Application>
    revoke(const ApplicationId& id);

private:
    [[nodiscard]] foundation::Result<Application> require(const ApplicationId& id) const;

    ApplicationRepository* m_repository;
    const foundation::ClockSource* m_clock;
};

}

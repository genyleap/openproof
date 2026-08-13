module;

#include <string>
#include <string_view>

export module openproof.application:model;

import openproof.foundation;
import openproof.identity.core;

export namespace openproof::application {

struct ApplicationIdTag {};
using ApplicationId = foundation::StrongId<ApplicationIdTag>;

enum class Environment {
    Development,
    Staging,
    Production,
};

[[nodiscard]] std::string_view environmentName(Environment environment) noexcept;

enum class ApplicationStatus {
    Active,
    Suspended,
    Revoked,
};

[[nodiscard]] std::string_view applicationStatusName(ApplicationStatus status) noexcept;
[[nodiscard]] bool applicationPermitsAuthorization(ApplicationStatus status) noexcept;

/**
 * @brief A product that delegates identity and access to OpenProof.
 *
 * Applications are stable logical products. OAuth clients are separate child
 * registrations so a web, native and service client can be rotated or revoked
 * independently without changing the product identity.
 */
class Application final {
public:
    Application(const Application& other);
    Application(Application&& other);
    Application& operator=(const Application& other);
    Application& operator=(Application&& other);
    ~Application();

    [[nodiscard]] static foundation::Result<Application>
    create(ApplicationId id, identity::core::OrganizationId owner,
           std::string identifier, std::string displayName,
           Environment environment, foundation::Instant createdAt);

    [[nodiscard]] static foundation::Result<Application>
    restore(ApplicationId id, identity::core::OrganizationId owner,
            std::string identifier, std::string displayName,
            Environment environment, ApplicationStatus status,
            foundation::Instant createdAt, foundation::Instant updatedAt);

    [[nodiscard]] const ApplicationId& id() const noexcept;
    [[nodiscard]] const identity::core::OrganizationId& owner() const noexcept;
    [[nodiscard]] std::string_view identifier() const noexcept;
    [[nodiscard]] std::string_view displayName() const noexcept;
    [[nodiscard]] Environment environment() const noexcept;
    [[nodiscard]] ApplicationStatus status() const noexcept;
    [[nodiscard]] foundation::Instant createdAt() const noexcept;
    [[nodiscard]] foundation::Instant updatedAt() const noexcept;
    [[nodiscard]] bool permitsAuthorization() const noexcept;

    [[nodiscard]] foundation::Status suspend(foundation::Instant now);
    [[nodiscard]] foundation::Status activate(foundation::Instant now);
    [[nodiscard]] foundation::Status revoke(foundation::Instant now);
    [[nodiscard]] foundation::Status rename(std::string displayName,
                                            foundation::Instant now);

private:
    Application(ApplicationId id, identity::core::OrganizationId owner,
                std::string identifier, std::string displayName,
                Environment environment, foundation::Instant createdAt);

    ApplicationId m_id;
    identity::core::OrganizationId m_owner;
    std::string m_identifier;
    std::string m_displayName;
    Environment m_environment{Environment::Development};
    ApplicationStatus m_status{ApplicationStatus::Active};
    foundation::Instant m_createdAt{};
    foundation::Instant m_updatedAt{};
};

}

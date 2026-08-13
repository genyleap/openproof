module;

#include <chrono>
#include <algorithm>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>

module openproof.application;

namespace openproof::application {
namespace {

[[nodiscard]] bool validIdentifier(std::string_view value) noexcept
{
    if (value.size() < 2U || value.size() > 64U) return false;
    if (value.front() < 'a' || value.front() > 'z') return false;
    if (value.back() == '-' || value.back() == '.') return false;
    bool previousSeparator = false;
    for (char symbol : value) {
        const bool alpha = symbol >= 'a' && symbol <= 'z';
        const bool digit = symbol >= '0' && symbol <= '9';
        const bool separator = symbol == '-' || symbol == '.';
        if (!alpha && !digit && !separator) return false;
        if (separator && previousSeparator) return false;
        previousSeparator = separator;
    }
    return true;
}

[[nodiscard]] bool validDisplayName(std::string_view value) noexcept
{
    if (value.empty() || value.size() > 120U) return false;
    return std::ranges::none_of(value, [](char symbol) {
        const auto byte = static_cast<unsigned char>(symbol);
        return byte < 0x20U || byte == 0x7FU;
    });
}

}

std::string_view environmentName(Environment environment) noexcept
{
    switch (environment) {
    case Environment::Development: return "development";
    case Environment::Staging: return "staging";
    case Environment::Production: return "production";
    }
    return "development";
}

std::string_view applicationStatusName(ApplicationStatus status) noexcept
{
    switch (status) {
    case ApplicationStatus::Active: return "active";
    case ApplicationStatus::Suspended: return "suspended";
    case ApplicationStatus::Revoked: return "revoked";
    }
    return "revoked";
}

bool applicationPermitsAuthorization(ApplicationStatus status) noexcept
{
    return status == ApplicationStatus::Active;
}

Application::Application(const Application& other)
    : m_id(other.m_id)
    , m_owner(other.m_owner)
    , m_identifier(other.m_identifier)
    , m_displayName(other.m_displayName)
    , m_environment(other.m_environment)
    , m_status(other.m_status)
    , m_createdAt(other.m_createdAt)
    , m_updatedAt(other.m_updatedAt)
{
}

Application::Application(Application&& other)
    : m_id(std::move(other.m_id))
    , m_owner(std::move(other.m_owner))
    , m_identifier(std::move(other.m_identifier))
    , m_displayName(std::move(other.m_displayName))
    , m_environment(other.m_environment)
    , m_status(other.m_status)
    , m_createdAt(other.m_createdAt)
    , m_updatedAt(other.m_updatedAt)
{
}

Application& Application::operator=(const Application& other)
{
    if (this != &other) {
        m_id = other.m_id;
        m_owner = other.m_owner;
        m_identifier = other.m_identifier;
        m_displayName = other.m_displayName;
        m_environment = other.m_environment;
        m_status = other.m_status;
        m_createdAt = other.m_createdAt;
        m_updatedAt = other.m_updatedAt;
    }
    return *this;
}

Application& Application::operator=(Application&& other)
{
    if (this != &other) {
        m_id = std::move(other.m_id);
        m_owner = std::move(other.m_owner);
        m_identifier = std::move(other.m_identifier);
        m_displayName = std::move(other.m_displayName);
        m_environment = other.m_environment;
        m_status = other.m_status;
        m_createdAt = other.m_createdAt;
        m_updatedAt = other.m_updatedAt;
    }
    return *this;
}

Application::~Application()
{
}

Application::Application(ApplicationId id, identity::core::OrganizationId owner,
                         std::string identifier, std::string displayName,
                         Environment environment, foundation::Instant createdAt)
    : m_id(std::move(id))
    , m_owner(std::move(owner))
    , m_identifier(std::move(identifier))
    , m_displayName(std::move(displayName))
    , m_environment(environment)
    , m_createdAt(createdAt)
    , m_updatedAt(createdAt)
{
}

foundation::Result<Application> Application::create(
    ApplicationId id, identity::core::OrganizationId owner,
    std::string identifier, std::string displayName,
    Environment environment, foundation::Instant createdAt)
{
    if (id.empty() || owner.empty() || !validIdentifier(identifier) || !validDisplayName(displayName)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The application registration is invalid.");
    }
    return Application{std::move(id), std::move(owner), std::move(identifier),
                       std::move(displayName), environment, createdAt};
}

foundation::Result<Application> Application::restore(
    ApplicationId id, identity::core::OrganizationId owner,
    std::string identifier, std::string displayName,
    Environment environment, ApplicationStatus status,
    foundation::Instant createdAt, foundation::Instant updatedAt)
{
    auto restored = create(std::move(id), std::move(owner), std::move(identifier),
                           std::move(displayName), environment, createdAt);
    if (!restored) return foundation::fail(restored.error());
    if (updatedAt < createdAt) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "Stored application timestamps are invalid.");
    }
    restored->m_status = status;
    restored->m_updatedAt = updatedAt;
    return restored;
}

const ApplicationId& Application::id() const noexcept { return m_id; }
const identity::core::OrganizationId& Application::owner() const noexcept { return m_owner; }
std::string_view Application::identifier() const noexcept { return m_identifier; }
std::string_view Application::displayName() const noexcept { return m_displayName; }
Environment Application::environment() const noexcept { return m_environment; }
ApplicationStatus Application::status() const noexcept { return m_status; }
foundation::Instant Application::createdAt() const noexcept { return m_createdAt; }
foundation::Instant Application::updatedAt() const noexcept { return m_updatedAt; }
bool Application::permitsAuthorization() const noexcept
{ return applicationPermitsAuthorization(m_status); }

foundation::Status Application::suspend(foundation::Instant now)
{
    if (m_status == ApplicationStatus::Revoked) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "A revoked application cannot change state.");
    }
    if (m_status != ApplicationStatus::Active || now < m_updatedAt) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The application cannot be suspended.");
    }
    m_status = ApplicationStatus::Suspended;
    m_updatedAt = now;
    return foundation::ok();
}

foundation::Status Application::activate(foundation::Instant now)
{
    if (m_status == ApplicationStatus::Revoked) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "A revoked application cannot be reactivated.");
    }
    if (m_status != ApplicationStatus::Suspended || now < m_updatedAt) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The application cannot be activated.");
    }
    m_status = ApplicationStatus::Active;
    m_updatedAt = now;
    return foundation::ok();
}

foundation::Status Application::revoke(foundation::Instant now)
{
    if (m_status == ApplicationStatus::Revoked || now < m_updatedAt) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The application cannot be revoked.");
    }
    m_status = ApplicationStatus::Revoked;
    m_updatedAt = now;
    return foundation::ok();
}

foundation::Status Application::rename(std::string displayName,
                                        foundation::Instant now)
{
    if (m_status == ApplicationStatus::Revoked || now < m_updatedAt
        || !validDisplayName(displayName)) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The application cannot be renamed.");
    }
    m_displayName = std::move(displayName);
    m_updatedAt = now;
    return foundation::ok();
}

}

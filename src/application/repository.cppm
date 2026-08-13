module;

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

export module openproof.application:repository;

import openproof.foundation;
import openproof.identity.core;
import :model;

export namespace openproof::application {

class ApplicationRepository {
public:
    ApplicationRepository(const ApplicationRepository&) = delete;
    ApplicationRepository& operator=(const ApplicationRepository&) = delete;
    virtual ~ApplicationRepository() = default;

    [[nodiscard]] virtual foundation::Status add(Application application) = 0;
    [[nodiscard]] virtual foundation::Status save(const Application& application) = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<Application>>
    findById(const ApplicationId& id) const = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<Application>>
    findByIdentifier(const identity::core::OrganizationId& owner,
                     std::string_view identifier) const = 0;
    [[nodiscard]] virtual foundation::Result<std::vector<Application>> list() const = 0;

protected:
    ApplicationRepository() = default;
};

class InMemoryApplicationRepository final : public ApplicationRepository {
public:
    InMemoryApplicationRepository();
    ~InMemoryApplicationRepository() override;
    InMemoryApplicationRepository(const InMemoryApplicationRepository&) = delete;
    InMemoryApplicationRepository& operator=(const InMemoryApplicationRepository&) = delete;
    InMemoryApplicationRepository(InMemoryApplicationRepository&&) = delete;
    InMemoryApplicationRepository& operator=(InMemoryApplicationRepository&&) = delete;

    [[nodiscard]] foundation::Status add(Application application) override;
    [[nodiscard]] foundation::Status save(const Application& application) override;
    [[nodiscard]] foundation::Result<std::optional<Application>>
    findById(const ApplicationId& id) const override;
    [[nodiscard]] foundation::Result<std::optional<Application>>
    findByIdentifier(const identity::core::OrganizationId& owner,
                     std::string_view identifier) const override;
    [[nodiscard]] foundation::Result<std::vector<Application>> list() const override;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}

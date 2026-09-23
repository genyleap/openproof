module;

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

export module openproof.identity.profile:repository;

import openproof.foundation;
import openproof.identity.core;
import :model;

export namespace openproof::identity::profile {

class IdentityProfileRepository {
public:
    IdentityProfileRepository(const IdentityProfileRepository&) = delete;
    IdentityProfileRepository& operator=(const IdentityProfileRepository&) = delete;
    virtual ~IdentityProfileRepository() = default;

    [[nodiscard]] virtual foundation::Status save(const IdentityProfile& profile) = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<IdentityProfile>>
    find(const core::IdentityId& identity) const = 0;
    [[nodiscard]] virtual foundation::Result<std::vector<core::IdentityId>>
    findVerifiedByEmail(std::string_view email) const = 0;

protected:
    IdentityProfileRepository() = default;
};

class InMemoryIdentityProfileRepository final : public IdentityProfileRepository {
public:
    InMemoryIdentityProfileRepository();
    ~InMemoryIdentityProfileRepository() override;
    InMemoryIdentityProfileRepository(const InMemoryIdentityProfileRepository&) = delete;
    InMemoryIdentityProfileRepository& operator=(const InMemoryIdentityProfileRepository&) = delete;
    InMemoryIdentityProfileRepository(InMemoryIdentityProfileRepository&&) = delete;
    InMemoryIdentityProfileRepository& operator=(InMemoryIdentityProfileRepository&&) = delete;

    [[nodiscard]] foundation::Status save(const IdentityProfile& profile) override;
    [[nodiscard]] foundation::Result<std::optional<IdentityProfile>>
    find(const core::IdentityId& identity) const override;
    [[nodiscard]] foundation::Result<std::vector<core::IdentityId>>
    findVerifiedByEmail(std::string_view email) const override;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}

#include <gtest/gtest.h>

#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

import openproof.enterprise.scim;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.profile;
import openproof.organization;

namespace {
namespace scim = openproof::enterprise::scim;
namespace fnd = openproof::foundation;
namespace identity = openproof::identity::core;
namespace profile = openproof::identity::profile;
namespace organization = openproof::organization;

constexpr fnd::Instant kNow{std::chrono::seconds{1'770'000'000}};

class MemoryDirectory final : public scim::DirectoryRepository {
public:
    [[nodiscard]] fnd::Status addUser(scim::UserRecord user) override
    {
        const auto key = std::pair{user.organization(), user.identity()};
        if (m_users.contains(key)) return fnd::fail(fnd::ErrorCode::AlreadyExists);
        m_users.emplace(key, std::move(user));
        return fnd::ok();
    }

    [[nodiscard]] fnd::Status saveUser(const scim::UserRecord& user) override
    {
        const auto key = std::pair{user.organization(), user.identity()};
        const auto it = m_users.find(key);
        if (it == m_users.end()) return fnd::fail(fnd::ErrorCode::NotFound);
        it->second = user;
        return fnd::ok();
    }

    [[nodiscard]] fnd::Status removeUser(
        const identity::OrganizationId& organization,
        const identity::IdentityId& id) override
    {
        return m_users.erase({organization, id}) == 1U
            ? fnd::ok() : fnd::fail(fnd::ErrorCode::NotFound);
    }

    [[nodiscard]] fnd::Result<std::optional<scim::UserRecord>> findUser(
        const identity::OrganizationId& organization,
        const identity::IdentityId& id) const override
    {
        const auto it = m_users.find({organization, id});
        if (it == m_users.end()) return std::optional<scim::UserRecord>{};
        return std::optional<scim::UserRecord>{it->second};
    }

    [[nodiscard]] fnd::Result<std::optional<scim::UserRecord>> findUserByName(
        const identity::OrganizationId& organization,
        std::string_view userName) const override
    {
        for (const auto& [key, value] : m_users) {
            if (key.first == organization && value.userName() == userName) {
                return std::optional<scim::UserRecord>{value};
            }
        }
        return std::optional<scim::UserRecord>{};
    }

    [[nodiscard]] fnd::Result<std::vector<scim::UserRecord>> users(
        const identity::OrganizationId& organization) const override
    {
        std::vector<scim::UserRecord> values;
        for (const auto& [key, value] : m_users) {
            if (key.first == organization) values.push_back(value);
        }
        return values;
    }

    [[nodiscard]] fnd::Status addGroup(scim::GroupRecord group) override
    {
        const auto key = std::pair{group.organization(), group.id()};
        if (m_groups.contains(key)) return fnd::fail(fnd::ErrorCode::AlreadyExists);
        m_groups.emplace(key, std::move(group));
        return fnd::ok();
    }

    [[nodiscard]] fnd::Status saveGroup(const scim::GroupRecord& group) override
    {
        const auto key = std::pair{group.organization(), group.id()};
        const auto it = m_groups.find(key);
        if (it == m_groups.end()) return fnd::fail(fnd::ErrorCode::NotFound);
        it->second = group;
        return fnd::ok();
    }

    [[nodiscard]] fnd::Status removeGroup(
        const identity::OrganizationId& organization,
        const scim::GroupId& id) override
    {
        m_members.erase({organization, id});
        return m_groups.erase({organization, id}) == 1U
            ? fnd::ok() : fnd::fail(fnd::ErrorCode::NotFound);
    }

    [[nodiscard]] fnd::Result<std::optional<scim::GroupRecord>> findGroup(
        const identity::OrganizationId& organization,
        const scim::GroupId& id) const override
    {
        const auto it = m_groups.find({organization, id});
        if (it == m_groups.end()) return std::optional<scim::GroupRecord>{};
        return std::optional<scim::GroupRecord>{it->second};
    }

    [[nodiscard]] fnd::Result<std::optional<scim::GroupRecord>> findGroupByName(
        const identity::OrganizationId& organization,
        std::string_view displayName) const override
    {
        for (const auto& [key, value] : m_groups) {
            if (key.first == organization && value.displayName() == displayName) {
                return std::optional<scim::GroupRecord>{value};
            }
        }
        return std::optional<scim::GroupRecord>{};
    }

    [[nodiscard]] fnd::Result<std::vector<scim::GroupRecord>> groups(
        const identity::OrganizationId& organization) const override
    {
        std::vector<scim::GroupRecord> values;
        for (const auto& [key, value] : m_groups) {
            if (key.first == organization) values.push_back(value);
        }
        return values;
    }

    [[nodiscard]] fnd::Result<std::vector<identity::IdentityId>> groupMembers(
        const identity::OrganizationId& organization,
        const scim::GroupId& id) const override
    {
        const auto it = m_members.find({organization, id});
        return it == m_members.end() ? std::vector<identity::IdentityId>{} : it->second;
    }

    [[nodiscard]] fnd::Status replaceGroupMembers(
        const identity::OrganizationId& organization, const scim::GroupId& id,
        std::vector<identity::IdentityId> members) override
    {
        if (!m_groups.contains({organization, id})) return fnd::fail(fnd::ErrorCode::NotFound);
        m_members[{organization, id}] = std::move(members);
        return fnd::ok();
    }

private:
    using UserKey = std::pair<identity::OrganizationId, identity::IdentityId>;
    using GroupKey = std::pair<identity::OrganizationId, scim::GroupId>;
    std::map<UserKey, scim::UserRecord> m_users;
    std::map<GroupKey, scim::GroupRecord> m_groups;
    std::map<GroupKey, std::vector<identity::IdentityId>> m_members;
};

TEST(ScimServiceTest, RemovedMembershipCannotReactivateCanonicalIdentity)
{
    const identity::OrganizationId organizationId{"org-scim"};
    const identity::IdentityId identityId{"identity-scim"};
    identity::InMemoryIdentityRepository identities;
    profile::InMemoryIdentityProfileRepository profiles;
    organization::InMemoryMembershipRepository memberships;
    MemoryDirectory directory;
    fnd::ManualClockSource clock{kNow};

    auto canonical = identity::Identity::create(identityId, identity::SubjectKind::Human, kNow);
    ASSERT_TRUE(canonical);
    ASSERT_TRUE(identities.add(organizationId, std::move(canonical).value()));
    ASSERT_TRUE(identities.changeStatus(organizationId, identityId, identity::IdentityStatus::Suspended));

    auto membership = organization::Membership::invite(organizationId, identityId, kNow);
    ASSERT_TRUE(membership);
    ASSERT_TRUE(membership->accept());
    ASSERT_TRUE(membership->remove());
    ASSERT_TRUE(memberships.add(std::move(membership).value()));

    auto identityProfile = profile::IdentityProfile::create(identityId, kNow);
    ASSERT_TRUE(identityProfile);
    ASSERT_TRUE(profiles.save(identityProfile.value()));

    auto record = scim::UserRecord::create(
        identityId, organizationId, "alice", std::nullopt, kNow, kNow);
    ASSERT_TRUE(record);
    ASSERT_TRUE(directory.addUser(record.value()));

    scim::Service service{organizationId, directory, identities, profiles, memberships, clock};
    auto replaced = service.replaceUser(
        identityId, "alice", std::nullopt, true, std::nullopt, std::nullopt);

    ASSERT_FALSE(replaced);
    EXPECT_EQ(replaced.error().code(), fnd::ErrorCode::FailedPrecondition);
    auto after = identities.findById(organizationId, identityId);
    ASSERT_TRUE(after);
    ASSERT_TRUE(after->has_value());
    EXPECT_EQ(after->value().status(), identity::IdentityStatus::Suspended);
}

} // namespace

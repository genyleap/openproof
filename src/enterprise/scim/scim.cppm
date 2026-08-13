module;

#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.enterprise.scim;

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.profile;
import openproof.organization;

export namespace openproof::enterprise::scim {

struct GroupIdTag {};
using GroupId = foundation::StrongId<GroupIdTag>;

/** @brief Durable SCIM metadata for one canonical human identity. */
class UserRecord final {
public:
    [[nodiscard]] static foundation::Result<UserRecord> create(
        identity::core::IdentityId identity, identity::core::OrganizationId organization,
        std::string userName, std::optional<std::string> externalId,
        foundation::Instant createdAt, foundation::Instant updatedAt);

    [[nodiscard]] const identity::core::IdentityId& identity() const noexcept;
    [[nodiscard]] const identity::core::OrganizationId& organization() const noexcept;
    [[nodiscard]] std::string_view userName() const noexcept;
    [[nodiscard]] const std::optional<std::string>& externalId() const noexcept;
    [[nodiscard]] foundation::Instant createdAt() const noexcept;
    [[nodiscard]] foundation::Instant updatedAt() const noexcept;
    [[nodiscard]] foundation::Status rename(std::string userName,
                                            std::optional<std::string> externalId,
                                            foundation::Instant now);

private:
    UserRecord(identity::core::IdentityId identity,
               identity::core::OrganizationId organization,
               std::string userName, std::optional<std::string> externalId,
               foundation::Instant createdAt, foundation::Instant updatedAt);
    identity::core::IdentityId m_identity;
    identity::core::OrganizationId m_organization;
    std::string m_userName;
    std::optional<std::string> m_externalId;
    foundation::Instant m_createdAt{};
    foundation::Instant m_updatedAt{};
};

/** @brief Durable SCIM group metadata; membership is stored separately. */
class GroupRecord final {
public:
    [[nodiscard]] static foundation::Result<GroupRecord> create(
        GroupId id, identity::core::OrganizationId organization,
        std::string displayName, std::optional<std::string> externalId,
        foundation::Instant createdAt, foundation::Instant updatedAt);

    [[nodiscard]] const GroupId& id() const noexcept;
    [[nodiscard]] const identity::core::OrganizationId& organization() const noexcept;
    [[nodiscard]] std::string_view displayName() const noexcept;
    [[nodiscard]] const std::optional<std::string>& externalId() const noexcept;
    [[nodiscard]] foundation::Instant createdAt() const noexcept;
    [[nodiscard]] foundation::Instant updatedAt() const noexcept;
    [[nodiscard]] foundation::Status rename(std::string displayName,
                                            std::optional<std::string> externalId,
                                            foundation::Instant now);

private:
    GroupRecord(GroupId id, identity::core::OrganizationId organization,
                std::string displayName, std::optional<std::string> externalId,
                foundation::Instant createdAt, foundation::Instant updatedAt);
    GroupId m_id;
    identity::core::OrganizationId m_organization;
    std::string m_displayName;
    std::optional<std::string> m_externalId;
    foundation::Instant m_createdAt{};
    foundation::Instant m_updatedAt{};
};

class DirectoryRepository {
public:
    DirectoryRepository(const DirectoryRepository&) = delete;
    DirectoryRepository& operator=(const DirectoryRepository&) = delete;
    virtual ~DirectoryRepository() = default;

    [[nodiscard]] virtual foundation::Status addUser(UserRecord user) = 0;
    [[nodiscard]] virtual foundation::Status saveUser(const UserRecord& user) = 0;
    [[nodiscard]] virtual foundation::Status removeUser(
        const identity::core::OrganizationId& organization,
        const identity::core::IdentityId& identity) = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<UserRecord>> findUser(
        const identity::core::OrganizationId& organization,
        const identity::core::IdentityId& identity) const = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<UserRecord>> findUserByName(
        const identity::core::OrganizationId& organization,
        std::string_view userName) const = 0;
    [[nodiscard]] virtual foundation::Result<std::vector<UserRecord>> users(
        const identity::core::OrganizationId& organization) const = 0;

    [[nodiscard]] virtual foundation::Status addGroup(GroupRecord group) = 0;
    [[nodiscard]] virtual foundation::Status saveGroup(const GroupRecord& group) = 0;
    [[nodiscard]] virtual foundation::Status removeGroup(
        const identity::core::OrganizationId& organization, const GroupId& id) = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<GroupRecord>> findGroup(
        const identity::core::OrganizationId& organization, const GroupId& id) const = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<GroupRecord>> findGroupByName(
        const identity::core::OrganizationId& organization,
        std::string_view displayName) const = 0;
    [[nodiscard]] virtual foundation::Result<std::vector<GroupRecord>> groups(
        const identity::core::OrganizationId& organization) const = 0;
    [[nodiscard]] virtual foundation::Result<std::vector<identity::core::IdentityId>> groupMembers(
        const identity::core::OrganizationId& organization, const GroupId& id) const = 0;
    [[nodiscard]] virtual foundation::Status replaceGroupMembers(
        const identity::core::OrganizationId& organization, const GroupId& id,
        std::vector<identity::core::IdentityId> members) = 0;

protected:
    DirectoryRepository() = default;
};

struct UserView final {
    UserRecord record;
    identity::core::IdentityStatus status{identity::core::IdentityStatus::Active};
    std::optional<identity::profile::IdentityProfile> profile;
};

struct GroupView final {
    GroupRecord record;
    std::vector<identity::core::IdentityId> members;
};

/** @brief SCIM 2.0 provisioning service backed by canonical identity/profile/membership aggregates. */
class Service final {
public:
    Service(identity::core::OrganizationId organization, DirectoryRepository& directory,
            identity::core::IdentityRepository& identities,
            identity::profile::IdentityProfileRepository& profiles,
            organization::MembershipRepository& memberships,
            const foundation::ClockSource& clock);

    [[nodiscard]] foundation::Result<UserView> createUser(
        std::string userName, std::optional<std::string> externalId, bool active,
        std::optional<std::string> displayName, std::optional<std::string> email);
    [[nodiscard]] foundation::Result<UserView> replaceUser(
        const identity::core::IdentityId& id, std::string userName,
        std::optional<std::string> externalId, bool active,
        std::optional<std::string> displayName, std::optional<std::string> email);
    [[nodiscard]] foundation::Result<UserView> user(const identity::core::IdentityId& id) const;
    [[nodiscard]] foundation::Result<std::vector<UserView>> users() const;
    [[nodiscard]] foundation::Result<std::optional<UserView>> userByName(std::string_view userName) const;
    [[nodiscard]] foundation::Status removeUser(const identity::core::IdentityId& id);

    [[nodiscard]] foundation::Result<GroupView> createGroup(
        std::string displayName, std::optional<std::string> externalId,
        std::vector<identity::core::IdentityId> members);
    [[nodiscard]] foundation::Result<GroupView> replaceGroup(
        const GroupId& id, std::string displayName, std::optional<std::string> externalId,
        std::vector<identity::core::IdentityId> members);
    [[nodiscard]] foundation::Result<GroupView> group(const GroupId& id) const;
    [[nodiscard]] foundation::Result<std::vector<GroupView>> groups() const;
    [[nodiscard]] foundation::Result<std::optional<GroupView>> groupByName(std::string_view displayName) const;
    [[nodiscard]] foundation::Status removeGroup(const GroupId& id);

private:
    [[nodiscard]] foundation::Result<UserView> hydrate(const UserRecord& record) const;
    [[nodiscard]] foundation::Status setActive(const identity::core::IdentityId& id, bool active);
    [[nodiscard]] foundation::Status validateMembers(
        const std::vector<identity::core::IdentityId>& members) const;

    identity::core::OrganizationId m_organization;
    DirectoryRepository* m_directory;
    identity::core::IdentityRepository* m_identities;
    identity::profile::IdentityProfileRepository* m_profiles;
    organization::MembershipRepository* m_memberships;
    const foundation::ClockSource* m_clock;
};

} // namespace openproof::enterprise::scim

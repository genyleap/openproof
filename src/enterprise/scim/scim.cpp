module;

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.enterprise.scim;

import openproof.security;

namespace openproof::enterprise::scim {
namespace {
using namespace std::chrono_literals;

[[nodiscard]] bool validText(std::string_view value, std::size_t maximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::none_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           });
}

[[nodiscard]] bool validOptional(const std::optional<std::string>& value,
                                 std::size_t maximum) noexcept
{
    return !value || validText(*value, maximum);
}

[[nodiscard]] foundation::Result<identity::core::IdentityId> newIdentityId()
{
    auto random = security::randomTokenBase64Url(24U);
    if (!random) return foundation::fail(random.error());
    return identity::core::IdentityId{"scim_" + random.value()};
}

[[nodiscard]] foundation::Result<GroupId> newGroupId()
{
    auto random = security::randomTokenBase64Url(24U);
    if (!random) return foundation::fail(random.error());
    return GroupId{"scim_group_" + random.value()};
}

} // namespace

UserRecord::UserRecord(identity::core::IdentityId identity,
                       identity::core::OrganizationId organization,
                       std::string userName, std::optional<std::string> externalId,
                       foundation::Instant createdAt, foundation::Instant updatedAt)
    : m_identity(std::move(identity)), m_organization(std::move(organization)),
      m_userName(std::move(userName)), m_externalId(std::move(externalId)),
      m_createdAt(createdAt), m_updatedAt(updatedAt) {}

foundation::Result<UserRecord> UserRecord::create(
    identity::core::IdentityId identity, identity::core::OrganizationId organization,
    std::string userName, std::optional<std::string> externalId,
    foundation::Instant createdAt, foundation::Instant updatedAt)
{
    if (identity.empty() || organization.empty() || !validText(userName, 320U)
        || !validOptional(externalId, 1024U) || updatedAt < createdAt) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The SCIM user metadata is invalid.");
    }
    return UserRecord{std::move(identity), std::move(organization), std::move(userName),
                      std::move(externalId), createdAt, updatedAt};
}

const identity::core::IdentityId& UserRecord::identity() const noexcept { return m_identity; }
const identity::core::OrganizationId& UserRecord::organization() const noexcept { return m_organization; }
std::string_view UserRecord::userName() const noexcept { return m_userName; }
const std::optional<std::string>& UserRecord::externalId() const noexcept { return m_externalId; }
foundation::Instant UserRecord::createdAt() const noexcept { return m_createdAt; }
foundation::Instant UserRecord::updatedAt() const noexcept { return m_updatedAt; }
foundation::Status UserRecord::rename(std::string userName,
                                      std::optional<std::string> externalId,
                                      foundation::Instant now)
{
    if (!validText(userName, 320U) || !validOptional(externalId, 1024U) || now < m_createdAt) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    m_userName = std::move(userName);
    m_externalId = std::move(externalId);
    m_updatedAt = now;
    return foundation::ok();
}

GroupRecord::GroupRecord(GroupId id, identity::core::OrganizationId organization,
                         std::string displayName, std::optional<std::string> externalId,
                         foundation::Instant createdAt, foundation::Instant updatedAt)
    : m_id(std::move(id)), m_organization(std::move(organization)),
      m_displayName(std::move(displayName)), m_externalId(std::move(externalId)),
      m_createdAt(createdAt), m_updatedAt(updatedAt) {}

foundation::Result<GroupRecord> GroupRecord::create(
    GroupId id, identity::core::OrganizationId organization,
    std::string displayName, std::optional<std::string> externalId,
    foundation::Instant createdAt, foundation::Instant updatedAt)
{
    if (id.empty() || organization.empty() || !validText(displayName, 512U)
        || !validOptional(externalId, 1024U) || updatedAt < createdAt) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The SCIM group metadata is invalid.");
    }
    return GroupRecord{std::move(id), std::move(organization), std::move(displayName),
                       std::move(externalId), createdAt, updatedAt};
}

const GroupId& GroupRecord::id() const noexcept { return m_id; }
const identity::core::OrganizationId& GroupRecord::organization() const noexcept { return m_organization; }
std::string_view GroupRecord::displayName() const noexcept { return m_displayName; }
const std::optional<std::string>& GroupRecord::externalId() const noexcept { return m_externalId; }
foundation::Instant GroupRecord::createdAt() const noexcept { return m_createdAt; }
foundation::Instant GroupRecord::updatedAt() const noexcept { return m_updatedAt; }
foundation::Status GroupRecord::rename(std::string displayName,
                                       std::optional<std::string> externalId,
                                       foundation::Instant now)
{
    if (!validText(displayName, 512U) || !validOptional(externalId, 1024U) || now < m_createdAt) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    m_displayName = std::move(displayName);
    m_externalId = std::move(externalId);
    m_updatedAt = now;
    return foundation::ok();
}

Service::Service(identity::core::OrganizationId organization, DirectoryRepository& directory,
                 identity::core::IdentityRepository& identities,
                 identity::profile::IdentityProfileRepository& profiles,
                 organization::MembershipRepository& memberships,
                 const foundation::ClockSource& clock)
    : m_organization(std::move(organization)), m_directory(&directory),
      m_identities(&identities), m_profiles(&profiles), m_memberships(&memberships),
      m_clock(&clock) {}

foundation::Result<UserView> Service::hydrate(const UserRecord& record) const
{
    auto identity = m_identities->findById(m_organization, record.identity());
    if (!identity) return foundation::fail(identity.error());
    if (!identity->has_value()) return foundation::fail(foundation::ErrorCode::NotFound);
    auto profile = m_profiles->find(record.identity());
    if (!profile) return foundation::fail(profile.error());
    return UserView{record, identity->value().status(), std::move(profile).value()};
}

foundation::Status Service::setActive(const identity::core::IdentityId& id, bool active)
{
    auto membership = m_memberships->find(m_organization, id);
    if (!membership) return foundation::fail(membership.error());
    if (!membership->has_value()) return foundation::fail(foundation::ErrorCode::NotFound);
    auto current = std::move(membership).value().value();

    if (current.state() == organization::MembershipState::Removed) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "A removed SCIM membership cannot change active state.");
    }

    if (active) {
        if (current.state() == organization::MembershipState::Suspended) {
            auto status = current.reinstate();
            if (!status) return status;
            status = m_memberships->save(current);
            if (!status) return status;
        }
        return m_identities->changeStatus(m_organization, id, identity::core::IdentityStatus::Active);
    }

    if (current.state() == organization::MembershipState::Active) {
        auto status = current.suspend();
        if (!status) return status;
        status = m_memberships->save(current);
        if (!status) return status;
    }
    return m_identities->changeStatus(m_organization, id, identity::core::IdentityStatus::Suspended);
}

foundation::Result<UserView> Service::createUser(
    std::string userName, std::optional<std::string> externalId, bool active,
    std::optional<std::string> displayName, std::optional<std::string> email)
{
    if (!validText(userName, 320U) || !validOptional(displayName, 512U)
        || !validOptional(email, 320U) || !validOptional(externalId, 1024U)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    auto existing = m_directory->findUserByName(m_organization, userName);
    if (!existing) return foundation::fail(existing.error());
    if (existing->has_value()) return foundation::fail(foundation::ErrorCode::AlreadyExists);
    auto id = newIdentityId();
    if (!id) return foundation::fail(id.error());
    const auto now = m_clock->now();
    auto identity = identity::core::Identity::create(id.value(), identity::core::SubjectKind::Human, now);
    auto membership = organization::Membership::invite(m_organization, id.value(), now);
    auto profile = identity::profile::IdentityProfile::create(id.value(), now);
    auto record = UserRecord::create(id.value(), m_organization, userName, externalId, now, now);
    if (!identity || !membership || !profile || !record) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    auto accepted = membership->accept();
    auto profiled = profile->updateSelfService(displayName, std::optional<std::string>{userName},
                                               std::nullopt, std::nullopt, now);
    if (profiled && email) profiled = profile->setEmail(*email, false, now);
    if (!accepted || !profiled) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    auto addedIdentity = m_identities->add(m_organization, std::move(identity).value());
    if (!addedIdentity) return foundation::fail(addedIdentity.error());
    auto addedMembership = m_memberships->add(std::move(membership).value());
    if (!addedMembership) {
        (void)m_identities->changeStatus(m_organization, id.value(), identity::core::IdentityStatus::Deactivated);
        return foundation::fail(addedMembership.error());
    }
    auto savedProfile = m_profiles->save(profile.value());
    if (!savedProfile) {
        (void)setActive(id.value(), false);
        return foundation::fail(savedProfile.error());
    }
    auto addedRecord = m_directory->addUser(record.value());
    if (!addedRecord) {
        (void)setActive(id.value(), false);
        return foundation::fail(addedRecord.error());
    }
    if (!active) {
        auto disabled = setActive(id.value(), false);
        if (!disabled) return foundation::fail(disabled.error());
    }
    return hydrate(record.value());
}

foundation::Result<UserView> Service::replaceUser(
    const identity::core::IdentityId& id, std::string userName,
    std::optional<std::string> externalId, bool active,
    std::optional<std::string> displayName, std::optional<std::string> email)
{
    auto existing = m_directory->findUser(m_organization, id);
    if (!existing) return foundation::fail(existing.error());
    if (!existing->has_value()) return foundation::fail(foundation::ErrorCode::NotFound);
    auto byName = m_directory->findUserByName(m_organization, userName);
    if (!byName) return foundation::fail(byName.error());
    if (byName->has_value() && byName->value().identity() != id) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists);
    }
    auto profile = m_profiles->find(id);
    if (!profile) return foundation::fail(profile.error());
    identity::profile::IdentityProfile updated = profile->has_value()
        ? std::move(profile).value().value()
        : std::move(identity::profile::IdentityProfile::create(id, m_clock->now())).value();
    const auto now = m_clock->now();
    auto status = updated.updateSelfService(displayName, std::optional<std::string>{userName},
                                            std::nullopt, std::nullopt, now);
    if (status && email) status = updated.setEmail(*email, false, now);
    if (!status) return foundation::fail(status.error());
    status = setActive(id, active);
    if (!status) return foundation::fail(status.error());
    status = m_profiles->save(updated);
    if (!status) return foundation::fail(status.error());
    auto record = std::move(existing).value().value();
    status = record.rename(std::move(userName), std::move(externalId), now);
    if (status) status = m_directory->saveUser(record);
    if (!status) return foundation::fail(status.error());
    return hydrate(record);
}

foundation::Result<UserView> Service::user(const identity::core::IdentityId& id) const
{
    auto record = m_directory->findUser(m_organization, id);
    if (!record) return foundation::fail(record.error());
    if (!record->has_value()) return foundation::fail(foundation::ErrorCode::NotFound);
    return hydrate(record->value());
}

foundation::Result<std::vector<UserView>> Service::users() const
{
    auto records = m_directory->users(m_organization);
    if (!records) return foundation::fail(records.error());
    std::vector<UserView> output;
    output.reserve(records->size());
    for (const auto& record : records.value()) {
        auto value = hydrate(record);
        if (!value) return foundation::fail(value.error());
        output.push_back(std::move(value).value());
    }
    return output;
}

foundation::Result<std::optional<UserView>> Service::userByName(std::string_view userName) const
{
    auto record = m_directory->findUserByName(m_organization, userName);
    if (!record) return foundation::fail(record.error());
    if (!record->has_value()) return std::optional<UserView>{};
    auto value = hydrate(record->value());
    if (!value) return foundation::fail(value.error());
    return std::optional<UserView>{std::move(value).value()};
}

foundation::Status Service::removeUser(const identity::core::IdentityId& id)
{
    auto membership = m_memberships->find(m_organization, id);
    if (!membership) return foundation::fail(membership.error());
    if (membership->has_value() && membership->value().state() != organization::MembershipState::Removed) {
        auto current = std::move(membership).value().value();
        auto removed = current.remove();
        if (!removed) return removed;
        auto saved = m_memberships->save(current);
        if (!saved) return saved;
    }
    auto deactivated = m_identities->changeStatus(m_organization, id, identity::core::IdentityStatus::Deactivated);
    if (!deactivated) return deactivated;
    return m_directory->removeUser(m_organization, id);
}

foundation::Status Service::validateMembers(const std::vector<identity::core::IdentityId>& members) const
{
    std::vector<identity::core::IdentityId> sorted = members;
    std::ranges::sort(sorted);
    if (std::ranges::adjacent_find(sorted) != sorted.end()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument, "A SCIM group contains duplicate members.");
    }
    for (const auto& member : members) {
        auto user = m_directory->findUser(m_organization, member);
        if (!user) return foundation::fail(user.error());
        if (!user->has_value()) return foundation::fail(foundation::ErrorCode::NotFound);
    }
    return foundation::ok();
}

foundation::Result<GroupView> Service::createGroup(
    std::string displayName, std::optional<std::string> externalId,
    std::vector<identity::core::IdentityId> members)
{
    auto existing = m_directory->findGroupByName(m_organization, displayName);
    if (!existing) return foundation::fail(existing.error());
    if (existing->has_value()) return foundation::fail(foundation::ErrorCode::AlreadyExists);
    auto validated = validateMembers(members);
    if (!validated) return foundation::fail(validated.error());
    auto id = newGroupId();
    if (!id) return foundation::fail(id.error());
    const auto now = m_clock->now();
    auto record = GroupRecord::create(id.value(), m_organization, std::move(displayName),
                                      std::move(externalId), now, now);
    if (!record) return foundation::fail(record.error());
    auto added = m_directory->addGroup(record.value());
    if (!added) return foundation::fail(added.error());
    auto replaced = m_directory->replaceGroupMembers(m_organization, id.value(), members);
    if (!replaced) {
        (void)m_directory->removeGroup(m_organization, id.value());
        return foundation::fail(replaced.error());
    }
    return GroupView{std::move(record).value(), std::move(members)};
}

foundation::Result<GroupView> Service::replaceGroup(
    const GroupId& id, std::string displayName, std::optional<std::string> externalId,
    std::vector<identity::core::IdentityId> members)
{
    auto existing = m_directory->findGroup(m_organization, id);
    if (!existing) return foundation::fail(existing.error());
    if (!existing->has_value()) return foundation::fail(foundation::ErrorCode::NotFound);
    auto duplicate = m_directory->findGroupByName(m_organization, displayName);
    if (!duplicate) return foundation::fail(duplicate.error());
    if (duplicate->has_value() && duplicate->value().id() != id) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists);
    }
    auto validated = validateMembers(members);
    if (!validated) return foundation::fail(validated.error());
    auto record = std::move(existing).value().value();
    auto renamed = record.rename(std::move(displayName), std::move(externalId), m_clock->now());
    if (!renamed) return foundation::fail(renamed.error());
    auto saved = m_directory->saveGroup(record);
    if (!saved) return foundation::fail(saved.error());
    auto replaced = m_directory->replaceGroupMembers(m_organization, id, members);
    if (!replaced) return foundation::fail(replaced.error());
    return GroupView{std::move(record), std::move(members)};
}

foundation::Result<GroupView> Service::group(const GroupId& id) const
{
    auto record = m_directory->findGroup(m_organization, id);
    if (!record) return foundation::fail(record.error());
    if (!record->has_value()) return foundation::fail(foundation::ErrorCode::NotFound);
    auto members = m_directory->groupMembers(m_organization, id);
    if (!members) return foundation::fail(members.error());
    return GroupView{record->value(), std::move(members).value()};
}

foundation::Result<std::vector<GroupView>> Service::groups() const
{
    auto records = m_directory->groups(m_organization);
    if (!records) return foundation::fail(records.error());
    std::vector<GroupView> output;
    output.reserve(records->size());
    for (const auto& record : records.value()) {
        auto members = m_directory->groupMembers(m_organization, record.id());
        if (!members) return foundation::fail(members.error());
        output.push_back(GroupView{record, std::move(members).value()});
    }
    return output;
}

foundation::Result<std::optional<GroupView>> Service::groupByName(std::string_view displayName) const
{
    auto record = m_directory->findGroupByName(m_organization, displayName);
    if (!record) return foundation::fail(record.error());
    if (!record->has_value()) return std::optional<GroupView>{};
    auto members = m_directory->groupMembers(m_organization, record->value().id());
    if (!members) return foundation::fail(members.error());
    return std::optional<GroupView>{GroupView{record->value(), std::move(members).value()}};
}

foundation::Status Service::removeGroup(const GroupId& id)
{
    return m_directory->removeGroup(m_organization, id);
}

} // namespace openproof::enterprise::scim

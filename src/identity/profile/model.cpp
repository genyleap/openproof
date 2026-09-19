module;

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>

module openproof.identity.profile;

namespace openproof::identity::profile {
namespace {

[[nodiscard]] bool validText(const std::optional<std::string>& value,
                             std::size_t maximum) noexcept
{
    if (!value.has_value()) return true;
    if (value->empty() || value->size() > maximum) return false;
    return std::ranges::none_of(*value, [](char symbol) {
        const auto byte = static_cast<unsigned char>(symbol);
        return byte < 0x20U || byte == 0x7FU;
    });
}

}

IdentityProfile::IdentityProfile(const IdentityProfile& other)
    : m_identity(other.m_identity)
    , m_displayName(other.m_displayName)
    , m_preferredUsername(other.m_preferredUsername)
    , m_email(other.m_email)
    , m_emailVerified(other.m_emailVerified)
    , m_phoneNumber(other.m_phoneNumber)
    , m_phoneNumberVerified(other.m_phoneNumberVerified)
    , m_locale(other.m_locale)
    , m_pictureUrl(other.m_pictureUrl)
    , m_avatarSource(other.m_avatarSource)
    , m_createdAt(other.m_createdAt)
    , m_updatedAt(other.m_updatedAt)
{
}
IdentityProfile::IdentityProfile(IdentityProfile&& other)
    : m_identity(std::move(other.m_identity))
    , m_displayName(std::move(other.m_displayName))
    , m_preferredUsername(std::move(other.m_preferredUsername))
    , m_email(std::move(other.m_email))
    , m_emailVerified(other.m_emailVerified)
    , m_phoneNumber(std::move(other.m_phoneNumber))
    , m_phoneNumberVerified(other.m_phoneNumberVerified)
    , m_locale(std::move(other.m_locale))
    , m_pictureUrl(std::move(other.m_pictureUrl))
    , m_avatarSource(std::move(other.m_avatarSource))
    , m_createdAt(other.m_createdAt)
    , m_updatedAt(other.m_updatedAt)
{
}
IdentityProfile& IdentityProfile::operator=(const IdentityProfile& other)
{
    if (this != &other) {
        m_identity = other.m_identity;
        m_displayName = other.m_displayName;
        m_preferredUsername = other.m_preferredUsername;
        m_email = other.m_email;
        m_emailVerified = other.m_emailVerified;
        m_phoneNumber = other.m_phoneNumber;
        m_phoneNumberVerified = other.m_phoneNumberVerified;
        m_locale = other.m_locale;
        m_pictureUrl = other.m_pictureUrl;
        m_avatarSource = other.m_avatarSource;
        m_createdAt = other.m_createdAt;
        m_updatedAt = other.m_updatedAt;
    }
    return *this;
}
IdentityProfile& IdentityProfile::operator=(IdentityProfile&& other)
{
    if (this != &other) {
        m_identity = std::move(other.m_identity);
        m_displayName = std::move(other.m_displayName);
        m_preferredUsername = std::move(other.m_preferredUsername);
        m_email = std::move(other.m_email);
        m_emailVerified = other.m_emailVerified;
        m_phoneNumber = std::move(other.m_phoneNumber);
        m_phoneNumberVerified = other.m_phoneNumberVerified;
        m_locale = std::move(other.m_locale);
        m_pictureUrl = std::move(other.m_pictureUrl);
        m_avatarSource = std::move(other.m_avatarSource);
        m_createdAt = other.m_createdAt;
        m_updatedAt = other.m_updatedAt;
    }
    return *this;
}
IdentityProfile::~IdentityProfile() {}

IdentityProfile::IdentityProfile(core::IdentityId identity,
                                 foundation::Instant createdAt)
    : m_identity(std::move(identity)), m_createdAt(createdAt), m_updatedAt(createdAt)
{
}

foundation::Result<IdentityProfile> IdentityProfile::create(
    core::IdentityId identity, foundation::Instant createdAt)
{
    if (identity.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An identity profile requires an identity.");
    }
    return IdentityProfile{std::move(identity), createdAt};
}

foundation::Result<IdentityProfile> IdentityProfile::restore(
    core::IdentityId identity, std::optional<std::string> displayName,
    std::optional<std::string> preferredUsername, std::optional<std::string> email,
    bool emailVerified, std::optional<std::string> phoneNumber,
    bool phoneNumberVerified, std::optional<std::string> locale,
    std::optional<std::string> pictureUrl, foundation::Instant createdAt,
    foundation::Instant updatedAt, std::string avatarSource)
{
    if (!validText(displayName, 256U) || !validText(preferredUsername, 128U)
        || !validText(email, 320U) || !validText(phoneNumber, 32U)
        || !validText(locale, 64U) || !validText(pictureUrl, 2048U)
        || avatarSource.empty() || avatarSource.size() > 128U
        || std::ranges::any_of(avatarSource, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           })
        || updatedAt < createdAt || (emailVerified && !email.has_value())
        || (phoneNumberVerified && !phoneNumber.has_value())) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "Stored identity profile data is invalid.");
    }
    auto profile = create(std::move(identity), createdAt);
    if (!profile) return foundation::fail(profile.error());
    profile->m_displayName = std::move(displayName);
    profile->m_preferredUsername = std::move(preferredUsername);
    profile->m_email = std::move(email);
    profile->m_emailVerified = emailVerified;
    profile->m_phoneNumber = std::move(phoneNumber);
    profile->m_phoneNumberVerified = phoneNumberVerified;
    profile->m_locale = std::move(locale);
    profile->m_pictureUrl = std::move(pictureUrl);
    profile->m_avatarSource = std::move(avatarSource);
    profile->m_updatedAt = updatedAt;
    return profile;
}

const core::IdentityId& IdentityProfile::identity() const noexcept { return m_identity; }
const std::optional<std::string>& IdentityProfile::displayName() const noexcept
{ return m_displayName; }
const std::optional<std::string>& IdentityProfile::preferredUsername() const noexcept
{ return m_preferredUsername; }
const std::optional<std::string>& IdentityProfile::email() const noexcept { return m_email; }
bool IdentityProfile::emailVerified() const noexcept { return m_emailVerified; }
const std::optional<std::string>& IdentityProfile::phoneNumber() const noexcept
{ return m_phoneNumber; }
bool IdentityProfile::phoneNumberVerified() const noexcept
{ return m_phoneNumberVerified; }
const std::optional<std::string>& IdentityProfile::locale() const noexcept { return m_locale; }
const std::optional<std::string>& IdentityProfile::pictureUrl() const noexcept
{ return m_pictureUrl; }
std::string_view IdentityProfile::avatarSource() const noexcept { return m_avatarSource; }
foundation::Instant IdentityProfile::createdAt() const noexcept { return m_createdAt; }
foundation::Instant IdentityProfile::updatedAt() const noexcept { return m_updatedAt; }

foundation::Status IdentityProfile::applyVerifiedClaims(
    const provider::VerifiedClaims& claims, foundation::Instant now)
{
    if (now < m_updatedAt) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "Profile claims cannot move time backwards.");
    }
    if (const auto value = claims.get(provider::ClaimName::DisplayName); value) {
        m_displayName = std::string{*value};
    }
    if (const auto value = claims.get(provider::ClaimName::PreferredUsername); value) {
        m_preferredUsername = std::string{*value};
    }
    if (const auto value = claims.get(provider::ClaimName::Email); value) {
        m_email = std::string{*value};
        m_emailVerified = claims.isTrue(provider::ClaimName::EmailVerified);
    }
    if (const auto value = claims.get(provider::ClaimName::PhoneNumber); value) {
        m_phoneNumber = std::string{*value};
        m_phoneNumberVerified = claims.isTrue(provider::ClaimName::PhoneNumberVerified);
    }
    if (const auto value = claims.get(provider::ClaimName::Locale); value) {
        m_locale = std::string{*value};
    }
    if (const auto value = claims.get(provider::ClaimName::PictureUrl); value) {
        m_pictureUrl = std::string{*value};
    }
    if (!validText(m_displayName, 256U) || !validText(m_preferredUsername, 128U)
        || !validText(m_email, 320U) || !validText(m_phoneNumber, 32U)
        || !validText(m_locale, 64U) || !validText(m_pictureUrl, 2048U)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Verified profile claims exceeded platform limits.");
    }
    m_updatedAt = now;
    return foundation::ok();
}

foundation::Status IdentityProfile::refreshPresentationClaims(
    const provider::VerifiedClaims& claims, foundation::Instant now)
{
    if (now < m_updatedAt) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "Profile claims cannot move time backwards.");
    }
    bool changed = false;
    if (!m_displayName) {
        if (const auto value = claims.get(provider::ClaimName::DisplayName); value) {
            m_displayName = std::string{*value};
            changed = true;
        }
    }
    if (!m_preferredUsername) {
        if (const auto value = claims.get(provider::ClaimName::PreferredUsername); value) {
            m_preferredUsername = std::string{*value};
            changed = true;
        }
    }
    if (!m_locale) {
        if (const auto value = claims.get(provider::ClaimName::Locale); value) {
            m_locale = std::string{*value};
            changed = true;
        }
    }
    if (!m_pictureUrl) {
        if (const auto value = claims.get(provider::ClaimName::PictureUrl); value) {
            m_pictureUrl = std::string{*value};
            changed = true;
        }
    }
    if (!validText(m_displayName, 256U) || !validText(m_preferredUsername, 128U)
        || !validText(m_locale, 64U) || !validText(m_pictureUrl, 2048U)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Provider presentation claims exceeded platform limits.");
    }
    if (changed) m_updatedAt = now;
    return foundation::ok();
}

foundation::Status IdentityProfile::updateSelfService(
    std::optional<std::string> displayName,
    std::optional<std::string> preferredUsername,
    std::optional<std::string> locale,
    std::optional<std::string> pictureUrl,
    foundation::Instant now)
{
    if (now < m_updatedAt) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "Profile updates cannot move time backwards.");
    }
    if (!validText(displayName, 256U) || !validText(preferredUsername, 128U)
        || !validText(locale, 64U) || !validText(pictureUrl, 2048U)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Profile fields are invalid.");
    }
    m_displayName = std::move(displayName);
    m_preferredUsername = std::move(preferredUsername);
    m_locale = std::move(locale);
    m_pictureUrl = std::move(pictureUrl);
    m_updatedAt = now;
    return foundation::ok();
}

foundation::Status IdentityProfile::setAvatarSource(
    std::string avatarSource, foundation::Instant now)
{
    if (now < m_updatedAt || avatarSource.empty() || avatarSource.size() > 128U
        || std::ranges::any_of(avatarSource, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Avatar source is invalid.");
    }
    m_avatarSource = std::move(avatarSource);
    m_updatedAt = now;
    return foundation::ok();
}

foundation::Status IdentityProfile::setEmail(
    std::string email, bool verified, foundation::Instant now)
{
    std::optional<std::string> candidate{std::move(email)};
    if (now < m_updatedAt || !validText(candidate, 320U)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The email claim is invalid.");
    }
    m_email = std::move(candidate);
    m_emailVerified = verified;
    m_updatedAt = now;
    return foundation::ok();
}

foundation::Status IdentityProfile::setPhoneNumber(
    std::string phoneNumber, bool verified, foundation::Instant now)
{
    std::optional<std::string> candidate{std::move(phoneNumber)};
    if (now < m_updatedAt || !validText(candidate, 32U)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The phone-number claim is invalid.");
    }
    m_phoneNumber = std::move(candidate);
    m_phoneNumberVerified = verified;
    m_updatedAt = now;
    return foundation::ok();
}

}

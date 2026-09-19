module;

#include <optional>
#include <string>
#include <string_view>

export module openproof.identity.profile:model;

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

export namespace openproof::identity::profile {

/**
 * @brief Canonical profile attributes exposed only when an OAuth scope permits them.
 *
 * Authentication provider subjects never become canonical identity keys. Profile
 * attributes are mutable presentation/communication data keyed by IdentityId.
 */
class IdentityProfile final {
public:
    IdentityProfile(const IdentityProfile& other);
    IdentityProfile(IdentityProfile&& other);
    IdentityProfile& operator=(const IdentityProfile& other);
    IdentityProfile& operator=(IdentityProfile&& other);
    ~IdentityProfile();

    [[nodiscard]] static foundation::Result<IdentityProfile>
    create(core::IdentityId identity, foundation::Instant createdAt);

    [[nodiscard]] static foundation::Result<IdentityProfile>
    restore(core::IdentityId identity, std::optional<std::string> displayName,
            std::optional<std::string> preferredUsername,
            std::optional<std::string> email, bool emailVerified,
            std::optional<std::string> phoneNumber, bool phoneNumberVerified,
            std::optional<std::string> locale,
            std::optional<std::string> pictureUrl,
            foundation::Instant createdAt, foundation::Instant updatedAt);

    [[nodiscard]] const core::IdentityId& identity() const noexcept;
    [[nodiscard]] const std::optional<std::string>& displayName() const noexcept;
    [[nodiscard]] const std::optional<std::string>& preferredUsername() const noexcept;
    [[nodiscard]] const std::optional<std::string>& email() const noexcept;
    [[nodiscard]] bool emailVerified() const noexcept;
    [[nodiscard]] const std::optional<std::string>& phoneNumber() const noexcept;
    [[nodiscard]] bool phoneNumberVerified() const noexcept;
    [[nodiscard]] const std::optional<std::string>& locale() const noexcept;
    [[nodiscard]] const std::optional<std::string>& pictureUrl() const noexcept;
    [[nodiscard]] foundation::Instant createdAt() const noexcept;
    [[nodiscard]] foundation::Instant updatedAt() const noexcept;

    [[nodiscard]] foundation::Status applyVerifiedClaims(
        const provider::VerifiedClaims& claims, foundation::Instant now);

    /**
     * @brief Refreshes non-security presentation data from an authenticated provider.
     *
     * Existing user-chosen display name, username and locale win. A verified provider
     * picture may refresh so the account can follow the connected profile avatar.
     * Email and phone claims are deliberately ignored by this path.
     */
    [[nodiscard]] foundation::Status refreshPresentationClaims(
        const provider::VerifiedClaims& claims, foundation::Instant now);

    /** @brief Updates subject-controlled non-verified presentation fields. */
    [[nodiscard]] foundation::Status updateSelfService(
        std::optional<std::string> displayName,
        std::optional<std::string> preferredUsername,
        std::optional<std::string> locale,
        std::optional<std::string> pictureUrl,
        foundation::Instant now);

    /** @brief Records an email claim; verified must come from a completed ceremony. */
    [[nodiscard]] foundation::Status setEmail(
        std::string email, bool verified, foundation::Instant now);

    /** @brief Records a phone claim; verified must come from a completed ceremony. */
    [[nodiscard]] foundation::Status setPhoneNumber(
        std::string phoneNumber, bool verified, foundation::Instant now);

private:
    IdentityProfile(core::IdentityId identity, foundation::Instant createdAt);

    core::IdentityId m_identity;
    std::optional<std::string> m_displayName;
    std::optional<std::string> m_preferredUsername;
    std::optional<std::string> m_email;
    bool m_emailVerified{};
    std::optional<std::string> m_phoneNumber;
    bool m_phoneNumberVerified{};
    std::optional<std::string> m_locale;
    std::optional<std::string> m_pictureUrl;
    foundation::Instant m_createdAt{};
    foundation::Instant m_updatedAt{};
};

}

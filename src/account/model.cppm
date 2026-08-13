module;

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

export module openproof.account:model;

import openproof.foundation;
import openproof.identity.core;

export namespace openproof::account {

struct VerificationIdTag {};
using VerificationId = foundation::StrongId<VerificationIdTag>;

enum class VerificationPurpose : std::uint8_t {
    SignupEmail,
    ChangeEmail,
    VerifyPhone,
    PasswordReset,
};

[[nodiscard]] std::string_view verificationPurposeName(VerificationPurpose purpose) noexcept;

enum class VerificationChannel : std::uint8_t {
    Email,
    Sms,
};

[[nodiscard]] std::string_view verificationChannelName(VerificationChannel channel) noexcept;

/** @brief Keyed digest of a one-time verification secret. */
class VerificationDigest final {
public:
    explicit VerificationDigest(std::array<std::byte, 32> bytes) noexcept
        : m_bytes(bytes)
    {
    }

    [[nodiscard]] const std::array<std::byte, 32>& bytes() const noexcept
    {
        return m_bytes;
    }

    [[nodiscard]] friend bool operator==(const VerificationDigest&, const VerificationDigest&) = default;

private:
    std::array<std::byte, 32> m_bytes{};
};

/** @brief Persisted single-use verification ceremony. */
class VerificationChallenge final {
public:
    [[nodiscard]] static foundation::Result<VerificationChallenge> create(
        VerificationId id, identity::core::IdentityId identity,
        VerificationPurpose purpose, VerificationChannel channel,
        std::string destination, VerificationDigest digest,
        foundation::Instant createdAt, foundation::Duration lifetime);

    [[nodiscard]] static foundation::Result<VerificationChallenge> restore(
        VerificationId id, identity::core::IdentityId identity,
        VerificationPurpose purpose, VerificationChannel channel,
        std::string destination, VerificationDigest digest,
        foundation::Instant createdAt, foundation::Instant expiresAt,
        std::uint32_t attempts);

    [[nodiscard]] const VerificationId& id() const noexcept;
    [[nodiscard]] const identity::core::IdentityId& identity() const noexcept;
    [[nodiscard]] VerificationPurpose purpose() const noexcept;
    [[nodiscard]] VerificationChannel channel() const noexcept;
    [[nodiscard]] std::string_view destination() const noexcept;
    [[nodiscard]] const VerificationDigest& digest() const noexcept;
    [[nodiscard]] foundation::Instant createdAt() const noexcept;
    [[nodiscard]] foundation::Instant expiresAt() const noexcept;
    [[nodiscard]] std::uint32_t attempts() const noexcept;
    [[nodiscard]] bool expiredAt(foundation::Instant now) const noexcept;

private:
    VerificationChallenge(VerificationId id, identity::core::IdentityId identity,
                          VerificationPurpose purpose, VerificationChannel channel,
                          std::string destination, VerificationDigest digest,
                          foundation::Instant createdAt,
                          foundation::Instant expiresAt,
                          std::uint32_t attempts);

    struct State;
    std::shared_ptr<const State> m_state;
};

/** @brief Move-only secret that must be sent through the configured delivery adapter. */
class VerificationDispatch final {
public:
    VerificationDispatch(const VerificationDispatch&) = delete;
    VerificationDispatch& operator=(const VerificationDispatch&) = delete;
    VerificationDispatch(VerificationDispatch&&) noexcept = default;
    VerificationDispatch& operator=(VerificationDispatch&&) noexcept = default;
    ~VerificationDispatch() = default;

    [[nodiscard]] const VerificationId& id() const noexcept;
    [[nodiscard]] const identity::core::IdentityId& identity() const noexcept;
    [[nodiscard]] VerificationPurpose purpose() const noexcept;
    [[nodiscard]] VerificationChannel channel() const noexcept;
    [[nodiscard]] std::string_view destination() const noexcept;
    [[nodiscard]] const foundation::SecretString& secret() const noexcept;
    [[nodiscard]] foundation::Instant expiresAt() const noexcept;

private:
    friend class AccountService;
    VerificationDispatch(VerificationId id, identity::core::IdentityId identity,
                         VerificationPurpose purpose, VerificationChannel channel,
                         std::string destination, foundation::SecretString secret,
                         foundation::Instant expiresAt);

    VerificationId m_id;
    identity::core::IdentityId m_identity;
    VerificationPurpose m_purpose{VerificationPurpose::SignupEmail};
    VerificationChannel m_channel{VerificationChannel::Email};
    std::string m_destination;
    foundation::SecretString m_secret;
    foundation::Instant m_expiresAt{};
};

}

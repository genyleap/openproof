module;

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

module openproof.account;

namespace openproof::account {

std::string_view verificationPurposeName(VerificationPurpose purpose) noexcept
{
    switch (purpose) {
    case VerificationPurpose::SignupEmail: return "signup_email";
    case VerificationPurpose::ChangeEmail: return "change_email";
    case VerificationPurpose::VerifyPhone: return "verify_phone";
    case VerificationPurpose::PasswordReset: return "password_reset";
    }
    return "signup_email";
}

std::string_view verificationChannelName(VerificationChannel channel) noexcept
{
    switch (channel) {
    case VerificationChannel::Email: return "email";
    case VerificationChannel::Sms: return "sms";
    }
    return "email";
}

struct VerificationChallenge::State final {
    VerificationId id;
    identity::core::IdentityId identity;
    VerificationPurpose purpose{VerificationPurpose::SignupEmail};
    VerificationChannel channel{VerificationChannel::Email};
    std::string destination;
    VerificationDigest digest;
    foundation::Instant createdAt{};
    foundation::Instant expiresAt{};
    std::uint32_t attempts{};
};

VerificationChallenge::VerificationChallenge(
    VerificationId id, identity::core::IdentityId identity,
    VerificationPurpose purpose, VerificationChannel channel,
    std::string destination, VerificationDigest digest,
    foundation::Instant createdAt, foundation::Instant expiresAt,
    std::uint32_t attempts)
    : m_state(std::make_shared<State>(State{
          .id = std::move(id), .identity = std::move(identity),
          .purpose = purpose, .channel = channel,
          .destination = std::move(destination), .digest = std::move(digest),
          .createdAt = createdAt, .expiresAt = expiresAt, .attempts = attempts}))
{
}

foundation::Result<VerificationChallenge> VerificationChallenge::create(
    VerificationId id, identity::core::IdentityId identity,
    VerificationPurpose purpose, VerificationChannel channel,
    std::string destination, VerificationDigest digest,
    foundation::Instant createdAt, foundation::Duration lifetime)
{
    if (id.empty() || identity.empty() || destination.empty()
        || destination.size() > 512U || lifetime <= foundation::Duration::zero()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The verification challenge is invalid.");
    }
    return VerificationChallenge{std::move(id), std::move(identity), purpose, channel,
                                 std::move(destination), std::move(digest), createdAt,
                                 createdAt + lifetime, 0U};
}

foundation::Result<VerificationChallenge> VerificationChallenge::restore(
    VerificationId id, identity::core::IdentityId identity,
    VerificationPurpose purpose, VerificationChannel channel,
    std::string destination, VerificationDigest digest,
    foundation::Instant createdAt, foundation::Instant expiresAt,
    std::uint32_t attempts)
{
    if (id.empty() || identity.empty() || destination.empty()
        || destination.size() > 512U || expiresAt <= createdAt) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "Stored verification challenge data is invalid.");
    }
    return VerificationChallenge{std::move(id), std::move(identity), purpose, channel,
                                 std::move(destination), std::move(digest), createdAt,
                                 expiresAt, attempts};
}

const VerificationId& VerificationChallenge::id() const noexcept { return m_state->id; }
const identity::core::IdentityId& VerificationChallenge::identity() const noexcept
{ return m_state->identity; }
VerificationPurpose VerificationChallenge::purpose() const noexcept { return m_state->purpose; }
VerificationChannel VerificationChallenge::channel() const noexcept { return m_state->channel; }
std::string_view VerificationChallenge::destination() const noexcept
{ return m_state->destination; }
const VerificationDigest& VerificationChallenge::digest() const noexcept
{ return m_state->digest; }
foundation::Instant VerificationChallenge::createdAt() const noexcept { return m_state->createdAt; }
foundation::Instant VerificationChallenge::expiresAt() const noexcept { return m_state->expiresAt; }
std::uint32_t VerificationChallenge::attempts() const noexcept { return m_state->attempts; }
bool VerificationChallenge::expiredAt(foundation::Instant now) const noexcept
{ return now >= m_state->expiresAt; }

VerificationDispatch::VerificationDispatch(
    VerificationId id, identity::core::IdentityId identity,
    VerificationPurpose purpose, VerificationChannel channel,
    std::string destination, foundation::SecretString secret,
    foundation::Instant expiresAt)
    : m_id(std::move(id)), m_identity(std::move(identity)), m_purpose(purpose),
      m_channel(channel), m_destination(std::move(destination)),
      m_secret(std::move(secret)), m_expiresAt(expiresAt)
{
}

const VerificationId& VerificationDispatch::id() const noexcept { return m_id; }
const identity::core::IdentityId& VerificationDispatch::identity() const noexcept
{ return m_identity; }
VerificationPurpose VerificationDispatch::purpose() const noexcept { return m_purpose; }
VerificationChannel VerificationDispatch::channel() const noexcept { return m_channel; }
std::string_view VerificationDispatch::destination() const noexcept { return m_destination; }
const foundation::SecretString& VerificationDispatch::secret() const noexcept { return m_secret; }
foundation::Instant VerificationDispatch::expiresAt() const noexcept { return m_expiresAt; }

}

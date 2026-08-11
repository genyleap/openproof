module;

#include <chrono>
#include <string>
#include <string_view>
#include <utility>

module openproof.session;

namespace openproof::session {

namespace {

[[nodiscard]] foundation::Error invalidSession(std::string detail)
{
    return foundation::Error{
        foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(
            foundation::ErrorCode::AuthenticationFailed)},
        std::move(detail)};
}

}

TokenDigest::TokenDigest(security::Sha256Digest bytes) noexcept
    : m_bytes(bytes)
{
}

TokenDigest::TokenDigest(const TokenDigest& other) noexcept
    : m_bytes(other.m_bytes)
{
}

TokenDigest& TokenDigest::operator=(const TokenDigest& other) noexcept
{
    m_bytes = other.m_bytes;
    return *this;
}

TokenDigest::TokenDigest(TokenDigest&& other) noexcept
    : m_bytes(other.m_bytes)
{
}

TokenDigest& TokenDigest::operator=(TokenDigest&& other) noexcept
{
    m_bytes = other.m_bytes;
    return *this;
}

TokenDigest::~TokenDigest() noexcept = default;

const security::Sha256Digest& TokenDigest::bytes() const noexcept
{
    return m_bytes;
}

bool operator==(const TokenDigest& left, const TokenDigest& right) noexcept
{
    return left.m_bytes == right.m_bytes;
}

std::strong_ordering operator<=>(const TokenDigest& left,
                                 const TokenDigest& right) noexcept
{
    return left.m_bytes <=> right.m_bytes;
}

Session::Session(const Session& other) = default;
Session& Session::operator=(const Session& other) = default;
Session::Session(Session&& other) noexcept = default;
Session& Session::operator=(Session&& other) noexcept = default;
Session::~Session() = default;

std::string_view sessionStateName(SessionState state) noexcept
{
    switch (state) {
    case SessionState::Active:
        return "active";
    case SessionState::Revoked:
        return "revoked";
    case SessionState::Expired:
        return "expired";
    }
    return "expired";
}

Session::Session(SessionId id, identity::core::IdentityId identity,
                 identity::provider::ProviderId provider,
                 identity::provider::AssuranceLevel assurance,
                 identity::provider::AuthenticationStrength strength,
                 foundation::Instant authenticatedAt, TokenDigest tokenDigest,
                 foundation::Instant issuedAt, foundation::Instant absoluteExpiresAt,
                 foundation::Duration idleTimeout)
    : m_id(std::move(id))
    , m_identity(std::move(identity))
    , m_provider(std::move(provider))
    , m_assurance(assurance)
    , m_strength(strength)
    , m_authenticatedAt(authenticatedAt)
    , m_tokenDigest(std::move(tokenDigest))
    , m_issuedAt(issuedAt)
    , m_lastSeenAt(issuedAt)
    , m_absoluteExpiresAt(absoluteExpiresAt)
    , m_idleTimeout(idleTimeout)
{
}

foundation::Result<Session> Session::create(
    SessionId id, identity::core::IdentityId identity,
    identity::provider::ProviderId provider,
    identity::provider::AssuranceLevel assurance,
    identity::provider::AuthenticationStrength strength,
    foundation::Instant authenticatedAt, TokenDigest tokenDigest,
    foundation::Instant issuedAt, foundation::Duration absoluteLifetime,
    foundation::Duration idleTimeout)
{
    if (id.empty() || identity.empty() || provider.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A session must name its id, identity and provider.");
    }
    if (absoluteLifetime <= foundation::Duration::zero()
        || idleTimeout <= foundation::Duration::zero()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Session lifetimes must be positive.");
    }
    if (authenticatedAt > issuedAt) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A session cannot predate its authentication.");
    }
    return Session{std::move(id), std::move(identity), std::move(provider), assurance,
                   strength, authenticatedAt, std::move(tokenDigest), issuedAt,
                   issuedAt + absoluteLifetime, idleTimeout};
}

foundation::Result<Session> Session::restore(
    SessionId id, identity::core::IdentityId identity,
    identity::provider::ProviderId provider,
    identity::provider::AssuranceLevel assurance,
    identity::provider::AuthenticationStrength strength, SessionState state,
    foundation::Instant authenticatedAt, TokenDigest tokenDigest,
    foundation::Instant issuedAt, foundation::Instant lastSeenAt,
    foundation::Instant absoluteExpiresAt, foundation::Duration idleTimeout,
    std::optional<foundation::Instant> revokedAt)
{
    if (id.empty() || identity.empty() || provider.empty()
        || authenticatedAt > issuedAt || lastSeenAt < issuedAt
        || lastSeenAt >= absoluteExpiresAt
        || idleTimeout <= foundation::Duration::zero()
        || (state == SessionState::Revoked) != revokedAt.has_value()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The persisted session is invalid.");
    }
    Session restored{std::move(id), std::move(identity), std::move(provider), assurance,
                     strength, authenticatedAt, std::move(tokenDigest), issuedAt,
                     absoluteExpiresAt, idleTimeout};
    restored.m_state = state;
    restored.m_lastSeenAt = lastSeenAt;
    restored.m_revokedAt = revokedAt;
    return restored;
}

const SessionId& Session::id() const noexcept { return m_id; }
const identity::core::IdentityId& Session::identity() const noexcept { return m_identity; }
const identity::provider::ProviderId& Session::provider() const noexcept { return m_provider; }
identity::provider::AssuranceLevel Session::assurance() const noexcept { return m_assurance; }
const identity::provider::AuthenticationStrength& Session::strength() const noexcept
{
    return m_strength;
}
SessionState Session::state() const noexcept { return m_state; }
foundation::Instant Session::authenticatedAt() const noexcept { return m_authenticatedAt; }
foundation::Instant Session::issuedAt() const noexcept { return m_issuedAt; }
foundation::Instant Session::lastSeenAt() const noexcept { return m_lastSeenAt; }
foundation::Instant Session::absoluteExpiresAt() const noexcept { return m_absoluteExpiresAt; }
foundation::Instant Session::idleExpiresAt() const noexcept { return m_lastSeenAt + m_idleTimeout; }
foundation::Duration Session::idleTimeout() const noexcept { return m_idleTimeout; }
const TokenDigest& Session::tokenDigest() const noexcept { return m_tokenDigest; }
const std::optional<foundation::Instant>& Session::revokedAt() const noexcept { return m_revokedAt; }

bool Session::isExpiredAt(foundation::Instant now) const noexcept
{
    return now >= m_absoluteExpiresAt || now >= idleExpiresAt();
}

foundation::Status Session::use(const TokenDigest& presented, foundation::Instant now)
{
    if (m_state != SessionState::Active) {
        return foundation::fail(invalidSession(
            std::string{"Session use refused; state is "}
            + std::string{sessionStateName(m_state)} + "."));
    }
    if (isExpiredAt(now)) {
        m_state = SessionState::Expired;
        return foundation::fail(invalidSession("Session use refused: deadline passed."));
    }
    if (!security::constantTimeEquals(m_tokenDigest.bytes(), presented.bytes())) {
        return foundation::fail(invalidSession("Session use refused: token digest mismatch."));
    }
    m_lastSeenAt = now;
    return foundation::ok();
}

foundation::Status Session::rotateToken(const TokenDigest& expected,
                                        TokenDigest replacement,
                                        foundation::Instant now)
{
    const foundation::Status usable = use(expected, now);
    if (!usable.has_value()) {
        return foundation::fail(usable.error());
    }
    m_tokenDigest = std::move(replacement);
    return foundation::ok();
}

foundation::Status Session::revoke(foundation::Instant now)
{
    if (m_state == SessionState::Revoked) {
        return foundation::ok();
    }
    if (m_state == SessionState::Expired) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "An expired session cannot be revoked.");
    }
    m_state = SessionState::Revoked;
    m_revokedAt = now;
    return foundation::ok();
}

void Session::markExpired() noexcept
{
    if (m_state == SessionState::Active) {
        m_state = SessionState::Expired;
    }
}

}

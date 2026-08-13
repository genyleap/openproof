module;

#include <array>

#include <chrono>
#include <compare>
#include <cstdint>
#include <memory>
#include <optional>
#include <ranges>
#include <algorithm>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.token;

namespace openproof::token {

SenderConstraint::SenderConstraint(SenderConstraintKind kind, std::string value)
    : m_kind(kind), m_value(std::move(value))
{
}

foundation::Result<SenderConstraint> SenderConstraint::create(
    SenderConstraintKind kind, std::string value)
{
    if (value.empty() || value.size() > 256U
        || std::ranges::any_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte <= 0x20U || byte == 0x7FU;
           })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The OAuth sender constraint is invalid.");
    }
    return SenderConstraint{kind, std::move(value)};
}

SenderConstraintKind SenderConstraint::kind() const noexcept { return m_kind; }
std::string_view SenderConstraint::value() const noexcept { return m_value; }

struct TokenContext::StateData final {
    client::ClientId client;
    identity::core::IdentityId identity;
    identity::provider::ProviderId provider;
    identity::provider::AssuranceLevel assurance{identity::provider::AssuranceLevel::Ial0};
    identity::provider::AuthenticationStrength strength;
    std::vector<std::string> scopes;
    std::vector<std::string> audiences;
    std::optional<SenderConstraint> senderConstraint;
    foundation::Instant authenticatedAt{};
};

TokenContext::TokenContext(client::ClientId client, identity::core::IdentityId identity,
                           identity::provider::ProviderId provider,
                           identity::provider::AssuranceLevel assurance,
                           identity::provider::AuthenticationStrength strength,
                           std::vector<std::string> scopes,
                           foundation::Instant authenticatedAt,
                           std::vector<std::string> audiences,
                           std::optional<SenderConstraint> senderConstraint)
{
    std::ranges::sort(scopes);
    scopes.erase(std::unique(scopes.begin(), scopes.end()), scopes.end());
    std::ranges::sort(audiences);
    audiences.erase(std::unique(audiences.begin(), audiences.end()), audiences.end());
    m_data = std::make_shared<StateData>(StateData{
        .client = std::move(client),
        .identity = std::move(identity),
        .provider = std::move(provider),
        .assurance = assurance,
        .strength = std::move(strength),
        .scopes = std::move(scopes),
        .audiences = std::move(audiences),
        .senderConstraint = std::move(senderConstraint),
        .authenticatedAt = authenticatedAt});
}

const client::ClientId& TokenContext::client() const noexcept { return m_data->client; }
const identity::core::IdentityId& TokenContext::identity() const noexcept { return m_data->identity; }
const identity::provider::ProviderId& TokenContext::provider() const noexcept { return m_data->provider; }
identity::provider::AssuranceLevel TokenContext::assurance() const noexcept { return m_data->assurance; }
const identity::provider::AuthenticationStrength& TokenContext::strength() const noexcept { return m_data->strength; }
const std::vector<std::string>& TokenContext::scopes() const noexcept { return m_data->scopes; }
const std::vector<std::string>& TokenContext::audiences() const noexcept { return m_data->audiences; }
const std::optional<SenderConstraint>& TokenContext::senderConstraint() const noexcept
{ return m_data->senderConstraint; }
foundation::Instant TokenContext::authenticatedAt() const noexcept { return m_data->authenticatedAt; }
bool TokenContext::permits(std::string_view scope) const noexcept
{ return scope.empty() || std::ranges::binary_search(m_data->scopes, std::string{scope}); }
bool TokenContext::permitsAudience(std::string_view audience) const noexcept
{ return audience.empty() || std::ranges::binary_search(m_data->audiences, std::string{audience}); }

struct AccessTokenRecord::StateData final {
    TokenDigest digest;
    TokenFamilyId family;
    TokenContext context;
    foundation::Instant issuedAt{};
    foundation::Instant expiresAt{};
    AccessTokenState state{AccessTokenState::Active};
    std::optional<foundation::Instant> revokedAt;
};

AccessTokenRecord::AccessTokenRecord(TokenDigest digest, TokenFamilyId family,
    TokenContext context, foundation::Instant issuedAt, foundation::Instant expiresAt,
    AccessTokenState state, std::optional<foundation::Instant> revokedAt)
    : m_data(std::make_shared<StateData>(StateData{
          .digest = std::move(digest), .family = std::move(family),
          .context = std::move(context), .issuedAt = issuedAt,
          .expiresAt = expiresAt, .state = state, .revokedAt = revokedAt}))
{
}

void AccessTokenRecord::detach()
{
    if (!m_data.unique()) m_data = std::make_shared<StateData>(*m_data);
}

const TokenDigest& AccessTokenRecord::digest() const noexcept { return m_data->digest; }
const TokenFamilyId& AccessTokenRecord::family() const noexcept { return m_data->family; }
const TokenContext& AccessTokenRecord::context() const noexcept { return m_data->context; }
foundation::Instant AccessTokenRecord::issuedAt() const noexcept { return m_data->issuedAt; }
foundation::Instant AccessTokenRecord::expiresAt() const noexcept { return m_data->expiresAt; }
AccessTokenState AccessTokenRecord::state() const noexcept { return m_data->state; }
const std::optional<foundation::Instant>& AccessTokenRecord::revokedAt() const noexcept { return m_data->revokedAt; }
bool AccessTokenRecord::usableAt(foundation::Instant now) const noexcept
{ return m_data->state == AccessTokenState::Active && now < m_data->expiresAt; }
void AccessTokenRecord::revoke(foundation::Instant now) noexcept
{
    detach();
    if (m_data->state == AccessTokenState::Active) {
        m_data->state = AccessTokenState::Revoked;
        m_data->revokedAt = now;
    }
}

struct RefreshTokenRecord::StateData final {
    TokenDigest digest;
    TokenFamilyId family;
    std::uint64_t sequence{};
    TokenContext context;
    foundation::Instant issuedAt{};
    foundation::Instant expiresAt{};
    RefreshTokenState state{RefreshTokenState::Active};
    std::optional<foundation::Instant> changedAt;
};

RefreshTokenRecord::RefreshTokenRecord(TokenDigest digest, TokenFamilyId family,
    std::uint64_t sequence, TokenContext context, foundation::Instant issuedAt,
    foundation::Instant expiresAt, RefreshTokenState state,
    std::optional<foundation::Instant> changedAt)
    : m_data(std::make_shared<StateData>(StateData{
          .digest = std::move(digest), .family = std::move(family),
          .sequence = sequence, .context = std::move(context),
          .issuedAt = issuedAt, .expiresAt = expiresAt,
          .state = state, .changedAt = changedAt}))
{
}

void RefreshTokenRecord::detach()
{
    if (!m_data.unique()) m_data = std::make_shared<StateData>(*m_data);
}

const TokenDigest& RefreshTokenRecord::digest() const noexcept { return m_data->digest; }
const TokenFamilyId& RefreshTokenRecord::family() const noexcept { return m_data->family; }
std::uint64_t RefreshTokenRecord::sequence() const noexcept { return m_data->sequence; }
const TokenContext& RefreshTokenRecord::context() const noexcept { return m_data->context; }
foundation::Instant RefreshTokenRecord::issuedAt() const noexcept { return m_data->issuedAt; }
foundation::Instant RefreshTokenRecord::expiresAt() const noexcept { return m_data->expiresAt; }
RefreshTokenState RefreshTokenRecord::state() const noexcept { return m_data->state; }
const std::optional<foundation::Instant>& RefreshTokenRecord::changedAt() const noexcept { return m_data->changedAt; }
bool RefreshTokenRecord::usableAt(foundation::Instant now) const noexcept
{ return m_data->state == RefreshTokenState::Active && now < m_data->expiresAt; }
void RefreshTokenRecord::markUsed(foundation::Instant now) noexcept
{
    detach();
    if (m_data->state == RefreshTokenState::Active) {
        m_data->state = RefreshTokenState::Used;
        m_data->changedAt = now;
    }
}
void RefreshTokenRecord::revoke(foundation::Instant now) noexcept
{
    detach();
    if (m_data->state != RefreshTokenState::Revoked) {
        m_data->state = RefreshTokenState::Revoked;
        m_data->changedAt = now;
    }
}

struct TokenClaims::StateData final {
    bool active{};
    TokenContext context;
    foundation::Instant issuedAt{};
    foundation::Instant expiresAt{};
};

TokenClaims::TokenClaims(bool active, TokenContext context,
                         foundation::Instant issuedAt, foundation::Instant expiresAt)
    : m_data(std::make_shared<StateData>(StateData{
          .active = active, .context = std::move(context),
          .issuedAt = issuedAt, .expiresAt = expiresAt}))
{
}

bool TokenClaims::active() const noexcept { return m_data->active; }
const TokenContext& TokenClaims::context() const noexcept { return m_data->context; }
foundation::Instant TokenClaims::issuedAt() const noexcept { return m_data->issuedAt; }
foundation::Instant TokenClaims::expiresAt() const noexcept { return m_data->expiresAt; }

}

module;

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>

module openproof.evidence;

namespace openproof::evidence {
namespace {

[[nodiscard]] bool validText(std::string_view value, std::size_t maximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::none_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           });
}

[[nodiscard]] bool validEvidence(
    const EvidenceId& id, const identity::core::IdentityId& identity,
    const identity::provider::ProviderId& provider, std::string_view kind,
    std::string_view claim, std::string_view value, unsigned int confidence,
    foundation::Instant verifiedAt,
    const std::optional<foundation::Instant>& expiresAt) noexcept
{
    return !id.empty() && !identity.empty() && !provider.empty()
        && validText(kind, 128U) && validText(claim, 128U)
        && validText(value, 4096U) && confidence <= 100U
        && (!expiresAt || expiresAt.value() > verifiedAt);
}

} // namespace

struct Evidence::StateData final {
    EvidenceId id;
    identity::core::IdentityId identity;
    identity::provider::ProviderId provider;
    std::string kind;
    std::string claim;
    std::string value;
    unsigned int confidence{};
    EvidenceStatus status{EvidenceStatus::Verified};
    foundation::Instant verifiedAt{};
    std::optional<foundation::Instant> expiresAt;
};

Evidence::Evidence(
    EvidenceId id, identity::core::IdentityId identity,
    identity::provider::ProviderId provider, std::string kind,
    std::string claim, std::string value, unsigned int confidence,
    EvidenceStatus status, foundation::Instant verifiedAt,
    std::optional<foundation::Instant> expiresAt)
    : m_data(std::make_shared<StateData>(StateData{
          .id = std::move(id), .identity = std::move(identity),
          .provider = std::move(provider), .kind = std::move(kind),
          .claim = std::move(claim), .value = std::move(value),
          .confidence = confidence, .status = status,
          .verifiedAt = verifiedAt, .expiresAt = expiresAt}))
{
}

void Evidence::detach()
{
    if (!m_data.unique()) m_data = std::make_shared<StateData>(*m_data);
}

foundation::Result<Evidence> Evidence::create(
    EvidenceId id, identity::core::IdentityId identity,
    identity::provider::ProviderId provider, std::string kind,
    std::string claim, std::string value, unsigned int confidence,
    foundation::Instant verifiedAt,
    std::optional<foundation::Instant> expiresAt)
{
    return restore(std::move(id), std::move(identity), std::move(provider),
                   std::move(kind), std::move(claim), std::move(value), confidence,
                   EvidenceStatus::Verified, verifiedAt, expiresAt);
}

foundation::Result<Evidence> Evidence::restore(
    EvidenceId id, identity::core::IdentityId identity,
    identity::provider::ProviderId provider, std::string kind,
    std::string claim, std::string value, unsigned int confidence,
    EvidenceStatus status, foundation::Instant verifiedAt,
    std::optional<foundation::Instant> expiresAt)
{
    if (!validEvidence(id, identity, provider, kind, claim, value, confidence,
                       verifiedAt, expiresAt)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The verified evidence is invalid.");
    }
    return Evidence{std::move(id), std::move(identity), std::move(provider),
                    std::move(kind), std::move(claim), std::move(value), confidence,
                    status, verifiedAt, expiresAt};
}

const EvidenceId& Evidence::id() const noexcept { return m_data->id; }
const identity::core::IdentityId& Evidence::identity() const noexcept { return m_data->identity; }
const identity::provider::ProviderId& Evidence::provider() const noexcept { return m_data->provider; }
std::string_view Evidence::kind() const noexcept { return m_data->kind; }
std::string_view Evidence::claim() const noexcept { return m_data->claim; }
std::string_view Evidence::value() const noexcept { return m_data->value; }
unsigned int Evidence::confidence() const noexcept { return m_data->confidence; }
EvidenceStatus Evidence::status() const noexcept { return m_data->status; }
foundation::Instant Evidence::verifiedAt() const noexcept { return m_data->verifiedAt; }
const std::optional<foundation::Instant>& Evidence::expiresAt() const noexcept { return m_data->expiresAt; }

bool Evidence::activeAt(foundation::Instant now) const noexcept
{
    return m_data->status == EvidenceStatus::Verified
        && (!m_data->expiresAt || now < m_data->expiresAt.value());
}

foundation::Status Evidence::revoke() noexcept
{
    detach();
    m_data->status = EvidenceStatus::Revoked;
    return foundation::ok();
}

} // namespace openproof::evidence

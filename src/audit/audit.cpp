module;

#include <optional>
#include <array>
#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.audit;

namespace openproof::audit {
namespace {

[[nodiscard]] bool validAtom(std::string_view value, std::size_t maximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::none_of(value, [](char symbol) {
            const auto byte = static_cast<unsigned char>(symbol);
            return byte < 0x20U || byte == 0x7FU;
        });
}

void appendPart(std::string& output, std::string_view value)
{
    output.append(std::to_string(value.size())).push_back(':');
    output.append(value);
}

[[nodiscard]] std::string canonical(const AuditEvent& event,
                                    std::uint64_t sequence,
                                    const std::optional<security::Sha256Digest>& previous)
{
    std::string output;
    appendPart(output, std::to_string(sequence));
    appendPart(output, event.id().value());
    appendPart(output, std::to_string(event.occurredAt().time_since_epoch().count()));
    appendPart(output, event.correlation().value());
    appendPart(output, event.organization().has_value()
                           ? event.organization()->value() : std::string_view{});
    appendPart(output, event.identity().has_value()
                           ? event.identity()->value() : std::string_view{});
    appendPart(output, event.category());
    appendPart(output, event.action());
    appendPart(output, event.outcome());
    appendPart(output, previous.has_value()
                           ? foundation::toHex(previous.value()) : std::string{});
    for (const auto& [name, value] : event.fields()) {
        appendPart(output, name);
        appendPart(output, value);
    }
    return output;
}

[[nodiscard]] foundation::Status validateFields(const AuditFields& fields)
{
    if (fields.size() > 64U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An audit event has too many fields.");
    }
    for (const auto& [name, value] : fields) {
        if (!validAtom(name, 100U) || value.size() > 4096U) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "An audit event field is invalid.");
        }
    }
    return foundation::ok();
}

}

AuditEvent::AuditEvent(AuditEventId id, foundation::Instant occurredAt,
                       foundation::CorrelationId correlation,
                       std::optional<identity::core::OrganizationId> organization,
                       std::optional<identity::core::IdentityId> identity,
                       std::string category, std::string action, std::string outcome,
                       AuditFields fields)
    : m_id(std::move(id)), m_occurredAt(occurredAt), m_correlation(std::move(correlation)),
      m_organization(std::move(organization)), m_identity(std::move(identity)),
      m_category(std::move(category)), m_action(std::move(action)),
      m_outcome(std::move(outcome)), m_fields(std::move(fields))
{
}

foundation::Result<AuditEvent> AuditEvent::create(
    AuditEventId id, foundation::Instant occurredAt,
    foundation::CorrelationId correlation,
    std::optional<identity::core::OrganizationId> organization,
    std::optional<identity::core::IdentityId> identity,
    std::string category, std::string action, std::string outcome, AuditFields fields)
{
    const foundation::Status fieldsStatus = validateFields(fields);
    if (id.empty() || correlation.empty() || !validAtom(category, 100U)
        || !validAtom(action, 200U) || !validAtom(outcome, 100U)
        || !fieldsStatus.has_value()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The audit event is invalid.");
    }
    return AuditEvent{std::move(id), occurredAt, std::move(correlation),
                      std::move(organization), std::move(identity),
                      std::move(category), std::move(action), std::move(outcome),
                      std::move(fields)};
}

const AuditEventId& AuditEvent::id() const noexcept { return m_id; }
foundation::Instant AuditEvent::occurredAt() const noexcept { return m_occurredAt; }
const foundation::CorrelationId& AuditEvent::correlation() const noexcept { return m_correlation; }
const std::optional<identity::core::OrganizationId>& AuditEvent::organization() const noexcept { return m_organization; }
const std::optional<identity::core::IdentityId>& AuditEvent::identity() const noexcept { return m_identity; }
std::string_view AuditEvent::category() const noexcept { return m_category; }
std::string_view AuditEvent::action() const noexcept { return m_action; }
std::string_view AuditEvent::outcome() const noexcept { return m_outcome; }
const AuditFields& AuditEvent::fields() const noexcept { return m_fields; }

AuditKey::AuditKey(foundation::SecretString key) : m_key(std::move(key)) {}
foundation::Result<AuditKey> AuditKey::create(foundation::SecretString key)
{
    if (key.expose().size() < 32U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An audit signing key must contain at least 32 bytes.");
    }
    return AuditKey{std::move(key)};
}
const foundation::SecretString& AuditKey::secret() const noexcept { return m_key; }

AuditRecord::AuditRecord(std::uint64_t sequence, AuditEvent event,
                         std::optional<security::Sha256Digest> previousHash,
                         security::Sha256Digest hash)
    : m_sequence(sequence), m_event(std::move(event)),
      m_previousHash(previousHash), m_hash(hash) {}
std::uint64_t AuditRecord::sequence() const noexcept { return m_sequence; }
const AuditEvent& AuditRecord::event() const noexcept { return m_event; }
const std::optional<security::Sha256Digest>& AuditRecord::previousHash() const noexcept { return m_previousHash; }
const security::Sha256Digest& AuditRecord::hash() const noexcept { return m_hash; }

foundation::Result<security::Sha256Digest> computeAuditRecordHash(
    const AuditEvent& event, std::uint64_t sequence,
    const std::optional<security::Sha256Digest>& previousHash,
    const AuditKey& key)
{
    return security::hmacSha256(
        key.secret(), canonical(event, sequence, previousHash));
}

foundation::Result<AuditRecord> InMemoryAuditRepository::append(
    AuditEvent event, const AuditKey& key)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    if (std::ranges::any_of(m_records, [&event](const AuditRecord& existing) {
            return existing.event().id() == event.id(); })) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The audit event already exists.");
    }
    const std::uint64_t sequence = static_cast<std::uint64_t>(m_records.size()) + 1U;
    const std::optional<security::Sha256Digest> previous = m_records.empty()
        ? std::nullopt : std::optional<security::Sha256Digest>{m_records.back().hash()};
    auto hash = computeAuditRecordHash(event, sequence, previous, key);
    if (!hash.has_value()) return foundation::fail(hash.error());
    m_records.emplace_back(sequence, std::move(event), previous, hash.value());
    return m_records.back();
}

foundation::Result<std::vector<AuditRecord>> InMemoryAuditRepository::records() const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    return m_records;
}

foundation::Status InMemoryAuditRepository::verify(const AuditKey& key) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    std::optional<security::Sha256Digest> previous;
    for (const AuditRecord& record : m_records) {
        if (record.previousHash() != previous) {
            return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                    "The audit chain is not intact.");
        }
        auto expected = computeAuditRecordHash(
            record.event(), record.sequence(), previous, key);
        if (!expected.has_value()) return foundation::fail(expected.error());
        if (!security::constantTimeEquals(expected.value(), record.hash())) {
            return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                    "The audit chain is not intact.");
        }
        previous = record.hash();
    }
    return foundation::ok();
}

std::string_view securitySeverityName(SecuritySeverity severity) noexcept
{
    switch (severity) {
    case SecuritySeverity::Informational: return "informational";
    case SecuritySeverity::Warning: return "warning";
    case SecuritySeverity::Critical: return "critical";
    }
    return "critical";
}

SecurityEvent::SecurityEvent(AuditEventId id, foundation::Instant occurredAt,
                             foundation::CorrelationId correlation,
                             SecuritySeverity severity, std::string type,
                             AuditFields fields)
    : m_id(std::move(id)), m_occurredAt(occurredAt), m_correlation(std::move(correlation)),
      m_severity(severity), m_type(std::move(type)), m_fields(std::move(fields)) {}

foundation::Result<SecurityEvent> SecurityEvent::create(
    AuditEventId id, foundation::Instant occurredAt,
    foundation::CorrelationId correlation, SecuritySeverity severity,
    std::string type, AuditFields fields)
{
    const foundation::Status fieldsStatus = validateFields(fields);
    if (id.empty() || correlation.empty() || !validAtom(type, 200U)
        || !fieldsStatus.has_value()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The security event is invalid.");
    }
    return SecurityEvent{std::move(id), occurredAt, std::move(correlation), severity,
                         std::move(type), std::move(fields)};
}
const AuditEventId& SecurityEvent::id() const noexcept { return m_id; }
foundation::Instant SecurityEvent::occurredAt() const noexcept { return m_occurredAt; }
const foundation::CorrelationId& SecurityEvent::correlation() const noexcept { return m_correlation; }
SecuritySeverity SecurityEvent::severity() const noexcept { return m_severity; }
std::string_view SecurityEvent::type() const noexcept { return m_type; }
const AuditFields& SecurityEvent::fields() const noexcept { return m_fields; }

foundation::Status InMemorySecurityEventSink::publish(SecurityEvent event)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    if (std::ranges::any_of(m_events, [&event](const SecurityEvent& existing) {
            return existing.id() == event.id(); })) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The security event already exists.");
    }
    m_events.push_back(std::move(event));
    return foundation::ok();
}

std::vector<SecurityEvent> InMemorySecurityEventSink::events() const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    return m_events;
}

}

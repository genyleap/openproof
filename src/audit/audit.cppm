module;

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.audit;

import openproof.foundation;
import openproof.identity.core;
import openproof.security;

export namespace openproof::audit {

struct AuditEventIdTag {};
using AuditEventId = foundation::StrongId<AuditEventIdTag>;
using AuditFields = std::map<std::string, std::string, std::less<>>;

class AuditEvent final {
public:
    [[nodiscard]] static foundation::Result<AuditEvent>
    create(AuditEventId id, foundation::Instant occurredAt,
           foundation::CorrelationId correlation,
           std::optional<identity::core::OrganizationId> organization,
           std::optional<identity::core::IdentityId> identity,
           std::string category, std::string action, std::string outcome,
           AuditFields fields = {});
    [[nodiscard]] const AuditEventId& id() const noexcept;
    [[nodiscard]] foundation::Instant occurredAt() const noexcept;
    [[nodiscard]] const foundation::CorrelationId& correlation() const noexcept;
    [[nodiscard]] const std::optional<identity::core::OrganizationId>& organization() const noexcept;
    [[nodiscard]] const std::optional<identity::core::IdentityId>& identity() const noexcept;
    [[nodiscard]] std::string_view category() const noexcept;
    [[nodiscard]] std::string_view action() const noexcept;
    [[nodiscard]] std::string_view outcome() const noexcept;
    [[nodiscard]] const AuditFields& fields() const noexcept;
private:
    AuditEvent(AuditEventId id, foundation::Instant occurredAt,
               foundation::CorrelationId correlation,
               std::optional<identity::core::OrganizationId> organization,
               std::optional<identity::core::IdentityId> identity,
               std::string category, std::string action, std::string outcome,
               AuditFields fields);
    AuditEventId m_id;
    foundation::Instant m_occurredAt{};
    foundation::CorrelationId m_correlation;
    std::optional<identity::core::OrganizationId> m_organization;
    std::optional<identity::core::IdentityId> m_identity;
    std::string m_category;
    std::string m_action;
    std::string m_outcome;
    AuditFields m_fields;
};

class AuditKey final {
public:
    [[nodiscard]] static foundation::Result<AuditKey>
    create(foundation::SecretString key);
    AuditKey(const AuditKey&) = delete;
    AuditKey& operator=(const AuditKey&) = delete;
    AuditKey(AuditKey&&) noexcept = default;
    AuditKey& operator=(AuditKey&&) noexcept = default;
    ~AuditKey() = default;
    [[nodiscard]] const foundation::SecretString& secret() const noexcept;
private:
    explicit AuditKey(foundation::SecretString key);
    foundation::SecretString m_key;
};

class AuditRecord final {
public:
    AuditRecord(std::uint64_t sequence, AuditEvent event,
                std::optional<security::Sha256Digest> previousHash,
                security::Sha256Digest hash);
    [[nodiscard]] std::uint64_t sequence() const noexcept;
    [[nodiscard]] const AuditEvent& event() const noexcept;
    [[nodiscard]] const std::optional<security::Sha256Digest>& previousHash() const noexcept;
    [[nodiscard]] const security::Sha256Digest& hash() const noexcept;
private:
    std::uint64_t m_sequence{};
    AuditEvent m_event;
    std::optional<security::Sha256Digest> m_previousHash;
    security::Sha256Digest m_hash{};
};

class AuditRepository {
public:
    AuditRepository(const AuditRepository&) = delete;
    AuditRepository& operator=(const AuditRepository&) = delete;
    virtual ~AuditRepository() = default;
    /** Sequence allocation, previous-hash read and append must be one atomic operation. */
    [[nodiscard]] virtual foundation::Result<AuditRecord>
    append(AuditEvent event, const AuditKey& key) = 0;
    [[nodiscard]] virtual foundation::Result<std::vector<AuditRecord>> records() const = 0;
    [[nodiscard]] virtual foundation::Status verify(const AuditKey& key) const = 0;
protected:
    AuditRepository() = default;
};

class InMemoryAuditRepository final : public AuditRepository {
public:
    [[nodiscard]] foundation::Result<AuditRecord>
    append(AuditEvent event, const AuditKey& key) override;
    [[nodiscard]] foundation::Result<std::vector<AuditRecord>> records() const override;
    [[nodiscard]] foundation::Status verify(const AuditKey& key) const override;
private:
    mutable std::mutex m_mutex;
    std::vector<AuditRecord> m_records;
};

enum class SecuritySeverity { Informational, Warning, Critical };
[[nodiscard]] std::string_view securitySeverityName(SecuritySeverity severity) noexcept;

class SecurityEvent final {
public:
    [[nodiscard]] static foundation::Result<SecurityEvent>
    create(AuditEventId id, foundation::Instant occurredAt,
           foundation::CorrelationId correlation, SecuritySeverity severity,
           std::string type, AuditFields fields = {});
    [[nodiscard]] const AuditEventId& id() const noexcept;
    [[nodiscard]] foundation::Instant occurredAt() const noexcept;
    [[nodiscard]] const foundation::CorrelationId& correlation() const noexcept;
    [[nodiscard]] SecuritySeverity severity() const noexcept;
    [[nodiscard]] std::string_view type() const noexcept;
    [[nodiscard]] const AuditFields& fields() const noexcept;
private:
    SecurityEvent(AuditEventId id, foundation::Instant occurredAt,
                  foundation::CorrelationId correlation,
                  SecuritySeverity severity, std::string type, AuditFields fields);
    AuditEventId m_id;
    foundation::Instant m_occurredAt{};
    foundation::CorrelationId m_correlation;
    SecuritySeverity m_severity{SecuritySeverity::Informational};
    std::string m_type;
    AuditFields m_fields;
};

class SecurityEventSink {
public:
    SecurityEventSink(const SecurityEventSink&) = delete;
    SecurityEventSink& operator=(const SecurityEventSink&) = delete;
    virtual ~SecurityEventSink() = default;
    [[nodiscard]] virtual foundation::Status publish(SecurityEvent event) = 0;
protected:
    SecurityEventSink() = default;
};

class InMemorySecurityEventSink final : public SecurityEventSink {
public:
    [[nodiscard]] foundation::Status publish(SecurityEvent event) override;
    [[nodiscard]] std::vector<SecurityEvent> events() const;
private:
    mutable std::mutex m_mutex;
    std::vector<SecurityEvent> m_events;
};

}

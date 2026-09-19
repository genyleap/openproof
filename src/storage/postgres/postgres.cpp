module;

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <libpq-fe.h>

module openproof.storage.postgres;

import openproof.account;
import openproof.administration;
import openproof.audit;
import openproof.consent;
import openproof.identity.core;
import openproof.provider.passkey;
import openproof.resource;
import openproof.security;

namespace openproof::storage::postgres {
namespace {

struct ResultDeleter final { void operator()(PGresult* result) const noexcept { PQclear(result); } };
using ResultPointer = std::unique_ptr<PGresult, ResultDeleter>;
struct ConnectionDeleter final { void operator()(PGconn* connection) const noexcept { PQfinish(connection); } };
using ConnectionPointer = std::unique_ptr<PGconn, ConnectionDeleter>;

[[nodiscard]] foundation::Error databaseError(PGresult* result, std::string_view operation)
{
    const char* state = result == nullptr ? nullptr : PQresultErrorField(result, PG_DIAG_SQLSTATE);
    const std::string detail = std::string{operation} + " failed"
        + (state == nullptr ? std::string{"."} : std::string{" (SQLSTATE "} + state + ").");
    foundation::ErrorCode code = foundation::ErrorCode::Unavailable;
    if (state != nullptr && std::string_view{state} == "23505") {
        code = foundation::ErrorCode::AlreadyExists;
    } else if (state != nullptr && (std::string_view{state} == "23503"
                                    || std::string_view{state} == "23514")) {
        code = foundation::ErrorCode::FailedPrecondition;
    } else if (state != nullptr && std::string_view{state} == "40001") {
        code = foundation::ErrorCode::Conflict;
    }
    return foundation::Error{code,
                             std::string{foundation::defaultErrorMessage(
                                 code)}, detail};
}

[[nodiscard]] foundation::Error authenticationFailure(std::string detail)
{
    return foundation::Error{
        foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(
            foundation::ErrorCode::AuthenticationFailed)}, std::move(detail)};
}

[[nodiscard]] bool commandOk(PGresult* result) noexcept
{ return result != nullptr && PQresultStatus(result) == PGRES_COMMAND_OK; }
[[nodiscard]] bool tuplesOk(PGresult* result) noexcept
{ return result != nullptr && PQresultStatus(result) == PGRES_TUPLES_OK; }

[[nodiscard]] ResultPointer exec(PGconn* connection, std::string_view sql)
{
    return ResultPointer{PQexec(connection, std::string{sql}.c_str())};
}

[[nodiscard]] ResultPointer execParams(PGconn* connection, std::string_view sql,
                                       const std::vector<std::string>& parameters)
{
    std::vector<const char*> values;
    values.reserve(parameters.size());
    for (const std::string& parameter : parameters) values.push_back(parameter.c_str());
    return ResultPointer{PQexecParams(connection, std::string{sql}.c_str(),
        static_cast<int>(values.size()), nullptr, values.data(), nullptr, nullptr, 0)};
}

[[nodiscard]] std::string integer(std::int64_t value) { return std::to_string(value); }
[[nodiscard]] std::string instant(foundation::Instant value)
{ return integer(value.time_since_epoch().count()); }

template <typename Integer>
[[nodiscard]] foundation::Result<Integer> parseInteger(std::string_view text)
{
    Integer value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "PostgreSQL returned malformed numeric data.");
    }
    return value;
}

[[nodiscard]] foundation::Result<security::Sha256Digest> parseDigest(std::string_view text)
{
    auto decoded = foundation::fromHex(text);
    if (!decoded.has_value() || decoded->size() != security::Sha256Digest{}.size()) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "PostgreSQL returned a malformed digest.");
    }
    security::Sha256Digest digest{};
    std::ranges::copy(decoded.value(), digest.begin());
    return digest;
}

[[nodiscard]] std::string field(PGresult* result, int row, int column)
{ return std::string{PQgetvalue(result, row, column)}; }

[[nodiscard]] foundation::Status beginTransaction(PGconn* connection)
{
    ResultPointer result = exec(connection, "BEGIN");
    return commandOk(result.get()) ? foundation::ok()
                                   : foundation::fail(databaseError(result.get(), "BEGIN"));
}

void rollback(PGconn* connection) noexcept
{
    ResultPointer ignored = exec(connection, "ROLLBACK");
}

[[nodiscard]] foundation::Status commit(PGconn* connection)
{
    ResultPointer result = exec(connection, "COMMIT");
    return commandOk(result.get()) ? foundation::ok()
                                   : foundation::fail(databaseError(result.get(), "COMMIT"));
}

[[nodiscard]] foundation::Status runCommand(
    PGconn* connection, std::string_view sql,
    const std::vector<std::string>& parameters,
    std::string_view operation)
{
    ResultPointer result = execParams(connection, sql, parameters);
    return commandOk(result.get()) ? foundation::ok()
        : foundation::fail(databaseError(result.get(), operation));
}

[[nodiscard]] foundation::Status prepareAdministrationTransaction(
    PGconn* connection)
{
    ResultPointer isolated = exec(
        connection, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    if (!commandOk(isolated.get())) {
        return foundation::fail(
            databaseError(isolated.get(), "set administration isolation"));
    }
    ResultPointer locked = exec(
        connection, "SELECT pg_advisory_xact_lock(7299730475761673315)");
    return tuplesOk(locked.get()) ? foundation::ok()
        : foundation::fail(
            databaseError(locked.get(), "lock administration mutation"));
}

[[nodiscard]] foundation::Status authorizeActiveOwner(
    PGconn* connection, const identity::core::OrganizationId& organizationId,
    const identity::core::IdentityId& actor)
{
    ResultPointer authorized = execParams(
        connection,
        "SELECT 1 FROM openproof.organizations o "
        "JOIN openproof.identities i ON i.organization_id=o.id AND i.id=$2 "
        "JOIN openproof.memberships m ON m.organization_id=o.id AND m.identity_id=i.id "
        "JOIN openproof.membership_roles r ON r.organization_id=m.organization_id "
        "AND r.identity_id=m.identity_id AND r.role='owner' "
        "WHERE o.id=$1 AND o.state=0 AND i.status=0 AND m.state=1 "
        "FOR UPDATE OF o,i,m",
        {std::string{organizationId.value()}, std::string{actor.value()}});
    if (!tuplesOk(authorized.get())) {
        return foundation::fail(
            databaseError(authorized.get(), "authorize administration"));
    }
    return PQntuples(authorized.get()) == 1 ? foundation::ok()
        : foundation::fail(foundation::ErrorCode::PermissionDenied,
                           "The operation is not permitted.");
}

struct LockedMember final {
    organization::MembershipState state{organization::MembershipState::Removed};
    bool owner{false};
};

[[nodiscard]] foundation::Result<LockedMember> lockLocalMember(
    PGconn* connection, const identity::core::OrganizationId& organizationId,
    const identity::core::IdentityId& identityId,
    const identity::provider::ProviderId& provider)
{
    ResultPointer target = execParams(
        connection,
        "SELECT m.state,EXISTS(SELECT 1 FROM openproof.membership_roles r "
        "WHERE r.organization_id=m.organization_id AND r.identity_id=m.identity_id "
        "AND r.role='owner') FROM openproof.organizations o "
        "JOIN openproof.identities i ON i.organization_id=o.id AND i.id=$2 "
        "JOIN openproof.memberships m ON m.organization_id=o.id AND m.identity_id=i.id "
        "WHERE o.id=$1 AND o.state=0 AND i.status=0 "
        "AND EXISTS(SELECT 1 FROM openproof.external_identities e "
        "WHERE e.identity_id=i.id AND e.provider=$3) FOR UPDATE OF o,i,m",
        {std::string{organizationId.value()}, std::string{identityId.value()},
         std::string{provider.value()}});
    if (!tuplesOk(target.get())) {
        return foundation::fail(
            databaseError(target.get(), "lock managed local member"));
    }
    if (PQntuples(target.get()) != 1) {
        return foundation::fail(foundation::ErrorCode::NotFound,
                                "That local member was not found.");
    }
    auto state = parseInteger<unsigned int>(field(target.get(), 0, 0));
    if (!state || state.value() > 3U) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "PostgreSQL returned invalid membership state.");
    }
    return LockedMember{
        static_cast<organization::MembershipState>(state.value()),
        field(target.get(), 0, 1) == "t"};
}

[[nodiscard]] foundation::Result<std::size_t> activeOwnerCount(
    PGconn* connection, const identity::core::OrganizationId& organizationId)
{
    ResultPointer result = execParams(
        connection,
        "SELECT count(*) FROM openproof.memberships m "
        "JOIN openproof.identities i ON i.id=m.identity_id "
        "JOIN openproof.membership_roles r ON r.organization_id=m.organization_id "
        "AND r.identity_id=m.identity_id AND r.role='owner' "
        "WHERE m.organization_id=$1 AND m.state=1 AND i.status=0",
        {std::string{organizationId.value()}});
    if (!tuplesOk(result.get()) || PQntuples(result.get()) != 1) {
        return foundation::fail(
            databaseError(result.get(), "count active owners"));
    }
    return parseInteger<std::size_t>(field(result.get(), 0, 0));
}

[[nodiscard]] foundation::Status revokeMemberSessions(
    PGconn* connection, const identity::core::IdentityId& identityId,
    foundation::Instant now)
{
    return runCommand(
        connection,
        "UPDATE openproof.sessions SET state=1,revoked_at_ms=$2 "
        "WHERE identity_id=$1 AND state=0",
        {std::string{identityId.value()}, instant(now)},
        "revoke managed member sessions");
}

[[nodiscard]] foundation::Result<audit::AuditEvent> administrationEvent(
    std::string action,
    const identity::core::OrganizationId& organizationId,
    const identity::core::IdentityId& target,
    const identity::core::IdentityId& actor,
    foundation::Instant now, audit::AuditFields fields = {})
{
    auto randomId = security::randomTokenBase64Url(24U);
    if (!randomId) return foundation::fail(randomId.error());
    const std::string eventId = "admin-" + randomId.value();
    fields.emplace("actor_identity_id", std::string{actor.value()});
    return audit::AuditEvent::create(
        audit::AuditEventId{eventId}, now, foundation::CorrelationId{eventId},
        std::optional<identity::core::OrganizationId>{organizationId},
        std::optional<identity::core::IdentityId>{target},
        "administration", std::move(action), "success", std::move(fields));
}

[[nodiscard]] foundation::Status appendAuditRecord(
    PGconn* connection, const audit::AuditEvent& event,
    const audit::AuditKey& key)
{
    ResultPointer auditLock = exec(
        connection, "SELECT pg_advisory_xact_lock(7299730475761673314)");
    if (!tuplesOk(auditLock.get())) {
        return foundation::fail(
            databaseError(auditLock.get(), "lock audit chain"));
    }
    ResultPointer previousResult = exec(
        connection,
        "SELECT encode(event_hash,'hex') FROM openproof.audit_events "
        "ORDER BY sequence DESC LIMIT 1");
    if (!tuplesOk(previousResult.get())) {
        return foundation::fail(
            databaseError(previousResult.get(), "read audit chain head"));
    }
    std::optional<security::Sha256Digest> previousHash;
    std::string previousHex;
    if (PQntuples(previousResult.get()) == 1) {
        auto parsed = parseDigest(field(previousResult.get(), 0, 0));
        if (!parsed) return foundation::fail(parsed.error());
        previousHash = parsed.value();
        previousHex = foundation::toHex(parsed.value());
    }
    foundation::JsonObjectWriter detail;
    for (const auto& [name, value] : event.fields()) detail.add(name, value);
    ResultPointer insertedAudit = execParams(
        connection,
        "INSERT INTO openproof.audit_events"
        "(event_id,occurred_at_ms,correlation_id,organization_id,identity_id,"
        "category,action,outcome,detail,previous_hash,event_hash) "
        "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,"
        "CASE WHEN $10='' THEN NULL ELSE decode($10,'hex') END,decode($11,'hex')) "
        "RETURNING sequence",
        {std::string{event.id().value()}, instant(event.occurredAt()),
         std::string{event.correlation().value()},
         std::string{event.organization()->value()},
         std::string{event.identity()->value()}, std::string{event.category()},
         std::string{event.action()}, std::string{event.outcome()}, detail.build(),
         previousHex, std::string(64U, '0')});
    if (!tuplesOk(insertedAudit.get()) || PQntuples(insertedAudit.get()) != 1) {
        return foundation::fail(
            databaseError(insertedAudit.get(), "append administration audit event"));
    }
    auto sequence = parseInteger<std::uint64_t>(field(insertedAudit.get(), 0, 0));
    if (!sequence) return foundation::fail(sequence.error());
    auto recordHash = audit::computeAuditRecordHash(
        event, sequence.value(), previousHash, key);
    if (!recordHash) return foundation::fail(recordHash.error());
    auto sealed = runCommand(
        connection,
        "UPDATE openproof.audit_events SET event_hash=decode($2,'hex') "
        "WHERE sequence=$1",
        {std::to_string(sequence.value()), foundation::toHex(recordHash.value())},
        "seal administration audit event");
    return sealed;
}

[[nodiscard]] foundation::Status appendSecurityRecord(
    PGconn* connection, const audit::AuditEvent& event,
    std::string_view securityType, std::string_view actorIdentity,
    std::string_view severity)
{
    foundation::JsonObjectWriter payload;
    payload.add("event_id", event.id().value())
        .add("type", securityType)
        .add("organization_id", event.organization()->value())
        .add("identity_id", event.identity()->value())
        .add("actor_identity_id", actorIdentity)
        .add("severity", severity);
    return runCommand(
        connection,
        "INSERT INTO openproof.security_event_outbox"
        "(event_id,occurred_at_ms,payload) VALUES($1,$2,$3::jsonb)",
        {std::string{event.id().value()}, instant(event.occurredAt()),
         payload.build()},
        "append security event");
}

[[nodiscard]] foundation::Status appendAdministrationRecords(
    PGconn* connection, const audit::AuditEvent& event,
    const audit::AuditKey& key, std::string_view securityType)
{
    auto recorded = appendAuditRecord(connection, event, key);
    if (!recorded) return recorded;
    return appendSecurityRecord(
        connection, event, securityType,
        event.fields().at("actor_identity_id"), "critical");
}

constexpr std::string_view kSessionColumns =
    "id, identity_id, provider, assurance, factors, phishing_resistant, state, "
    "encode(token_digest, 'hex'), authenticated_at_ms, issued_at_ms, "
    "last_seen_at_ms, absolute_expires_at_ms, idle_timeout_ms, revoked_at_ms, "
    "user_agent, remote_address";

[[nodiscard]] foundation::Result<session::Session> sessionFromRow(PGresult* result, int row)
{
    if (PQnfields(result) != 16) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "PostgreSQL returned an invalid session shape.");
    }
    auto assurance = parseInteger<unsigned int>(field(result, row, 3));
    auto factors = parseInteger<unsigned int>(field(result, row, 4));
    auto state = parseInteger<unsigned int>(field(result, row, 6));
    auto digest = parseDigest(field(result, row, 7));
    auto authenticated = parseInteger<std::int64_t>(field(result, row, 8));
    auto issued = parseInteger<std::int64_t>(field(result, row, 9));
    auto lastSeen = parseInteger<std::int64_t>(field(result, row, 10));
    auto absolute = parseInteger<std::int64_t>(field(result, row, 11));
    auto idle = parseInteger<std::int64_t>(field(result, row, 12));
    if (!assurance || !factors || !state || !digest || !authenticated || !issued
        || !lastSeen || !absolute || !idle || assurance.value() > 4U
        || factors.value() > 7U || state.value() > 2U) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "PostgreSQL returned invalid session data.");
    }
    std::optional<foundation::Instant> revokedAt;
    if (PQgetisnull(result, row, 13) == 0) {
        auto revoked = parseInteger<std::int64_t>(field(result, row, 13));
        if (!revoked) return foundation::fail(revoked.error());
        revokedAt = foundation::Instant{foundation::Duration{revoked.value()}};
    }
    std::optional<std::string> userAgent;
    if (PQgetisnull(result, row, 14) == 0) userAgent = field(result, row, 14);
    std::optional<std::string> remoteAddress;
    if (PQgetisnull(result, row, 15) == 0) remoteAddress = field(result, row, 15);
    return session::Session::restore(
        session::SessionId{field(result, row, 0)},
        identity::core::IdentityId{field(result, row, 1)},
        identity::provider::ProviderId{field(result, row, 2)},
        static_cast<identity::provider::AssuranceLevel>(assurance.value()),
        identity::provider::AuthenticationStrength{
            static_cast<identity::provider::AuthenticationFactor>(factors.value()),
            field(result, row, 5) == "t"},
        static_cast<session::SessionState>(state.value()),
        foundation::Instant{foundation::Duration{authenticated.value()}},
        session::TokenDigest{digest.value()},
        foundation::Instant{foundation::Duration{issued.value()}},
        foundation::Instant{foundation::Duration{lastSeen.value()}},
        foundation::Instant{foundation::Duration{absolute.value()}},
        foundation::Duration{idle.value()}, revokedAt,
        std::move(userAgent), std::move(remoteAddress));
}

constexpr std::string_view kTransactionColumns =
    "id, provider, interaction, encode(nonce_digest, 'hex'), "
    "encode(binding_digest, 'hex'), correlation_id, state, created_at_ms, expires_at_ms";

[[nodiscard]] foundation::Result<identity::provider::AttributeMap>
metadata(PGconn* connection, std::string_view transactionId)
{
    ResultPointer result = execParams(connection,
        "SELECT key, value FROM openproof.authentication_transaction_metadata "
        "WHERE transaction_id = $1 ORDER BY key", {std::string{transactionId}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "read transaction metadata"));
    identity::provider::AttributeMap output;
    for (int row = 0; row < PQntuples(result.get()); ++row) {
        output.emplace(field(result.get(), row, 0), field(result.get(), row, 1));
    }
    return output;
}

[[nodiscard]] foundation::Result<identity::provider::AuthenticationTransaction>
transactionFromRow(PGconn* connection, PGresult* result, int row)
{
    if (PQnfields(result) != 9) return foundation::fail(foundation::ErrorCode::Internal,
                                                        "PostgreSQL returned an invalid transaction shape.");
    auto interaction = parseInteger<unsigned int>(field(result, row, 2));
    auto nonce = parseDigest(field(result, row, 3));
    auto binding = parseDigest(field(result, row, 4));
    auto state = parseInteger<unsigned int>(field(result, row, 6));
    auto created = parseInteger<std::int64_t>(field(result, row, 7));
    auto expires = parseInteger<std::int64_t>(field(result, row, 8));
    auto values = metadata(connection, field(result, row, 0));
    if (!interaction || !nonce || !binding || !state || !created || !expires || !values
        || interaction.value() > 4U || state.value() > 3U) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "PostgreSQL returned invalid transaction data.");
    }
    return identity::provider::AuthenticationTransaction::restore(
        identity::provider::TransactionId{field(result, row, 0)},
        identity::provider::ProviderId{field(result, row, 1)},
        static_cast<identity::provider::InteractionModel>(interaction.value()),
        nonce.value(), binding.value(),
        foundation::CorrelationId{field(result, row, 5)},
        static_cast<identity::provider::TransactionState>(state.value()),
        foundation::Instant{foundation::Duration{created.value()}},
        foundation::Instant{foundation::Duration{expires.value()}},
        std::move(values).value());
}

}

PoolConfig::PoolConfig(foundation::SecretString connectionString,
                       std::size_t connections, foundation::Duration acquireTimeout)
    : m_connectionString(std::move(connectionString)), m_connections(connections),
      m_acquireTimeout(acquireTimeout)
{
}

foundation::Result<PoolConfig> PoolConfig::create(
    foundation::SecretString connectionString, std::size_t connections,
    foundation::Duration acquireTimeout)
{
    if (connectionString.empty() || connections == 0U || connections > 256U
        || acquireTimeout <= foundation::Duration::zero()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The PostgreSQL pool configuration is invalid.");
    }
    return PoolConfig{std::move(connectionString), connections, acquireTimeout};
}

class ConnectionPool::Implementation final {
public:
    class Lease final {
    public:
        Lease() = default;
        Lease(Implementation& owner, PGconn* connection) : m_owner(&owner), m_connection(connection) {}
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& other) noexcept
            : m_owner(std::exchange(other.m_owner, nullptr)),
              m_connection(std::exchange(other.m_connection, nullptr)) {}
        Lease& operator=(Lease&&) = delete;
        ~Lease() { if (m_owner != nullptr) m_owner->release(m_connection); }
        [[nodiscard]] PGconn* get() const noexcept { return m_connection; }
    private:
        Implementation* m_owner{};
        PGconn* m_connection{};
    };

    static foundation::Result<std::unique_ptr<Implementation>> create(PoolConfig config)
    {
        auto implementation = std::unique_ptr<Implementation>{new Implementation{
            config.m_connections, config.m_acquireTimeout}};
        implementation->m_connections.reserve(config.m_connections);
        implementation->m_available.reserve(config.m_connections);
        for (std::size_t index = 0U; index < config.m_connections; ++index) {
            ConnectionPointer connection{PQconnectdb(config.m_connectionString.expose().c_str())};
            if (connection == nullptr || PQstatus(connection.get()) != CONNECTION_OK) {
                return foundation::fail(foundation::ErrorCode::Unavailable,
                                        "The PostgreSQL database is unavailable.",
                                        "A PostgreSQL pool connection could not be established.");
            }
            implementation->m_available.push_back(connection.get());
            implementation->m_connections.push_back(std::move(connection));
        }
        return implementation;
    }

    foundation::Result<Lease> acquire()
    {
        std::unique_lock<std::mutex> lock{m_mutex};
        if (!m_condition.wait_for(lock, m_acquireTimeout,
                                  [this] { return !m_available.empty(); })) {
            return foundation::fail(foundation::ErrorCode::Timeout,
                                    "Timed out waiting for a database connection.");
        }
        PGconn* connection = m_available.back();
        m_available.pop_back();
        return Lease{*this, connection};
    }

    [[nodiscard]] std::size_t size() const noexcept { return m_size; }

private:
    Implementation(std::size_t size, foundation::Duration timeout)
        : m_size(size), m_acquireTimeout(timeout) {}
    void release(PGconn* connection) noexcept
    {
        if (connection == nullptr) return;
        if (PQtransactionStatus(connection) != PQTRANS_IDLE) {
            PGresult* rolledBack = PQexec(connection, "ROLLBACK");
            if (rolledBack != nullptr) PQclear(rolledBack);
        }
        if (PQstatus(connection) != CONNECTION_OK) PQreset(connection);
        if (PQstatus(connection) != CONNECTION_OK) return;
        const std::lock_guard<std::mutex> guard{m_mutex};
        m_available.push_back(connection);
        m_condition.notify_one();
    }
    std::size_t m_size;
    foundation::Duration m_acquireTimeout;
    std::vector<ConnectionPointer> m_connections;
    std::vector<PGconn*> m_available;
    std::mutex m_mutex;
    std::condition_variable m_condition;
};

ConnectionPool::ConnectionPool(std::unique_ptr<Implementation> implementation)
    : m_implementation(std::move(implementation)) {}
ConnectionPool::~ConnectionPool() = default;

foundation::Result<std::unique_ptr<ConnectionPool>> ConnectionPool::create(PoolConfig config)
{
    auto implementation = Implementation::create(std::move(config));
    if (!implementation) return foundation::fail(implementation.error());
    return std::unique_ptr<ConnectionPool>{new ConnectionPool{std::move(implementation).value()}};
}

foundation::Status ConnectionPool::healthCheck()
{
    auto lease = m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = exec(lease->get(), "SELECT 1");
    if (!tuplesOk(result.get()) || PQntuples(result.get()) != 1) {
        return foundation::fail(databaseError(result.get(), "PostgreSQL health check"));
    }
    return foundation::ok();
}

std::size_t ConnectionPool::size() const noexcept { return m_implementation->size(); }

Migrator::Migrator(ConnectionPool& pool) : m_pool(&pool) {}

foundation::Result<MigrationReport> Migrator::applyDirectory(
    const std::filesystem::path& directory)
{
    std::error_code filesystemError;
    if (!std::filesystem::is_directory(directory, filesystemError) || filesystemError) {
        return foundation::fail(foundation::ErrorCode::NotFound,
                                "The migration directory was not found.");
    }
    std::vector<std::filesystem::path> files;
    for (std::filesystem::directory_iterator iterator{directory, filesystemError};
         !filesystemError && iterator != std::filesystem::directory_iterator{}; ++iterator) {
        if (iterator->is_regular_file() && iterator->path().extension() == ".sql") {
            files.push_back(iterator->path());
        }
    }
    if (filesystemError) return foundation::fail(foundation::ErrorCode::Internal,
                                                  "The migration directory could not be read.");
    std::ranges::sort(files);
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    ResultPointer bootstrap = exec(connection,
        "CREATE SCHEMA IF NOT EXISTS openproof;"
        "CREATE TABLE IF NOT EXISTS openproof.schema_migrations ("
        "version text PRIMARY KEY, checksum bytea NOT NULL CHECK (octet_length(checksum)=32),"
        "applied_at timestamptz NOT NULL DEFAULT clock_timestamp())");
    if (!commandOk(bootstrap.get())) return foundation::fail(databaseError(bootstrap.get(), "bootstrap migrations"));

    MigrationReport report;
    for (const auto& path : files) {
        std::ifstream stream{path, std::ios::binary};
        std::string sql{std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
        if (stream.bad() || sql.empty()) return foundation::fail(foundation::ErrorCode::Internal,
                                                                 "A migration file could not be read.");
        auto checksum = security::sha256(sql);
        if (!checksum) return foundation::fail(checksum.error());
        const std::string version = path.filename().string();
        const std::string hex = foundation::toHex(checksum.value());
        auto begun = beginTransaction(connection);
        if (!begun) return foundation::fail(begun.error());
        ResultPointer lock = exec(connection, "SELECT pg_advisory_xact_lock(1827364512)");
        if (!tuplesOk(lock.get())) { rollback(connection); return foundation::fail(databaseError(lock.get(), "lock migrations")); }
        ResultPointer existing = execParams(connection,
            "SELECT encode(checksum, 'hex') FROM openproof.schema_migrations WHERE version=$1",
            {version});
        if (!tuplesOk(existing.get())) { rollback(connection); return foundation::fail(databaseError(existing.get(), "read migration state")); }
        if (PQntuples(existing.get()) == 1) {
            if (field(existing.get(), 0, 0) != hex) {
                rollback(connection);
                return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                        "An applied migration file has changed.");
            }
            auto committed = commit(connection);
            if (!committed) return foundation::fail(committed.error());
            ++report.alreadyApplied;
            continue;
        }
        ResultPointer applied = exec(connection, sql);
        if (!commandOk(applied.get())) { rollback(connection); return foundation::fail(databaseError(applied.get(), "apply migration")); }
        ResultPointer recorded = execParams(connection,
            "INSERT INTO openproof.schema_migrations(version, checksum) VALUES($1, decode($2,'hex'))",
            {version, hex});
        if (!commandOk(recorded.get())) { rollback(connection); return foundation::fail(databaseError(recorded.get(), "record migration")); }
        auto committed = commit(connection);
        if (!committed) return foundation::fail(committed.error());
        ++report.applied;
    }
    return report;
}

PostgresCredentialRekeyer::PostgresCredentialRekeyer(ConnectionPool& pool)
    : m_pool(&pool)
{
}

foundation::Result<CredentialRekeyReport> PostgresCredentialRekeyer::rotateTotp(
    const security::AeadKey& currentKey, unsigned int currentVersion,
    const security::AeadKey& replacementKey, unsigned int replacementVersion,
    bool dryRun)
{
    if (currentVersion == 0U || replacementVersion <= currentVersion
        || replacementVersion > 2'147'483'647U) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "Credential key versions must increase monotonically.");
    }
    if (currentKey.matches(replacementKey)) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "The replacement credential key must use different key material.");
    }
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());
    auto failTransaction = [&](const foundation::Error& error)
        -> foundation::Result<CredentialRekeyReport> {
        rollback(connection);
        return foundation::fail(error);
    };

    ResultPointer isolated = exec(
        connection, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    if (!commandOk(isolated.get())) {
        return failTransaction(databaseError(
            isolated.get(), "set credential rekey isolation"));
    }
    ResultPointer advisory = exec(
        connection, "SELECT pg_advisory_xact_lock(7299730475761673316)");
    if (!tuplesOk(advisory.get())) {
        return failTransaction(databaseError(
            advisory.get(), "lock credential rekey"));
    }
    ResultPointer tableLock = exec(
        connection, "LOCK TABLE openproof.totp_credentials IN ACCESS EXCLUSIVE MODE");
    if (!commandOk(tableLock.get())) {
        return failTransaction(databaseError(
            tableLock.get(), "lock TOTP credentials"));
    }
    ResultPointer duplicate = execParams(
        connection,
        "SELECT 1 FROM openproof.credential_key_rotations "
        "WHERE purpose='totp' AND to_version=$1",
        {std::to_string(replacementVersion)});
    if (!tuplesOk(duplicate.get())) {
        return failTransaction(databaseError(
            duplicate.get(), "read credential rekey journal"));
    }
    if (PQntuples(duplicate.get()) != 0) {
        return failTransaction(foundation::Error{
            foundation::ErrorCode::AlreadyExists,
            "That credential key version was already committed."});
    }

    ResultPointer rows = exec(
        connection,
        "SELECT identity_id,encode(encrypted_seed,'hex'),key_version "
        "FROM openproof.totp_credentials ORDER BY identity_id FOR UPDATE");
    if (!tuplesOk(rows.get())) {
        return failTransaction(databaseError(rows.get(), "inventory TOTP credentials"));
    }

    CredentialRekeyReport report{0U, 0U, dryRun};
    for (int row = 0; row < PQntuples(rows.get()); ++row) {
        const std::string identityId = field(rows.get(), row, 0);
        const std::string encryptedHex = field(rows.get(), row, 1);
        auto version = parseInteger<unsigned int>(field(rows.get(), row, 2));
        auto envelope = foundation::fromHex(encryptedHex);
        if (!version || !envelope) {
            return failTransaction(foundation::Error{
                foundation::ErrorCode::Internal,
                "A persisted credential envelope is malformed."});
        }
        const std::string associatedData = "openproof/totp/v1:" + identityId;
        if (version.value() == replacementVersion) {
            auto validated = security::openAes256Gcm(
                replacementKey, envelope.value(), associatedData);
            if (!validated) return failTransaction(validated.error());
            ++report.alreadyCurrent;
            continue;
        }
        if (version.value() != currentVersion) {
            return failTransaction(foundation::Error{
                foundation::ErrorCode::FailedPrecondition,
                "A TOTP credential uses an unavailable key version."});
        }
        auto plaintext = security::openAes256Gcm(
            currentKey, envelope.value(), associatedData);
        if (!plaintext) return failTransaction(plaintext.error());
        auto replacement = security::sealAes256Gcm(
            replacementKey, plaintext.value(), associatedData);
        if (!replacement) return failTransaction(replacement.error());
        ResultPointer updated = execParams(
            connection,
            "UPDATE openproof.totp_credentials "
            "SET encrypted_seed=decode($2,'hex'),key_version=$3 "
            "WHERE identity_id=$1 AND key_version=$4 "
            "AND encrypted_seed=decode($5,'hex') RETURNING identity_id",
            {identityId, foundation::toHex(replacement.value()),
             std::to_string(replacementVersion), std::to_string(currentVersion),
             encryptedHex});
        if (!tuplesOk(updated.get())) {
            return failTransaction(databaseError(
                updated.get(), "replace TOTP credential envelope"));
        }
        if (PQntuples(updated.get()) != 1) {
            return failTransaction(foundation::Error{
                foundation::ErrorCode::Conflict,
                "A TOTP credential changed during the offline rekey operation."});
        }
        ++report.rekeyed;
    }

    if (dryRun) {
        rollback(connection);
        return report;
    }
    ResultPointer journal = execParams(
        connection,
        "INSERT INTO openproof.credential_key_rotations"
        "(purpose,from_version,to_version,rekeyed_rows,unchanged_rows,rotated_at_ms) "
        "VALUES('totp',$1,$2,$3,$4,"
        "(extract(epoch FROM clock_timestamp())*1000)::bigint)",
        {std::to_string(currentVersion), std::to_string(replacementVersion),
         std::to_string(report.rekeyed), std::to_string(report.alreadyCurrent)});
    if (!commandOk(journal.get())) {
        return failTransaction(databaseError(
            journal.get(), "record credential rekey"));
    }
    auto committed = commit(connection);
    if (!committed) return foundation::fail(committed.error());
    return report;
}

PostgresMasterKeyRotator::PostgresMasterKeyRotator(ConnectionPool& pool)
    : m_pool(&pool)
{
}

foundation::Status PostgresMasterKeyRotator::verifyActive(
    unsigned int version, const security::Sha256Digest& fingerprint) const
{
    if (version == 0U) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "The active master key version is invalid.");
    }
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer head = exec(
        lease->get(),
        "SELECT to_version,encode(to_fingerprint,'hex') "
        "FROM openproof.master_key_rotations ORDER BY sequence DESC LIMIT 1");
    if (!tuplesOk(head.get())) {
        return foundation::fail(databaseError(
            head.get(), "verify active master-key journal"));
    }
    if (PQntuples(head.get()) == 0) {
        return version == 1U ? foundation::ok() : foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "The configured master key version has no committed rotation journal.");
    }
    auto journalVersion = parseInteger<unsigned int>(field(head.get(), 0, 0));
    auto journalBytes = foundation::fromHex(field(head.get(), 0, 1));
    if (!journalVersion || !journalBytes
        || journalBytes->size() != fingerprint.size()
        || journalVersion.value() != version
        || !security::constantTimeEquals(
            std::span<const std::byte>{journalBytes->data(), journalBytes->size()},
            std::span<const std::byte>{fingerprint.data(), fingerprint.size()})) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "The configured master key does not match the committed rotation journal.");
    }
    return foundation::ok();
}

foundation::Result<MasterKeyRotationReport> PostgresMasterKeyRotator::rotate(
    unsigned int currentVersion, const security::Sha256Digest& currentFingerprint,
    unsigned int replacementVersion,
    const security::Sha256Digest& replacementFingerprint, bool dryRun)
{
    if (currentVersion == 0U || replacementVersion <= currentVersion
        || replacementVersion > 2'147'483'647U) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "Master key versions must increase monotonically.");
    }
    if (security::constantTimeEquals(currentFingerprint, replacementFingerprint)) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "The replacement master key must use different key material.");
    }
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());
    auto failTransaction = [&](const foundation::Error& error)
        -> foundation::Result<MasterKeyRotationReport> {
        rollback(connection);
        return foundation::fail(error);
    };
    ResultPointer isolated = exec(
        connection, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    if (!commandOk(isolated.get())) {
        return failTransaction(databaseError(
            isolated.get(), "set master-key rotation isolation"));
    }
    ResultPointer advisory = exec(
        connection, "SELECT pg_advisory_xact_lock(7299730475761673317)");
    if (!tuplesOk(advisory.get())) {
        return failTransaction(databaseError(
            advisory.get(), "lock master-key rotation"));
    }
    ResultPointer locked = exec(
        connection,
        "LOCK TABLE openproof.authentication_transactions,openproof.sessions,"
        "openproof.account_verification_challenges,"
        "openproof.passkey_registration_ceremonies,"
        "openproof.oauth_authorization_codes,openproof.oauth_token_families,"
        "openproof.oauth_device_authorizations,"
        "openproof.oauth_pushed_authorization_requests IN ACCESS EXCLUSIVE MODE");
    if (!commandOk(locked.get())) {
        return failTransaction(databaseError(
            locked.get(), "lock master-derived state"));
    }
    ResultPointer duplicate = execParams(
        connection,
        "SELECT 1 FROM openproof.master_key_rotations WHERE to_version=$1",
        {std::to_string(replacementVersion)});
    if (!tuplesOk(duplicate.get())) {
        return failTransaction(databaseError(
            duplicate.get(), "read master-key rotation journal"));
    }
    if (PQntuples(duplicate.get()) != 0) {
        return failTransaction(foundation::Error{
            foundation::ErrorCode::AlreadyExists,
            "That master key version was already committed."});
    }
    ResultPointer previous = exec(
        connection,
        "SELECT to_version,encode(to_fingerprint,'hex') "
        "FROM openproof.master_key_rotations ORDER BY sequence DESC LIMIT 1");
    if (!tuplesOk(previous.get())) {
        return failTransaction(databaseError(
            previous.get(), "read previous master-key rotation"));
    }
    if (PQntuples(previous.get()) == 1) {
        auto priorVersion = parseInteger<unsigned int>(field(previous.get(), 0, 0));
        const auto priorFingerprint = foundation::fromHex(field(previous.get(), 0, 1));
        if (!priorVersion || !priorFingerprint
            || priorFingerprint->size() != currentFingerprint.size()
            || priorVersion.value() != currentVersion
            || !security::constantTimeEquals(
                std::span<const std::byte>{priorFingerprint->data(), priorFingerprint->size()},
                std::span<const std::byte>{currentFingerprint.data(), currentFingerprint.size()})) {
            return failTransaction(foundation::Error{
                foundation::ErrorCode::FailedPrecondition,
                "The configured master key does not match the rotation journal head."});
        }
    }

    const auto remove = [&](std::string_view sql, std::string_view operation)
        -> foundation::Result<std::size_t> {
        ResultPointer result = exec(connection, sql);
        if (!commandOk(result.get())) {
            return foundation::fail(databaseError(result.get(), operation));
        }
        const char* affected = PQcmdTuples(result.get());
        if (affected == nullptr || *affected == '\0') {
            return foundation::fail(
                foundation::ErrorCode::Internal,
                "PostgreSQL did not report the invalidated state count.");
        }
        return parseInteger<std::size_t>(affected);
    };

    MasterKeyRotationReport report{};
    report.dryRun = dryRun;
    auto authenticationTransactions = remove(
        "DELETE FROM openproof.authentication_transactions",
        "invalidate authentication transactions");
    auto sessions = remove(
        "DELETE FROM openproof.sessions", "invalidate sessions");
    auto accountChallenges = remove(
        "DELETE FROM openproof.account_verification_challenges",
        "invalidate account verification challenges");
    auto passkeyRegistrations = remove(
        "DELETE FROM openproof.passkey_registration_ceremonies",
        "invalidate passkey registration ceremonies");
    auto authorizationCodes = remove(
        "DELETE FROM openproof.oauth_authorization_codes",
        "invalidate authorization codes");
    auto tokenFamilies = remove(
        "DELETE FROM openproof.oauth_token_families",
        "invalidate OAuth token families");
    auto deviceAuthorizations = remove(
        "DELETE FROM openproof.oauth_device_authorizations",
        "invalidate device authorizations");
    auto pushedRequests = remove(
        "DELETE FROM openproof.oauth_pushed_authorization_requests",
        "invalidate pushed authorization requests");
    if (!authenticationTransactions || !sessions || !accountChallenges
        || !passkeyRegistrations
        || !authorizationCodes || !tokenFamilies || !deviceAuthorizations
        || !pushedRequests) {
        if (!authenticationTransactions) return failTransaction(authenticationTransactions.error());
        if (!sessions) return failTransaction(sessions.error());
        if (!accountChallenges) return failTransaction(accountChallenges.error());
        if (!passkeyRegistrations) return failTransaction(passkeyRegistrations.error());
        if (!authorizationCodes) return failTransaction(authorizationCodes.error());
        if (!tokenFamilies) return failTransaction(tokenFamilies.error());
        if (!deviceAuthorizations) return failTransaction(deviceAuthorizations.error());
        return failTransaction(pushedRequests.error());
    }
    report.authenticationTransactions = authenticationTransactions.value();
    report.sessions = sessions.value();
    report.accountChallenges = accountChallenges.value();
    report.passkeyRegistrations = passkeyRegistrations.value();
    report.authorizationCodes = authorizationCodes.value();
    report.tokenFamilies = tokenFamilies.value();
    report.deviceAuthorizations = deviceAuthorizations.value();
    report.pushedRequests = pushedRequests.value();
    if (dryRun) {
        rollback(connection);
        return report;
    }
    ResultPointer journal = execParams(
        connection,
        "INSERT INTO openproof.master_key_rotations"
        "(from_version,to_version,from_fingerprint,to_fingerprint,"
        "authentication_transactions,sessions,account_challenges,"
        "passkey_registrations,authorization_codes,token_families,"
        "device_authorizations,pushed_requests,"
        "rotated_at_ms) VALUES($1,$2,decode($3,'hex'),decode($4,'hex'),"
        "$5,$6,$7,$8,$9,$10,$11,$12,"
        "(extract(epoch FROM clock_timestamp())*1000)::bigint)",
        {std::to_string(currentVersion), std::to_string(replacementVersion),
         foundation::toHex(currentFingerprint), foundation::toHex(replacementFingerprint),
         std::to_string(report.authenticationTransactions),
         std::to_string(report.sessions), std::to_string(report.accountChallenges),
         std::to_string(report.passkeyRegistrations),
         std::to_string(report.authorizationCodes),
         std::to_string(report.tokenFamilies),
         std::to_string(report.deviceAuthorizations),
         std::to_string(report.pushedRequests)});
    if (!commandOk(journal.get())) {
        return failTransaction(databaseError(
            journal.get(), "record master-key rotation"));
    }
    auto committed = commit(connection);
    if (!committed) return foundation::fail(committed.error());
    return report;
}

PostgresSessionRepository::PostgresSessionRepository(ConnectionPool& pool) : m_pool(&pool) {}

foundation::Status PostgresSessionRepository::add(session::Session value)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    const auto factorValue = static_cast<unsigned int>(value.strength().factors());
    ResultPointer result = execParams(lease->get(),
        "INSERT INTO openproof.sessions(id,identity_id,provider,assurance,factors,"
        "phishing_resistant,state,token_digest,authenticated_at_ms,issued_at_ms,"
        "last_seen_at_ms,absolute_expires_at_ms,idle_timeout_ms,revoked_at_ms,"
        "user_agent,remote_address) "
        "VALUES($1,$2,$3,$4,$5,$6,$7,decode($8,'hex'),$9,$10,$11,$12,$13,NULL,"
        "NULLIF($14,''),NULLIF($15,''))",
        {std::string{value.id().value()}, std::string{value.identity().value()},
         std::string{value.provider().value()},
         std::to_string(static_cast<unsigned int>(value.assurance())),
         std::to_string(factorValue), value.strength().isPhishingResistant() ? "true" : "false",
         std::to_string(static_cast<unsigned int>(value.state())),
         foundation::toHex(value.tokenDigest().bytes()), instant(value.authenticatedAt()),
         instant(value.issuedAt()), instant(value.lastSeenAt()), instant(value.absoluteExpiresAt()),
         integer(value.idleTimeout().count()),
         value.userAgent().value_or(""), value.remoteAddress().value_or("")});
    if (!commandOk(result.get())) return foundation::fail(databaseError(result.get(), "insert session"));
    return foundation::ok();
}

foundation::Result<session::Session> PostgresSessionRepository::use(
    const session::TokenDigest& token, foundation::Instant now)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    const std::string sql = "UPDATE openproof.sessions SET "
        "state=CASE WHEN $2::bigint>=absolute_expires_at_ms OR "
        "$2::bigint>=last_seen_at_ms+idle_timeout_ms THEN 2 ELSE state END, "
        "last_seen_at_ms=CASE WHEN $2::bigint<absolute_expires_at_ms AND "
        "$2::bigint<last_seen_at_ms+idle_timeout_ms THEN $2::bigint ELSE last_seen_at_ms END "
        "WHERE token_digest=decode($1,'hex') AND state=0 RETURNING " + std::string{kSessionColumns};
    ResultPointer result = execParams(lease->get(), sql,
        {foundation::toHex(token.bytes()), instant(now)});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "use session"));
    if (PQntuples(result.get()) != 1) return foundation::fail(authenticationFailure("Session is unknown or inactive."));
    auto restored = sessionFromRow(result.get(), 0);
    if (!restored) return foundation::fail(restored.error());
    if (restored->state() != session::SessionState::Active) {
        return foundation::fail(authenticationFailure("Session deadline passed."));
    }
    return restored;
}

foundation::Status PostgresSessionRepository::rotate(
    const session::SessionId& id, const session::TokenDigest& expected,
    session::TokenDigest replacement, foundation::Instant now)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "UPDATE openproof.sessions SET token_digest=decode($3,'hex'),last_seen_at_ms=$4 "
        "WHERE id=$1 AND token_digest=decode($2,'hex') AND state=0 "
        "AND $4::bigint<absolute_expires_at_ms AND $4::bigint<last_seen_at_ms+idle_timeout_ms "
        "RETURNING id", {std::string{id.value()}, foundation::toHex(expected.bytes()),
                          foundation::toHex(replacement.bytes()), instant(now)});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "rotate session"));
    return PQntuples(result.get()) == 1 ? foundation::ok()
        : foundation::fail(authenticationFailure("Session rotation was refused."));
}

foundation::Status PostgresSessionRepository::revoke(
    const session::SessionId& id, foundation::Instant now)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "UPDATE openproof.sessions SET state=1,revoked_at_ms=$2 WHERE id=$1 AND state=0 RETURNING id",
        {std::string{id.value()}, instant(now)});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "revoke session"));
    if (PQntuples(result.get()) == 1) return foundation::ok();
    ResultPointer state = execParams(lease->get(), "SELECT state FROM openproof.sessions WHERE id=$1",
                                     {std::string{id.value()}});
    if (!tuplesOk(state.get())) return foundation::fail(databaseError(state.get(), "read session state"));
    if (PQntuples(state.get()) == 0) return foundation::fail(foundation::ErrorCode::NotFound, "That session was not found.");
    return field(state.get(), 0, 0) == "1" ? foundation::ok()
        : foundation::fail(foundation::ErrorCode::FailedPrecondition,
                           "An expired session cannot be revoked.");
}

foundation::Result<std::size_t> PostgresSessionRepository::revokeAll(
    const identity::core::IdentityId& identity, foundation::Instant now)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "UPDATE openproof.sessions SET state=1,revoked_at_ms=$2 WHERE identity_id=$1 AND state=0",
        {std::string{identity.value()}, instant(now)});
    if (!commandOk(result.get())) return foundation::fail(databaseError(result.get(), "revoke identity sessions"));
    auto count = parseInteger<std::size_t>(PQcmdTuples(result.get()));
    return count ? count : foundation::Result<std::size_t>{foundation::fail(count.error())};
}

foundation::Result<std::optional<session::Session>> PostgresSessionRepository::find(
    const session::SessionId& id) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT " + std::string{kSessionColumns} + " FROM openproof.sessions WHERE id=$1",
        {std::string{id.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "find session"));
    if (PQntuples(result.get()) == 0) return std::optional<session::Session>{};
    auto value = sessionFromRow(result.get(), 0);
    if (!value) return foundation::fail(value.error());
    return std::optional<session::Session>{std::move(value).value()};
}

foundation::Result<std::vector<session::Session>>
PostgresSessionRepository::list(const identity::core::IdentityId& identity) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT " + std::string{kSessionColumns}
        + " FROM openproof.sessions WHERE identity_id=$1 ORDER BY last_seen_at_ms DESC",
        {std::string{identity.value()}});
    if (!tuplesOk(result.get())) {
        return foundation::fail(databaseError(result.get(), "list identity sessions"));
    }
    std::vector<session::Session> values;
    values.reserve(static_cast<std::size_t>(PQntuples(result.get())));
    for (int row = 0; row < PQntuples(result.get()); ++row) {
        auto value = sessionFromRow(result.get(), row);
        if (!value) return foundation::fail(value.error());
        values.emplace_back(std::move(value).value());
    }
    return values;
}

std::size_t PostgresSessionRepository::purgeExpired(foundation::Instant now)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return 0U;
    ResultPointer result = execParams(lease->get(),
        "DELETE FROM openproof.sessions WHERE $1::bigint>=absolute_expires_at_ms "
        "OR $1::bigint>=last_seen_at_ms+idle_timeout_ms", {instant(now)});
    if (!commandOk(result.get())) return 0U;
    auto count = parseInteger<std::size_t>(PQcmdTuples(result.get()));
    return count ? count.value() : 0U;
}

std::size_t PostgresSessionRepository::size() const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return 0U;
    ResultPointer result = exec(lease->get(), "SELECT count(*) FROM openproof.sessions");
    if (!tuplesOk(result.get()) || PQntuples(result.get()) != 1) return 0U;
    auto count = parseInteger<std::size_t>(field(result.get(), 0, 0));
    return count ? count.value() : 0U;
}

PostgresAuthenticationTransactionStore::PostgresAuthenticationTransactionStore(ConnectionPool& pool)
    : m_pool(&pool) {}

foundation::Status PostgresAuthenticationTransactionStore::begin(
    identity::provider::AuthenticationTransaction transaction)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());
    ResultPointer result = execParams(connection,
        "INSERT INTO openproof.authentication_transactions(id,provider,interaction,nonce_digest,"
        "binding_digest,correlation_id,state,created_at_ms,expires_at_ms) "
        "VALUES($1,$2,$3,decode($4,'hex'),decode($5,'hex'),$6,$7,$8,$9)",
        {std::string{transaction.id().value()}, std::string{transaction.provider().value()},
         std::to_string(static_cast<unsigned int>(transaction.interactionModel())),
         foundation::toHex(transaction.nonceDigest()), foundation::toHex(transaction.binding()),
         std::string{transaction.correlation().value()},
         std::to_string(static_cast<unsigned int>(transaction.state())),
         instant(transaction.createdAt()), instant(transaction.expiresAt())});
    if (!commandOk(result.get())) { rollback(connection); return foundation::fail(databaseError(result.get(), "insert authentication transaction")); }
    for (const auto& [key, value] : transaction.metadata()) {
        ResultPointer metadataResult = execParams(connection,
            "INSERT INTO openproof.authentication_transaction_metadata(transaction_id,key,value) VALUES($1,$2,$3)",
            {std::string{transaction.id().value()}, key, value});
        if (!commandOk(metadataResult.get())) { rollback(connection); return foundation::fail(databaseError(metadataResult.get(), "insert transaction metadata")); }
    }
    return commit(connection);
}

foundation::Result<identity::provider::AuthenticationTransaction>
PostgresAuthenticationTransactionStore::consume(
    const identity::provider::TransactionId& id,
    const foundation::SecretString& presentedNonce,
    const identity::provider::BindingDigest& presentedBinding,
    foundation::Instant now)
{
    auto nonce = security::sha256(presentedNonce.expose());
    if (!nonce) return foundation::fail(nonce.error());
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());
    const std::string sql = "UPDATE openproof.authentication_transactions SET state=CASE "
        "WHEN expires_at_ms<=$4::bigint THEN 3 WHEN nonce_digest<>decode($2,'hex') "
        "OR binding_digest<>decode($3,'hex') THEN 2 ELSE 1 END "
        "WHERE id=$1 AND state=0 RETURNING " + std::string{kTransactionColumns};
    ResultPointer result = execParams(connection, sql,
        {std::string{id.value()}, foundation::toHex(nonce.value()),
         foundation::toHex(presentedBinding), instant(now)});
    if (!tuplesOk(result.get())) { rollback(connection); return foundation::fail(databaseError(result.get(), "consume authentication transaction")); }
    if (PQntuples(result.get()) != 1) { rollback(connection); return foundation::fail(authenticationFailure("Transaction is unknown or no longer pending.")); }
    auto restored = transactionFromRow(connection, result.get(), 0);
    if (!restored) { rollback(connection); return foundation::fail(restored.error()); }
    auto committed = commit(connection);
    if (!committed) return foundation::fail(committed.error());
    if (restored->state() == identity::provider::TransactionState::Expired) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "This authentication request has expired.");
    }
    if (restored->state() != identity::provider::TransactionState::Consumed) {
        return foundation::fail(authenticationFailure("Transaction verification failed."));
    }
    return restored;
}

foundation::Result<std::optional<identity::provider::AuthenticationTransaction>>
PostgresAuthenticationTransactionStore::find(const identity::provider::TransactionId& id) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    const std::string sql = "SELECT " + std::string{kTransactionColumns}
        + " FROM openproof.authentication_transactions WHERE id=$1";
    ResultPointer result = execParams(lease->get(), sql, {std::string{id.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "find authentication transaction"));
    if (PQntuples(result.get()) == 0) return std::optional<identity::provider::AuthenticationTransaction>{};
    auto value = transactionFromRow(lease->get(), result.get(), 0);
    if (!value) return foundation::fail(value.error());
    return std::optional<identity::provider::AuthenticationTransaction>{std::move(value).value()};
}

std::size_t PostgresAuthenticationTransactionStore::purgeExpired(foundation::Instant now)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return 0U;
    ResultPointer result = execParams(lease->get(),
        "DELETE FROM openproof.authentication_transactions WHERE expires_at_ms<=$1",
        {instant(now)});
    if (!commandOk(result.get())) return 0U;
    auto count = parseInteger<std::size_t>(PQcmdTuples(result.get()));
    return count ? count.value() : 0U;
}

std::size_t PostgresAuthenticationTransactionStore::size() const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return 0U;
    ResultPointer result = exec(lease->get(),
        "SELECT count(*) FROM openproof.authentication_transactions");
    if (!tuplesOk(result.get()) || PQntuples(result.get()) != 1) return 0U;
    auto count = parseInteger<std::size_t>(field(result.get(), 0, 0));
    return count ? count.value() : 0U;
}

PostgresRecoveryCodeRepository::PostgresRecoveryCodeRepository(ConnectionPool& pool)
    : m_pool(&pool) {}

foundation::Status PostgresRecoveryCodeRepository::replace(
    const identity::core::IdentityId& identity,
    std::vector<credentials::RecoveryCodeDigest> digests)
{
    if (identity.empty() || digests.size() > 64U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The recovery-code replacement is invalid.");
    }
    std::ranges::sort(digests);
    if (std::ranges::adjacent_find(digests) != digests.end()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Recovery-code digests must be unique.");
    }
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());
    ResultPointer removed = execParams(connection,
        "DELETE FROM openproof.recovery_codes WHERE identity_id=$1",
        {std::string{identity.value()}});
    if (!commandOk(removed.get())) {
        rollback(connection);
        return foundation::fail(databaseError(removed.get(), "replace recovery codes"));
    }
    for (const auto& digest : digests) {
        ResultPointer inserted = execParams(connection,
            "INSERT INTO openproof.recovery_codes(identity_id,code_digest,issued_at_ms) "
            "VALUES($1,decode($2,'hex'),(extract(epoch FROM clock_timestamp())*1000)::bigint)",
            {std::string{identity.value()}, foundation::toHex(digest)});
        if (!commandOk(inserted.get())) {
            rollback(connection);
            return foundation::fail(databaseError(inserted.get(), "insert recovery code"));
        }
    }
    return commit(connection);
}

foundation::Status PostgresRecoveryCodeRepository::consume(
    const identity::core::IdentityId& identity,
    const credentials::RecoveryCodeDigest& digest)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "DELETE FROM openproof.recovery_codes WHERE identity_id=$1 "
        "AND code_digest=decode($2,'hex') RETURNING identity_id",
        {std::string{identity.value()}, foundation::toHex(digest)});
    if (!tuplesOk(result.get())) {
        return foundation::fail(databaseError(result.get(), "consume recovery code"));
    }
    return PQntuples(result.get()) == 1 ? foundation::ok()
        : foundation::fail(authenticationFailure("Recovery code is unknown or already used."));
}

foundation::Result<std::size_t> PostgresRecoveryCodeRepository::remaining(
    const identity::core::IdentityId& identity) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT count(*) FROM openproof.recovery_codes WHERE identity_id=$1",
        {std::string{identity.value()}});
    if (!tuplesOk(result.get()) || PQntuples(result.get()) != 1) {
        return foundation::fail(databaseError(result.get(), "count recovery codes"));
    }
    return parseInteger<std::size_t>(field(result.get(), 0, 0));
}

namespace {

[[nodiscard]] foundation::Result<identity::core::Identity>
identityFromRow(PGresult* result, int row)
{
    auto kind = parseInteger<unsigned int>(field(result, row, 1));
    auto status = parseInteger<unsigned int>(field(result, row, 2));
    auto created = parseInteger<std::int64_t>(field(result, row, 3));
    if (!kind || !status || !created || kind.value() > 3U || status.value() > 5U) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "PostgreSQL returned invalid identity data.");
    }
    auto value = identity::core::Identity::create(
        identity::core::IdentityId{field(result, row, 0)},
        static_cast<identity::core::SubjectKind>(kind.value()),
        foundation::Instant{foundation::Duration{created.value()}});
    if (!value) return foundation::fail(value.error());
    if (status.value() != static_cast<unsigned int>(identity::core::IdentityStatus::Active)) {
        auto changed = value->changeStatus(
            static_cast<identity::core::IdentityStatus>(status.value()));
        if (!changed) return foundation::fail(changed.error());
    }
    return value;
}

[[nodiscard]] foundation::Result<organization::Organization>
organizationFromRow(PGresult* result, int row)
{
    auto state = parseInteger<unsigned int>(field(result, row, 2));
    auto created = parseInteger<std::int64_t>(field(result, row, 3));
    if (!state || !created || state.value() > 2U) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "PostgreSQL returned invalid organization data.");
    }
    auto value = organization::Organization::create(
        organization::OrganizationId{field(result, row, 0)}, field(result, row, 1),
        foundation::Instant{foundation::Duration{created.value()}});
    if (!value) return foundation::fail(value.error());
    if (state.value() != static_cast<unsigned int>(organization::OrganizationStatus::Active)) {
        auto changed = value->changeStatus(
            static_cast<organization::OrganizationStatus>(state.value()));
        if (!changed) return foundation::fail(changed.error());
    }
    return value;
}

[[nodiscard]] foundation::Result<organization::Membership>
membershipFromRow(PGconn* connection, PGresult* result, int row)
{
    auto state = parseInteger<unsigned int>(field(result, row, 2));
    auto invited = parseInteger<std::int64_t>(field(result, row, 3));
    if (!state || !invited || state.value() > 3U) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "PostgreSQL returned invalid membership data.");
    }
    organization::OrganizationId organizationId{field(result, row, 0)};
    organization::IdentityId identityId{field(result, row, 1)};
    auto value = organization::Membership::invite(
        organizationId, identityId,
        foundation::Instant{foundation::Duration{invited.value()}});
    if (!value) return foundation::fail(value.error());
    ResultPointer roles = execParams(connection,
        "SELECT role FROM openproof.membership_roles "
        "WHERE organization_id=$1 AND identity_id=$2 ORDER BY role",
        {std::string{organizationId.value()}, std::string{identityId.value()}});
    if (!tuplesOk(roles.get())) {
        return foundation::fail(databaseError(roles.get(), "read membership roles"));
    }
    if (state.value() == static_cast<unsigned int>(organization::MembershipState::Removed)
        && PQntuples(roles.get()) != 0) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "A removed PostgreSQL membership retained roles.");
    }
    for (int role = 0; role < PQntuples(roles.get()); ++role) {
        auto granted = value->grantRole(organization::Role{field(roles.get(), role, 0)});
        if (!granted) return foundation::fail(granted.error());
    }
    if (state.value() >= static_cast<unsigned int>(organization::MembershipState::Active)) {
        auto accepted = value->accept();
        if (!accepted) return foundation::fail(accepted.error());
    }
    if (state.value() == static_cast<unsigned int>(organization::MembershipState::Suspended)) {
        auto suspended = value->suspend();
        if (!suspended) return foundation::fail(suspended.error());
    } else if (state.value() == static_cast<unsigned int>(organization::MembershipState::Removed)) {
        auto removed = value->remove();
        if (!removed) return foundation::fail(removed.error());
    }
    return value;
}

}

PostgresIdentityRepository::PostgresIdentityRepository(ConnectionPool& pool) : m_pool(&pool) {}

foundation::Status PostgresIdentityRepository::add(
    const identity::core::OrganizationId& organization, identity::core::Identity value)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) "
        "VALUES($1,$2,$3,$4,$5)",
        {std::string{value.id().value()}, std::string{organization.value()},
         std::to_string(static_cast<unsigned int>(value.kind())),
         std::to_string(static_cast<unsigned int>(value.status())), instant(value.createdAt())});
    return commandOk(result.get()) ? foundation::ok()
                                   : foundation::fail(databaseError(result.get(), "insert identity"));
}

foundation::Result<std::optional<identity::core::Identity>>
PostgresIdentityRepository::findById(const identity::core::OrganizationId& organization,
                                     const identity::core::IdentityId& id) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT id,kind,status,created_at_ms FROM openproof.identities "
        "WHERE organization_id=$1 AND id=$2",
        {std::string{organization.value()}, std::string{id.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "find identity"));
    if (PQntuples(result.get()) == 0) return std::optional<identity::core::Identity>{};
    auto value = identityFromRow(result.get(), 0);
    if (!value) return foundation::fail(value.error());
    return std::optional<identity::core::Identity>{std::move(value).value()};
}

foundation::Status PostgresIdentityRepository::changeStatus(
    const identity::core::OrganizationId& organization,
    const identity::core::IdentityId& id, identity::core::IdentityStatus status)
{
    auto current = findById(organization, id);
    if (!current) return foundation::fail(current.error());
    if (!current->has_value()) return foundation::fail(foundation::ErrorCode::NotFound);
    const auto previous = current->value().status();
    auto transition = current->value().changeStatus(status);
    if (!transition) return foundation::fail(transition.error());
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "UPDATE openproof.identities SET status=$3 WHERE organization_id=$1 AND id=$2 "
        "AND status=$4 RETURNING id",
        {std::string{organization.value()}, std::string{id.value()},
         std::to_string(static_cast<unsigned int>(status)),
         std::to_string(static_cast<unsigned int>(previous))});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "change identity status"));
    return PQntuples(result.get()) == 1 ? foundation::ok()
        : foundation::fail(foundation::ErrorCode::Conflict,
                           "The identity changed concurrently.");
}

foundation::Result<std::vector<identity::core::IdentityId>>
PostgresIdentityRepository::idsOfKind(
    const identity::core::OrganizationId& organization,
    identity::core::SubjectKind kind) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT id FROM openproof.identities WHERE organization_id=$1 AND kind=$2 ORDER BY id",
        {std::string{organization.value()}, std::to_string(static_cast<unsigned int>(kind))});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "list identities"));
    std::vector<identity::core::IdentityId> output;
    for (int row = 0; row < PQntuples(result.get()); ++row) output.emplace_back(field(result.get(), row, 0));
    return output;
}

foundation::Result<std::size_t> PostgresIdentityRepository::countIn(
    const identity::core::OrganizationId& organization) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT count(*) FROM openproof.identities WHERE organization_id=$1",
        {std::string{organization.value()}});
    if (!tuplesOk(result.get()) || PQntuples(result.get()) != 1) {
        return foundation::fail(databaseError(result.get(), "count identities"));
    }
    return parseInteger<std::size_t>(field(result.get(), 0, 0));
}

PostgresExternalIdentityDirectory::PostgresExternalIdentityDirectory(ConnectionPool& pool)
    : m_pool(&pool) {}

foundation::Status PostgresExternalIdentityDirectory::attach(
    const identity::core::IdentityLink& link)
{
    if (link.state() != identity::core::LinkState::Linked) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "This account link is not complete.");
    }
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    const auto optionalText = [](const std::optional<std::string>& value) {
        return value.value_or(std::string{});
    };
    ResultPointer result = execParams(lease->get(),
        "INSERT INTO openproof.external_identities("
        "provider,external_subject,identity_id,linked_at_ms,display_name,preferred_username,picture_url) "
        "VALUES($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),NULLIF($7,'')) "
        "ON CONFLICT(provider,external_subject) DO UPDATE SET "
        "identity_id=EXCLUDED.identity_id,display_name=COALESCE(EXCLUDED.display_name,openproof.external_identities.display_name),"
        "preferred_username=COALESCE(EXCLUDED.preferred_username,openproof.external_identities.preferred_username),"
        "picture_url=COALESCE(EXCLUDED.picture_url,openproof.external_identities.picture_url) "
        "WHERE openproof.external_identities.identity_id=EXCLUDED.identity_id",
        {std::string{link.external().providerId().value()},
         std::string{link.external().subject().value()}, std::string{link.owner().value()},
         instant(link.requestedAt()), optionalText(link.external().displayName()),
         optionalText(link.external().preferredUsername()), optionalText(link.external().pictureUrl())});
    if (!commandOk(result.get())) return foundation::fail(databaseError(result.get(), "attach external identity"));
    return std::string_view{PQcmdTuples(result.get())} == "1" ? foundation::ok()
        : foundation::fail(foundation::ErrorCode::Conflict,
                           "That account is already connected to a different identity.");
}

foundation::Result<std::optional<identity::core::IdentityId>>
PostgresExternalIdentityDirectory::ownerOf(
    const identity::core::ExternalIdentityRef& external) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT identity_id FROM openproof.external_identities WHERE provider=$1 AND external_subject=$2",
        {std::string{external.providerId().value()}, std::string{external.subject().value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "find external identity"));
    if (PQntuples(result.get()) == 0) return std::optional<identity::core::IdentityId>{};
    return std::optional<identity::core::IdentityId>{identity::core::IdentityId{field(result.get(), 0, 0)}};
}

foundation::Status PostgresExternalIdentityDirectory::detach(
    const identity::core::ExternalIdentityRef& external,
    const identity::core::IdentityId& expectedOwner)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "DELETE FROM openproof.external_identities WHERE provider=$1 AND external_subject=$2 "
        "AND identity_id=$3 RETURNING identity_id",
        {std::string{external.providerId().value()}, std::string{external.subject().value()},
         std::string{expectedOwner.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "detach external identity"));
    if (PQntuples(result.get()) == 1) return foundation::ok();
    auto owner = ownerOf(external);
    if (!owner) return foundation::fail(owner.error());
    return owner->has_value()
        ? foundation::fail(foundation::ErrorCode::PermissionDenied)
        : foundation::fail(foundation::ErrorCode::NotFound);
}

foundation::Status
PostgresExternalIdentityDirectory::detachIfAnotherAuthenticationMethod(
    const identity::core::ExternalIdentityRef& external,
    const identity::core::IdentityId& expectedOwner,
    const std::vector<identity::provider::ProviderId>& authenticationProviders)
{
    if (authenticationProviders.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Authentication providers are required.");
    }
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) return begun;
    const auto failTransaction = [&](foundation::Error error) -> foundation::Status {
        rollback(connection);
        return foundation::fail(std::move(error));
    };
    ResultPointer locked = execParams(
        connection,
        "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 684271993))",
        {std::string{expectedOwner.value()}});
    if (!tuplesOk(locked.get())) {
        return failTransaction(databaseError(
            locked.get(), "lock external identity methods"));
    }
    ResultPointer owner = execParams(
        connection,
        "SELECT identity_id FROM openproof.external_identities "
        "WHERE provider=$1 AND external_subject=$2",
        {std::string{external.providerId().value()},
         std::string{external.subject().value()}});
    if (!tuplesOk(owner.get())) {
        return failTransaction(databaseError(owner.get(), "find external identity"));
    }
    if (PQntuples(owner.get()) == 0) {
        return failTransaction(foundation::Error{foundation::ErrorCode::NotFound});
    }
    if (field(owner.get(), 0, 0) != expectedOwner.value()) {
        return failTransaction(foundation::Error{foundation::ErrorCode::PermissionDenied});
    }

    std::string countSql =
        "SELECT count(*) FROM openproof.external_identities WHERE identity_id=$1 "
        "AND provider IN (";
    std::vector<std::string> countParameters{std::string{expectedOwner.value()}};
    countParameters.reserve(authenticationProviders.size() + 1U);
    for (std::size_t index = 0; index < authenticationProviders.size(); ++index) {
        if (index != 0U) countSql.push_back(',');
        countSql.push_back('$');
        countSql.append(std::to_string(index + 2U));
        countParameters.emplace_back(authenticationProviders[index].value());
    }
    countSql.push_back(')');
    ResultPointer count = execParams(connection, countSql, countParameters);
    if (!tuplesOk(count.get()) || PQntuples(count.get()) != 1) {
        return failTransaction(databaseError(
            count.get(), "count authentication methods"));
    }
    auto methodCount = parseInteger<std::size_t>(field(count.get(), 0, 0));
    if (!methodCount) return failTransaction(methodCount.error());
    if (methodCount.value() <= 1U) {
        return failTransaction(foundation::Error{
            foundation::ErrorCode::FailedPrecondition,
            "The last available sign-in method cannot be disconnected."});
    }
    ResultPointer removed = execParams(
        connection,
        "DELETE FROM openproof.external_identities WHERE provider=$1 "
        "AND external_subject=$2 AND identity_id=$3 RETURNING identity_id",
        {std::string{external.providerId().value()},
         std::string{external.subject().value()},
         std::string{expectedOwner.value()}});
    if (!tuplesOk(removed.get()) || PQntuples(removed.get()) != 1) {
        return failTransaction(databaseError(
            removed.get(), "detach authentication method"));
    }
    auto committed = commit(connection);
    if (!committed) return foundation::fail(committed.error());
    return foundation::ok();
}

foundation::Status PostgresExternalIdentityDirectory::reassign(
    const identity::core::ExternalIdentityRef& external,
    const identity::core::IdentityId& expectedCurrentOwner,
    const identity::core::IdentityId& newOwner)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "UPDATE openproof.external_identities SET identity_id=$4 WHERE provider=$1 "
        "AND external_subject=$2 AND identity_id=$3 RETURNING identity_id",
        {std::string{external.providerId().value()}, std::string{external.subject().value()},
         std::string{expectedCurrentOwner.value()}, std::string{newOwner.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "reassign external identity"));
    if (PQntuples(result.get()) == 1) return foundation::ok();
    auto owner = ownerOf(external);
    if (!owner) return foundation::fail(owner.error());
    return owner->has_value()
        ? foundation::fail(foundation::ErrorCode::PermissionDenied)
        : foundation::fail(foundation::ErrorCode::NotFound);
}

foundation::Status
PostgresExternalIdentityDirectory::updatePresentation(
    const identity::core::ExternalIdentityRef& external)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    const auto optionalText = [](const std::optional<std::string>& value) {
        return value.value_or(std::string{});
    };
    ResultPointer result = execParams(lease->get(),
        "UPDATE openproof.external_identities SET "
        "display_name=COALESCE(NULLIF($3,''),display_name),"
        "preferred_username=COALESCE(NULLIF($4,''),preferred_username),"
        "picture_url=COALESCE(NULLIF($5,''),picture_url) "
        "WHERE provider=$1 AND external_subject=$2 RETURNING identity_id",
        {std::string{external.providerId().value()}, std::string{external.subject().value()},
         optionalText(external.displayName()), optionalText(external.preferredUsername()),
         optionalText(external.pictureUrl())});
    if (!tuplesOk(result.get())) {
        return foundation::fail(databaseError(result.get(), "update external identity presentation"));
    }
    return PQntuples(result.get()) == 1
        ? foundation::ok()
        : foundation::fail(foundation::ErrorCode::NotFound);
}

foundation::Result<std::vector<identity::core::ExternalIdentityRef>>
PostgresExternalIdentityDirectory::externalIdentitiesOf(
    const identity::core::IdentityId& owner) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT provider,external_subject,display_name,preferred_username,picture_url "
        "FROM openproof.external_identities "
        "WHERE identity_id=$1 ORDER BY provider,external_subject", {std::string{owner.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "list external identities"));
    std::vector<identity::core::ExternalIdentityRef> output;
    const auto nullable = [&](int row, int column) -> std::optional<std::string> {
        return PQgetisnull(result.get(), row, column)
            ? std::nullopt
            : std::optional<std::string>{field(result.get(), row, column)};
    };
    for (int row = 0; row < PQntuples(result.get()); ++row) {
        output.emplace_back(identity::provider::ProviderId{field(result.get(), row, 0)},
                            identity::provider::ExternalSubject{field(result.get(), row, 1)},
                            nullable(row, 2), nullable(row, 3), nullable(row, 4));
    }
    return output;
}

std::size_t PostgresExternalIdentityDirectory::size() const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return 0U;
    ResultPointer result = exec(lease->get(), "SELECT count(*) FROM openproof.external_identities");
    if (!tuplesOk(result.get()) || PQntuples(result.get()) != 1) return 0U;
    auto count = parseInteger<std::size_t>(field(result.get(), 0, 0));
    return count ? count.value() : 0U;
}

PostgresOrganizationRepository::PostgresOrganizationRepository(ConnectionPool& pool)
    : m_pool(&pool) {}

foundation::Status PostgresOrganizationRepository::add(organization::Organization value)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "INSERT INTO openproof.organizations(id,name,state,created_at_ms) VALUES($1,$2,$3,$4)",
        {std::string{value.id().value()}, std::string{value.displayName()},
         std::to_string(static_cast<unsigned int>(value.status())), instant(value.createdAt())});
    return commandOk(result.get()) ? foundation::ok()
        : foundation::fail(databaseError(result.get(), "insert organization"));
}

foundation::Result<std::optional<organization::Organization>>
PostgresOrganizationRepository::findById(const organization::OrganizationId& id) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT id,name,state,created_at_ms FROM openproof.organizations WHERE id=$1",
        {std::string{id.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "find organization"));
    if (PQntuples(result.get()) == 0) return std::optional<organization::Organization>{};
    auto value = organizationFromRow(result.get(), 0);
    if (!value) return foundation::fail(value.error());
    return std::optional<organization::Organization>{std::move(value).value()};
}

foundation::Status PostgresOrganizationRepository::changeStatus(
    const organization::OrganizationId& id, organization::OrganizationStatus status)
{
    auto current = findById(id);
    if (!current) return foundation::fail(current.error());
    if (!current->has_value()) return foundation::fail(foundation::ErrorCode::NotFound);
    const auto previous = current->value().status();
    auto transition = current->value().changeStatus(status);
    if (!transition) return foundation::fail(transition.error());
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "UPDATE openproof.organizations SET state=$2 WHERE id=$1 AND state=$3 RETURNING id",
        {std::string{id.value()}, std::to_string(static_cast<unsigned int>(status)),
         std::to_string(static_cast<unsigned int>(previous))});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "change organization state"));
    return PQntuples(result.get()) == 1 ? foundation::ok()
        : foundation::fail(foundation::ErrorCode::Conflict,
                           "The organization changed concurrently.");
}

foundation::Result<std::size_t> PostgresOrganizationRepository::count() const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = exec(lease->get(), "SELECT count(*) FROM openproof.organizations");
    if (!tuplesOk(result.get()) || PQntuples(result.get()) != 1) {
        return foundation::fail(databaseError(result.get(), "count organizations"));
    }
    return parseInteger<std::size_t>(field(result.get(), 0, 0));
}

PostgresMembershipRepository::PostgresMembershipRepository(ConnectionPool& pool)
    : m_pool(&pool) {}

foundation::Status PostgresMembershipRepository::add(organization::Membership value)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());
    ResultPointer result = execParams(connection,
        "INSERT INTO openproof.memberships(organization_id,identity_id,state,invited_at_ms) "
        "VALUES($1,$2,$3,$4)",
        {std::string{value.organization().value()}, std::string{value.identity().value()},
         std::to_string(static_cast<unsigned int>(value.state())), instant(value.invitedAt())});
    if (!commandOk(result.get())) { rollback(connection); return foundation::fail(databaseError(result.get(), "insert membership")); }
    for (const auto& role : value.roles()) {
        ResultPointer inserted = execParams(connection,
            "INSERT INTO openproof.membership_roles(organization_id,identity_id,role) VALUES($1,$2,$3)",
            {std::string{value.organization().value()}, std::string{value.identity().value()},
             std::string{role.value()}});
        if (!commandOk(inserted.get())) { rollback(connection); return foundation::fail(databaseError(inserted.get(), "insert membership role")); }
    }
    return commit(connection);
}

foundation::Result<std::optional<organization::Membership>>
PostgresMembershipRepository::find(const organization::OrganizationId& organizationId,
                                   const organization::IdentityId& identityId) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT organization_id,identity_id,state,invited_at_ms FROM openproof.memberships "
        "WHERE organization_id=$1 AND identity_id=$2",
        {std::string{organizationId.value()}, std::string{identityId.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "find membership"));
    if (PQntuples(result.get()) == 0) return std::optional<organization::Membership>{};
    auto value = membershipFromRow(lease->get(), result.get(), 0);
    if (!value) return foundation::fail(value.error());
    return std::optional<organization::Membership>{std::move(value).value()};
}

foundation::Status PostgresMembershipRepository::save(const organization::Membership& value)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());
    ResultPointer updated = execParams(connection,
        "UPDATE openproof.memberships SET state=$3 WHERE organization_id=$1 AND identity_id=$2 RETURNING identity_id",
        {std::string{value.organization().value()}, std::string{value.identity().value()},
         std::to_string(static_cast<unsigned int>(value.state()))});
    if (!tuplesOk(updated.get())) { rollback(connection); return foundation::fail(databaseError(updated.get(), "save membership")); }
    if (PQntuples(updated.get()) != 1) { rollback(connection); return foundation::fail(foundation::ErrorCode::NotFound); }
    ResultPointer removed = execParams(connection,
        "DELETE FROM openproof.membership_roles WHERE organization_id=$1 AND identity_id=$2",
        {std::string{value.organization().value()}, std::string{value.identity().value()}});
    if (!commandOk(removed.get())) { rollback(connection); return foundation::fail(databaseError(removed.get(), "replace membership roles")); }
    for (const auto& role : value.roles()) {
        ResultPointer inserted = execParams(connection,
            "INSERT INTO openproof.membership_roles(organization_id,identity_id,role) VALUES($1,$2,$3)",
            {std::string{value.organization().value()}, std::string{value.identity().value()}, std::string{role.value()}});
        if (!commandOk(inserted.get())) { rollback(connection); return foundation::fail(databaseError(inserted.get(), "save membership role")); }
    }
    return commit(connection);
}

foundation::Result<std::vector<organization::IdentityId>>
PostgresMembershipRepository::membersOf(const organization::OrganizationId& organizationId) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT identity_id FROM openproof.memberships WHERE organization_id=$1 ORDER BY identity_id",
        {std::string{organizationId.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "list members"));
    std::vector<organization::IdentityId> output;
    for (int row = 0; row < PQntuples(result.get()); ++row) output.emplace_back(field(result.get(), row, 0));
    return output;
}

foundation::Result<std::vector<organization::OrganizationId>>
PostgresMembershipRepository::organizationsOf(const organization::IdentityId& identityId) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT organization_id FROM openproof.memberships WHERE identity_id=$1 ORDER BY organization_id",
        {std::string{identityId.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "list identity organizations"));
    std::vector<organization::OrganizationId> output;
    for (int row = 0; row < PQntuples(result.get()); ++row) output.emplace_back(field(result.get(), row, 0));
    return output;
}

foundation::Result<std::size_t> PostgresMembershipRepository::countIn(
    const organization::OrganizationId& organizationId) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT count(*) FROM openproof.memberships WHERE organization_id=$1",
        {std::string{organizationId.value()}});
    if (!tuplesOk(result.get()) || PQntuples(result.get()) != 1) {
        return foundation::fail(databaseError(result.get(), "count memberships"));
    }
    return parseInteger<std::size_t>(field(result.get(), 0, 0));
}

PostgresLocalAccountDirectory::PostgresLocalAccountDirectory(
    ConnectionPool& pool, credentials::PasswordHasher passwordHasher,
    credentials::TotpPolicy totpPolicy, security::AeadKey totpKey,
    unsigned int keyVersion, identity::provider::ProviderId providerId,
    credentials::PasswordHash dummyHash)
    : m_pool(&pool), m_passwordHasher(std::move(passwordHasher)),
      m_totpPolicy(totpPolicy), m_totpKey(std::move(totpKey)),
      m_keyVersion(keyVersion), m_provider(std::move(providerId)),
      m_dummyHash(std::move(dummyHash))
{
}

PostgresLocalAccountDirectory::~PostgresLocalAccountDirectory() = default;

foundation::Result<std::unique_ptr<PostgresLocalAccountDirectory>>
PostgresLocalAccountDirectory::create(
    ConnectionPool& pool, credentials::PasswordHasher passwordHasher,
    credentials::TotpPolicy totpPolicy, security::AeadKey totpKey,
    unsigned int keyVersion, identity::provider::ProviderId providerId)
{
    if (keyVersion == 0U || providerId.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The persistent local-account configuration is invalid.");
    }
    auto dummyHash = passwordHasher.hash(foundation::SecretString{
        "openproof-dummy-password-never-valid"});
    if (!dummyHash) return foundation::fail(dummyHash.error());
    return std::unique_ptr<PostgresLocalAccountDirectory>{
        new PostgresLocalAccountDirectory{
            pool, std::move(passwordHasher), totpPolicy, std::move(totpKey),
            keyVersion, std::move(providerId), std::move(dummyHash).value()}};
}

foundation::Status PostgresLocalAccountDirectory::enroll(
    identity::provider::ExternalSubject subject,
    const foundation::SecretString& password,
    std::optional<credentials::TotpSecret> totp)
{
    if (subject.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A local account subject must not be empty.");
    }
    auto passwordHash = m_passwordHasher.hash(password);
    if (!passwordHash) return foundation::fail(passwordHash.error());
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    ResultPointer owner = execParams(connection,
        "SELECT e.identity_id FROM openproof.external_identities e "
        "JOIN openproof.identities i ON i.id=e.identity_id "
        "WHERE e.provider=$1 AND e.external_subject=$2",
        {std::string{m_provider.value()}, std::string{subject.value()}});
    if (!tuplesOk(owner.get())) return foundation::fail(databaseError(owner.get(), "resolve local account"));
    if (PQntuples(owner.get()) != 1) {
        return foundation::fail(authenticationFailure(
            "Local enrollment requires a pre-existing explicit identity link."));
    }
    const std::string identityId = field(owner.get(), 0, 0);
    std::optional<std::vector<std::byte>> sealed;
    if (totp.has_value()) {
        auto encrypted = security::sealAes256Gcm(
            m_totpKey, totp->bytes(), "openproof/totp/v1:" + identityId);
        if (!encrypted) return foundation::fail(encrypted.error());
        sealed = std::move(encrypted).value();
    }
    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());
    ResultPointer insertedPassword = execParams(connection,
        "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
        "VALUES($1,$2,(extract(epoch FROM clock_timestamp())*1000)::bigint)",
        {identityId, std::string{passwordHash->encoded()}});
    if (!commandOk(insertedPassword.get())) {
        rollback(connection);
        return foundation::fail(databaseError(insertedPassword.get(), "enroll local password"));
    }
    if (sealed.has_value()) {
        ResultPointer insertedTotp = execParams(connection,
            "INSERT INTO openproof.totp_credentials(identity_id,encrypted_seed,key_version,last_accepted_step,enrolled_at_ms) "
            "VALUES($1,decode($2,'hex'),$3,NULL,(extract(epoch FROM clock_timestamp())*1000)::bigint)",
            {identityId, foundation::toHex(sealed.value()), std::to_string(m_keyVersion)});
        if (!commandOk(insertedTotp.get())) {
            rollback(connection);
            return foundation::fail(databaseError(insertedTotp.get(), "enroll local TOTP"));
        }
    }
    return commit(connection);
}

foundation::Status PostgresLocalAccountDirectory::enrollPending(
    identity::core::IdentityId canonicalIdentity,
    identity::provider::ExternalSubject subject,
    const foundation::SecretString& password,
    std::optional<credentials::TotpSecret> totp)
{
    if (canonicalIdentity.empty() || subject.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A pending local account requires identity and subject.");
    }
    auto passwordHash = m_passwordHasher.hash(password);
    if (!passwordHash) return foundation::fail(passwordHash.error());
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();

    ResultPointer canonical = execParams(connection,
        "SELECT status FROM openproof.identities WHERE id=$1",
        {std::string{canonicalIdentity.value()}});
    if (!tuplesOk(canonical.get())) {
        return foundation::fail(databaseError(canonical.get(), "resolve pending local identity"));
    }
    if (PQntuples(canonical.get()) != 1) {
        return foundation::fail(foundation::ErrorCode::NotFound,
                                "The canonical identity does not exist.");
    }
    auto status = parseInteger<unsigned int>(field(canonical.get(), 0, 0));
    if (!status || status.value() == static_cast<unsigned int>(identity::core::IdentityStatus::Deleted)
        || status.value() == static_cast<unsigned int>(identity::core::IdentityStatus::Merged)) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The canonical identity cannot receive credentials.");
    }

    std::optional<std::vector<std::byte>> sealed;
    if (totp.has_value()) {
        auto encrypted = security::sealAes256Gcm(
            m_totpKey, totp->bytes(),
            "openproof/totp/v1:" + std::string{canonicalIdentity.value()});
        if (!encrypted) return foundation::fail(encrypted.error());
        sealed = std::move(encrypted).value();
    }

    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());
    auto failTransaction = [&](const foundation::Error& error) -> foundation::Status {
        rollback(connection);
        return foundation::fail(error);
    };

    ResultPointer duplicate = execParams(connection,
        "SELECT 1 FROM openproof.external_identities WHERE provider=$1 AND external_subject=$2",
        {std::string{m_provider.value()}, std::string{subject.value()}});
    if (!tuplesOk(duplicate.get())) {
        return failTransaction(databaseError(duplicate.get(), "check pending local subject"));
    }
    if (PQntuples(duplicate.get()) != 0) {
        return failTransaction(foundation::Error{
            foundation::ErrorCode::AlreadyExists,
            "The local account already exists."});
    }

    ResultPointer insertedPassword = execParams(connection,
        "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
        "VALUES($1,$2,(extract(epoch FROM clock_timestamp())*1000)::bigint)",
        {std::string{canonicalIdentity.value()}, std::string{passwordHash->encoded()}});
    if (!commandOk(insertedPassword.get())) {
        return failTransaction(databaseError(insertedPassword.get(), "enroll pending local password"));
    }
    if (sealed.has_value()) {
        ResultPointer insertedTotp = execParams(connection,
            "INSERT INTO openproof.totp_credentials(identity_id,encrypted_seed,key_version,last_accepted_step,enrolled_at_ms) "
            "VALUES($1,decode($2,'hex'),$3,NULL,(extract(epoch FROM clock_timestamp())*1000)::bigint)",
            {std::string{canonicalIdentity.value()}, foundation::toHex(sealed.value()),
             std::to_string(m_keyVersion)});
        if (!commandOk(insertedTotp.get())) {
            return failTransaction(databaseError(insertedTotp.get(), "enroll pending local TOTP"));
        }
    }
    return commit(connection);
}

foundation::Status PostgresLocalAccountDirectory::rebindSubject(
    const identity::core::IdentityId& identity,
    const identity::provider::ExternalSubject& previous,
    identity::provider::ExternalSubject replacement)
{
    if (identity.empty() || previous.empty() || replacement.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A local account rebind requires valid identifiers.");
    }
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer credential = execParams(lease->get(),
        "SELECT 1 FROM openproof.password_credentials WHERE identity_id=$1",
        {std::string{identity.value()}});
    if (!tuplesOk(credential.get())) {
        return foundation::fail(databaseError(credential.get(), "confirm local credential for rebind"));
    }
    return PQntuples(credential.get()) == 1
        ? foundation::ok()
        : foundation::fail(authenticationFailure("Local account is unknown."));
}

foundation::Status PostgresLocalAccountDirectory::removePending(
    const identity::core::IdentityId& identity,
    const identity::provider::ExternalSubject& subject)
{
    if (identity.empty() || subject.empty()) return foundation::ok();
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());
    ResultPointer linked = execParams(connection,
        "SELECT 1 FROM openproof.external_identities WHERE provider=$1 AND external_subject=$2",
        {std::string{m_provider.value()}, std::string{subject.value()}});
    if (!tuplesOk(linked.get())) {
        rollback(connection);
        return foundation::fail(databaseError(linked.get(), "check pending local link"));
    }
    if (PQntuples(linked.get()) != 0) {
        rollback(connection);
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "A linked local credential cannot be removed as pending.");
    }
    ResultPointer totp = execParams(connection,
        "DELETE FROM openproof.totp_credentials WHERE identity_id=$1",
        {std::string{identity.value()}});
    if (!commandOk(totp.get())) {
        rollback(connection);
        return foundation::fail(databaseError(totp.get(), "remove pending local TOTP"));
    }
    ResultPointer password = execParams(connection,
        "DELETE FROM openproof.password_credentials WHERE identity_id=$1",
        {std::string{identity.value()}});
    if (!commandOk(password.get())) {
        rollback(connection);
        return foundation::fail(databaseError(password.get(), "remove pending local password"));
    }
    return commit(connection);
}

foundation::Status PostgresLocalAccountDirectory::changePassword(
    const identity::provider::ExternalSubject& subject,
    const foundation::SecretString& password)
{
    auto passwordHash = m_passwordHasher.hash(password);
    if (!passwordHash) return foundation::fail(passwordHash.error());
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "UPDATE openproof.password_credentials p SET password_hash=$3,"
        "changed_at_ms=(extract(epoch FROM clock_timestamp())*1000)::bigint "
        "FROM openproof.external_identities e WHERE e.provider=$1 AND e.external_subject=$2 "
        "AND e.identity_id=p.identity_id RETURNING p.identity_id",
        {std::string{m_provider.value()}, std::string{subject.value()},
         std::string{passwordHash->encoded()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "change local password"));
    return PQntuples(result.get()) == 1 ? foundation::ok()
        : foundation::fail(authenticationFailure("Local account is unknown."));
}

foundation::Result<provider::local::LocalVerification>
PostgresLocalAccountDirectory::verify(
    const identity::provider::ExternalSubject& subject,
    const foundation::SecretString& password,
    std::optional<std::string_view> presentedTotp, foundation::Instant now)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT e.identity_id,p.password_hash,encode(t.encrypted_seed,'hex'),"
        "t.key_version,t.last_accepted_step FROM openproof.external_identities e "
        "JOIN openproof.identities i ON i.id=e.identity_id AND i.status=0 "
        "JOIN openproof.password_credentials p ON p.identity_id=e.identity_id "
        "LEFT JOIN openproof.totp_credentials t ON t.identity_id=e.identity_id "
        "WHERE e.provider=$1 AND e.external_subject=$2",
        {std::string{m_provider.value()}, std::string{subject.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "verify local account"));
    if (PQntuples(result.get()) != 1) {
        auto dummy = m_passwordHasher.verify(password, m_dummyHash);
        if (!dummy) return foundation::fail(dummy.error());
        return foundation::fail(authenticationFailure("Local account is unknown or inactive."));
    }
    const std::string identityId = field(result.get(), 0, 0);
    const std::string encodedHash = field(result.get(), 0, 1);
    auto parsedHash = credentials::PasswordHash::parse(encodedHash);
    if (!parsedHash) return foundation::fail(parsedHash.error());
    auto passwordMatches = m_passwordHasher.verify(password, parsedHash.value());
    if (!passwordMatches) return foundation::fail(passwordMatches.error());
    if (!passwordMatches.value()) {
        return foundation::fail(authenticationFailure("Local credential verification failed."));
    }
    const bool hasTotp = PQgetisnull(result.get(), 0, 2) == 0;
    if (!hasTotp) {
        ResultPointer current = execParams(lease->get(),
            "SELECT 1 FROM openproof.password_credentials p "
            "JOIN openproof.identities i ON i.id=p.identity_id AND i.status=0 "
            "JOIN openproof.external_identities e ON e.identity_id=p.identity_id "
            "WHERE p.identity_id=$1 AND p.password_hash=$2 AND e.provider=$3 AND e.external_subject=$4",
            {identityId, encodedHash, std::string{m_provider.value()}, std::string{subject.value()}});
        if (!tuplesOk(current.get())) return foundation::fail(databaseError(current.get(), "confirm local credential"));
        return PQntuples(current.get()) == 1
            ? foundation::Result<provider::local::LocalVerification>{provider::local::LocalVerification::Password}
            : foundation::Result<provider::local::LocalVerification>{foundation::fail(
                authenticationFailure("Local credential changed during verification."))};
    }
    if (!presentedTotp.has_value()) {
        return foundation::fail(authenticationFailure("A second factor is required."));
    }
    auto version = parseInteger<unsigned int>(field(result.get(), 0, 3));
    if (!version || version.value() != m_keyVersion) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The TOTP credential key version is unavailable.");
    }
    const std::string encryptedHex = field(result.get(), 0, 2);
    auto encrypted = foundation::fromHex(encryptedHex);
    if (!encrypted) return foundation::fail(encrypted.error());
    auto plaintext = security::openAes256Gcm(
        m_totpKey, encrypted.value(), "openproof/totp/v1:" + identityId);
    if (!plaintext) return foundation::fail(plaintext.error());
    auto secret = credentials::TotpSecret::create(std::move(plaintext).value());
    if (!secret) return foundation::fail(secret.error());
    std::optional<std::uint64_t> lastAccepted;
    if (PQgetisnull(result.get(), 0, 4) == 0) {
        auto parsed = parseInteger<std::uint64_t>(field(result.get(), 0, 4));
        if (!parsed) return foundation::fail(parsed.error());
        lastAccepted = parsed.value();
    }
    auto accepted = credentials::verifyTotp(
        secret.value(), m_totpPolicy, presentedTotp.value(), now, lastAccepted);
    if (!accepted) return foundation::fail(accepted.error());
    ResultPointer consumed = execParams(lease->get(),
        "UPDATE openproof.totp_credentials t SET last_accepted_step=$5 WHERE t.identity_id=$1 "
        "AND t.key_version=$6 AND t.encrypted_seed=decode($7,'hex') "
        "AND (t.last_accepted_step IS NULL OR t.last_accepted_step<$5::bigint) "
        "AND EXISTS(SELECT 1 FROM openproof.password_credentials p "
        "JOIN openproof.identities i ON i.id=p.identity_id AND i.status=0 "
        "JOIN openproof.external_identities e ON e.identity_id=p.identity_id "
        "WHERE p.identity_id=$1 AND p.password_hash=$2 AND e.provider=$3 AND e.external_subject=$4) "
        "RETURNING t.identity_id",
        {identityId, encodedHash, std::string{m_provider.value()}, std::string{subject.value()},
         std::to_string(accepted.value()), std::to_string(m_keyVersion), encryptedHex});
    if (!tuplesOk(consumed.get())) return foundation::fail(databaseError(consumed.get(), "consume TOTP step"));
    return PQntuples(consumed.get()) == 1
        ? foundation::Result<provider::local::LocalVerification>{provider::local::LocalVerification::PasswordAndTotp}
        : foundation::Result<provider::local::LocalVerification>{foundation::fail(
            authenticationFailure("Local credential changed or TOTP was replayed."))};
}

PostgresAdministrationRepository::PostgresAdministrationRepository(
    ConnectionPool& pool, credentials::PasswordHasher passwordHasher,
    security::AeadKey totpKey, unsigned int keyVersion,
    identity::provider::ProviderId providerId, audit::AuditKey auditKey)
    : m_pool(&pool), m_passwordHasher(std::move(passwordHasher)),
      m_totpKey(std::move(totpKey)), m_keyVersion(keyVersion),
      m_provider(std::move(providerId)), m_auditKey(std::move(auditKey))
{
}

PostgresAdministrationRepository::~PostgresAdministrationRepository() = default;

foundation::Result<std::unique_ptr<PostgresAdministrationRepository>>
PostgresAdministrationRepository::create(
    ConnectionPool& pool, credentials::PasswordHasher passwordHasher,
    security::AeadKey totpKey, unsigned int keyVersion,
    identity::provider::ProviderId providerId, audit::AuditKey auditKey)
{
    if (keyVersion == 0U || providerId.empty()) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "The PostgreSQL bootstrap configuration is invalid.");
    }
    return std::unique_ptr<PostgresAdministrationRepository>{
        new PostgresAdministrationRepository{
            pool, std::move(passwordHasher), std::move(totpKey), keyVersion,
            std::move(providerId), std::move(auditKey)}};
}

foundation::Status PostgresAdministrationRepository::initialize(
    const administration::InitialAdministrator& administrator)
{
    const auto& tenant = administrator.organization();
    const auto& identityValue = administrator.identity();
    const auto& link = administrator.link();
    const auto& membership = administrator.membership();
    if (!tenant.isUsable() || !identityValue.canAuthenticate()
        || identityValue.kind() != identity::core::SubjectKind::Human
        || link.state() != identity::core::LinkState::Linked
        || link.external().providerId() != m_provider
        || link.owner() != identityValue.id()
        || membership.organization() != tenant.id()
        || membership.identity() != identityValue.id()
        || membership.state() != organization::MembershipState::Active
        || !membership.hasRole(organization::Role{"owner"})) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "The initial-administrator ceremony is incomplete.");
    }

    auto passwordHash = m_passwordHasher.hash(administrator.password());
    if (!passwordHash) return foundation::fail(passwordHash.error());
    auto encryptedTotp = security::sealAes256Gcm(
        m_totpKey, administrator.totp().bytes(),
        "openproof/totp/v1:" + std::string{identityValue.id().value()});
    if (!encryptedTotp) return foundation::fail(encryptedTotp.error());
    auto randomId = security::randomTokenBase64Url(24U);
    if (!randomId) return foundation::fail(randomId.error());
    const std::string eventId = "bootstrap-" + randomId.value();
    auto auditEvent = audit::AuditEvent::create(
        audit::AuditEventId{eventId}, identityValue.createdAt(),
        foundation::CorrelationId{eventId},
        std::optional<identity::core::OrganizationId>{tenant.id()},
        std::optional<identity::core::IdentityId>{identityValue.id()},
        "administration", "bootstrap.initial-owner", "success",
        audit::AuditFields{{"provider", std::string{m_provider.value()}},
                           {"role", "owner"}});
    if (!auditEvent) return foundation::fail(auditEvent.error());

    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());

    auto run = [&](std::string_view sql, const std::vector<std::string>& parameters,
                   std::string_view operation) -> foundation::Status {
        ResultPointer result = execParams(connection, sql, parameters);
        return commandOk(result.get()) ? foundation::ok()
            : foundation::fail(databaseError(result.get(), operation));
    };
    auto failTransaction = [&](const foundation::Error& error) -> foundation::Status {
        rollback(connection);
        return foundation::fail(error);
    };

    ResultPointer isolated = exec(connection, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    if (!commandOk(isolated.get())) {
        return failTransaction(databaseError(isolated.get(), "set bootstrap isolation"));
    }
    ResultPointer locked = exec(
        connection, "SELECT pg_advisory_xact_lock(7299730475761673313)");
    if (!tuplesOk(locked.get())) {
        return failTransaction(databaseError(locked.get(), "lock bootstrap ceremony"));
    }
    ResultPointer count = exec(connection, "SELECT count(*) FROM openproof.organizations");
    if (!tuplesOk(count.get()) || PQntuples(count.get()) != 1) {
        return failTransaction(databaseError(count.get(), "check bootstrap state"));
    }
    auto organizationCount = parseInteger<std::size_t>(field(count.get(), 0, 0));
    if (!organizationCount) return failTransaction(organizationCount.error());
    if (organizationCount.value() != 0U) {
        return failTransaction(foundation::Error{
            foundation::ErrorCode::AlreadyExists,
            "The deployment has already been initialized."});
    }

    foundation::Status status = run(
        "INSERT INTO openproof.organizations(id,name,state,created_at_ms) "
        "VALUES($1,$2,$3,$4)",
        {std::string{tenant.id().value()}, std::string{tenant.displayName()},
         std::to_string(static_cast<unsigned int>(tenant.status())),
         instant(tenant.createdAt())}, "bootstrap organization");
    if (!status) return failTransaction(status.error());
    status = run(
        "INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) "
        "VALUES($1,$2,$3,$4,$5)",
        {std::string{identityValue.id().value()}, std::string{tenant.id().value()},
         std::to_string(static_cast<unsigned int>(identityValue.kind())),
         std::to_string(static_cast<unsigned int>(identityValue.status())),
         instant(identityValue.createdAt())}, "bootstrap identity");
    if (!status) return failTransaction(status.error());
    status = run(
        "INSERT INTO openproof.external_identities"
        "(provider,external_subject,identity_id,linked_at_ms) VALUES($1,$2,$3,$4)",
        {std::string{link.external().providerId().value()},
         std::string{link.external().subject().value()},
         std::string{identityValue.id().value()}, instant(link.requestedAt())},
        "bootstrap external identity");
    if (!status) return failTransaction(status.error());
    status = run(
        "INSERT INTO openproof.memberships"
        "(organization_id,identity_id,state,invited_at_ms) VALUES($1,$2,$3,$4)",
        {std::string{tenant.id().value()}, std::string{identityValue.id().value()},
         std::to_string(static_cast<unsigned int>(membership.state())),
         instant(membership.invitedAt())}, "bootstrap membership");
    if (!status) return failTransaction(status.error());
    for (const organization::Role& role : membership.roles()) {
        status = run(
            "INSERT INTO openproof.membership_roles"
            "(organization_id,identity_id,role) VALUES($1,$2,$3)",
            {std::string{tenant.id().value()},
             std::string{identityValue.id().value()}, std::string{role.value()}},
            "bootstrap membership role");
        if (!status) return failTransaction(status.error());
    }
    status = run(
        "INSERT INTO openproof.password_credentials"
        "(identity_id,password_hash,changed_at_ms) VALUES($1,$2,$3)",
        {std::string{identityValue.id().value()},
         std::string{passwordHash->encoded()}, instant(identityValue.createdAt())},
        "bootstrap password");
    if (!status) return failTransaction(status.error());
    status = run(
        "INSERT INTO openproof.totp_credentials"
        "(identity_id,encrypted_seed,key_version,last_accepted_step,enrolled_at_ms) "
        "VALUES($1,decode($2,'hex'),$3,NULL,$4)",
        {std::string{identityValue.id().value()},
         foundation::toHex(encryptedTotp.value()), std::to_string(m_keyVersion),
         instant(identityValue.createdAt())}, "bootstrap TOTP");
    if (!status) return failTransaction(status.error());

    ResultPointer auditLock = exec(
        connection, "SELECT pg_advisory_xact_lock(7299730475761673314)");
    if (!tuplesOk(auditLock.get())) {
        return failTransaction(databaseError(auditLock.get(), "lock audit chain"));
    }
    ResultPointer previousResult = exec(
        connection,
        "SELECT encode(event_hash,'hex') FROM openproof.audit_events "
        "ORDER BY sequence DESC LIMIT 1");
    if (!tuplesOk(previousResult.get())) {
        return failTransaction(databaseError(previousResult.get(), "read audit chain head"));
    }
    std::optional<security::Sha256Digest> previousHash;
    std::string previousHex;
    if (PQntuples(previousResult.get()) == 1) {
        auto parsed = parseDigest(field(previousResult.get(), 0, 0));
        if (!parsed) return failTransaction(parsed.error());
        previousHash = parsed.value();
        previousHex = foundation::toHex(parsed.value());
    }
    foundation::JsonObjectWriter detail;
    for (const auto& [name, value] : auditEvent->fields()) detail.add(name, value);
    ResultPointer insertedAudit = execParams(
        connection,
        "INSERT INTO openproof.audit_events"
        "(event_id,occurred_at_ms,correlation_id,organization_id,identity_id,"
        "category,action,outcome,detail,previous_hash,event_hash) "
        "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,"
        "CASE WHEN $10='' THEN NULL ELSE decode($10,'hex') END,decode($11,'hex')) "
        "RETURNING sequence",
        {eventId, instant(auditEvent->occurredAt()),
         std::string{auditEvent->correlation().value()},
         std::string{tenant.id().value()}, std::string{identityValue.id().value()},
         std::string{auditEvent->category()}, std::string{auditEvent->action()},
         std::string{auditEvent->outcome()}, detail.build(), previousHex,
         std::string(64U, '0')});
    if (!tuplesOk(insertedAudit.get()) || PQntuples(insertedAudit.get()) != 1) {
        return failTransaction(databaseError(insertedAudit.get(), "append bootstrap audit event"));
    }
    auto sequence = parseInteger<std::uint64_t>(field(insertedAudit.get(), 0, 0));
    if (!sequence) return failTransaction(sequence.error());
    auto recordHash = audit::computeAuditRecordHash(
        auditEvent.value(), sequence.value(), previousHash, m_auditKey);
    if (!recordHash) return failTransaction(recordHash.error());
    status = run(
        "UPDATE openproof.audit_events SET event_hash=decode($2,'hex') "
        "WHERE sequence=$1",
        {std::to_string(sequence.value()), foundation::toHex(recordHash.value())},
        "seal bootstrap audit event");
    if (!status) return failTransaction(status.error());

    foundation::JsonObjectWriter payload;
    payload.add("event_id", eventId)
        .add("type", "bootstrap.initial-owner")
        .add("organization_id", tenant.id().value())
        .add("identity_id", identityValue.id().value())
        .add("severity", "critical");
    status = run(
        "INSERT INTO openproof.security_event_outbox"
        "(event_id,occurred_at_ms,payload) VALUES($1,$2,$3::jsonb)",
        {eventId, instant(identityValue.createdAt()), payload.build()},
        "append bootstrap security event");
    if (!status) return failTransaction(status.error());

    return commit(connection);
}

foundation::Status PostgresAdministrationRepository::provision(
    const identity::core::IdentityId& actor,
    const administration::LocalMemberEnrollment& enrollment)
{
    const auto& identityValue = enrollment.identity();
    const auto& link = enrollment.link();
    const auto& membership = enrollment.membership();
    if (actor.empty() || !identityValue.canAuthenticate()
        || identityValue.kind() != identity::core::SubjectKind::Human
        || link.state() != identity::core::LinkState::Linked
        || link.external().providerId() != m_provider
        || link.owner() != identityValue.id()
        || membership.organization() != enrollment.organizationId()
        || membership.identity() != identityValue.id()
        || membership.state() != organization::MembershipState::Active) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "The local-member enrollment ceremony is incomplete.");
    }

    auto passwordHash = m_passwordHasher.hash(enrollment.generatedPassword());
    if (!passwordHash) return foundation::fail(passwordHash.error());
    auto encryptedTotp = security::sealAes256Gcm(
        m_totpKey, enrollment.generatedTotp().bytes(),
        "openproof/totp/v1:" + std::string{identityValue.id().value()});
    if (!encryptedTotp) return foundation::fail(encryptedTotp.error());
    auto randomId = security::randomTokenBase64Url(24U);
    if (!randomId) return foundation::fail(randomId.error());
    const std::string eventId = "admin-member-" + randomId.value();
    std::string roleList;
    for (const organization::Role& role : membership.roles()) {
        if (!roleList.empty()) roleList.push_back(',');
        roleList.append(role.value());
    }
    auto auditEvent = audit::AuditEvent::create(
        audit::AuditEventId{eventId}, identityValue.createdAt(),
        foundation::CorrelationId{eventId},
        std::optional<identity::core::OrganizationId>{enrollment.organizationId()},
        std::optional<identity::core::IdentityId>{identityValue.id()},
        "administration", "local-member.create", "success",
        audit::AuditFields{{"actor_identity_id", std::string{actor.value()}},
                           {"provider", std::string{m_provider.value()}},
                           {"roles", roleList}});
    if (!auditEvent) return foundation::fail(auditEvent.error());

    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());
    auto failTransaction = [&](const foundation::Error& error) -> foundation::Status {
        rollback(connection);
        return foundation::fail(error);
    };
    auto run = [&](std::string_view sql, const std::vector<std::string>& parameters,
                   std::string_view operation) -> foundation::Status {
        ResultPointer result = execParams(connection, sql, parameters);
        return commandOk(result.get()) ? foundation::ok()
            : foundation::fail(databaseError(result.get(), operation));
    };

    ResultPointer isolated = exec(connection, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    if (!commandOk(isolated.get())) {
        return failTransaction(databaseError(isolated.get(), "set administration isolation"));
    }
    ResultPointer locked = exec(
        connection, "SELECT pg_advisory_xact_lock(7299730475761673315)");
    if (!tuplesOk(locked.get())) {
        return failTransaction(databaseError(locked.get(), "lock administration mutation"));
    }
    ResultPointer authorized = execParams(
        connection,
        "SELECT 1 FROM openproof.organizations o "
        "JOIN openproof.identities i ON i.organization_id=o.id AND i.id=$2 "
        "JOIN openproof.memberships m ON m.organization_id=o.id AND m.identity_id=i.id "
        "JOIN openproof.membership_roles r ON r.organization_id=m.organization_id "
        "AND r.identity_id=m.identity_id AND r.role='owner' "
        "WHERE o.id=$1 AND o.state=0 AND i.status=0 AND m.state=1 "
        "FOR UPDATE OF o,i,m",
        {std::string{enrollment.organizationId().value()}, std::string{actor.value()}});
    if (!tuplesOk(authorized.get())) {
        return failTransaction(databaseError(authorized.get(), "authorize member provisioning"));
    }
    if (PQntuples(authorized.get()) != 1) {
        return failTransaction(foundation::Error{
            foundation::ErrorCode::PermissionDenied,
            "The operation is not permitted."});
    }

    foundation::Status status = run(
        "INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) "
        "VALUES($1,$2,$3,$4,$5)",
        {std::string{identityValue.id().value()},
         std::string{enrollment.organizationId().value()},
         std::to_string(static_cast<unsigned int>(identityValue.kind())),
         std::to_string(static_cast<unsigned int>(identityValue.status())),
         instant(identityValue.createdAt())}, "create managed identity");
    if (!status) return failTransaction(status.error());
    status = run(
        "INSERT INTO openproof.external_identities"
        "(provider,external_subject,identity_id,linked_at_ms) VALUES($1,$2,$3,$4)",
        {std::string{link.external().providerId().value()},
         std::string{link.external().subject().value()},
         std::string{identityValue.id().value()}, instant(link.requestedAt())},
        "create managed external identity");
    if (!status) return failTransaction(status.error());
    status = run(
        "INSERT INTO openproof.memberships"
        "(organization_id,identity_id,state,invited_at_ms) VALUES($1,$2,$3,$4)",
        {std::string{enrollment.organizationId().value()},
         std::string{identityValue.id().value()},
         std::to_string(static_cast<unsigned int>(membership.state())),
         instant(membership.invitedAt())}, "create managed membership");
    if (!status) return failTransaction(status.error());
    for (const organization::Role& role : membership.roles()) {
        status = run(
            "INSERT INTO openproof.membership_roles"
            "(organization_id,identity_id,role) VALUES($1,$2,$3)",
            {std::string{enrollment.organizationId().value()},
             std::string{identityValue.id().value()}, std::string{role.value()}},
            "create managed membership role");
        if (!status) return failTransaction(status.error());
    }
    status = run(
        "INSERT INTO openproof.password_credentials"
        "(identity_id,password_hash,changed_at_ms) VALUES($1,$2,$3)",
        {std::string{identityValue.id().value()},
         std::string{passwordHash->encoded()}, instant(identityValue.createdAt())},
        "create managed password");
    if (!status) return failTransaction(status.error());
    status = run(
        "INSERT INTO openproof.totp_credentials"
        "(identity_id,encrypted_seed,key_version,last_accepted_step,enrolled_at_ms) "
        "VALUES($1,decode($2,'hex'),$3,NULL,$4)",
        {std::string{identityValue.id().value()},
         foundation::toHex(encryptedTotp.value()), std::to_string(m_keyVersion),
         instant(identityValue.createdAt())}, "create managed TOTP");
    if (!status) return failTransaction(status.error());

    ResultPointer auditLock = exec(
        connection, "SELECT pg_advisory_xact_lock(7299730475761673314)");
    if (!tuplesOk(auditLock.get())) {
        return failTransaction(databaseError(auditLock.get(), "lock audit chain"));
    }
    ResultPointer previousResult = exec(
        connection,
        "SELECT encode(event_hash,'hex') FROM openproof.audit_events "
        "ORDER BY sequence DESC LIMIT 1");
    if (!tuplesOk(previousResult.get())) {
        return failTransaction(databaseError(previousResult.get(), "read audit chain head"));
    }
    std::optional<security::Sha256Digest> previousHash;
    std::string previousHex;
    if (PQntuples(previousResult.get()) == 1) {
        auto parsed = parseDigest(field(previousResult.get(), 0, 0));
        if (!parsed) return failTransaction(parsed.error());
        previousHash = parsed.value();
        previousHex = foundation::toHex(parsed.value());
    }
    foundation::JsonObjectWriter detail;
    for (const auto& [name, value] : auditEvent->fields()) detail.add(name, value);
    ResultPointer insertedAudit = execParams(
        connection,
        "INSERT INTO openproof.audit_events"
        "(event_id,occurred_at_ms,correlation_id,organization_id,identity_id,"
        "category,action,outcome,detail,previous_hash,event_hash) "
        "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,"
        "CASE WHEN $10='' THEN NULL ELSE decode($10,'hex') END,decode($11,'hex')) "
        "RETURNING sequence",
        {eventId, instant(auditEvent->occurredAt()),
         std::string{auditEvent->correlation().value()},
         std::string{enrollment.organizationId().value()},
         std::string{identityValue.id().value()},
         std::string{auditEvent->category()}, std::string{auditEvent->action()},
         std::string{auditEvent->outcome()}, detail.build(), previousHex,
         std::string(64U, '0')});
    if (!tuplesOk(insertedAudit.get()) || PQntuples(insertedAudit.get()) != 1) {
        return failTransaction(databaseError(insertedAudit.get(), "append member audit event"));
    }
    auto sequence = parseInteger<std::uint64_t>(field(insertedAudit.get(), 0, 0));
    if (!sequence) return failTransaction(sequence.error());
    auto recordHash = audit::computeAuditRecordHash(
        auditEvent.value(), sequence.value(), previousHash, m_auditKey);
    if (!recordHash) return failTransaction(recordHash.error());
    status = run(
        "UPDATE openproof.audit_events SET event_hash=decode($2,'hex') WHERE sequence=$1",
        {std::to_string(sequence.value()), foundation::toHex(recordHash.value())},
        "seal member audit event");
    if (!status) return failTransaction(status.error());

    foundation::JsonObjectWriter payload;
    payload.add("event_id", eventId)
        .add("type", "administration.local-member.created")
        .add("organization_id", enrollment.organizationId().value())
        .add("actor_identity_id", actor.value())
        .add("identity_id", identityValue.id().value())
        .add("severity", "critical");
    status = run(
        "INSERT INTO openproof.security_event_outbox"
        "(event_id,occurred_at_ms,payload) VALUES($1,$2,$3::jsonb)",
        {eventId, instant(identityValue.createdAt()), payload.build()},
        "append member security event");
    if (!status) return failTransaction(status.error());
    return commit(connection);
}

foundation::Status PostgresAdministrationRepository::replaceRoles(
    const identity::core::IdentityId& actor,
    const administration::MemberRoleReplacement& replacement)
{
    if (actor.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The administrative actor is invalid.");
    }
    std::string roleList;
    bool replacementHasOwner = false;
    for (const organization::Role& role : replacement.roles()) {
        if (!roleList.empty()) roleList.push_back(',');
        roleList.append(role.value());
        replacementHasOwner = replacementHasOwner || role.value() == "owner";
    }
    auto event = administrationEvent(
        "local-member.roles.replace", replacement.organizationId(),
        replacement.identityId(), actor, replacement.occurredAt(),
        audit::AuditFields{{"roles", roleList}});
    if (!event) return foundation::fail(event.error());

    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());
    auto failTransaction = [&](const foundation::Error& error) -> foundation::Status {
        rollback(connection);
        return foundation::fail(error);
    };
    auto prepared = prepareAdministrationTransaction(connection);
    if (!prepared) return failTransaction(prepared.error());
    auto authorized = authorizeActiveOwner(
        connection, replacement.organizationId(), actor);
    if (!authorized) return failTransaction(authorized.error());
    auto member = lockLocalMember(
        connection, replacement.organizationId(), replacement.identityId(), m_provider);
    if (!member) return failTransaction(member.error());
    if (member->state == organization::MembershipState::Removed) {
        return failTransaction(foundation::Error{
            foundation::ErrorCode::FailedPrecondition,
            "A removed membership cannot receive roles."});
    }
    if (member->state == organization::MembershipState::Active
        && member->owner && !replacementHasOwner) {
        auto owners = activeOwnerCount(connection, replacement.organizationId());
        if (!owners) return failTransaction(owners.error());
        if (owners.value() <= 1U) {
            return failTransaction(foundation::Error{
                foundation::ErrorCode::FailedPrecondition,
                "The final active owner cannot lose the owner role."});
        }
    }
    auto status = runCommand(
        connection,
        "DELETE FROM openproof.membership_roles "
        "WHERE organization_id=$1 AND identity_id=$2",
        {std::string{replacement.organizationId().value()},
         std::string{replacement.identityId().value()}},
        "replace managed member roles");
    if (!status) return failTransaction(status.error());
    for (const organization::Role& role : replacement.roles()) {
        status = runCommand(
            connection,
            "INSERT INTO openproof.membership_roles"
            "(organization_id,identity_id,role) VALUES($1,$2,$3)",
            {std::string{replacement.organizationId().value()},
             std::string{replacement.identityId().value()},
             std::string{role.value()}},
            "insert replacement member role");
        if (!status) return failTransaction(status.error());
    }
    status = revokeMemberSessions(
        connection, replacement.identityId(), replacement.occurredAt());
    if (!status) return failTransaction(status.error());
    status = appendAdministrationRecords(
        connection, event.value(), m_auditKey,
        "administration.local-member.roles-replaced");
    if (!status) return failTransaction(status.error());
    return commit(connection);
}

foundation::Status PostgresAdministrationRepository::changeLifecycle(
    const identity::core::IdentityId& actor,
    const administration::MemberLifecycleChange& change)
{
    if (actor.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The administrative actor is invalid.");
    }
    const std::string actionName{
        administration::memberLifecycleActionName(change.action())};
    auto event = administrationEvent(
        "local-member." + actionName, change.organizationId(),
        change.identityId(), actor, change.occurredAt());
    if (!event) return foundation::fail(event.error());

    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());
    auto failTransaction = [&](const foundation::Error& error) -> foundation::Status {
        rollback(connection);
        return foundation::fail(error);
    };
    auto prepared = prepareAdministrationTransaction(connection);
    if (!prepared) return failTransaction(prepared.error());
    auto authorized = authorizeActiveOwner(connection, change.organizationId(), actor);
    if (!authorized) return failTransaction(authorized.error());
    auto member = lockLocalMember(
        connection, change.organizationId(), change.identityId(), m_provider);
    if (!member) return failTransaction(member.error());

    organization::MembershipState next{};
    switch (change.action()) {
    case administration::MemberLifecycleAction::Suspend:
        if (member->state != organization::MembershipState::Active) {
            return failTransaction(foundation::Error{
                foundation::ErrorCode::FailedPrecondition,
                "Only an active membership can be suspended."});
        }
        next = organization::MembershipState::Suspended;
        break;
    case administration::MemberLifecycleAction::Reinstate:
        if (member->state != organization::MembershipState::Suspended) {
            return failTransaction(foundation::Error{
                foundation::ErrorCode::FailedPrecondition,
                "Only a suspended membership can be reinstated."});
        }
        next = organization::MembershipState::Active;
        break;
    case administration::MemberLifecycleAction::Remove:
        if (member->state == organization::MembershipState::Removed) {
            return failTransaction(foundation::Error{
                foundation::ErrorCode::FailedPrecondition,
                "This membership has already been removed."});
        }
        next = organization::MembershipState::Removed;
        break;
    }
    if (member->state == organization::MembershipState::Active && member->owner
        && change.action() != administration::MemberLifecycleAction::Reinstate) {
        auto owners = activeOwnerCount(connection, change.organizationId());
        if (!owners) return failTransaction(owners.error());
        if (owners.value() <= 1U) {
            return failTransaction(foundation::Error{
                foundation::ErrorCode::FailedPrecondition,
                "The final active owner cannot be suspended or removed."});
        }
    }
    auto status = runCommand(
        connection,
        "UPDATE openproof.memberships SET state=$3 "
        "WHERE organization_id=$1 AND identity_id=$2",
        {std::string{change.organizationId().value()},
         std::string{change.identityId().value()},
         std::to_string(static_cast<unsigned int>(next))},
        "change managed member lifecycle");
    if (!status) return failTransaction(status.error());
    if (next == organization::MembershipState::Removed) {
        status = runCommand(
            connection,
            "DELETE FROM openproof.membership_roles "
            "WHERE organization_id=$1 AND identity_id=$2",
            {std::string{change.organizationId().value()},
             std::string{change.identityId().value()}},
            "drop removed member roles");
        if (!status) return failTransaction(status.error());
    }
    status = revokeMemberSessions(
        connection, change.identityId(), change.occurredAt());
    if (!status) return failTransaction(status.error());
    status = appendAdministrationRecords(
        connection, event.value(), m_auditKey,
        "administration.local-member." + actionName);
    if (!status) return failTransaction(status.error());
    return commit(connection);
}

foundation::Status PostgresAdministrationRepository::resetCredentials(
    const identity::core::IdentityId& actor,
    const administration::LocalCredentialReset& reset)
{
    if (actor.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The administrative actor is invalid.");
    }
    auto passwordHash = m_passwordHasher.hash(reset.generatedPassword());
    if (!passwordHash) return foundation::fail(passwordHash.error());
    auto encryptedTotp = security::sealAes256Gcm(
        m_totpKey, reset.generatedTotp().bytes(),
        "openproof/totp/v1:" + std::string{reset.identityId().value()});
    if (!encryptedTotp) return foundation::fail(encryptedTotp.error());
    auto event = administrationEvent(
        "local-member.credentials.reset", reset.organizationId(),
        reset.identityId(), actor, reset.occurredAt(),
        audit::AuditFields{{"provider", std::string{m_provider.value()}}});
    if (!event) return foundation::fail(event.error());

    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());
    auto failTransaction = [&](const foundation::Error& error) -> foundation::Status {
        rollback(connection);
        return foundation::fail(error);
    };
    auto prepared = prepareAdministrationTransaction(connection);
    if (!prepared) return failTransaction(prepared.error());
    auto authorized = authorizeActiveOwner(connection, reset.organizationId(), actor);
    if (!authorized) return failTransaction(authorized.error());
    auto member = lockLocalMember(
        connection, reset.organizationId(), reset.identityId(), m_provider);
    if (!member) return failTransaction(member.error());
    if (member->state != organization::MembershipState::Active) {
        return failTransaction(foundation::Error{
            foundation::ErrorCode::FailedPrecondition,
            "Credentials can be reset only for an active member."});
    }

    ResultPointer password = execParams(
        connection,
        "UPDATE openproof.password_credentials "
        "SET password_hash=$2,changed_at_ms=$3 WHERE identity_id=$1 RETURNING identity_id",
        {std::string{reset.identityId().value()},
         std::string{passwordHash->encoded()}, instant(reset.occurredAt())});
    if (!tuplesOk(password.get())) {
        return failTransaction(
            databaseError(password.get(), "reset managed member password"));
    }
    ResultPointer totp = execParams(
        connection,
        "UPDATE openproof.totp_credentials SET encrypted_seed=decode($2,'hex'),"
        "key_version=$3,last_accepted_step=NULL,enrolled_at_ms=$4 "
        "WHERE identity_id=$1 RETURNING identity_id",
        {std::string{reset.identityId().value()},
         foundation::toHex(encryptedTotp.value()), std::to_string(m_keyVersion),
         instant(reset.occurredAt())});
    if (!tuplesOk(totp.get())) {
        return failTransaction(
            databaseError(totp.get(), "reset managed member TOTP"));
    }
    if (PQntuples(password.get()) != 1 || PQntuples(totp.get()) != 1) {
        return failTransaction(foundation::Error{
            foundation::ErrorCode::FailedPrecondition,
            "The local member does not have a complete credential set."});
    }
    auto status = runCommand(
        connection, "DELETE FROM openproof.recovery_codes WHERE identity_id=$1",
        {std::string{reset.identityId().value()}},
        "invalidate managed member recovery codes");
    if (!status) return failTransaction(status.error());
    status = revokeMemberSessions(
        connection, reset.identityId(), reset.occurredAt());
    if (!status) return failTransaction(status.error());
    status = appendAdministrationRecords(
        connection, event.value(), m_auditKey,
        "administration.local-member.credentials-reset");
    if (!status) return failTransaction(status.error());
    return commit(connection);
}

PostgresAuthorizationDecisionSink::PostgresAuthorizationDecisionSink(
    ConnectionPool& pool, audit::AuditKey auditKey,
    const foundation::ClockSource& clock)
    : m_pool(&pool), m_auditKey(std::move(auditKey)), m_clock(&clock)
{
}

foundation::Status PostgresAuthorizationDecisionSink::record(
    const session::AuthenticatedSession& authenticatedSession,
    const identity::core::OrganizationId& organization,
    const policy::Action& action, const policy::Resource& resource,
    const policy::AuthorizationDecision& decision,
    const foundation::CorrelationId& correlation)
{
    auto randomId = security::randomTokenBase64Url(24U);
    if (!randomId) return foundation::fail(randomId.error());
    const foundation::Instant now = m_clock->now();
    auto event = audit::AuditEvent::create(
        audit::AuditEventId{"authorization-" + randomId.value()}, now,
        correlation,
        std::optional<identity::core::OrganizationId>{organization},
        std::optional<identity::core::IdentityId>{
            authenticatedSession.session().identity()},
        "authorization", "protected-route.evaluate",
        std::string{policy::decisionKindName(decision.kind())},
        audit::AuditFields{
            {"action", std::string{action.value()}},
            {"assurance", std::string{identity::provider::assuranceLevelName(
                              authenticatedSession.session().assurance())}},
            {"provider", std::string{
                             authenticatedSession.session().provider().value()}},
            {"reason", std::string{decision.reason()}},
            {"resource", std::string{resource.value()}}});
    if (!event) return foundation::fail(event.error());

    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) return foundation::fail(begun.error());
    const auto failTransaction = [&](const foundation::Error& error) {
        rollback(connection);
        return foundation::fail(error);
    };
    auto recorded = appendAuditRecord(connection, event.value(), m_auditKey);
    if (!recorded) return failTransaction(recorded.error());
    recorded = appendSecurityRecord(
        connection, event.value(), "authorization.protected-route.denied",
        authenticatedSession.session().identity().value(), "warning");
    if (!recorded) return failTransaction(recorded.error());
    auto committed = commit(connection);
    return committed ? committed : failTransaction(committed.error());
}

}

namespace openproof::storage::postgres {
    namespace {

        [[nodiscard]] foundation::Instant storedInstant(std::int64_t milliseconds) noexcept
        {
            return foundation::Instant{foundation::Duration{milliseconds}};
        }

        [[nodiscard]] foundation::Result<application::Application>
        applicationFromRow(PGresult* result, int row)
        {
            auto environment = parseInteger<unsigned int>(field(result, row, 4));
            auto status = parseInteger<unsigned int>(field(result, row, 5));
            auto created = parseInteger<std::int64_t>(field(result, row, 6));
            auto updated = parseInteger<std::int64_t>(field(result, row, 7));
            if (!environment || !status || !created || !updated
            || environment.value() > 2U || status.value() > 2U) {
                return foundation::fail(foundation::ErrorCode::Internal,
                "PostgreSQL returned malformed application data.");
            }
            return application::Application::restore(
            application::ApplicationId{field(result, row, 0)},
            identity::core::OrganizationId{field(result, row, 1)},
            field(result, row, 2), field(result, row, 3),
            static_cast<application::Environment>(environment.value()),
            static_cast<application::ApplicationStatus>(status.value()),
            storedInstant(created.value()), storedInstant(updated.value()));
        }

        [[nodiscard]] foundation::Result<std::vector<client::RedirectUri>>
        loadRedirectUris(PGconn* connection, const client::ClientId& id, client::ClientKind kind)
        {
            ResultPointer result = execParams(connection,
            "SELECT redirect_uri FROM openproof.oauth_client_redirect_uris "
            "WHERE client_id=$1 ORDER BY redirect_uri",
            {std::string{id.value()}});
            if (!tuplesOk(result.get())) {
                return foundation::fail(databaseError(result.get(), "load OAuth client redirect URIs"));
            }
            std::vector<client::RedirectUri> values;
            values.reserve(static_cast<std::size_t>(PQntuples(result.get())));
            for (int row = 0; row < PQntuples(result.get()); ++row) {
                auto parsed = client::RedirectUri::create(field(result.get(), row, 0), kind);
                if (!parsed) return foundation::fail(parsed.error());
                values.push_back(std::move(parsed).value());
            }
            return values;
        }

        [[nodiscard]] foundation::Result<std::vector<client::Scope>>
        loadClientScopes(PGconn* connection, const client::ClientId& id)
        {
            ResultPointer result = execParams(connection,
            "SELECT scope FROM openproof.oauth_client_scopes WHERE client_id=$1 ORDER BY scope",
            {std::string{id.value()}});
            if (!tuplesOk(result.get())) {
                return foundation::fail(databaseError(result.get(), "load OAuth client scopes"));
            }
            std::vector<client::Scope> values;
            values.reserve(static_cast<std::size_t>(PQntuples(result.get())));
            for (int row = 0; row < PQntuples(result.get()); ++row) {
                auto parsed = client::Scope::create(field(result.get(), row, 0));
                if (!parsed) return foundation::fail(parsed.error());
                values.push_back(std::move(parsed).value());
            }
            return values;
        }

        [[nodiscard]] foundation::Result<client::Client>
        clientFromRow(PGconn* connection, PGresult* result, int row)
        {
            auto kind = parseInteger<unsigned int>(field(result, row, 3));
            auto status = parseInteger<unsigned int>(field(result, row, 4));
            auto created = parseInteger<std::int64_t>(field(result, row, 6));
            auto updated = parseInteger<std::int64_t>(field(result, row, 7));
            if (!kind || !status || !created || !updated || kind.value() > 3U || status.value() > 2U) {
                return foundation::fail(foundation::ErrorCode::Internal,
                "PostgreSQL returned malformed OAuth client data.");
            }
            const auto clientKind = static_cast<client::ClientKind>(kind.value());
            client::ClientId id{field(result, row, 0)};
            auto redirects = loadRedirectUris(connection, id, clientKind);
            auto scopes = loadClientScopes(connection, id);
            if (!redirects || !scopes) return foundation::fail(redirects ? scopes.error() : redirects.error());
            std::optional<client::ClientSecretDigest> secret;
            if (!PQgetisnull(result, row, 5)) {
                auto digest = parseDigest(field(result, row, 5));
                if (!digest) return foundation::fail(digest.error());
                secret.emplace(digest.value());
            }
            return client::Client::restore(
            std::move(id), application::ApplicationId{field(result, row, 1)},
            field(result, row, 2), clientKind,
            static_cast<client::ClientStatus>(status.value()),
            std::move(redirects).value(), std::move(scopes).value(), std::move(secret),
            storedInstant(created.value()), storedInstant(updated.value()));
        }

        [[nodiscard]] foundation::Status insertClientChildren(PGconn* connection,
        const client::Client& value)
        {
            for (const auto& redirect : value.redirectUris()) {
                auto status = runCommand(connection,
                "INSERT INTO openproof.oauth_client_redirect_uris(client_id,redirect_uri) VALUES($1,$2)",
                {std::string{value.id().value()}, std::string{redirect.value()}},
                "insert OAuth client redirect URI");
                if (!status) return status;
            }
            for (const auto& scope : value.scopes()) {
                auto status = runCommand(connection,
                "INSERT INTO openproof.oauth_client_scopes(client_id,scope) VALUES($1,$2)",
                {std::string{value.id().value()}, std::string{scope.value()}},
                "insert OAuth client scope");
                if (!status) return status;
            }
            return foundation::ok();
        }

        [[nodiscard]] foundation::Result<std::vector<std::string>>
        loadResourceScopes(PGconn* connection, const resource::ResourceId& id)
        {
            ResultPointer result = execParams(
                connection,
                "SELECT scope FROM openproof.oauth_resource_scopes "
                "WHERE resource_id=$1 ORDER BY scope",
                {std::string{id.value()}});
            if (!tuplesOk(result.get())) {
                return foundation::fail(
                    databaseError(result.get(), "load OAuth resource scopes"));
            }
            std::vector<std::string> scopes;
            scopes.reserve(static_cast<std::size_t>(PQntuples(result.get())));
            for (int row = 0; row < PQntuples(result.get()); ++row) {
                scopes.push_back(field(result.get(), row, 0));
            }
            return scopes;
        }

        [[nodiscard]] foundation::Result<resource::ResourceServer>
        resourceFromRow(PGconn* connection, PGresult* result, int row)
        {
            auto status = parseInteger<unsigned int>(field(result, row, 3));
            auto created = parseInteger<std::int64_t>(field(result, row, 4));
            auto updated = parseInteger<std::int64_t>(field(result, row, 5));
            if (!status || !created || !updated || status.value() > 2U) {
                return foundation::fail(
                    foundation::ErrorCode::Internal,
                    "PostgreSQL returned malformed OAuth resource data.");
            }
            resource::ResourceId id{field(result, row, 0)};
            auto scopes = loadResourceScopes(connection, id);
            if (!scopes) return foundation::fail(scopes.error());
            return resource::ResourceServer::restore(
                std::move(id), field(result, row, 1), field(result, row, 2),
                std::move(scopes).value(),
                static_cast<resource::ResourceStatus>(status.value()),
                storedInstant(created.value()), storedInstant(updated.value()));
        }

        [[nodiscard]] foundation::Result<std::vector<std::string>>
        loadServiceAudiences(PGconn* connection, const client::ClientId& id)
        {
            ResultPointer result = execParams(
                connection,
                "SELECT audience FROM openproof.service_identity_audiences "
                "WHERE client_id=$1 ORDER BY audience",
                {std::string{id.value()}});
            if (!tuplesOk(result.get())) {
                return foundation::fail(
                    databaseError(result.get(), "load service identity audiences"));
            }
            std::vector<std::string> values;
            values.reserve(static_cast<std::size_t>(PQntuples(result.get())));
            for (int row = 0; row < PQntuples(result.get()); ++row) {
                values.push_back(field(result.get(), row, 0));
            }
            return values;
        }

        [[nodiscard]] foundation::Result<std::vector<std::string>>
        loadServiceScopes(PGconn* connection, const client::ClientId& id)
        {
            ResultPointer result = execParams(
                connection,
                "SELECT scope FROM openproof.service_identity_scopes "
                "WHERE client_id=$1 ORDER BY scope",
                {std::string{id.value()}});
            if (!tuplesOk(result.get())) {
                return foundation::fail(
                    databaseError(result.get(), "load service identity scopes"));
            }
            std::vector<std::string> values;
            values.reserve(static_cast<std::size_t>(PQntuples(result.get())));
            for (int row = 0; row < PQntuples(result.get()); ++row) {
                values.push_back(field(result.get(), row, 0));
            }
            return values;
        }

        [[nodiscard]] foundation::Result<resource::ServiceIdentity>
        serviceIdentityFromRow(PGconn* connection, PGresult* result, int row)
        {
            auto created = parseInteger<std::int64_t>(field(result, row, 3));
            auto updated = parseInteger<std::int64_t>(field(result, row, 4));
            if (!created || !updated) {
                return foundation::fail(
                    foundation::ErrorCode::Internal,
                    "PostgreSQL returned malformed service identity data.");
            }
            client::ClientId clientId{field(result, row, 0)};
            auto audiences = loadServiceAudiences(connection, clientId);
            auto scopes = loadServiceScopes(connection, clientId);
            if (!audiences || !scopes) {
                return foundation::fail(audiences ? scopes.error() : audiences.error());
            }
            return resource::ServiceIdentity::restore(
                identity::core::IdentityId{field(result, row, 1)},
                std::move(clientId), std::move(audiences).value(),
                std::move(scopes).value(), field(result, row, 2) == "t",
                storedInstant(created.value()), storedInstant(updated.value()));
        }

        [[nodiscard]] foundation::Result<std::vector<std::string>>
        loadConsentScopes(PGconn* connection, const consent::ConsentId& id)
        {
            ResultPointer result = execParams(
                connection,
                "SELECT scope FROM openproof.oauth_consent_scopes "
                "WHERE consent_id=$1 ORDER BY scope",
                {std::string{id.value()}});
            if (!tuplesOk(result.get())) {
                return foundation::fail(
                    databaseError(result.get(), "load OAuth consent scopes"));
            }
            std::vector<std::string> scopes;
            scopes.reserve(static_cast<std::size_t>(PQntuples(result.get())));
            for (int row = 0; row < PQntuples(result.get()); ++row) {
                scopes.push_back(field(result.get(), row, 0));
            }
            return scopes;
        }

        [[nodiscard]] foundation::Result<consent::ConsentGrant>
        consentFromRow(PGconn* connection, PGresult* result, int row)
        {
            auto granted = parseInteger<std::int64_t>(field(result, row, 4));
            if (!granted) return foundation::fail(granted.error());
            std::optional<foundation::Instant> expires;
            if (!PQgetisnull(result, row, 5)) {
                auto parsed = parseInteger<std::int64_t>(field(result, row, 5));
                if (!parsed) return foundation::fail(parsed.error());
                expires = storedInstant(parsed.value());
            }
            std::optional<foundation::Instant> revoked;
            if (!PQgetisnull(result, row, 6)) {
                auto parsed = parseInteger<std::int64_t>(field(result, row, 6));
                if (!parsed) return foundation::fail(parsed.error());
                revoked = storedInstant(parsed.value());
            }
            consent::ConsentId id{field(result, row, 0)};
            auto scopes = loadConsentScopes(connection, id);
            if (!scopes) return foundation::fail(scopes.error());
            return consent::ConsentGrant::restore(
                std::move(id), identity::core::IdentityId{field(result, row, 1)},
                client::ClientId{field(result, row, 2)}, field(result, row, 3),
                std::move(scopes).value(), storedInstant(granted.value()),
                expires, revoked);
        }

        [[nodiscard]] unsigned int factorsValue(
        const identity::provider::AuthenticationStrength& strength) noexcept
        {
            return static_cast<unsigned int>(strength.factors());
        }

        [[nodiscard]] foundation::Result<std::vector<client::Scope>>
        loadDeviceScopes(PGconn* connection, const oauth::DeviceCodeDigest& deviceCode)
        {
            ResultPointer result = execParams(
                connection,
                "SELECT scope FROM openproof.oauth_device_authorization_scopes "
                "WHERE device_digest=decode($1,'hex') ORDER BY scope",
                {foundation::toHex(deviceCode.bytes())});
            if (!tuplesOk(result.get())) {
                return foundation::fail(databaseError(result.get(), "load device authorization scopes"));
            }
            std::vector<client::Scope> scopes;
            scopes.reserve(static_cast<std::size_t>(PQntuples(result.get())));
            for (int row = 0; row < PQntuples(result.get()); ++row) {
                auto scope = client::Scope::create(field(result.get(), row, 0));
                if (!scope) return foundation::fail(scope.error());
                scopes.push_back(std::move(scope).value());
            }
            return scopes;
        }

        [[nodiscard]] foundation::Result<oauth::DeviceAuthorization>
        deviceAuthorizationFromRow(PGconn* connection, PGresult* result, int row)
        {
            if (PQnfields(result) != 15) {
                return foundation::fail(foundation::ErrorCode::Internal,
                                        "PostgreSQL returned an invalid device authorization shape.");
            }
            auto deviceDigest = parseDigest(field(result, row, 0));
            auto userDigest = parseDigest(field(result, row, 1));
            auto status = parseInteger<unsigned int>(field(result, row, 4));
            auto issuedAt = parseInteger<std::int64_t>(field(result, row, 5));
            auto expiresAt = parseInteger<std::int64_t>(field(result, row, 6));
            auto pollInterval = parseInteger<std::int64_t>(field(result, row, 7));
            if (!deviceDigest || !userDigest || !status || !issuedAt || !expiresAt
                || !pollInterval || status.value() > 3U || pollInterval.value() <= 0) {
                return foundation::fail(foundation::ErrorCode::Internal,
                                        "PostgreSQL returned malformed device authorization data.");
            }

            oauth::DeviceCodeDigest deviceCode{deviceDigest.value()};
            auto scopes = loadDeviceScopes(connection, deviceCode);
            if (!scopes) return foundation::fail(scopes.error());

            std::optional<std::string> resource;
            if (PQgetisnull(result, row, 3) == 0) resource = field(result, row, 3);
            std::optional<identity::core::IdentityId> identity;
            std::optional<identity::provider::ProviderId> provider;
            std::optional<identity::provider::AssuranceLevel> assurance;
            std::optional<identity::provider::AuthenticationStrength> strength;
            std::optional<foundation::Instant> authenticatedAt;
            if (PQgetisnull(result, row, 8) == 0) {
                if (PQgetisnull(result, row, 9) != 0 || PQgetisnull(result, row, 10) != 0
                    || PQgetisnull(result, row, 11) != 0 || PQgetisnull(result, row, 12) != 0
                    || PQgetisnull(result, row, 13) != 0) {
                    return foundation::fail(foundation::ErrorCode::Internal,
                                            "PostgreSQL returned incomplete device authorization claims.");
                }
                auto assuranceValue = parseInteger<unsigned int>(field(result, row, 10));
                auto factors = parseInteger<unsigned int>(field(result, row, 11));
                auto authenticated = parseInteger<std::int64_t>(field(result, row, 13));
                if (!assuranceValue || !factors || !authenticated
                    || assuranceValue.value() > 4U || factors.value() > 7U) {
                    return foundation::fail(foundation::ErrorCode::Internal,
                                            "PostgreSQL returned malformed device authorization claims.");
                }
                identity = identity::core::IdentityId{field(result, row, 8)};
                provider = identity::provider::ProviderId{field(result, row, 9)};
                assurance = static_cast<identity::provider::AssuranceLevel>(assuranceValue.value());
                strength = identity::provider::AuthenticationStrength{
                    static_cast<identity::provider::AuthenticationFactor>(factors.value()),
                    field(result, row, 12) == "t"};
                authenticatedAt = storedInstant(authenticated.value());
            }
            std::optional<foundation::Instant> lastPollAt;
            if (PQgetisnull(result, row, 14) == 0) {
                auto lastPoll = parseInteger<std::int64_t>(field(result, row, 14));
                if (!lastPoll) return foundation::fail(lastPoll.error());
                lastPollAt = storedInstant(lastPoll.value());
            }
            return oauth::DeviceAuthorization::restore(
                std::move(deviceCode), oauth::DeviceUserCodeDigest{userDigest.value()},
                client::ClientId{field(result, row, 2)}, std::move(scopes).value(),
                std::move(resource), storedInstant(issuedAt.value()),
                storedInstant(expiresAt.value()), foundation::Duration{pollInterval.value()},
                static_cast<oauth::DeviceAuthorizationStatus>(status.value()),
                std::move(identity), std::move(provider), std::move(assurance),
                std::move(strength), authenticatedAt, lastPollAt);
        }

        constexpr std::string_view kDeviceAuthorizationColumns =
            "encode(device_digest,'hex'),encode(user_code_digest,'hex'),client_id,resource,status,"
            "issued_at_ms,expires_at_ms,poll_interval_ms,identity_id,provider,assurance,factors,"
            "phishing_resistant,authenticated_at_ms,last_poll_at_ms";

        [[nodiscard]] foundation::Result<std::vector<client::Scope>>
        loadPushedAuthorizationScopes(PGconn* connection,
                                      const oauth::PushedRequestDigest& digest)
        {
            ResultPointer result = execParams(
                connection,
                "SELECT scope FROM openproof.oauth_pushed_authorization_request_scopes "
                "WHERE request_digest=decode($1,'hex') ORDER BY scope",
                {foundation::toHex(digest.bytes())});
            if (!tuplesOk(result.get())) {
                return foundation::fail(
                    databaseError(result.get(), "load pushed authorization request scopes"));
            }
            std::vector<client::Scope> scopes;
            scopes.reserve(static_cast<std::size_t>(PQntuples(result.get())));
            for (int row = 0; row < PQntuples(result.get()); ++row) {
                auto parsed = client::Scope::create(field(result.get(), row, 0));
                if (!parsed) return foundation::fail(parsed.error());
                scopes.push_back(std::move(parsed).value());
            }
            return scopes;
        }

        [[nodiscard]] foundation::Result<oauth::PushedAuthorizationRequest>
        pushedAuthorizationFromRow(PGconn* connection, PGresult* result, int row)
        {
            if (PQnfields(result) != 11) {
                return foundation::fail(foundation::ErrorCode::Internal,
                                        "PostgreSQL returned an invalid PAR shape.");
            }
            auto digestValue = parseDigest(field(result, row, 0));
            auto responseMode = parseInteger<unsigned int>(field(result, row, 8));
            auto issuedAt = parseInteger<std::int64_t>(field(result, row, 9));
            auto expiresAt = parseInteger<std::int64_t>(field(result, row, 10));
            if (!digestValue || !responseMode || !issuedAt || !expiresAt
                || responseMode.value() > 1U) {
                return foundation::fail(foundation::ErrorCode::Internal,
                                        "PostgreSQL returned malformed PAR data.");
            }
            oauth::PushedRequestDigest digest{digestValue.value()};
            auto requestedScopes = loadPushedAuthorizationScopes(connection, digest);
            if (!requestedScopes) return foundation::fail(requestedScopes.error());
            auto challenge = oauth::PkceChallenge::create(field(result, row, 3));
            if (!challenge) return foundation::fail(challenge.error());
            std::optional<std::string> state;
            if (PQgetisnull(result, row, 4) == 0) state = field(result, row, 4);
            std::optional<std::string> nonce;
            if (PQgetisnull(result, row, 5) == 0) nonce = field(result, row, 5);
            std::optional<foundation::Duration> maximumAuthenticationAge;
            if (PQgetisnull(result, row, 6) == 0) {
                auto value = parseInteger<std::int64_t>(field(result, row, 6));
                if (!value || value.value() < 0) {
                    return foundation::fail(foundation::ErrorCode::Internal,
                                            "PostgreSQL returned malformed PAR max_age.");
                }
                maximumAuthenticationAge = foundation::Duration{value.value()};
            }
            std::optional<std::string> resource;
            if (PQgetisnull(result, row, 7) == 0) resource = field(result, row, 7);
            auto request = oauth::AuthorizationRequest::create(
                client::ClientId{field(result, row, 1)}, field(result, row, 2),
                std::move(requestedScopes).value(), std::move(challenge).value(),
                std::move(state), std::move(nonce), maximumAuthenticationAge,
                std::move(resource),
                static_cast<oauth::AuthorizationResponseMode>(responseMode.value()));
            if (!request) return foundation::fail(request.error());
            return oauth::PushedAuthorizationRequest::restore(
                std::move(digest), std::move(request).value(),
                storedInstant(issuedAt.value()), storedInstant(expiresAt.value()));
        }

        constexpr std::string_view kPushedAuthorizationColumns =
            "encode(request_digest,'hex'),client_id,redirect_uri,code_challenge,state,nonce,"
            "maximum_authentication_age_ms,resource,response_mode,issued_at_ms,expires_at_ms";

        [[nodiscard]] foundation::Result<token::TokenContext>
        loadTokenContext(PGconn* connection, const token::TokenFamilyId& family)
        {
            ResultPointer base = execParams(connection,
            "SELECT client_id,identity_id,provider,assurance,factors,phishing_resistant,authenticated_at_ms,"
            "sender_constraint_kind,sender_constraint_value "
            "FROM openproof.oauth_token_families WHERE id=$1",
            {std::string{family.value()}});
            if (!tuplesOk(base.get())) return foundation::fail(databaseError(base.get(), "load OAuth token family"));
            if (PQntuples(base.get()) != 1) {
                return foundation::fail(authenticationFailure("OAuth token family is unavailable."));
            }
            auto assurance = parseInteger<unsigned int>(field(base.get(), 0, 3));
            auto factors = parseInteger<unsigned int>(field(base.get(), 0, 4));
            auto authenticatedAt = parseInteger<std::int64_t>(field(base.get(), 0, 6));
            if (!assurance || !factors || !authenticatedAt || assurance.value() > 4U || factors.value() > 7U) {
                return foundation::fail(foundation::ErrorCode::Internal,
                "PostgreSQL returned malformed OAuth token context.");
            }
            ResultPointer scopesResult = execParams(connection,
            "SELECT scope FROM openproof.oauth_token_family_scopes WHERE family_id=$1 ORDER BY scope",
            {std::string{family.value()}});
            if (!tuplesOk(scopesResult.get())) {
                return foundation::fail(databaseError(scopesResult.get(), "load OAuth token scopes"));
            }
            std::vector<std::string> scopes;
            for (int row = 0; row < PQntuples(scopesResult.get()); ++row) {
                scopes.push_back(field(scopesResult.get(), row, 0));
            }
            ResultPointer audiencesResult = execParams(
                connection,
                "SELECT audience FROM openproof.oauth_token_family_audiences "
                "WHERE family_id=$1 ORDER BY audience",
                {std::string{family.value()}});
            if (!tuplesOk(audiencesResult.get())) {
                return foundation::fail(
                    databaseError(audiencesResult.get(), "load OAuth token audiences"));
            }
            std::vector<std::string> audiences;
            for (int row = 0; row < PQntuples(audiencesResult.get()); ++row) {
                audiences.push_back(field(audiencesResult.get(), row, 0));
            }
            std::optional<token::SenderConstraint> senderConstraint;
            if (PQgetisnull(base.get(), 0, 7) == 0 || PQgetisnull(base.get(), 0, 8) == 0) {
                if (PQgetisnull(base.get(), 0, 7) != 0 || PQgetisnull(base.get(), 0, 8) != 0) {
                    return foundation::fail(foundation::ErrorCode::Internal,
                                            "PostgreSQL returned malformed OAuth sender constraint.");
                }
                auto kind = parseInteger<unsigned int>(field(base.get(), 0, 7));
                if (!kind || kind.value() > 1U) {
                    return foundation::fail(foundation::ErrorCode::Internal,
                                            "PostgreSQL returned malformed OAuth sender constraint.");
                }
                auto constraint = token::SenderConstraint::create(
                    static_cast<token::SenderConstraintKind>(kind.value()),
                    field(base.get(), 0, 8));
                if (!constraint) return foundation::fail(constraint.error());
                senderConstraint = std::move(constraint).value();
            }
            return token::TokenContext{
                client::ClientId{field(base.get(), 0, 0)},
                identity::core::IdentityId{field(base.get(), 0, 1)},
                identity::provider::ProviderId{field(base.get(), 0, 2)},
                static_cast<identity::provider::AssuranceLevel>(assurance.value()),
                identity::provider::AuthenticationStrength{
                    static_cast<identity::provider::AuthenticationFactor>(factors.value()),
                    field(base.get(), 0, 5) == "t"},
                std::move(scopes), storedInstant(authenticatedAt.value()),
                std::move(audiences), std::move(senderConstraint)};
        }

        [[nodiscard]] foundation::Status revokeTokenFamilySql(
        PGconn* connection, const token::TokenFamilyId& family, foundation::Instant now)
        {
            auto familyStatus = runCommand(connection,
            "UPDATE openproof.oauth_token_families SET revoked_at_ms=COALESCE(revoked_at_ms,$2) WHERE id=$1",
            {std::string{family.value()}, instant(now)}, "revoke OAuth token family");
            if (!familyStatus) return familyStatus;
            auto accessStatus = runCommand(connection,
            "UPDATE openproof.oauth_access_tokens SET state=1,revoked_at_ms=COALESCE(revoked_at_ms,$2) "
            "WHERE family_id=$1 AND state=0",
            {std::string{family.value()}, instant(now)}, "revoke OAuth family access tokens");
            if (!accessStatus) return accessStatus;
            return runCommand(connection,
            "UPDATE openproof.oauth_refresh_tokens SET state=2,changed_at_ms=COALESCE(changed_at_ms,$2) "
            "WHERE family_id=$1 AND state<>2",
            {std::string{family.value()}, instant(now)}, "revoke OAuth family refresh tokens");
        }

    }

    PostgresAccountRepository::PostgresAccountRepository(ConnectionPool& pool)
        : m_pool(&pool)
    {
    }

    foundation::Status PostgresAccountRepository::replace(account::VerificationChallenge challenge)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        const auto failTransaction = [&](const foundation::Error& error) {
            rollback(connection);
            return foundation::fail(error);
        };

        auto removed = runCommand(
            connection,
            "DELETE FROM openproof.account_verification_challenges "
            "WHERE identity_id=$1 AND purpose=$2",
            {std::string{challenge.identity().value()},
             integer(static_cast<unsigned int>(challenge.purpose()))},
            "replace account verification challenge");
        if (!removed) return failTransaction(removed.error());

        auto inserted = runCommand(
            connection,
            "INSERT INTO openproof.account_verification_challenges("
            "id,identity_id,purpose,channel,destination,secret_digest,attempts,created_at_ms,expires_at_ms) "
            "VALUES($1,$2,$3,$4,$5,decode($6,'hex'),$7,$8,$9)",
            {std::string{challenge.id().value()}, std::string{challenge.identity().value()},
             integer(static_cast<unsigned int>(challenge.purpose())),
             integer(static_cast<unsigned int>(challenge.channel())),
             std::string{challenge.destination()}, foundation::toHex(challenge.digest().bytes()),
             integer(static_cast<std::int64_t>(challenge.attempts())),
             instant(challenge.createdAt()), instant(challenge.expiresAt())},
            "insert account verification challenge");
        if (!inserted) return failTransaction(inserted.error());

        auto committed = commit(connection);
        return committed ? committed : failTransaction(committed.error());
    }

    foundation::Result<account::VerificationChallenge> PostgresAccountRepository::consume(
        const account::VerificationId& id, const account::VerificationDigest& presented,
        foundation::Instant now, std::uint32_t maximumAttempts,
        const identity::core::IdentityId* expectedIdentity)
    {
        if (maximumAttempts == 0U) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "Verification attempt policy is invalid.");
        }
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return foundation::fail(begun.error());
        const auto failTransaction = [&](const foundation::Error& error)
            -> foundation::Result<account::VerificationChallenge> {
            rollback(connection);
            return foundation::fail(error);
        };

        ResultPointer row = execParams(
            connection,
            "SELECT identity_id,purpose,channel,destination,encode(secret_digest,'hex'),"
            "attempts,created_at_ms,expires_at_ms "
            "FROM openproof.account_verification_challenges WHERE id=$1 FOR UPDATE",
            {std::string{id.value()}});
        if (!tuplesOk(row.get())) {
            return failTransaction(databaseError(row.get(), "consume account verification challenge"));
        }
        if (PQntuples(row.get()) != 1) {
            rollback(connection);
            return foundation::fail(authenticationFailure(
                "Verification challenge is unknown or consumed."));
        }
        if (expectedIdentity != nullptr
            && field(row.get(), 0, 0) != expectedIdentity->value()) {
            rollback(connection);
            return foundation::fail(authenticationFailure(
                "Verification challenge does not belong to the authenticated identity."));
        }

        auto purpose = parseInteger<unsigned int>(field(row.get(), 0, 1));
        auto channel = parseInteger<unsigned int>(field(row.get(), 0, 2));
        auto attempts = parseInteger<std::uint32_t>(field(row.get(), 0, 5));
        auto created = parseInteger<std::int64_t>(field(row.get(), 0, 6));
        auto expires = parseInteger<std::int64_t>(field(row.get(), 0, 7));
        auto decoded = foundation::fromHex(field(row.get(), 0, 4));
        if (!purpose || !channel || !attempts || !created || !expires
            || purpose.value() > 3U || channel.value() > 1U
            || !decoded.has_value() || decoded->size() != 32U) {
            return failTransaction(foundation::Error{
                foundation::ErrorCode::Internal,
                std::string{foundation::defaultErrorMessage(foundation::ErrorCode::Internal)},
                "PostgreSQL returned malformed account verification data."});
        }

        std::array<std::byte, 32> storedBytes{};
        std::ranges::copy(decoded.value(), storedBytes.begin());
        const account::VerificationDigest stored{storedBytes};
        const foundation::Instant expiresAt = storedInstant(expires.value());
        if (now >= expiresAt || attempts.value() >= maximumAttempts) {
            auto removed = runCommand(
                connection,
                "DELETE FROM openproof.account_verification_challenges WHERE id=$1",
                {std::string{id.value()}}, "expire account verification challenge");
            if (!removed) return failTransaction(removed.error());
            auto committed = commit(connection);
            if (!committed) return failTransaction(committed.error());
            return foundation::fail(authenticationFailure(
                "Verification challenge expired or exhausted."));
        }

        if (!security::constantTimeEquals(stored.bytes(), presented.bytes())) {
            const std::uint32_t nextAttempts = attempts.value() + 1U;
            foundation::Status changed = nextAttempts >= maximumAttempts
                ? runCommand(connection,
                    "DELETE FROM openproof.account_verification_challenges WHERE id=$1",
                    {std::string{id.value()}}, "exhaust account verification challenge")
                : runCommand(connection,
                    "UPDATE openproof.account_verification_challenges SET attempts=$2 WHERE id=$1",
                    {std::string{id.value()}, integer(static_cast<std::int64_t>(nextAttempts))},
                    "record account verification mismatch");
            if (!changed) return failTransaction(changed.error());
            auto committed = commit(connection);
            if (!committed) return failTransaction(committed.error());
            return foundation::fail(authenticationFailure(
                "Verification secret did not match."));
        }

        auto restored = account::VerificationChallenge::restore(
            id, identity::core::IdentityId{field(row.get(), 0, 0)},
            static_cast<account::VerificationPurpose>(purpose.value()),
            static_cast<account::VerificationChannel>(channel.value()),
            field(row.get(), 0, 3), stored,
            storedInstant(created.value()), expiresAt, attempts.value());
        if (!restored) return failTransaction(restored.error());

        auto removed = runCommand(
            connection,
            "DELETE FROM openproof.account_verification_challenges WHERE id=$1",
            {std::string{id.value()}}, "consume account verification challenge");
        if (!removed) return failTransaction(removed.error());
        auto committed = commit(connection);
        if (!committed) return failTransaction(committed.error());
        return std::move(restored).value();
    }

    foundation::Status PostgresAccountRepository::reserveSubject(
        const identity::core::ExternalIdentityRef& external,
        const identity::core::IdentityId& identity,
        foundation::Instant now, foundation::Instant expiresAt)
    {
        if (external.providerId().empty() || external.subject().empty() || identity.empty()
            || expiresAt <= now) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "An account subject reservation is invalid.");
        }
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        const auto failTransaction = [&](const foundation::Error& error) {
            rollback(connection);
            return foundation::fail(error);
        };

        auto expired = runCommand(
            connection,
            "DELETE FROM openproof.pending_external_identity_reservations "
            "WHERE provider=$1 AND external_subject=$2 AND expires_at_ms<=$3",
            {std::string{external.providerId().value()}, std::string{external.subject().value()},
             instant(now)}, "expire pending external identity reservation");
        if (!expired) return failTransaction(expired.error());

        ResultPointer existing = execParams(
            connection,
            "SELECT identity_id FROM openproof.pending_external_identity_reservations "
            "WHERE provider=$1 AND external_subject=$2 FOR UPDATE",
            {std::string{external.providerId().value()}, std::string{external.subject().value()}});
        if (!tuplesOk(existing.get())) {
            return failTransaction(databaseError(existing.get(), "read pending external identity reservation"));
        }
        foundation::Status changed = foundation::ok();
        if (PQntuples(existing.get()) == 1) {
            if (field(existing.get(), 0, 0) != identity.value()) {
                rollback(connection);
                return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                        "That account identifier is already reserved.");
            }
            changed = runCommand(
                connection,
                "UPDATE openproof.pending_external_identity_reservations SET expires_at_ms=$3 "
                "WHERE provider=$1 AND external_subject=$2",
                {std::string{external.providerId().value()}, std::string{external.subject().value()},
                 instant(expiresAt)}, "extend pending external identity reservation");
        } else {
            changed = runCommand(
                connection,
                "INSERT INTO openproof.pending_external_identity_reservations("
                "provider,external_subject,identity_id,expires_at_ms) VALUES($1,$2,$3,$4)",
                {std::string{external.providerId().value()}, std::string{external.subject().value()},
                 std::string{identity.value()}, instant(expiresAt)},
                "reserve pending external identity subject");
        }
        if (!changed) return failTransaction(changed.error());
        auto committed = commit(connection);
        return committed ? committed : failTransaction(committed.error());
    }

    foundation::Result<std::optional<identity::core::IdentityId>>
    PostgresAccountRepository::reservedOwner(
        const identity::core::ExternalIdentityRef& external,
        foundation::Instant now) const
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(
            lease->get(),
            "SELECT identity_id FROM openproof.pending_external_identity_reservations "
            "WHERE provider=$1 AND external_subject=$2 AND expires_at_ms>$3",
            {std::string{external.providerId().value()}, std::string{external.subject().value()},
             instant(now)});
        if (!tuplesOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "read pending external identity reservation"));
        }
        if (PQntuples(result.get()) == 0) {
            return std::optional<identity::core::IdentityId>{};
        }
        return std::optional<identity::core::IdentityId>{
            identity::core::IdentityId{field(result.get(), 0, 0)}};
    }

    foundation::Status PostgresAccountRepository::releaseSubject(
        const identity::core::ExternalIdentityRef& external,
        const identity::core::IdentityId& expectedOwner)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        const auto failTransaction = [&](const foundation::Error& error) {
            rollback(connection);
            return foundation::fail(error);
        };
        ResultPointer existing = execParams(
            connection,
            "SELECT identity_id FROM openproof.pending_external_identity_reservations "
            "WHERE provider=$1 AND external_subject=$2 FOR UPDATE",
            {std::string{external.providerId().value()}, std::string{external.subject().value()}});
        if (!tuplesOk(existing.get())) {
            return failTransaction(databaseError(existing.get(), "release pending external identity reservation"));
        }
        if (PQntuples(existing.get()) == 0) {
            auto committed = commit(connection);
            return committed ? committed : failTransaction(committed.error());
        }
        if (field(existing.get(), 0, 0) != expectedOwner.value()) {
            rollback(connection);
            return foundation::fail(foundation::ErrorCode::PermissionDenied,
                                    "That account reservation belongs to another identity.");
        }
        auto removed = runCommand(
            connection,
            "DELETE FROM openproof.pending_external_identity_reservations "
            "WHERE provider=$1 AND external_subject=$2",
            {std::string{external.providerId().value()}, std::string{external.subject().value()}},
            "release pending external identity reservation");
        if (!removed) return failTransaction(removed.error());
        auto committed = commit(connection);
        return committed ? committed : failTransaction(committed.error());
    }

    PostgresResourceRepository::PostgresResourceRepository(ConnectionPool& pool)
        : m_pool(&pool)
    {
    }

    foundation::Status PostgresResourceRepository::add(resource::ResourceServer value)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        ResultPointer inserted = execParams(
            connection,
            "INSERT INTO openproof.oauth_resources"
            "(id,audience,display_name,status,created_at_ms,updated_at_ms) "
            "VALUES($1,$2,$3,$4,$5,$6)",
            {std::string{value.id().value()}, std::string{value.audience()},
             std::string{value.displayName()},
             integer(static_cast<unsigned int>(value.status())),
             instant(value.createdAt()), instant(value.updatedAt())});
        if (!commandOk(inserted.get())) {
            auto failure = databaseError(inserted.get(), "insert OAuth resource");
            rollback(connection);
            return foundation::fail(failure);
        }
        for (const auto& scope : value.scopes()) {
            auto status = runCommand(
                connection,
                "INSERT INTO openproof.oauth_resource_scopes(resource_id,scope) "
                "VALUES($1,$2)",
                {std::string{value.id().value()}, scope},
                "insert OAuth resource scope");
            if (!status) {
                rollback(connection);
                return status;
            }
        }
        return commit(connection);
    }

    foundation::Status PostgresResourceRepository::save(
        const resource::ResourceServer& value)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        ResultPointer updated = execParams(
            connection,
            "UPDATE openproof.oauth_resources SET display_name=$2,status=$3,updated_at_ms=$4 "
            "WHERE id=$1 AND audience=$5",
            {std::string{value.id().value()}, std::string{value.displayName()},
             integer(static_cast<unsigned int>(value.status())), instant(value.updatedAt()),
             std::string{value.audience()}});
        if (!commandOk(updated.get()) || std::string_view{PQcmdTuples(updated.get())} != "1") {
            const auto failure = commandOk(updated.get())
                ? foundation::Error{foundation::ErrorCode::NotFound}
                : databaseError(updated.get(), "save OAuth resource");
            rollback(connection);
            return foundation::fail(failure);
        }
        auto removed = runCommand(
            connection,
            "DELETE FROM openproof.oauth_resource_scopes WHERE resource_id=$1",
            {std::string{value.id().value()}}, "replace OAuth resource scopes");
        if (!removed) {
            rollback(connection);
            return removed;
        }
        for (const auto& scope : value.scopes()) {
            auto status = runCommand(
                connection,
                "INSERT INTO openproof.oauth_resource_scopes(resource_id,scope) VALUES($1,$2)",
                {std::string{value.id().value()}, scope}, "insert OAuth resource scope");
            if (!status) {
                rollback(connection);
                return status;
            }
        }
        return commit(connection);
    }

    foundation::Result<std::optional<resource::ResourceServer>>
    PostgresResourceRepository::findByAudience(std::string_view audience) const
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(
            lease->get(),
            "SELECT id,audience,display_name,status,created_at_ms,updated_at_ms "
            "FROM openproof.oauth_resources WHERE audience=$1",
            {std::string{audience}});
        if (!tuplesOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "find OAuth resource"));
        }
        if (PQntuples(result.get()) == 0) return std::optional<resource::ResourceServer>{};
        auto restored = resourceFromRow(lease->get(), result.get(), 0);
        if (!restored) return foundation::fail(restored.error());
        return std::optional<resource::ResourceServer>{std::move(restored).value()};
    }

    foundation::Result<std::vector<resource::ResourceServer>>
    PostgresResourceRepository::list() const
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = exec(
            lease->get(),
            "SELECT id,audience,display_name,status,created_at_ms,updated_at_ms "
            "FROM openproof.oauth_resources ORDER BY audience");
        if (!tuplesOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "list OAuth resources"));
        }
        std::vector<resource::ResourceServer> values;
        values.reserve(static_cast<std::size_t>(PQntuples(result.get())));
        for (int row = 0; row < PQntuples(result.get()); ++row) {
            auto restored = resourceFromRow(lease->get(), result.get(), row);
            if (!restored) return foundation::fail(restored.error());
            values.push_back(std::move(restored).value());
        }
        return values;
    }

    foundation::Status PostgresResourceRepository::saveService(
        resource::ServiceIdentity value)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        ResultPointer current = execParams(
            connection,
            "SELECT identity_id FROM openproof.service_identities WHERE client_id=$1 FOR UPDATE",
            {std::string{value.client().value()}});
        if (!tuplesOk(current.get())) {
            auto failure = databaseError(current.get(), "lock service identity");
            rollback(connection);
            return foundation::fail(failure);
        }
        if (PQntuples(current.get()) == 1
            && field(current.get(), 0, 0) != value.identity().value()) {
            rollback(connection);
            return foundation::fail(
                foundation::ErrorCode::FailedPrecondition,
                "A service client cannot be rebound to another canonical identity.");
        }
        ResultPointer stored = execParams(
            connection,
            "INSERT INTO openproof.service_identities"
            "(client_id,identity_id,active,created_at_ms,updated_at_ms) VALUES($1,$2,$3,$4,$5) "
            "ON CONFLICT(client_id) DO UPDATE SET active=EXCLUDED.active,updated_at_ms=EXCLUDED.updated_at_ms",
            {std::string{value.client().value()}, std::string{value.identity().value()},
             value.active() ? "true" : "false", instant(value.createdAt()),
             instant(value.updatedAt())});
        if (!commandOk(stored.get())) {
            auto failure = databaseError(stored.get(), "save service identity");
            rollback(connection);
            return foundation::fail(failure);
        }
        auto removedAudiences = runCommand(
            connection,
            "DELETE FROM openproof.service_identity_audiences WHERE client_id=$1",
            {std::string{value.client().value()}}, "replace service identity audiences");
        auto removedScopes = runCommand(
            connection,
            "DELETE FROM openproof.service_identity_scopes WHERE client_id=$1",
            {std::string{value.client().value()}}, "replace service identity scopes");
        if (!removedAudiences || !removedScopes) {
            rollback(connection);
            return foundation::fail(
                (!removedAudiences ? removedAudiences : removedScopes).error());
        }
        for (const auto& audience : value.audiences()) {
            auto status = runCommand(
                connection,
                "INSERT INTO openproof.service_identity_audiences(client_id,audience) "
                "VALUES($1,$2)",
                {std::string{value.client().value()}, audience},
                "insert service identity audience");
            if (!status) {
                rollback(connection);
                return status;
            }
        }
        for (const auto& scope : value.scopes()) {
            auto status = runCommand(
                connection,
                "INSERT INTO openproof.service_identity_scopes(client_id,scope) VALUES($1,$2)",
                {std::string{value.client().value()}, scope},
                "insert service identity scope");
            if (!status) {
                rollback(connection);
                return status;
            }
        }
        return commit(connection);
    }

    foundation::Result<std::optional<resource::ServiceIdentity>>
    PostgresResourceRepository::serviceForClient(const client::ClientId& clientId) const
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(
            lease->get(),
            "SELECT client_id,identity_id,active,created_at_ms,updated_at_ms "
            "FROM openproof.service_identities WHERE client_id=$1",
            {std::string{clientId.value()}});
        if (!tuplesOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "find service identity"));
        }
        if (PQntuples(result.get()) == 0) return std::optional<resource::ServiceIdentity>{};
        auto restored = serviceIdentityFromRow(lease->get(), result.get(), 0);
        if (!restored) return foundation::fail(restored.error());
        return std::optional<resource::ServiceIdentity>{std::move(restored).value()};
    }

    PostgresConsentRepository::PostgresConsentRepository(ConnectionPool& pool)
        : m_pool(&pool)
    {
    }

    foundation::Status PostgresConsentRepository::save(consent::ConsentGrant value)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        auto superseded = runCommand(
            connection,
            "UPDATE openproof.oauth_consents SET revoked_at_ms=$5 "
            "WHERE identity_id=$1 AND client_id=$2 AND audience=$3 AND revoked_at_ms IS NULL "
            "AND (expires_at_ms IS NULL OR expires_at_ms>$4)",
            {std::string{value.identity().value()}, std::string{value.client().value()},
             std::string{value.audience()}, instant(value.grantedAt()),
             instant(value.grantedAt())},
            "supersede OAuth consent");
        if (!superseded) {
            rollback(connection);
            return superseded;
        }
        const std::string expires = value.expiresAt()
            ? instant(*value.expiresAt()) : std::string{};
        const std::string revoked = value.revokedAt()
            ? instant(*value.revokedAt()) : std::string{};
        ResultPointer inserted = execParams(
            connection,
            "INSERT INTO openproof.oauth_consents"
            "(id,identity_id,client_id,audience,granted_at_ms,expires_at_ms,revoked_at_ms) "
            "VALUES($1,$2,$3,$4,$5,CASE WHEN $6='' THEN NULL ELSE $6::bigint END,"
            "CASE WHEN $7='' THEN NULL ELSE $7::bigint END)",
            {std::string{value.id().value()}, std::string{value.identity().value()},
             std::string{value.client().value()}, std::string{value.audience()},
             instant(value.grantedAt()), expires, revoked});
        if (!commandOk(inserted.get())) {
            auto failure = databaseError(inserted.get(), "insert OAuth consent");
            rollback(connection);
            return foundation::fail(failure);
        }
        for (const auto& scope : value.scopes()) {
            auto status = runCommand(
                connection,
                "INSERT INTO openproof.oauth_consent_scopes(consent_id,scope) VALUES($1,$2)",
                {std::string{value.id().value()}, scope}, "insert OAuth consent scope");
            if (!status) {
                rollback(connection);
                return status;
            }
        }
        return commit(connection);
    }

    foundation::Result<std::optional<consent::ConsentGrant>>
    PostgresConsentRepository::findActive(
        const identity::core::IdentityId& identityId, const client::ClientId& clientId,
        std::string_view audience, foundation::Instant now) const
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(
            lease->get(),
            "SELECT id,identity_id,client_id,audience,granted_at_ms,expires_at_ms,revoked_at_ms "
            "FROM openproof.oauth_consents WHERE identity_id=$1 AND client_id=$2 AND audience=$3 "
            "AND revoked_at_ms IS NULL AND (expires_at_ms IS NULL OR expires_at_ms>$4) "
            "ORDER BY granted_at_ms DESC LIMIT 1",
            {std::string{identityId.value()}, std::string{clientId.value()},
             std::string{audience}, instant(now)});
        if (!tuplesOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "find active OAuth consent"));
        }
        if (PQntuples(result.get()) == 0) return std::optional<consent::ConsentGrant>{};
        auto restored = consentFromRow(lease->get(), result.get(), 0);
        if (!restored) return foundation::fail(restored.error());
        return std::optional<consent::ConsentGrant>{std::move(restored).value()};
    }

    foundation::Result<std::vector<consent::ConsentGrant>>
    PostgresConsentRepository::list(const identity::core::IdentityId& identityId) const
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(
            lease->get(),
            "SELECT id,identity_id,client_id,audience,granted_at_ms,expires_at_ms,revoked_at_ms "
            "FROM openproof.oauth_consents WHERE identity_id=$1 ORDER BY granted_at_ms DESC,id",
            {std::string{identityId.value()}});
        if (!tuplesOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "list OAuth consents"));
        }
        std::vector<consent::ConsentGrant> values;
        values.reserve(static_cast<std::size_t>(PQntuples(result.get())));
        for (int row = 0; row < PQntuples(result.get()); ++row) {
            auto restored = consentFromRow(lease->get(), result.get(), row);
            if (!restored) return foundation::fail(restored.error());
            values.push_back(std::move(restored).value());
        }
        return values;
    }

    foundation::Status PostgresConsentRepository::revoke(
        const consent::ConsentId& id, const identity::core::IdentityId& identityId,
        foundation::Instant now)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(
            lease->get(),
            "UPDATE openproof.oauth_consents SET revoked_at_ms=COALESCE(revoked_at_ms,$3) "
            "WHERE id=$1 AND identity_id=$2",
            {std::string{id.value()}, std::string{identityId.value()}, instant(now)});
        if (!commandOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "revoke OAuth consent"));
        }
        if (std::string_view{PQcmdTuples(result.get())} != "1") {
            return foundation::fail(foundation::ErrorCode::NotFound);
        }
        return foundation::ok();
    }

    PostgresPasskeyRepository::PostgresPasskeyRepository(ConnectionPool& pool)
        : m_pool(&pool)
    {
    }

    foundation::Status PostgresPasskeyRepository::addCeremony(
        provider::passkey::RegistrationCeremony ceremony)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        return runCommand(
            lease->get(),
            "INSERT INTO openproof.passkey_registration_ceremonies"
            "(id,identity_id,expires_at_ms) VALUES($1,$2,$3)",
            {std::string{ceremony.id.value()}, std::string{ceremony.identity.value()},
             instant(ceremony.expiresAt)},
            "insert passkey registration ceremony");
    }

    foundation::Status PostgresPasskeyRepository::consumeCeremony(
        const identity::provider::ChallengeId& id,
        const identity::core::IdentityId& identityId,
        foundation::Instant now)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(
            lease->get(),
            "UPDATE openproof.passkey_registration_ceremonies "
            "SET consumed_at_ms=$3 WHERE id=$1 AND identity_id=$2 "
            "AND consumed_at_ms IS NULL AND expires_at_ms>$3",
            {std::string{id.value()}, std::string{identityId.value()}, instant(now)});
        if (!commandOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "consume passkey registration ceremony"));
        }
        if (std::string_view{PQcmdTuples(result.get())} != "1") {
            return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        return foundation::ok();
    }

    foundation::Status PostgresPasskeyRepository::addCredential(
        provider::passkey::PasskeyCredential credential)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        return runCommand(
            lease->get(),
            "INSERT INTO openproof.passkey_credentials"
            "(credential_id,identity_id,public_key_x,public_key_y,sign_count,created_at_ms,last_used_at_ms) "
            "VALUES($1,$2,$3,$4,$5,$6,$7)",
            {credential.credentialId, std::string{credential.identity.value()},
             credential.publicKeyX, credential.publicKeyY,
             integer(static_cast<std::int64_t>(credential.signCount)),
             instant(credential.createdAt), instant(credential.lastUsedAt)},
            "insert passkey credential");
    }

    foundation::Result<std::optional<provider::passkey::PasskeyCredential>>
    PostgresPasskeyRepository::findCredential(std::string_view credentialId) const
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(
            lease->get(),
            "SELECT credential_id,identity_id,public_key_x,public_key_y,sign_count,created_at_ms,last_used_at_ms "
            "FROM openproof.passkey_credentials WHERE credential_id=$1",
            {std::string{credentialId}});
        if (!tuplesOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "find passkey credential"));
        }
        if (PQntuples(result.get()) == 0) {
            return std::optional<provider::passkey::PasskeyCredential>{};
        }
        auto count = parseInteger<std::uint32_t>(field(result.get(), 0, 4));
        auto created = parseInteger<std::int64_t>(field(result.get(), 0, 5));
        auto used = parseInteger<std::int64_t>(field(result.get(), 0, 6));
        if (!count || !created || !used) return foundation::fail(foundation::ErrorCode::Internal);
        return std::optional<provider::passkey::PasskeyCredential>{
            provider::passkey::PasskeyCredential{
                std::string{field(result.get(), 0, 0)},
                identity::core::IdentityId{std::string{field(result.get(), 0, 1)}},
                std::string{field(result.get(), 0, 2)},
                std::string{field(result.get(), 0, 3)}, count.value(),
                foundation::Instant{foundation::Duration{created.value()}},
                foundation::Instant{foundation::Duration{used.value()}}}};
    }

    foundation::Result<std::vector<provider::passkey::PasskeyCredential>>
    PostgresPasskeyRepository::listCredentials(
        const identity::core::IdentityId& identityId) const
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(
            lease->get(),
            "SELECT credential_id,identity_id,public_key_x,public_key_y,sign_count,created_at_ms,last_used_at_ms "
            "FROM openproof.passkey_credentials WHERE identity_id=$1 ORDER BY created_at_ms,credential_id",
            {std::string{identityId.value()}});
        if (!tuplesOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "list passkey credentials"));
        }
        std::vector<provider::passkey::PasskeyCredential> output;
        output.reserve(static_cast<std::size_t>(PQntuples(result.get())));
        for (int row = 0; row < PQntuples(result.get()); ++row) {
            auto count = parseInteger<std::uint32_t>(field(result.get(), row, 4));
            auto created = parseInteger<std::int64_t>(field(result.get(), row, 5));
            auto used = parseInteger<std::int64_t>(field(result.get(), row, 6));
            if (!count || !created || !used) return foundation::fail(foundation::ErrorCode::Internal);
            output.push_back(provider::passkey::PasskeyCredential{
                std::string{field(result.get(), row, 0)},
                identity::core::IdentityId{std::string{field(result.get(), row, 1)}},
                std::string{field(result.get(), row, 2)},
                std::string{field(result.get(), row, 3)}, count.value(),
                foundation::Instant{foundation::Duration{created.value()}},
                foundation::Instant{foundation::Duration{used.value()}}});
        }
        return output;
    }

    foundation::Status PostgresPasskeyRepository::advanceCounter(
        std::string_view credentialId, std::uint32_t expected,
        std::uint32_t replacement, foundation::Instant usedAt)
    {
        const bool counterUnsupported = expected == 0U && replacement == 0U;
        if (!counterUnsupported && replacement <= expected) {
            return foundation::fail(foundation::ErrorCode::Conflict);
        }
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(
            lease->get(),
            "UPDATE openproof.passkey_credentials "
            "SET sign_count=$3,last_used_at_ms=GREATEST(last_used_at_ms,$4) "
            "WHERE credential_id=$1 AND sign_count=$2",
            {std::string{credentialId}, integer(static_cast<std::int64_t>(expected)),
             integer(static_cast<std::int64_t>(replacement)), instant(usedAt)});
        if (!commandOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "advance passkey signature counter"));
        }
        return std::string_view{PQcmdTuples(result.get())} == "1"
            ? foundation::ok() : foundation::fail(foundation::ErrorCode::Conflict);
    }

    foundation::Status PostgresPasskeyRepository::removeCredentialIfAnotherExists(
        const identity::core::IdentityId& identityId,
        std::string_view credentialId)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        const auto failTransaction = [&](foundation::Error error) -> foundation::Status {
            rollback(connection);
            return foundation::fail(std::move(error));
        };

        ResultPointer locked = execParams(
            connection,
            "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 684271993))",
            {std::string{identityId.value()}});
        if (!tuplesOk(locked.get())) {
            return failTransaction(databaseError(locked.get(), "lock passkey credentials"));
        }

        ResultPointer counts = execParams(
            connection,
            "SELECT count(*), count(*) FILTER (WHERE credential_id=$2) "
            "FROM openproof.passkey_credentials WHERE identity_id=$1",
            {std::string{identityId.value()}, std::string{credentialId}});
        if (!tuplesOk(counts.get()) || PQntuples(counts.get()) != 1) {
            return failTransaction(databaseError(counts.get(), "count passkey credentials"));
        }
        auto total = parseInteger<std::size_t>(field(counts.get(), 0, 0));
        auto matching = parseInteger<std::size_t>(field(counts.get(), 0, 1));
        if (!total || !matching) {
            return failTransaction(foundation::Error{foundation::ErrorCode::Internal});
        }
        if (matching.value() != 1U) {
            return failTransaction(foundation::Error{foundation::ErrorCode::NotFound});
        }
        if (total.value() <= 1U) {
            return failTransaction(foundation::Error{
                foundation::ErrorCode::FailedPrecondition,
                "The final passkey credential cannot be removed while passkey sign-in is connected."});
        }

        ResultPointer removed = execParams(
            connection,
            "DELETE FROM openproof.passkey_credentials WHERE credential_id=$1 AND identity_id=$2",
            {std::string{credentialId}, std::string{identityId.value()}});
        if (!commandOk(removed.get()) || std::string_view{PQcmdTuples(removed.get())} != "1") {
            return failTransaction(databaseError(removed.get(), "remove passkey credential"));
        }
        auto committed = commit(connection);
        if (!committed) return foundation::fail(committed.error());
        return foundation::ok();
    }

    foundation::Status PostgresPasskeyRepository::removeCredential(
        const identity::core::IdentityId& identityId,
        std::string_view credentialId)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(
            lease->get(),
            "DELETE FROM openproof.passkey_credentials WHERE credential_id=$1 AND identity_id=$2",
            {std::string{credentialId}, std::string{identityId.value()}});
        if (!commandOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "remove passkey credential"));
        }
        return std::string_view{PQcmdTuples(result.get())} == "1"
            ? foundation::ok() : foundation::fail(foundation::ErrorCode::NotFound);
    }


PostgresScimDirectoryRepository::PostgresScimDirectoryRepository(ConnectionPool& pool)
    : m_pool(&pool) {}

foundation::Status PostgresScimDirectoryRepository::addUser(enterprise::scim::UserRecord user)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "INSERT INTO openproof.scim_users(identity_id,organization_id,user_name,external_id,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,$3,NULLIF($4,''),$5,$6)",
        {std::string{user.identity().value()}, std::string{user.organization().value()},
         std::string{user.userName()}, user.externalId().value_or(std::string{}),
         instant(user.createdAt()), instant(user.updatedAt())});
    if (!commandOk(result.get())) return foundation::fail(databaseError(result.get(), "insert SCIM user"));
    return foundation::ok();
}

foundation::Status PostgresScimDirectoryRepository::saveUser(const enterprise::scim::UserRecord& user)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "UPDATE openproof.scim_users SET user_name=$3,external_id=NULLIF($4,''),updated_at_ms=$5 "
        "WHERE organization_id=$1 AND identity_id=$2",
        {std::string{user.organization().value()}, std::string{user.identity().value()},
         std::string{user.userName()}, user.externalId().value_or(std::string{}), instant(user.updatedAt())});
    if (!commandOk(result.get())) return foundation::fail(databaseError(result.get(), "save SCIM user"));
    if (std::string_view{PQcmdTuples(result.get())} != "1") return foundation::fail(foundation::ErrorCode::NotFound);
    return foundation::ok();
}

foundation::Status PostgresScimDirectoryRepository::removeUser(
    const identity::core::OrganizationId& organization,
    const identity::core::IdentityId& identityId)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "DELETE FROM openproof.scim_users WHERE organization_id=$1 AND identity_id=$2",
        {std::string{organization.value()}, std::string{identityId.value()}});
    if (!commandOk(result.get())) return foundation::fail(databaseError(result.get(), "remove SCIM user"));
    if (std::string_view{PQcmdTuples(result.get())} != "1") return foundation::fail(foundation::ErrorCode::NotFound);
    return foundation::ok();
}

foundation::Result<std::optional<enterprise::scim::UserRecord>>
PostgresScimDirectoryRepository::findUser(
    const identity::core::OrganizationId& organization,
    const identity::core::IdentityId& identityId) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT identity_id,organization_id,user_name,external_id,created_at_ms,updated_at_ms "
        "FROM openproof.scim_users WHERE organization_id=$1 AND identity_id=$2",
        {std::string{organization.value()}, std::string{identityId.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "find SCIM user"));
    if (PQntuples(result.get()) == 0) return std::optional<enterprise::scim::UserRecord>{};
    auto created = parseInteger<std::int64_t>(field(result.get(), 0, 4));
    auto updated = parseInteger<std::int64_t>(field(result.get(), 0, 5));
    if (!created || !updated) return foundation::fail(foundation::ErrorCode::Internal);
    std::optional<std::string> external;
    if (!PQgetisnull(result.get(), 0, 3)) external = field(result.get(), 0, 3);
    auto record = enterprise::scim::UserRecord::create(
        identity::core::IdentityId{field(result.get(), 0, 0)},
        identity::core::OrganizationId{field(result.get(), 0, 1)}, field(result.get(), 0, 2),
        std::move(external), storedInstant(created.value()), storedInstant(updated.value()));
    if (!record) return foundation::fail(record.error());
    return std::optional<enterprise::scim::UserRecord>{std::move(record).value()};
}

foundation::Result<std::optional<enterprise::scim::UserRecord>>
PostgresScimDirectoryRepository::findUserByName(
    const identity::core::OrganizationId& organization, std::string_view userName) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT identity_id,organization_id,user_name,external_id,created_at_ms,updated_at_ms "
        "FROM openproof.scim_users WHERE organization_id=$1 AND user_name=$2",
        {std::string{organization.value()}, std::string{userName}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "find SCIM user by name"));
    if (PQntuples(result.get()) == 0) return std::optional<enterprise::scim::UserRecord>{};
    auto created = parseInteger<std::int64_t>(field(result.get(), 0, 4));
    auto updated = parseInteger<std::int64_t>(field(result.get(), 0, 5));
    if (!created || !updated) return foundation::fail(foundation::ErrorCode::Internal);
    std::optional<std::string> external;
    if (!PQgetisnull(result.get(), 0, 3)) external = field(result.get(), 0, 3);
    auto record = enterprise::scim::UserRecord::create(
        identity::core::IdentityId{field(result.get(), 0, 0)},
        identity::core::OrganizationId{field(result.get(), 0, 1)}, field(result.get(), 0, 2),
        std::move(external), storedInstant(created.value()), storedInstant(updated.value()));
    if (!record) return foundation::fail(record.error());
    return std::optional<enterprise::scim::UserRecord>{std::move(record).value()};
}

foundation::Result<std::vector<enterprise::scim::UserRecord>>
PostgresScimDirectoryRepository::users(const identity::core::OrganizationId& organization) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT identity_id,organization_id,user_name,external_id,created_at_ms,updated_at_ms "
        "FROM openproof.scim_users WHERE organization_id=$1 ORDER BY user_name,identity_id",
        {std::string{organization.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "list SCIM users"));
    std::vector<enterprise::scim::UserRecord> output;
    output.reserve(static_cast<std::size_t>(PQntuples(result.get())));
    for (int row = 0; row < PQntuples(result.get()); ++row) {
        auto created = parseInteger<std::int64_t>(field(result.get(), row, 4));
        auto updated = parseInteger<std::int64_t>(field(result.get(), row, 5));
        if (!created || !updated) return foundation::fail(foundation::ErrorCode::Internal);
        std::optional<std::string> external;
        if (!PQgetisnull(result.get(), row, 3)) external = field(result.get(), row, 3);
        auto record = enterprise::scim::UserRecord::create(
            identity::core::IdentityId{field(result.get(), row, 0)},
            identity::core::OrganizationId{field(result.get(), row, 1)}, field(result.get(), row, 2),
            std::move(external), storedInstant(created.value()), storedInstant(updated.value()));
        if (!record) return foundation::fail(record.error());
        output.push_back(std::move(record).value());
    }
    return output;
}

foundation::Status PostgresScimDirectoryRepository::addGroup(enterprise::scim::GroupRecord group)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "INSERT INTO openproof.scim_groups(id,organization_id,display_name,external_id,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,$3,NULLIF($4,''),$5,$6)",
        {std::string{group.id().value()}, std::string{group.organization().value()},
         std::string{group.displayName()}, group.externalId().value_or(std::string{}),
         instant(group.createdAt()), instant(group.updatedAt())});
    if (!commandOk(result.get())) return foundation::fail(databaseError(result.get(), "insert SCIM group"));
    return foundation::ok();
}

foundation::Status PostgresScimDirectoryRepository::saveGroup(const enterprise::scim::GroupRecord& group)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "UPDATE openproof.scim_groups SET display_name=$3,external_id=NULLIF($4,''),updated_at_ms=$5 "
        "WHERE organization_id=$1 AND id=$2",
        {std::string{group.organization().value()}, std::string{group.id().value()},
         std::string{group.displayName()}, group.externalId().value_or(std::string{}), instant(group.updatedAt())});
    if (!commandOk(result.get())) return foundation::fail(databaseError(result.get(), "save SCIM group"));
    if (std::string_view{PQcmdTuples(result.get())} != "1") return foundation::fail(foundation::ErrorCode::NotFound);
    return foundation::ok();
}

foundation::Status PostgresScimDirectoryRepository::removeGroup(
    const identity::core::OrganizationId& organization, const enterprise::scim::GroupId& id)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "DELETE FROM openproof.scim_groups WHERE organization_id=$1 AND id=$2",
        {std::string{organization.value()}, std::string{id.value()}});
    if (!commandOk(result.get())) return foundation::fail(databaseError(result.get(), "remove SCIM group"));
    if (std::string_view{PQcmdTuples(result.get())} != "1") return foundation::fail(foundation::ErrorCode::NotFound);
    return foundation::ok();
}

foundation::Result<std::optional<enterprise::scim::GroupRecord>>
PostgresScimDirectoryRepository::findGroup(
    const identity::core::OrganizationId& organization, const enterprise::scim::GroupId& id) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT id,organization_id,display_name,external_id,created_at_ms,updated_at_ms "
        "FROM openproof.scim_groups WHERE organization_id=$1 AND id=$2",
        {std::string{organization.value()}, std::string{id.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "find SCIM group"));
    if (PQntuples(result.get()) == 0) return std::optional<enterprise::scim::GroupRecord>{};
    auto created = parseInteger<std::int64_t>(field(result.get(), 0, 4));
    auto updated = parseInteger<std::int64_t>(field(result.get(), 0, 5));
    if (!created || !updated) return foundation::fail(foundation::ErrorCode::Internal);
    std::optional<std::string> external;
    if (!PQgetisnull(result.get(), 0, 3)) external = field(result.get(), 0, 3);
    auto record = enterprise::scim::GroupRecord::create(
        enterprise::scim::GroupId{field(result.get(), 0, 0)},
        identity::core::OrganizationId{field(result.get(), 0, 1)}, field(result.get(), 0, 2),
        std::move(external), storedInstant(created.value()), storedInstant(updated.value()));
    if (!record) return foundation::fail(record.error());
    return std::optional<enterprise::scim::GroupRecord>{std::move(record).value()};
}

foundation::Result<std::optional<enterprise::scim::GroupRecord>>
PostgresScimDirectoryRepository::findGroupByName(
    const identity::core::OrganizationId& organization, std::string_view displayName) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT id,organization_id,display_name,external_id,created_at_ms,updated_at_ms "
        "FROM openproof.scim_groups WHERE organization_id=$1 AND display_name=$2",
        {std::string{organization.value()}, std::string{displayName}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "find SCIM group by name"));
    if (PQntuples(result.get()) == 0) return std::optional<enterprise::scim::GroupRecord>{};
    auto created = parseInteger<std::int64_t>(field(result.get(), 0, 4));
    auto updated = parseInteger<std::int64_t>(field(result.get(), 0, 5));
    if (!created || !updated) return foundation::fail(foundation::ErrorCode::Internal);
    std::optional<std::string> external;
    if (!PQgetisnull(result.get(), 0, 3)) external = field(result.get(), 0, 3);
    auto record = enterprise::scim::GroupRecord::create(
        enterprise::scim::GroupId{field(result.get(), 0, 0)},
        identity::core::OrganizationId{field(result.get(), 0, 1)}, field(result.get(), 0, 2),
        std::move(external), storedInstant(created.value()), storedInstant(updated.value()));
    if (!record) return foundation::fail(record.error());
    return std::optional<enterprise::scim::GroupRecord>{std::move(record).value()};
}

foundation::Result<std::vector<enterprise::scim::GroupRecord>>
PostgresScimDirectoryRepository::groups(const identity::core::OrganizationId& organization) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT id,organization_id,display_name,external_id,created_at_ms,updated_at_ms "
        "FROM openproof.scim_groups WHERE organization_id=$1 ORDER BY display_name,id",
        {std::string{organization.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "list SCIM groups"));
    std::vector<enterprise::scim::GroupRecord> output;
    output.reserve(static_cast<std::size_t>(PQntuples(result.get())));
    for (int row = 0; row < PQntuples(result.get()); ++row) {
        auto created = parseInteger<std::int64_t>(field(result.get(), row, 4));
        auto updated = parseInteger<std::int64_t>(field(result.get(), row, 5));
        if (!created || !updated) return foundation::fail(foundation::ErrorCode::Internal);
        std::optional<std::string> external;
        if (!PQgetisnull(result.get(), row, 3)) external = field(result.get(), row, 3);
        auto record = enterprise::scim::GroupRecord::create(
            enterprise::scim::GroupId{field(result.get(), row, 0)},
            identity::core::OrganizationId{field(result.get(), row, 1)}, field(result.get(), row, 2),
            std::move(external), storedInstant(created.value()), storedInstant(updated.value()));
        if (!record) return foundation::fail(record.error());
        output.push_back(std::move(record).value());
    }
    return output;
}

foundation::Result<std::vector<identity::core::IdentityId>>
PostgresScimDirectoryRepository::groupMembers(
    const identity::core::OrganizationId& organization, const enterprise::scim::GroupId& id) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer exists = execParams(lease->get(),
        "SELECT 1 FROM openproof.scim_groups WHERE organization_id=$1 AND id=$2",
        {std::string{organization.value()}, std::string{id.value()}});
    if (!tuplesOk(exists.get())) return foundation::fail(databaseError(exists.get(), "find SCIM group for membership"));
    if (PQntuples(exists.get()) == 0) return foundation::fail(foundation::ErrorCode::NotFound);
    ResultPointer result = execParams(lease->get(),
        "SELECT identity_id FROM openproof.scim_group_members WHERE organization_id=$1 AND group_id=$2 ORDER BY identity_id",
        {std::string{organization.value()}, std::string{id.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "list SCIM group members"));
    std::vector<identity::core::IdentityId> output;
    output.reserve(static_cast<std::size_t>(PQntuples(result.get())));
    for (int row = 0; row < PQntuples(result.get()); ++row) output.emplace_back(field(result.get(), row, 0));
    return output;
}

foundation::Status PostgresScimDirectoryRepository::replaceGroupMembers(
    const identity::core::OrganizationId& organization, const enterprise::scim::GroupId& id,
    std::vector<identity::core::IdentityId> members)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) {
        return foundation::fail(lease.error());
    }

    PGconn* connection = lease->get();
    auto begun = beginTransaction(connection);
    if (!begun) {
        return begun;
    }

    ResultPointer group = execParams(
        connection,
        "SELECT 1 FROM openproof.scim_groups WHERE organization_id=$1 AND id=$2 FOR UPDATE",
        {std::string{organization.value()}, std::string{id.value()}});
    if (!tuplesOk(group.get())) {
        auto error = databaseError(group.get(), "lock SCIM group");
        rollback(connection);
        return foundation::fail(error);
    }
    if (PQntuples(group.get()) != 1) {
        rollback(connection);
        return foundation::fail(foundation::ErrorCode::NotFound);
    }

    auto removed = runCommand(
        connection,
        "DELETE FROM openproof.scim_group_members WHERE organization_id=$1 AND group_id=$2",
        {std::string{organization.value()}, std::string{id.value()}},
        "replace SCIM group members");
    if (!removed) {
        rollback(connection);
        return removed;
    }

    for (const auto& member : members) {
        auto inserted = runCommand(
            connection,
            "INSERT INTO openproof.scim_group_members(organization_id,group_id,identity_id) "
            "VALUES($1,$2,$3)",
            {std::string{organization.value()}, std::string{id.value()},
             std::string{member.value()}},
            "insert SCIM group member");
        if (!inserted) {
            rollback(connection);
            return inserted;
        }
    }
    return commit(connection);
}

    PostgresEvidenceChallengeStore::PostgresEvidenceChallengeStore(ConnectionPool& pool)
    : m_pool(&pool)
{
}

foundation::Status PostgresEvidenceChallengeStore::add(
    evidence::verification::Challenge challenge)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "INSERT INTO openproof.evidence_verification_challenges"
        "(digest,identity_id,provider,issued_at_ms,expires_at_ms,consumed_at_ms) "
        "VALUES($1,$2,$3,$4,$5,NULL)",
        {std::string{challenge.digest().value()}, std::string{challenge.identity().value()},
         std::string{challenge.provider().value()}, instant(challenge.issuedAt()),
         instant(challenge.expiresAt())});
    if (!commandOk(result.get())) {
        return foundation::fail(databaseError(result.get(), "insert evidence verification challenge"));
    }
    return foundation::ok();
}

foundation::Status PostgresEvidenceChallengeStore::consume(
    const evidence::verification::ChallengeDigest& digest,
    const identity::core::IdentityId& identity,
    const identity::provider::ProviderId& provider,
    foundation::Instant now)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "UPDATE openproof.evidence_verification_challenges "
        "SET consumed_at_ms=$4 "
        "WHERE digest=$1 AND identity_id=$2 AND provider=$3 "
        "AND consumed_at_ms IS NULL AND expires_at_ms>$4",
        {std::string{digest.value()}, std::string{identity.value()},
         std::string{provider.value()}, instant(now)});
    if (!commandOk(result.get())) {
        return foundation::fail(databaseError(result.get(), "consume evidence verification challenge"));
    }
    if (std::string_view{PQcmdTuples(result.get())} != "1") {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The evidence verification challenge is invalid or expired.");
    }
    return foundation::ok();
}

PostgresIdentityProviderStore::PostgresIdentityProviderStore(ConnectionPool& pool)
    : m_pool(&pool) {}

    foundation::Status PostgresIdentityProviderStore::add(application::Application value)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        return runCommand(lease->get(),
        "INSERT INTO openproof.applications(id,organization_id,identifier,display_name,environment,status,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
        {std::string{value.id().value()}, std::string{value.owner().value()},
            std::string{value.identifier()}, std::string{value.displayName()},
            integer(static_cast<unsigned int>(value.environment())),
            integer(static_cast<unsigned int>(value.status())),
            instant(value.createdAt()), instant(value.updatedAt())},
        "insert application");
    }

    foundation::Status PostgresIdentityProviderStore::save(const application::Application& value)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(lease->get(),
        "UPDATE openproof.applications SET display_name=$2,status=$3,updated_at_ms=$4 "
        "WHERE id=$1 AND organization_id=$5 AND identifier=$6 AND environment=$7",
        {std::string{value.id().value()}, std::string{value.displayName()},
            integer(static_cast<unsigned int>(value.status())), instant(value.updatedAt()),
            std::string{value.owner().value()}, std::string{value.identifier()},
            integer(static_cast<unsigned int>(value.environment()))});
        if (!commandOk(result.get())) return foundation::fail(databaseError(result.get(), "save application"));
        return std::string_view{PQcmdTuples(result.get())} == "1" ? foundation::ok()
        : foundation::fail(foundation::ErrorCode::NotFound);
    }

    foundation::Result<std::optional<application::Application>>
    PostgresIdentityProviderStore::findById(const application::ApplicationId& id) const
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(lease->get(),
        "SELECT id,organization_id,identifier,display_name,environment,status,created_at_ms,updated_at_ms "
        "FROM openproof.applications WHERE id=$1", {std::string{id.value()}});
        if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "find application"));
        if (PQntuples(result.get()) == 0) return std::optional<application::Application>{};
        auto value = applicationFromRow(result.get(), 0);
        if (!value) return foundation::fail(value.error());
        return std::optional<application::Application>{std::move(value).value()};
    }

    foundation::Result<std::optional<application::Application>>
    PostgresIdentityProviderStore::findByIdentifier(
    const identity::core::OrganizationId& owner, std::string_view identifierValue) const
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(lease->get(),
        "SELECT id,organization_id,identifier,display_name,environment,status,created_at_ms,updated_at_ms "
        "FROM openproof.applications WHERE organization_id=$1 AND identifier=$2",
        {std::string{owner.value()}, std::string{identifierValue}});
        if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "find application by identifier"));
        if (PQntuples(result.get()) == 0) return std::optional<application::Application>{};
        auto value = applicationFromRow(result.get(), 0);
        if (!value) return foundation::fail(value.error());
        return std::optional<application::Application>{std::move(value).value()};
    }

    foundation::Result<std::vector<application::Application>> PostgresIdentityProviderStore::list() const
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = exec(lease->get(),
        "SELECT id,organization_id,identifier,display_name,environment,status,created_at_ms,updated_at_ms "
        "FROM openproof.applications ORDER BY identifier");
        if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "list applications"));
        std::vector<application::Application> output;
        for (int row = 0; row < PQntuples(result.get()); ++row) {
            auto value = applicationFromRow(result.get(), row);
            if (!value) return foundation::fail(value.error());
            output.push_back(std::move(value).value());
        }
        return output;
    }

    foundation::Status PostgresIdentityProviderStore::add(client::Client value)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        const std::string secretHex = value.secretDigest() ? foundation::toHex(value.secretDigest()->bytes()) : std::string{};
        ResultPointer inserted = execParams(connection,
        "INSERT INTO openproof.oauth_clients(id,application_id,display_name,kind,status,secret_digest,created_at_ms,updated_at_ms) "
        "VALUES($1,$2,$3,$4,$5,CASE WHEN $6='' THEN NULL ELSE decode($6,'hex') END,$7,$8)",
        {std::string{value.id().value()}, std::string{value.applicationId().value()},
            std::string{value.displayName()}, integer(static_cast<unsigned int>(value.kind())),
            integer(static_cast<unsigned int>(value.status())), secretHex,
            instant(value.createdAt()), instant(value.updatedAt())});
        if (!commandOk(inserted.get())) { auto error=databaseError(inserted.get(),"insert OAuth client");
            rollback(connection);
            return foundation::fail(error);
        }
        auto children = insertClientChildren(connection, value);
        if (!children) { rollback(connection);
            return children;
        }
        return commit(connection);
    }

    foundation::Status PostgresIdentityProviderStore::save(const client::Client& value)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection=lease->get();
        auto begun=beginTransaction(connection);
        if(!begun)return begun;
        const std::string secretHex=value.secretDigest()?foundation::toHex(value.secretDigest()->bytes()):std::string{};
        ResultPointer updated=execParams(connection,
        "UPDATE openproof.oauth_clients SET display_name=$2,status=$3,secret_digest=CASE WHEN $4='' THEN NULL ELSE decode($4,'hex') END,updated_at_ms=$5 "
        "WHERE id=$1 AND application_id=$6 AND kind=$7",
        {std::string{value.id().value()},std::string{value.displayName()},integer(static_cast<unsigned int>(value.status())),secretHex,instant(value.updatedAt()),std::string{value.applicationId().value()},integer(static_cast<unsigned int>(value.kind()))});
        if(!commandOk(updated.get())||std::string_view{PQcmdTuples(updated.get())}!="1"){auto error=commandOk(updated.get())?foundation::Error{foundation::ErrorCode::NotFound}:databaseError(updated.get(),"save OAuth client");
            rollback(connection);
            return foundation::fail(error);
        }
        auto deletedRedirects=runCommand(connection,"DELETE FROM openproof.oauth_client_redirect_uris WHERE client_id=$1",{std::string{value.id().value()}},"replace OAuth client redirect URIs");
        auto deletedScopes=runCommand(connection,"DELETE FROM openproof.oauth_client_scopes WHERE client_id=$1",{std::string{value.id().value()}},"replace OAuth client scopes");
        if(!deletedRedirects||!deletedScopes){rollback(connection);
            return foundation::fail((!deletedRedirects?deletedRedirects:deletedScopes).error());
        }
        auto children=insertClientChildren(connection,value);
        if(!children){rollback(connection);
            return children;
        }
        return commit(connection);
    }

    foundation::Result<std::optional<client::Client>>
    PostgresIdentityProviderStore::findById(const client::ClientId& id) const
    {
        auto lease=m_pool->m_implementation->acquire();
        if(!lease)return foundation::fail(lease.error());
        ResultPointer result=execParams(lease->get(),
        "SELECT id,application_id,display_name,kind,status,CASE WHEN secret_digest IS NULL THEN NULL ELSE encode(secret_digest,'hex') END,created_at_ms,updated_at_ms "
        "FROM openproof.oauth_clients WHERE id=$1",{std::string{id.value()}});
        if(!tuplesOk(result.get()))return foundation::fail(databaseError(result.get(),"find OAuth client"));
        if(PQntuples(result.get())==0)return std::optional<client::Client>{};
        auto value=clientFromRow(lease->get(),result.get(),0);
        if(!value)return foundation::fail(value.error());
        return std::optional<client::Client>{std::move(value).value()};
    }

    foundation::Result<std::vector<client::Client>>
    PostgresIdentityProviderStore::clientsOf(const application::ApplicationId& applicationId) const
    {
        auto lease=m_pool->m_implementation->acquire();
        if(!lease)return foundation::fail(lease.error());
        ResultPointer result=execParams(lease->get(),
        "SELECT id,application_id,display_name,kind,status,CASE WHEN secret_digest IS NULL THEN NULL ELSE encode(secret_digest,'hex') END,created_at_ms,updated_at_ms "
        "FROM openproof.oauth_clients WHERE application_id=$1 ORDER BY id",{std::string{applicationId.value()}});
        if(!tuplesOk(result.get()))return foundation::fail(databaseError(result.get(),"list OAuth clients"));
        std::vector<client::Client> output;
        for(int row=0;row<PQntuples(result.get());++row){auto value=clientFromRow(lease->get(),result.get(),row);
            if(!value)return foundation::fail(value.error());
            output.push_back(std::move(value).value());
        }
        return output;
    }

    foundation::Status PostgresIdentityProviderStore::save(const identity::profile::IdentityProfile& value)
    {
        auto lease=m_pool->m_implementation->acquire();
        if(!lease)return foundation::fail(lease.error());
        const auto optionalText = [](const std::optional<std::string>& optionalValue) {
            return optionalValue.value_or(std::string{});
        };
        return runCommand(lease->get(),
        "INSERT INTO openproof.identity_profiles(identity_id,display_name,preferred_username,email,email_verified,phone_number,phone_number_verified,locale,picture_url,avatar_source,created_at_ms,updated_at_ms) "
        "VALUES($1,NULLIF($2,''),NULLIF($3,''),NULLIF($4,''),$5,NULLIF($6,''),$7,NULLIF($8,''),NULLIF($9,''),$10,$11,$12) "
        "ON CONFLICT(identity_id) DO UPDATE SET display_name=EXCLUDED.display_name,preferred_username=EXCLUDED.preferred_username,email=EXCLUDED.email,email_verified=EXCLUDED.email_verified,phone_number=EXCLUDED.phone_number,phone_number_verified=EXCLUDED.phone_number_verified,locale=EXCLUDED.locale,picture_url=EXCLUDED.picture_url,avatar_source=EXCLUDED.avatar_source,updated_at_ms=EXCLUDED.updated_at_ms",
        {std::string{value.identity().value()}, optionalText(value.displayName()),
            optionalText(value.preferredUsername()), optionalText(value.email()),
            value.emailVerified() ? "true" : "false", optionalText(value.phoneNumber()),
            value.phoneNumberVerified() ? "true" : "false", optionalText(value.locale()),
            optionalText(value.pictureUrl()), std::string{value.avatarSource()},
            instant(value.createdAt()), instant(value.updatedAt())},
        "save identity profile");
    }

    foundation::Result<std::optional<identity::profile::IdentityProfile>>
    PostgresIdentityProviderStore::find(const identity::core::IdentityId& identityId) const
    {
        auto lease=m_pool->m_implementation->acquire();
        if(!lease)return foundation::fail(lease.error());
        ResultPointer result=execParams(lease->get(),"SELECT identity_id,display_name,preferred_username,email,email_verified,phone_number,phone_number_verified,locale,picture_url,avatar_source,created_at_ms,updated_at_ms FROM openproof.identity_profiles WHERE identity_id=$1",{std::string{identityId.value()}});
        if (!tuplesOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "find identity profile"));
        }
        if (PQntuples(result.get()) == 0) {
            return std::optional<identity::profile::IdentityProfile>{};
        }
        const auto nullable=[&](int column)->std::optional<std::string>{return PQgetisnull(result.get(),0,column)?std::nullopt:std::optional<std::string>{field(result.get(),0,column)};
        };
        auto created=parseInteger<std::int64_t>(field(result.get(),0,10));
        auto updated=parseInteger<std::int64_t>(field(result.get(),0,11));
        if(!created||!updated)return foundation::fail(foundation::ErrorCode::Internal);
        auto profile=identity::profile::IdentityProfile::restore(identity::core::IdentityId{field(result.get(),0,0)},nullable(1),nullable(2),nullable(3),field(result.get(),0,4)=="t",nullable(5),field(result.get(),0,6)=="t",nullable(7),nullable(8),storedInstant(created.value()),storedInstant(updated.value()),field(result.get(),0,9));
        if(!profile)return foundation::fail(profile.error());
        return std::optional<identity::profile::IdentityProfile>{std::move(profile).value()};
    }

    foundation::Status PostgresIdentityProviderStore::add(evidence::Evidence value)
    {
        std::vector<evidence::Evidence> batch;
        batch.push_back(std::move(value));
        return addBatch(std::move(batch));
    }

    foundation::Status PostgresIdentityProviderStore::addBatch(
    std::vector<evidence::Evidence> values)
    {
        if (values.empty()) return foundation::ok();
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        for (const auto& value : values) {
            const std::string expires = value.expiresAt().has_value()
            ? instant(value.expiresAt().value()) : std::string{};
            auto status = runCommand(connection,
            "INSERT INTO openproof.evidence(id,identity_id,provider,kind,claim,value,confidence,status,verified_at_ms,expires_at_ms) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,CASE WHEN $10='' THEN NULL ELSE $10::bigint END)",
            {std::string{value.id().value()}, std::string{value.identity().value()},
                std::string{value.provider().value()}, std::string{value.kind()},
                std::string{value.claim()}, std::string{value.value()},
                integer(value.confidence()), integer(static_cast<unsigned int>(value.status())),
                instant(value.verifiedAt()), expires}, "insert evidence");
            if (!status) {
                rollback(connection);
                return status;
            }
        }
        return commit(connection);
    }

    foundation::Status PostgresIdentityProviderStore::revoke(
    const evidence::EvidenceId& id)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(lease->get(),
        "UPDATE openproof.evidence SET status=1 WHERE id=$1 AND status=0",
        {std::string{id.value()}});
        if (!commandOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "revoke evidence"));
        }
        if (std::string_view{PQcmdTuples(result.get())} != "1") {
            return foundation::fail(foundation::ErrorCode::NotFound);
        }
        return foundation::ok();
    }

    foundation::Result<std::optional<evidence::Evidence>>
    PostgresIdentityProviderStore::find(const evidence::EvidenceId& id) const
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(lease->get(),
        "SELECT id,identity_id,provider,kind,claim,value,confidence,status,verified_at_ms,expires_at_ms "
        "FROM openproof.evidence WHERE id=$1", {std::string{id.value()}});
        if (!tuplesOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "find evidence"));
        }
        if (PQntuples(result.get()) == 0) return std::optional<evidence::Evidence>{};
        auto confidence = parseInteger<unsigned int>(field(result.get(), 0, 6));
        auto status = parseInteger<unsigned int>(field(result.get(), 0, 7));
        auto verified = parseInteger<std::int64_t>(field(result.get(), 0, 8));
        if (!confidence || !status || !verified || confidence.value() > 100U
        || status.value() > 1U) {
            return foundation::fail(foundation::ErrorCode::Internal);
        }
        std::optional<foundation::Instant> expires;
        if (!PQgetisnull(result.get(), 0, 9)) {
            auto parsed = parseInteger<std::int64_t>(field(result.get(), 0, 9));
            if (!parsed) return foundation::fail(parsed.error());
            expires = storedInstant(parsed.value());
        }
        auto restored = evidence::Evidence::restore(
        evidence::EvidenceId{field(result.get(), 0, 0)},
        identity::core::IdentityId{field(result.get(), 0, 1)},
        identity::provider::ProviderId{field(result.get(), 0, 2)},
        field(result.get(), 0, 3), field(result.get(), 0, 4),
        field(result.get(), 0, 5), confidence.value(),
        static_cast<evidence::EvidenceStatus>(status.value()),
        storedInstant(verified.value()), expires);
        if (!restored) return foundation::fail(restored.error());
        return std::optional<evidence::Evidence>{std::move(restored).value()};
    }

    foundation::Result<std::vector<evidence::Evidence>>
    PostgresIdentityProviderStore::forIdentity(
    const identity::core::IdentityId& identityId) const
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(lease->get(),
        "SELECT id,identity_id,provider,kind,claim,value,confidence,status,verified_at_ms,expires_at_ms "
        "FROM openproof.evidence WHERE identity_id=$1 ORDER BY verified_at_ms,id",
        {std::string{identityId.value()}});
        if (!tuplesOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "list identity evidence"));
        }
        std::vector<evidence::Evidence> output;
        output.reserve(static_cast<std::size_t>(PQntuples(result.get())));
        for (int row = 0; row < PQntuples(result.get()); ++row) {
            auto confidence = parseInteger<unsigned int>(field(result.get(), row, 6));
            auto status = parseInteger<unsigned int>(field(result.get(), row, 7));
            auto verified = parseInteger<std::int64_t>(field(result.get(), row, 8));
            if (!confidence || !status || !verified || confidence.value() > 100U
            || status.value() > 1U) {
                return foundation::fail(foundation::ErrorCode::Internal);
            }
            std::optional<foundation::Instant> expires;
            if (!PQgetisnull(result.get(), row, 9)) {
                auto parsed = parseInteger<std::int64_t>(field(result.get(), row, 9));
                if (!parsed) return foundation::fail(parsed.error());
                expires = storedInstant(parsed.value());
            }
            auto restored = evidence::Evidence::restore(
            evidence::EvidenceId{field(result.get(), row, 0)},
            identity::core::IdentityId{field(result.get(), row, 1)},
            identity::provider::ProviderId{field(result.get(), row, 2)},
            field(result.get(), row, 3), field(result.get(), row, 4),
            field(result.get(), row, 5), confidence.value(),
            static_cast<evidence::EvidenceStatus>(status.value()),
            storedInstant(verified.value()), expires);
            if (!restored) return foundation::fail(restored.error());
            output.push_back(std::move(restored).value());
        }
        return output;
    }

    foundation::Status PostgresIdentityProviderStore::add(oauth::AuthorizationCode value)
    {
        auto lease=m_pool->m_implementation->acquire();
        if(!lease)return foundation::fail(lease.error());
        PGconn* connection=lease->get();
        auto begun=beginTransaction(connection);
        if(!begun)return begun;
        const std::string digest=foundation::toHex(value.digest().bytes());
        ResultPointer inserted=execParams(connection,
        "INSERT INTO openproof.oauth_authorization_codes(code_digest,client_id,identity_id,redirect_uri,code_challenge,nonce,provider,assurance,factors,phishing_resistant,authenticated_at_ms,issued_at_ms,expires_at_ms,resource) "
        "VALUES(decode($1,'hex'),$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9,$10,$11,$12,$13,NULLIF($14,''))",
        {digest,std::string{value.clientId().value()},std::string{value.identity().value()},std::string{value.redirectUri()},std::string{value.codeChallenge().value()},value.nonce().value_or(std::string{}),std::string{value.provider().value()},integer(static_cast<unsigned int>(value.assurance())),integer(factorsValue(value.strength())),value.strength().isPhishingResistant()?"true":"false",instant(value.authenticatedAt()),instant(value.issuedAt()),instant(value.expiresAt()),value.resource().value_or(std::string{})});
        if(!commandOk(inserted.get())){auto error=databaseError(inserted.get(),"insert OAuth authorization code");
            rollback(connection);
            return foundation::fail(error);
        }
        for(const auto& scope:value.scopes()){auto status=runCommand(connection,"INSERT INTO openproof.oauth_authorization_code_scopes(code_digest,scope) VALUES(decode($1,'hex'),$2)",{digest,std::string{scope.value()}},"insert authorization code scope");
            if(!status){rollback(connection);
                return status;
            }}
        return commit(connection);
    }

    foundation::Result<oauth::AuthorizationCode> PostgresIdentityProviderStore::consumeBound(
    const oauth::CodeDigest& digestValue, foundation::Instant now,
    std::string_view expectedClientId, std::string_view expectedRedirectUri,
    std::string_view expectedCodeChallenge)
    {
        auto lease=m_pool->m_implementation->acquire();
        if(!lease)return foundation::fail(lease.error());
        PGconn* connection=lease->get();
        auto begun=beginTransaction(connection);
        if(!begun)return foundation::fail(begun.error());
        const std::string digest=foundation::toHex(digestValue.bytes());
        ResultPointer base=execParams(connection,"SELECT client_id,identity_id,redirect_uri,code_challenge,nonce,provider,assurance,factors,phishing_resistant,authenticated_at_ms,issued_at_ms,expires_at_ms,resource FROM openproof.oauth_authorization_codes WHERE code_digest=decode($1,'hex') FOR UPDATE",{digest});
        if(!tuplesOk(base.get())){auto error=databaseError(base.get(),"consume authorization code");
            rollback(connection);
            return foundation::fail(error);
        }
        if(PQntuples(base.get())!=1){rollback(connection);
            return foundation::fail(authenticationFailure("Authorization code was not found or was already consumed."));
        }
        ResultPointer scopeRows=execParams(connection,"SELECT scope FROM openproof.oauth_authorization_code_scopes WHERE code_digest=decode($1,'hex') ORDER BY scope",{digest});
        if(!tuplesOk(scopeRows.get())){auto error=databaseError(scopeRows.get(),"load authorization code scopes");
            rollback(connection);
            return foundation::fail(error);
        }
        std::vector<client::Scope> scopes;
        for(int row=0;row<PQntuples(scopeRows.get());++row){auto parsed=client::Scope::create(field(scopeRows.get(),row,0));
            if(!parsed){rollback(connection);
                return foundation::fail(parsed.error());
            }scopes.push_back(std::move(parsed).value());
        }
        auto assurance=parseInteger<unsigned int>(field(base.get(),0,6));
        auto factors=parseInteger<unsigned int>(field(base.get(),0,7));
        auto authenticated=parseInteger<std::int64_t>(field(base.get(),0,9));
        auto issued=parseInteger<std::int64_t>(field(base.get(),0,10));
        auto expires=parseInteger<std::int64_t>(field(base.get(),0,11));
        if(!assurance||!factors||!authenticated||!issued||!expires||assurance.value()>4U||factors.value()>7U){rollback(connection);
            return foundation::fail(foundation::ErrorCode::Internal);
        }
        auto challenge=oauth::PkceChallenge::create(field(base.get(),0,3));
        if(!challenge){rollback(connection);
            return foundation::fail(challenge.error());
        }
        std::optional<std::string> nonce=PQgetisnull(base.get(),0,4)?std::nullopt:std::optional<std::string>{field(base.get(),0,4)};
        std::optional<std::string> resourceValue=PQgetisnull(base.get(),0,12)?std::nullopt:std::optional<std::string>{field(base.get(),0,12)};
        auto code=oauth::AuthorizationCode::restore(oauth::CodeDigest{digestValue},client::ClientId{field(base.get(),0,0)},identity::core::IdentityId{field(base.get(),0,1)},field(base.get(),0,2),std::move(scopes),std::move(challenge).value(),std::move(nonce),identity::provider::ProviderId{field(base.get(),0,5)},static_cast<identity::provider::AssuranceLevel>(assurance.value()),identity::provider::AuthenticationStrength{static_cast<identity::provider::AuthenticationFactor>(factors.value()),field(base.get(),0,8)=="t"},storedInstant(authenticated.value()),storedInstant(issued.value()),storedInstant(expires.value()),std::move(resourceValue));
        if(!code){rollback(connection);
            return foundation::fail(code.error());
        }
        if(code->expiredAt(now)){
            auto deleted=runCommand(connection,"DELETE FROM openproof.oauth_authorization_codes WHERE code_digest=decode($1,'hex')",{digest},"delete expired authorization code");
            if(!deleted){rollback(connection);
                return foundation::fail(deleted.error());
            }
            auto committed=commit(connection);
            if(!committed)return foundation::fail(committed.error());
            return foundation::fail(authenticationFailure("Authorization code was not found or was already consumed."));
        }
        if(code->clientId().value()!=expectedClientId
            || code->redirectUri()!=expectedRedirectUri
            || code->codeChallenge().value()!=expectedCodeChallenge){
            rollback(connection);
            return foundation::fail(authenticationFailure("Authorization code was not found or was already consumed."));
        }
        auto deleted=runCommand(connection,"DELETE FROM openproof.oauth_authorization_codes WHERE code_digest=decode($1,'hex')",{digest},"delete consumed authorization code");
        if(!deleted){rollback(connection);
            return foundation::fail(deleted.error());
        }
        auto committed=commit(connection);
        if(!committed)return foundation::fail(committed.error());
        return code;
    }

    foundation::Status PostgresIdentityProviderStore::add(
        oauth::DeviceAuthorization authorization)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        const std::string deviceDigest = foundation::toHex(authorization.deviceCode().bytes());
        const std::string userDigest = foundation::toHex(authorization.userCode().bytes());
        ResultPointer inserted = execParams(
            connection,
            "INSERT INTO openproof.oauth_device_authorizations("
            "device_digest,user_code_digest,client_id,resource,status,issued_at_ms,expires_at_ms,"
            "poll_interval_ms) VALUES(decode($1,'hex'),decode($2,'hex'),$3,NULLIF($4,''),0,$5,$6,$7)",
            {deviceDigest, userDigest, std::string{authorization.clientId().value()},
             authorization.resource().value_or(std::string{}), instant(authorization.issuedAt()),
             instant(authorization.expiresAt()), integer(authorization.pollInterval().count())});
        if (!commandOk(inserted.get())) {
            auto error = databaseError(inserted.get(), "insert device authorization");
            rollback(connection);
            return foundation::fail(error);
        }
        for (const auto& scope : authorization.scopes()) {
            auto stored = runCommand(
                connection,
                "INSERT INTO openproof.oauth_device_authorization_scopes(device_digest,scope) "
                "VALUES(decode($1,'hex'),$2)",
                {deviceDigest, std::string{scope.value()}}, "insert device authorization scope");
            if (!stored) {
                rollback(connection);
                return stored;
            }
        }
        return commit(connection);
    }

    foundation::Result<oauth::DeviceAuthorization>
    PostgresIdentityProviderStore::findByUserCode(
        const oauth::DeviceUserCodeDigest& userCode, foundation::Instant now)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        const std::string query = "SELECT " + std::string{kDeviceAuthorizationColumns}
            + " FROM openproof.oauth_device_authorizations "
              "WHERE user_code_digest=decode($1,'hex')";
        ResultPointer result = execParams(
            lease->get(), query, {foundation::toHex(userCode.bytes())});
        if (!tuplesOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "find device user code"));
        }
        if (PQntuples(result.get()) != 1) return foundation::fail(foundation::ErrorCode::NotFound);
        auto authorization = deviceAuthorizationFromRow(lease->get(), result.get(), 0);
        if (!authorization) return foundation::fail(authorization.error());
        if (authorization->expiredAt(now)
            || authorization->status() != oauth::DeviceAuthorizationStatus::Pending) {
            return foundation::fail(foundation::ErrorCode::NotFound);
        }
        return authorization;
    }

    foundation::Result<oauth::DeviceAuthorization> PostgresIdentityProviderStore::approve(
        const oauth::DeviceUserCodeDigest& userCode,
        const session::AuthenticatedSession& authenticated, foundation::Instant now)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return foundation::fail(begun.error());
        const std::string query = "SELECT " + std::string{kDeviceAuthorizationColumns}
            + " FROM openproof.oauth_device_authorizations "
              "WHERE user_code_digest=decode($1,'hex') FOR UPDATE";
        ResultPointer row = execParams(connection, query, {foundation::toHex(userCode.bytes())});
        if (!tuplesOk(row.get())) {
            auto error = databaseError(row.get(), "lock device authorization for approval");
            rollback(connection);
            return foundation::fail(error);
        }
        if (PQntuples(row.get()) != 1) {
            rollback(connection);
            return foundation::fail(foundation::ErrorCode::NotFound);
        }
        auto authorization = deviceAuthorizationFromRow(connection, row.get(), 0);
        if (!authorization) {
            rollback(connection);
            return foundation::fail(authorization.error());
        }
        auto approved = authorization->approve(authenticated, now);
        if (!approved) {
            rollback(connection);
            return foundation::fail(approved.error());
        }
        const auto& sessionValue = authenticated.session();
        auto updated = runCommand(
            connection,
            "UPDATE openproof.oauth_device_authorizations SET status=1,identity_id=$2,provider=$3,"
            "assurance=$4,factors=$5,phishing_resistant=$6,authenticated_at_ms=$7 "
            "WHERE user_code_digest=decode($1,'hex') AND status=0",
            {foundation::toHex(userCode.bytes()), std::string{sessionValue.identity().value()},
             std::string{sessionValue.provider().value()},
             integer(static_cast<unsigned int>(sessionValue.assurance())),
             integer(factorsValue(sessionValue.strength())),
             sessionValue.strength().isPhishingResistant() ? "true" : "false",
             instant(sessionValue.authenticatedAt())},
            "approve device authorization");
        if (!updated) {
            rollback(connection);
            return foundation::fail(updated.error());
        }
        auto committed = commit(connection);
        if (!committed) return foundation::fail(committed.error());
        return authorization;
    }

    foundation::Status PostgresIdentityProviderStore::deny(
        const oauth::DeviceUserCodeDigest& userCode, foundation::Instant now)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        const std::string query = "SELECT " + std::string{kDeviceAuthorizationColumns}
            + " FROM openproof.oauth_device_authorizations "
              "WHERE user_code_digest=decode($1,'hex') FOR UPDATE";
        ResultPointer row = execParams(connection, query, {foundation::toHex(userCode.bytes())});
        if (!tuplesOk(row.get())) {
            auto error = databaseError(row.get(), "lock device authorization for denial");
            rollback(connection);
            return foundation::fail(error);
        }
        if (PQntuples(row.get()) != 1) {
            rollback(connection);
            return foundation::fail(foundation::ErrorCode::NotFound);
        }
        auto authorization = deviceAuthorizationFromRow(connection, row.get(), 0);
        if (!authorization) {
            rollback(connection);
            return foundation::fail(authorization.error());
        }
        auto denied = authorization->deny(now);
        if (!denied) {
            rollback(connection);
            return denied;
        }
        auto updated = runCommand(
            connection,
            "UPDATE openproof.oauth_device_authorizations SET status=2 "
            "WHERE user_code_digest=decode($1,'hex') AND status=0",
            {foundation::toHex(userCode.bytes())}, "deny device authorization");
        if (!updated) {
            rollback(connection);
            return updated;
        }
        return commit(connection);
    }

    foundation::Result<oauth::DevicePollResult> PostgresIdentityProviderStore::poll(
        const oauth::DeviceCodeDigest& deviceCode, const client::ClientId& expectedClient,
        foundation::Instant now)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return foundation::fail(begun.error());
        const std::string query = "SELECT " + std::string{kDeviceAuthorizationColumns}
            + " FROM openproof.oauth_device_authorizations "
              "WHERE device_digest=decode($1,'hex') FOR UPDATE";
        const std::string digest = foundation::toHex(deviceCode.bytes());
        ResultPointer row = execParams(connection, query, {digest});
        if (!tuplesOk(row.get())) {
            auto error = databaseError(row.get(), "lock device authorization for poll");
            rollback(connection);
            return foundation::fail(error);
        }
        if (PQntuples(row.get()) != 1) {
            rollback(connection);
            return foundation::fail(authenticationFailure("Unknown device code."));
        }
        auto authorization = deviceAuthorizationFromRow(connection, row.get(), 0);
        if (!authorization) {
            rollback(connection);
            return foundation::fail(authorization.error());
        }
        auto value = std::move(authorization).value();
        if (value.clientId() != expectedClient) {
            rollback(connection);
            return foundation::fail(authenticationFailure(
                "The device code is not bound to this client."));
        }
        if (value.expiredAt(now)) {
            auto committed = commit(connection);
            if (!committed) return foundation::fail(committed.error());
            return oauth::DevicePollResult{
                oauth::DevicePollDisposition::Expired, std::nullopt, value.pollInterval()};
        }
        if (value.status() == oauth::DeviceAuthorizationStatus::Denied) {
            auto committed = commit(connection);
            if (!committed) return foundation::fail(committed.error());
            return oauth::DevicePollResult{
                oauth::DevicePollDisposition::Denied, std::nullopt, value.pollInterval()};
        }
        if (value.status() == oauth::DeviceAuthorizationStatus::Consumed) {
            rollback(connection);
            return foundation::fail(authenticationFailure("The device code has already been consumed."));
        }
        if (value.lastPollAt() && now < *value.lastPollAt() + value.pollInterval()) {
            auto slowed = value.slowDown(now);
            if (!slowed) {
                rollback(connection);
                return foundation::fail(slowed.error());
            }
            auto updated = runCommand(
                connection,
                "UPDATE openproof.oauth_device_authorizations "
                "SET poll_interval_ms=$2,last_poll_at_ms=$3 WHERE device_digest=decode($1,'hex')",
                {digest, integer(value.pollInterval().count()), instant(now)},
                "slow device authorization polling");
            if (!updated) {
                rollback(connection);
                return foundation::fail(updated.error());
            }
            auto committed = commit(connection);
            if (!committed) return foundation::fail(committed.error());
            return oauth::DevicePollResult{
                oauth::DevicePollDisposition::SlowDown, std::nullopt, value.pollInterval()};
        }
        if (value.status() == oauth::DeviceAuthorizationStatus::Approved) {
            auto consumed = value.consume(now);
            if (!consumed) {
                rollback(connection);
                return foundation::fail(consumed.error());
            }
            auto updated = runCommand(
                connection,
                "UPDATE openproof.oauth_device_authorizations SET status=3,last_poll_at_ms=$2 "
                "WHERE device_digest=decode($1,'hex') AND status=1",
                {digest, instant(now)}, "consume device authorization");
            if (!updated) {
                rollback(connection);
                return foundation::fail(updated.error());
            }
            auto committed = commit(connection);
            if (!committed) return foundation::fail(committed.error());
            const auto retryAfter = value.pollInterval();
            return oauth::DevicePollResult{
                oauth::DevicePollDisposition::Approved, std::move(value), retryAfter};
        }
        auto polled = value.markPolled(now);
        if (!polled) {
            rollback(connection);
            return foundation::fail(polled.error());
        }
        auto updated = runCommand(
            connection,
            "UPDATE openproof.oauth_device_authorizations SET last_poll_at_ms=$2 "
            "WHERE device_digest=decode($1,'hex') AND status=0",
            {digest, instant(now)}, "record device authorization poll");
        if (!updated) {
            rollback(connection);
            return foundation::fail(updated.error());
        }
        auto committed = commit(connection);
        if (!committed) return foundation::fail(committed.error());
        return oauth::DevicePollResult{
            oauth::DevicePollDisposition::Pending, std::nullopt, value.pollInterval()};
    }

    foundation::Status PostgresIdentityProviderStore::add(
        oauth::PushedAuthorizationRequest pushed)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        const auto& request = pushed.request();
        const std::string digest = foundation::toHex(pushed.digest().bytes());
        const std::string maximumAge = request.maximumAuthenticationAge()
            ? integer(request.maximumAuthenticationAge()->count()) : std::string{};
        ResultPointer inserted = execParams(
            connection,
            "INSERT INTO openproof.oauth_pushed_authorization_requests("
            "request_digest,client_id,redirect_uri,code_challenge,state,nonce,"
            "maximum_authentication_age_ms,resource,response_mode,issued_at_ms,expires_at_ms) "
            "VALUES(decode($1,'hex'),$2,$3,$4,NULLIF($5,''),NULLIF($6,''),"
            "NULLIF($7,'')::bigint,NULLIF($8,''),$9,$10,$11)",
            {digest, std::string{request.clientId().value()}, std::string{request.redirectUri()},
             std::string{request.codeChallenge().value()}, request.state().value_or(std::string{}),
             request.nonce().value_or(std::string{}), maximumAge,
             request.resource().value_or(std::string{}),
             integer(static_cast<unsigned int>(request.responseMode())),
             instant(pushed.issuedAt()), instant(pushed.expiresAt())});
        if (!commandOk(inserted.get())) {
            auto error = databaseError(inserted.get(), "insert pushed authorization request");
            rollback(connection);
            return foundation::fail(error);
        }
        for (const auto& scope : request.scopes()) {
            auto stored = runCommand(
                connection,
                "INSERT INTO openproof.oauth_pushed_authorization_request_scopes("
                "request_digest,scope) VALUES(decode($1,'hex'),$2)",
                {digest, std::string{scope.value()}}, "insert PAR scope");
            if (!stored) {
                rollback(connection);
                return stored;
            }
        }
        return commit(connection);
    }

    foundation::Result<oauth::PushedAuthorizationRequest>
    PostgresIdentityProviderStore::find(
        const oauth::PushedRequestDigest& digest, foundation::Instant now) const
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        const std::string query = "SELECT " + std::string{kPushedAuthorizationColumns}
            + " FROM openproof.oauth_pushed_authorization_requests "
              "WHERE request_digest=decode($1,'hex')";
        ResultPointer row = execParams(
            lease->get(), query, {foundation::toHex(digest.bytes())});
        if (!tuplesOk(row.get())) {
            return foundation::fail(databaseError(row.get(), "find pushed authorization request"));
        }
        if (PQntuples(row.get()) != 1) return foundation::fail(foundation::ErrorCode::NotFound);
        auto pushed = pushedAuthorizationFromRow(lease->get(), row.get(), 0);
        if (!pushed) return foundation::fail(pushed.error());
        if (pushed->expiredAt(now)) return foundation::fail(foundation::ErrorCode::NotFound);
        return pushed;
    }

    foundation::Result<oauth::PushedAuthorizationRequest>
    PostgresIdentityProviderStore::consume(
        const oauth::PushedRequestDigest& digest, const client::ClientId& expectedClient,
        foundation::Instant now)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return foundation::fail(begun.error());
        const std::string query = "SELECT " + std::string{kPushedAuthorizationColumns}
            + " FROM openproof.oauth_pushed_authorization_requests "
              "WHERE request_digest=decode($1,'hex') FOR UPDATE";
        const std::string encodedDigest = foundation::toHex(digest.bytes());
        ResultPointer row = execParams(connection, query, {encodedDigest});
        if (!tuplesOk(row.get())) {
            auto error = databaseError(row.get(), "lock pushed authorization request");
            rollback(connection);
            return foundation::fail(error);
        }
        if (PQntuples(row.get()) != 1) {
            rollback(connection);
            return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                    "The pushed authorization request is invalid.");
        }
        auto pushed = pushedAuthorizationFromRow(connection, row.get(), 0);
        if (!pushed || pushed->expiredAt(now)
            || pushed->request().clientId() != expectedClient) {
            rollback(connection);
            return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                    "The pushed authorization request is invalid.");
        }
        auto removed = runCommand(
            connection,
            "DELETE FROM openproof.oauth_pushed_authorization_requests "
            "WHERE request_digest=decode($1,'hex')",
            {encodedDigest}, "consume pushed authorization request");
        if (!removed) {
            rollback(connection);
            return foundation::fail(removed.error());
        }
        auto committed = commit(connection);
        if (!committed) return foundation::fail(committed.error());
        return pushed;
    }

    foundation::Status PostgresIdentityProviderStore::save(
        oauth::ClientRequestSigningKey key)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        return runCommand(
            lease->get(),
            "INSERT INTO openproof.oauth_client_request_signing_keys("
            "client_id,key_id,public_key_pem,updated_at_ms) VALUES($1,$2,$3,$4) "
            "ON CONFLICT(client_id) DO UPDATE SET key_id=EXCLUDED.key_id,"
            "public_key_pem=EXCLUDED.public_key_pem,updated_at_ms=EXCLUDED.updated_at_ms",
            {std::string{key.clientId().value()}, std::string{key.keyId()},
             std::string{key.publicKeyPem()}, instant(key.updatedAt())},
            "save JAR client request signing key");
    }

    foundation::Result<std::optional<oauth::ClientRequestSigningKey>>
    PostgresIdentityProviderStore::find(const client::ClientId& clientId) const
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        ResultPointer result = execParams(
            lease->get(),
            "SELECT key_id,public_key_pem,updated_at_ms "
            "FROM openproof.oauth_client_request_signing_keys WHERE client_id=$1",
            {std::string{clientId.value()}});
        if (!tuplesOk(result.get())) {
            return foundation::fail(databaseError(result.get(), "find JAR client request signing key"));
        }
        if (PQntuples(result.get()) == 0) {
            return std::optional<oauth::ClientRequestSigningKey>{};
        }
        auto updatedAt = parseInteger<std::int64_t>(field(result.get(), 0, 2));
        if (!updatedAt) return foundation::fail(updatedAt.error());
        auto key = oauth::ClientRequestSigningKey::create(
            clientId, field(result.get(), 0, 0), field(result.get(), 0, 1),
            storedInstant(updatedAt.value()));
        if (!key) return foundation::fail(foundation::ErrorCode::Internal,
                                          "Stored JAR client key is invalid.");
        return std::optional<oauth::ClientRequestSigningKey>{std::move(key).value()};
    }

    foundation::Status PostgresIdentityProviderStore::remove(const client::ClientId& clientId)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        return runCommand(
            lease->get(),
            "DELETE FROM openproof.oauth_client_request_signing_keys WHERE client_id=$1",
            {std::string{clientId.value()}}, "remove JAR client request signing key");
    }

    foundation::Status PostgresIdentityProviderStore::consume(
        const client::ClientId& clientId, std::string_view jwtId,
        foundation::Instant expiresAt, foundation::Instant now)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        auto purged = runCommand(
            connection, "DELETE FROM openproof.oauth_jar_replays WHERE expires_at_ms <= $1",
            {instant(now)}, "purge expired JAR replay identifiers");
        if (!purged) {
            rollback(connection);
            return purged;
        }
        ResultPointer inserted = execParams(
            connection,
            "INSERT INTO openproof.oauth_jar_replays(client_id,jwt_id,expires_at_ms) "
            "VALUES($1,$2,$3)",
            {std::string{clientId.value()}, std::string{jwtId}, instant(expiresAt)});
        if (!commandOk(inserted.get())) {
            auto error = databaseError(inserted.get(), "consume JAR replay identifier");
            rollback(connection);
            if (error.code() == foundation::ErrorCode::AlreadyExists) {
                return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                        "The JAR request object was replayed.");
            }
            return foundation::fail(error);
        }
        return commit(connection);
    }

    foundation::Status PostgresIdentityProviderStore::consumeDpopReplay(
        std::string_view jwkThumbprint, std::string_view jwtId,
        foundation::Instant expiresAt, foundation::Instant now)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        auto purged = runCommand(
            connection, "DELETE FROM openproof.oauth_dpop_replays WHERE expires_at_ms <= $1",
            {instant(now)}, "purge expired DPoP replay identifiers");
        if (!purged) {
            rollback(connection);
            return purged;
        }
        ResultPointer inserted = execParams(
            connection,
            "INSERT INTO openproof.oauth_dpop_replays(jwk_thumbprint,jwt_id,expires_at_ms) "
            "VALUES($1,$2,$3)",
            {std::string{jwkThumbprint}, std::string{jwtId}, instant(expiresAt)});
        if (!commandOk(inserted.get())) {
            auto error = databaseError(inserted.get(), "consume DPoP replay identifier");
            rollback(connection);
            if (error.code() == foundation::ErrorCode::AlreadyExists) {
                return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                        "The DPoP proof was replayed.");
            }
            return foundation::fail(error);
        }
        return commit(connection);
    }

    foundation::Status PostgresIdentityProviderStore::consumeMtlsForwardingReplay(
        std::string_view certificateThumbprint, std::string_view nonce,
        foundation::Instant expiresAt, foundation::Instant now)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) return foundation::fail(lease.error());
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) return begun;
        auto purged = runCommand(
            connection, "DELETE FROM openproof.oauth_mtls_forwarding_replays WHERE expires_at_ms <= $1",
            {instant(now)}, "purge expired mTLS forwarding replay identifiers");
        if (!purged) {
            rollback(connection);
            return purged;
        }
        ResultPointer inserted = execParams(
            connection,
            "INSERT INTO openproof.oauth_mtls_forwarding_replays"
            "(certificate_thumbprint,nonce,expires_at_ms) VALUES($1,$2,$3)",
            {std::string{certificateThumbprint}, std::string{nonce}, instant(expiresAt)});
        if (!commandOk(inserted.get())) {
            auto error = databaseError(inserted.get(), "consume mTLS forwarding replay identifier");
            rollback(connection);
            if (error.code() == foundation::ErrorCode::AlreadyExists) {
                return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                        "The authenticated mTLS forwarding assertion was replayed.");
            }
            return foundation::fail(error);
        }
        return commit(connection);
    }

    foundation::Status PostgresIdentityProviderStore::storeInitial(
        token::AccessTokenRecord access, token::RefreshTokenRecord refresh)
    {
        if (access.family() != refresh.family()
            || access.context().client() != refresh.context().client()
            || access.context().identity() != refresh.context().identity()) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "OAuth token records disagree.");
        }

        auto lease = m_pool->m_implementation->acquire();
        if (!lease) {
            return foundation::fail(lease.error());
        }
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) {
            return begun;
        }

        const auto& context = access.context();
        const std::string senderKind = context.senderConstraint()
            ? integer(static_cast<unsigned int>(context.senderConstraint()->kind()))
            : std::string{};
        const std::string senderValue = context.senderConstraint()
            ? std::string{context.senderConstraint()->value()}
            : std::string{};
        ResultPointer family = execParams(
            connection,
            "INSERT INTO openproof.oauth_token_families"
            "(id,client_id,identity_id,provider,assurance,factors,phishing_resistant,"
            "authenticated_at_ms,sender_constraint_kind,sender_constraint_value) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,'')::smallint,NULLIF($10,''))",
            {std::string{access.family().value()}, std::string{context.client().value()},
             std::string{context.identity().value()}, std::string{context.provider().value()},
             integer(static_cast<unsigned int>(context.assurance())),
             integer(factorsValue(context.strength())),
             context.strength().isPhishingResistant() ? "true" : "false",
             instant(context.authenticatedAt()), senderKind, senderValue});
        if (!commandOk(family.get())) {
            auto error = databaseError(family.get(), "insert token family");
            rollback(connection);
            return foundation::fail(error);
        }

        for (const auto& scope : context.scopes()) {
            auto status = runCommand(
                connection,
                "INSERT INTO openproof.oauth_token_family_scopes(family_id,scope) "
                "VALUES($1,$2)",
                {std::string{access.family().value()}, scope},
                "insert token family scope");
            if (!status) {
                rollback(connection);
                return status;
            }
        }
        for (const auto& audience : context.audiences()) {
            auto status = runCommand(
                connection,
                "INSERT INTO openproof.oauth_token_family_audiences(family_id,audience) "
                "VALUES($1,$2)",
                {std::string{access.family().value()}, audience},
                "insert token family audience");
            if (!status) {
                rollback(connection);
                return status;
            }
        }

        auto accessStatus = runCommand(
            connection,
            "INSERT INTO openproof.oauth_access_tokens"
            "(token_digest,family_id,state,issued_at_ms,expires_at_ms) "
            "VALUES(decode($1,'hex'),$2,0,$3,$4)",
            {foundation::toHex(access.digest().bytes()), std::string{access.family().value()},
             instant(access.issuedAt()), instant(access.expiresAt())},
            "insert access token");
        if (!accessStatus) {
            rollback(connection);
            return accessStatus;
        }

        auto refreshStatus = runCommand(
            connection,
            "INSERT INTO openproof.oauth_refresh_tokens"
            "(token_digest,family_id,sequence,state,issued_at_ms,expires_at_ms) "
            "VALUES(decode($1,'hex'),$2,$3,0,$4,$5)",
            {foundation::toHex(refresh.digest().bytes()), std::string{refresh.family().value()},
             integer(static_cast<std::int64_t>(refresh.sequence())), instant(refresh.issuedAt()),
             instant(refresh.expiresAt())},
            "insert refresh token");
        if (!refreshStatus) {
            rollback(connection);
            return refreshStatus;
        }
        return commit(connection);
    }

    foundation::Status PostgresIdentityProviderStore::storeAccessOnly(
        token::AccessTokenRecord access)
    {
        auto lease = m_pool->m_implementation->acquire();
        if (!lease) {
            return foundation::fail(lease.error());
        }
        PGconn* connection = lease->get();
        auto begun = beginTransaction(connection);
        if (!begun) {
            return begun;
        }

        const auto& context = access.context();
        const std::string senderKind = context.senderConstraint()
            ? integer(static_cast<unsigned int>(context.senderConstraint()->kind()))
            : std::string{};
        const std::string senderValue = context.senderConstraint()
            ? std::string{context.senderConstraint()->value()}
            : std::string{};
        ResultPointer family = execParams(
            connection,
            "INSERT INTO openproof.oauth_token_families"
            "(id,client_id,identity_id,provider,assurance,factors,phishing_resistant,"
            "authenticated_at_ms,sender_constraint_kind,sender_constraint_value) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,'')::smallint,NULLIF($10,''))",
            {std::string{access.family().value()}, std::string{context.client().value()},
             std::string{context.identity().value()}, std::string{context.provider().value()},
             integer(static_cast<unsigned int>(context.assurance())),
             integer(factorsValue(context.strength())),
             context.strength().isPhishingResistant() ? "true" : "false",
             instant(context.authenticatedAt()), senderKind, senderValue});
        if (!commandOk(family.get())) {
            auto error = databaseError(family.get(), "insert access-only token family");
            rollback(connection);
            return foundation::fail(error);
        }

        for (const auto& scope : context.scopes()) {
            auto status = runCommand(
                connection,
                "INSERT INTO openproof.oauth_token_family_scopes(family_id,scope) "
                "VALUES($1,$2)",
                {std::string{access.family().value()}, scope},
                "insert token family scope");
            if (!status) {
                rollback(connection);
                return status;
            }
        }
        for (const auto& audience : context.audiences()) {
            auto status = runCommand(
                connection,
                "INSERT INTO openproof.oauth_token_family_audiences(family_id,audience) "
                "VALUES($1,$2)",
                {std::string{access.family().value()}, audience},
                "insert token family audience");
            if (!status) {
                rollback(connection);
                return status;
            }
        }

        auto accessStatus = runCommand(
            connection,
            "INSERT INTO openproof.oauth_access_tokens"
            "(token_digest,family_id,state,issued_at_ms,expires_at_ms) "
            "VALUES(decode($1,'hex'),$2,0,$3,$4)",
            {foundation::toHex(access.digest().bytes()), std::string{access.family().value()},
             instant(access.issuedAt()), instant(access.expiresAt())},
            "insert access-only token");
        if (!accessStatus) {
            rollback(connection);
            return accessStatus;
        }
        return commit(connection);
    }

    foundation::Result<token::AccessTokenRecord> PostgresIdentityProviderStore::findAccess(const token::TokenDigest& digestValue)
    {
        auto lease=m_pool->m_implementation->acquire();
        if(!lease)return foundation::fail(lease.error());
        ResultPointer result=execParams(lease->get(),"SELECT family_id,state,issued_at_ms,expires_at_ms,revoked_at_ms FROM openproof.oauth_access_tokens WHERE token_digest=decode($1,'hex')",{foundation::toHex(digestValue.bytes())});
        if(!tuplesOk(result.get()))return foundation::fail(databaseError(result.get(),"find access token"));
        if(PQntuples(result.get())!=1)return foundation::fail(authenticationFailure("Unknown access token."));
        auto state=parseInteger<unsigned int>(field(result.get(),0,1));
        auto issued=parseInteger<std::int64_t>(field(result.get(),0,2));
        auto expires=parseInteger<std::int64_t>(field(result.get(),0,3));
        if(!state||!issued||!expires||state.value()>1U)return foundation::fail(foundation::ErrorCode::Internal);
        token::TokenFamilyId family{field(result.get(),0,0)};
        auto context=loadTokenContext(lease->get(),family);
        if(!context)return foundation::fail(context.error());
        std::optional<foundation::Instant> revoked;
        if(!PQgetisnull(result.get(),0,4)){auto value=parseInteger<std::int64_t>(field(result.get(),0,4));
            if(!value)return foundation::fail(value.error());
            revoked=storedInstant(value.value());
        }
        return token::AccessTokenRecord{digestValue,std::move(family),std::move(context).value(),storedInstant(issued.value()),storedInstant(expires.value()),static_cast<token::AccessTokenState>(state.value()),revoked};
    }

    foundation::Result<token::RefreshTokenRecord> PostgresIdentityProviderStore::findRefresh(const token::TokenDigest& digestValue)
    {
        auto lease=m_pool->m_implementation->acquire();
        if(!lease)return foundation::fail(lease.error());
        ResultPointer result=execParams(lease->get(),"SELECT family_id,sequence,state,issued_at_ms,expires_at_ms,changed_at_ms FROM openproof.oauth_refresh_tokens WHERE token_digest=decode($1,'hex')",{foundation::toHex(digestValue.bytes())});
        if(!tuplesOk(result.get()))return foundation::fail(databaseError(result.get(),"find refresh token"));
        if(PQntuples(result.get())!=1)return foundation::fail(authenticationFailure("Unknown refresh token."));
        auto sequence=parseInteger<std::uint64_t>(field(result.get(),0,1));
        auto state=parseInteger<unsigned int>(field(result.get(),0,2));
        auto issued=parseInteger<std::int64_t>(field(result.get(),0,3));
        auto expires=parseInteger<std::int64_t>(field(result.get(),0,4));
        if(!sequence||!state||!issued||!expires||state.value()>2U)return foundation::fail(foundation::ErrorCode::Internal);
        token::TokenFamilyId family{field(result.get(),0,0)};
        auto context=loadTokenContext(lease->get(),family);
        if(!context)return foundation::fail(context.error());
        std::optional<foundation::Instant> changed;
        if(!PQgetisnull(result.get(),0,5)){auto value=parseInteger<std::int64_t>(field(result.get(),0,5));
            if(!value)return foundation::fail(value.error());
            changed=storedInstant(value.value());
        }
        return token::RefreshTokenRecord{digestValue,std::move(family),sequence.value(),std::move(context).value(),storedInstant(issued.value()),storedInstant(expires.value()),static_cast<token::RefreshTokenState>(state.value()),changed};
    }

    foundation::Status PostgresIdentityProviderStore::rotateRefresh(
    const token::TokenDigest& presented, foundation::Instant now,
    token::AccessTokenRecord replacementAccess, token::RefreshTokenRecord replacementRefresh)
    {
        auto lease=m_pool->m_implementation->acquire();
        if(!lease)return foundation::fail(lease.error());
        PGconn* connection=lease->get();
        auto begun=beginTransaction(connection);
        if(!begun)return begun;
        ResultPointer current=execParams(connection,"SELECT family_id,sequence,state,expires_at_ms FROM openproof.oauth_refresh_tokens WHERE token_digest=decode($1,'hex') FOR UPDATE",{foundation::toHex(presented.bytes())});
        if(!tuplesOk(current.get())){auto error=databaseError(current.get(),"lock refresh token");
            rollback(connection);
            return foundation::fail(error);
        }
        if(PQntuples(current.get())!=1){rollback(connection);
            return foundation::fail(authenticationFailure("Unknown refresh token."));
        }
        auto sequence=parseInteger<std::uint64_t>(field(current.get(),0,1));
        auto state=parseInteger<unsigned int>(field(current.get(),0,2));
        auto expires=parseInteger<std::int64_t>(field(current.get(),0,3));
        if(!sequence||!state||!expires){rollback(connection);
            return foundation::fail(foundation::ErrorCode::Internal);
        }
        token::TokenFamilyId family{field(current.get(),0,0)};
        if(state.value()!=0U||storedInstant(expires.value())<=now){auto revoked=revokeTokenFamilySql(connection,family,now);
            if(!revoked){rollback(connection);
                return revoked;
            }
            auto committed=commit(connection);
            if(!committed)return committed;
            return foundation::fail(authenticationFailure("Refresh token reuse or expiry detected; family revoked."));
        }
        if(replacementAccess.family()!=family||replacementRefresh.family()!=family||replacementRefresh.sequence()!=sequence.value()+1U){rollback(connection);
            return foundation::fail(foundation::ErrorCode::InvalidArgument,"The refresh rotation replacement is inconsistent.");
        }
        auto used=runCommand(connection,"UPDATE openproof.oauth_refresh_tokens SET state=1,changed_at_ms=$2 WHERE token_digest=decode($1,'hex') AND state=0",{foundation::toHex(presented.bytes()),instant(now)},"consume refresh token");
        if(!used){rollback(connection);
            return used;
        }
        auto accessStatus=runCommand(connection,"INSERT INTO openproof.oauth_access_tokens(token_digest,family_id,state,issued_at_ms,expires_at_ms) VALUES(decode($1,'hex'),$2,0,$3,$4)",{foundation::toHex(replacementAccess.digest().bytes()),std::string{family.value()},instant(replacementAccess.issuedAt()),instant(replacementAccess.expiresAt())},"rotate access token");
        auto refreshStatus=runCommand(connection,"INSERT INTO openproof.oauth_refresh_tokens(token_digest,family_id,sequence,state,issued_at_ms,expires_at_ms) VALUES(decode($1,'hex'),$2,$3,0,$4,$5)",{foundation::toHex(replacementRefresh.digest().bytes()),std::string{family.value()},integer(static_cast<std::int64_t>(replacementRefresh.sequence())),instant(replacementRefresh.issuedAt()),instant(replacementRefresh.expiresAt())},"rotate refresh token");
        if(!accessStatus||!refreshStatus){rollback(connection);
            return foundation::fail((!accessStatus?accessStatus:refreshStatus).error());
        }
        return commit(connection);
    }

    foundation::Status PostgresIdentityProviderStore::revokeFamily(const token::TokenFamilyId& family, foundation::Instant now)
    {
        auto lease=m_pool->m_implementation->acquire();
        if(!lease)return foundation::fail(lease.error());
        PGconn* connection=lease->get();
        auto begun=beginTransaction(connection);
        if(!begun)return begun;
        auto status=revokeTokenFamilySql(connection,family,now);
        if(!status){rollback(connection);
            return status;
        }
        return commit(connection);
    }

    foundation::Status PostgresIdentityProviderStore::revokeToken(const token::TokenDigest& digestValue, foundation::Instant now)
    {
        auto lease=m_pool->m_implementation->acquire();
        if(!lease)return foundation::fail(lease.error());
        PGconn* connection=lease->get();
        auto begun=beginTransaction(connection);
        if(!begun)return begun;
        const std::string digest=foundation::toHex(digestValue.bytes());
        ResultPointer access=execParams(connection,"SELECT family_id FROM openproof.oauth_access_tokens WHERE token_digest=decode($1,'hex') FOR UPDATE",{digest});
        if(!tuplesOk(access.get())){auto error=databaseError(access.get(),"find token to revoke");
            rollback(connection);
            return foundation::fail(error);
        }
        if(PQntuples(access.get())==1){auto status=runCommand(connection,"UPDATE openproof.oauth_access_tokens SET state=1,revoked_at_ms=COALESCE(revoked_at_ms,$2) WHERE token_digest=decode($1,'hex')",{digest,instant(now)},"revoke access token");
            if(!status){rollback(connection);
                return status;
            }
            return commit(connection);
        }
        ResultPointer refresh=execParams(connection,"SELECT family_id FROM openproof.oauth_refresh_tokens WHERE token_digest=decode($1,'hex') FOR UPDATE",{digest});
        if(!tuplesOk(refresh.get())){auto error=databaseError(refresh.get(),"find refresh token to revoke");
            rollback(connection);
            return foundation::fail(error);
        }
        if(PQntuples(refresh.get())==1){auto status=revokeTokenFamilySql(connection,token::TokenFamilyId{field(refresh.get(),0,0)},now);
            if(!status){rollback(connection);
                return status;
            }}
        return commit(connection);
    }

}

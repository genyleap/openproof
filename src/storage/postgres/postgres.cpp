module;

#include <algorithm>
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
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <libpq-fe.h>

module openproof.storage.postgres;

import openproof.administration;
import openproof.audit;
import openproof.identity.core;
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
    "last_seen_at_ms, absolute_expires_at_ms, idle_timeout_ms, revoked_at_ms";

[[nodiscard]] foundation::Result<session::Session> sessionFromRow(PGresult* result, int row)
{
    if (PQnfields(result) != 14) {
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
        foundation::Duration{idle.value()}, revokedAt);
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

PostgresSessionRepository::PostgresSessionRepository(ConnectionPool& pool) : m_pool(&pool) {}

foundation::Status PostgresSessionRepository::add(session::Session value)
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    const auto factorValue = static_cast<unsigned int>(value.strength().factors());
    ResultPointer result = execParams(lease->get(),
        "INSERT INTO openproof.sessions(id,identity_id,provider,assurance,factors,"
        "phishing_resistant,state,token_digest,authenticated_at_ms,issued_at_ms,"
        "last_seen_at_ms,absolute_expires_at_ms,idle_timeout_ms,revoked_at_ms) "
        "VALUES($1,$2,$3,$4,$5,$6,$7,decode($8,'hex'),$9,$10,$11,$12,$13,NULL)",
        {std::string{value.id().value()}, std::string{value.identity().value()},
         std::string{value.provider().value()},
         std::to_string(static_cast<unsigned int>(value.assurance())),
         std::to_string(factorValue), value.strength().isPhishingResistant() ? "true" : "false",
         std::to_string(static_cast<unsigned int>(value.state())),
         foundation::toHex(value.tokenDigest().bytes()), instant(value.authenticatedAt()),
         instant(value.issuedAt()), instant(value.lastSeenAt()), instant(value.absoluteExpiresAt()),
         integer(value.idleTimeout().count())});
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
    ResultPointer result = execParams(lease->get(),
        "INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) "
        "VALUES($1,$2,$3,$4) ON CONFLICT(provider,external_subject) DO UPDATE SET "
        "identity_id=EXCLUDED.identity_id WHERE openproof.external_identities.identity_id=EXCLUDED.identity_id",
        {std::string{link.external().providerId().value()},
         std::string{link.external().subject().value()}, std::string{link.owner().value()},
         instant(link.requestedAt())});
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

foundation::Result<std::vector<identity::core::ExternalIdentityRef>>
PostgresExternalIdentityDirectory::externalIdentitiesOf(
    const identity::core::IdentityId& owner) const
{
    auto lease = m_pool->m_implementation->acquire();
    if (!lease) return foundation::fail(lease.error());
    ResultPointer result = execParams(lease->get(),
        "SELECT provider,external_subject FROM openproof.external_identities "
        "WHERE identity_id=$1 ORDER BY provider,external_subject", {std::string{owner.value()}});
    if (!tuplesOk(result.get())) return foundation::fail(databaseError(result.get(), "list external identities"));
    std::vector<identity::core::ExternalIdentityRef> output;
    for (int row = 0; row < PQntuples(result.get()); ++row) {
        output.emplace_back(identity::provider::ProviderId{field(result.get(), row, 0)},
                            identity::provider::ExternalSubject{field(result.get(), row, 1)});
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

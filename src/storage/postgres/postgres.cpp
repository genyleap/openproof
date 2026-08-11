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

}

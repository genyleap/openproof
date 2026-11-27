#include "async_connection.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <exception>
#include <filesystem>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include "coroutine_startup.hpp"

import openproof.storage.migration_package;

namespace openproof::storage::postgres {
namespace {
namespace asio=boost::asio;
namespace pg=async_detail;
using E=foundation::ErrorCode;
using Clock=std::chrono::steady_clock;
using Params=std::vector<std::optional<std::string>>;
std::chrono::milliseconds remaining(Clock::time_point deadline)
{
    auto budget=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now());
    if (budget<=std::chrono::milliseconds::zero()) throw std::runtime_error{"Startup deadline expired"};
    return budget;
}
asio::awaitable<foundation::Status> validateAsync(foundation::SecretString dsn,
    std::optional<identity::core::OrganizationId> tenant,unsigned int version,security::Sha256Digest fingerprint)
{
    if (version==0U || (tenant && tenant->empty())) co_return foundation::fail(E::InvalidArgument);
    try {
        const auto deadline=Clock::now()+std::chrono::seconds{10};
        auto connection=co_await pg::AsyncConnection::connect(std::string{dsn.expose()},remaining(deadline));
        static_cast<void>(co_await connection->query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",{},remaining(deadline)));
        auto journal=co_await connection->query(
            "SELECT to_version,encode(to_fingerprint,'hex') FROM openproof.master_key_rotations ORDER BY sequence DESC LIMIT 1",
            {},remaining(deadline));
        if (journal.rows.empty()) {
            if (version!=1U) co_return foundation::fail(E::FailedPrecondition,"Configured master key has no committed rotation journal.");
        } else {
            if (journal.rows.size()!=1U || journal.rows.front().size()!=2U ||
                !journal.rows.front()[0] || !journal.rows.front()[1])
                co_return foundation::fail(E::FailedPrecondition);
            const auto& row=journal.rows.front();
            unsigned int storedVersion{};
            const auto& number=*row[0];
            const auto [end,error]=std::from_chars(number.data(),number.data()+number.size(),storedVersion);
            auto bytes=foundation::fromHex(*row[1]);
            if (error!=std::errc{} || end!=number.data()+number.size() || storedVersion!=version ||
                !bytes || bytes->size()!=fingerprint.size() ||
                !security::constantTimeEquals(std::span<const std::byte>{bytes->data(),bytes->size()},
                    std::span<const std::byte>{fingerprint.data(),fingerprint.size()}))
                co_return foundation::fail(E::FailedPrecondition,"Configured master key does not match the committed rotation journal.");
        }
        if (tenant) {
            Params args{std::string{tenant->value()}};
            const auto organization=co_await connection->query(
                "SELECT id FROM openproof.organizations WHERE id=$1 AND state=0",std::move(args),remaining(deadline));
            if (organization.rows.size()!=1U || organization.rows.front().size()!=1U ||
                organization.rows.front()[0]!=std::optional<std::string>{std::string{tenant->value()}})
                co_return foundation::fail(E::FailedPrecondition,"Configured authentication organization is absent or inactive.");
        }
        const auto committed=co_await connection->query("COMMIT",{},remaining(deadline));
        if (committed.commandTag!="COMMIT" || !connection->reusable()) co_return foundation::fail(E::Unavailable);
        co_return foundation::ok();
    } catch (const std::exception&) {co_return foundation::fail(E::Unavailable,"Database startup validation is unavailable.");}
}
}
asio::awaitable<foundation::Result<NativeMigrationReport>>
migrateSchemaAsync(foundation::SecretString dsn,std::filesystem::path directory,foundation::Duration timeout)
{
    if (timeout<=foundation::Duration::zero() || timeout>std::chrono::minutes{10})
        co_return foundation::fail(E::InvalidArgument);
    try {
        // Files are trusted deployment artifacts, read only during startup or CLI.
        auto package=migration::loadPackage(directory);
        if (!package) co_return foundation::fail(package.error());
        auto& [migrations,baselineSql]=package.value();
        const auto deadline=Clock::now()+timeout;
        auto connection=co_await pg::AsyncConnection::connect(std::string{dsn.expose()},remaining(deadline));
        const auto execute=[&](std::string sql,Params args) {
            return connection->query(std::move(sql),std::move(args),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        static_cast<void>(co_await execute("SELECT pg_advisory_xact_lock(1827364512)",{}));
        bool freshNamespace=false;
        if (baselineSql) {
            const auto existing=co_await execute(
                "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='openproof')",{});
            if (existing.rows.size()!=1U || existing.rows.front().size()!=1U ||
                !existing.rows.front()[0]) co_return foundation::fail(E::Unavailable);
            freshNamespace=*existing.rows.front()[0]=="f";
        }
        co_await connection->executeMigrationScript(
            "CREATE SCHEMA IF NOT EXISTS openproof;"
            "CREATE TABLE IF NOT EXISTS openproof.schema_migrations ("
            "version text PRIMARY KEY, checksum bytea NOT NULL CHECK (octet_length(checksum)=32),"
            "applied_at timestamptz NOT NULL DEFAULT clock_timestamp())",remaining(deadline));
        NativeMigrationReport report;
        const auto ledger=co_await execute("SELECT version,encode(checksum,'hex') FROM openproof.schema_migrations",{});
        for (const auto& row:ledger.rows) {
            if (row.size()!=2U || !row[0] || !row[1]) co_return foundation::fail(E::FailedPrecondition);
            const auto existing=std::ranges::find_if(migrations,[&](const auto& entry){return entry.version==*row[0];});
            if (existing==migrations.end() || existing->checksum!=*row[1])
                co_return foundation::fail(E::FailedPrecondition,"An applied migration is missing or has changed.");
            existing->recorded=true;
            ++report.alreadyApplied;
        }
        if (baselineSql && ledger.rows.empty()) {
            if (!freshNamespace) co_return foundation::fail(E::FailedPrecondition,"An empty migration ledger does not identify a fresh schema.");
            co_await connection->executeMigrationScript(*baselineSql,remaining(deadline));
            report.usedBaseline=true;
        }
        for (const auto& migration:migrations) {
            if (migration.archived || migration.recorded) continue;
            if (!report.usedBaseline)
                co_await connection->executeMigrationScript(migration.sql,remaining(deadline));
            Params args{migration.version,migration.checksum};
            const auto inserted=co_await execute(
                "INSERT INTO openproof.schema_migrations(version,checksum) VALUES($1,decode($2,'hex')) RETURNING version",
                std::move(args));
            if (inserted.rows.size()!=1U || inserted.rows.front().size()!=1U ||
                inserted.rows.front()[0]!=std::optional<std::string>{migration.version})
                co_return foundation::fail(E::Unavailable);
            ++report.applied;
        }
        const auto committed=co_await execute("COMMIT",{});
        if (committed.commandTag!="COMMIT" || !connection->reusable()) co_return foundation::fail(E::Unavailable);
        co_return report;
    } catch (const std::exception&) {
        co_return foundation::fail(E::Unavailable,"Native schema migration is unavailable.");
    }
}
foundation::Result<NativeMigrationReport> migrateSchemaBeforeListener(
    foundation::SecretString dsn,std::filesystem::path directory)
{
    try {
        asio::io_context io;
        auto migrated=asio::co_spawn(io,migrateSchemaAsync(std::move(dsn),std::move(directory),std::chrono::minutes{5}),asio::use_future);
        io.run();
        return migrated.get();
    } catch (const std::exception&) {return foundation::fail(E::Unavailable,"Database migration failed.");}
}
foundation::Status verifyMasterKeyBeforeListener(foundation::SecretString dsn,
    unsigned int version,security::Sha256Digest fingerprint)
{
    try {
        asio::io_context io;
        auto checked=asio::co_spawn(io,validateAsync(std::move(dsn),std::nullopt,version,fingerprint),asio::use_future);
        io.run();return checked.get();
    } catch (const std::exception&) {return foundation::fail(E::Unavailable,"Master key validation failed.");}
}

namespace {
asio::awaitable<foundation::Result<NativeMasterRotationReport>> rotateMasterAsync(
    foundation::SecretString dsn,unsigned int currentVersion,security::Sha256Digest currentFingerprint,
    unsigned int replacementVersion,security::Sha256Digest replacementFingerprint,bool dryRun)
{
    if (currentVersion==0U || replacementVersion<=currentVersion || replacementVersion>2147483647U
        || security::constantTimeEquals(currentFingerprint,replacementFingerprint))
        co_return foundation::fail(E::InvalidArgument);
    try {
        const auto deadline=Clock::now()+std::chrono::minutes{5};
        auto connection=co_await pg::AsyncConnection::connect(std::string{dsn.expose()},remaining(deadline));
        const auto execute=[&](std::string sql,Params args){
            return connection->query(std::move(sql),std::move(args),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL SERIALIZABLE",{}));
        static_cast<void>(co_await execute("SELECT pg_advisory_xact_lock(7299730475761673317)",{}));
        static_cast<void>(co_await execute(
            "LOCK TABLE openproof.authentication_transactions,openproof.sessions,"
            "openproof.account_verification_challenges,openproof.passkey_registration_ceremonies,"
            "openproof.oauth_authorization_codes,openproof.oauth_token_families,"
            "openproof.oauth_device_authorizations,openproof.oauth_pushed_authorization_requests IN ACCESS EXCLUSIVE MODE",{}));
        Params duplicateArgs{std::to_string(replacementVersion)};
        const auto duplicate=co_await execute("SELECT 1 FROM openproof.master_key_rotations WHERE to_version=$1",std::move(duplicateArgs));
        if (!duplicate.rows.empty()) co_return foundation::fail(E::AlreadyExists);
        const auto head=co_await execute(
            "SELECT to_version,encode(to_fingerprint,'hex') FROM openproof.master_key_rotations ORDER BY sequence DESC LIMIT 1",{});
        if (head.rows.empty()) {
            if (currentVersion!=1U) co_return foundation::fail(E::FailedPrecondition);
        } else {
            if (head.rows.size()!=1U || head.rows.front().size()!=2U || !head.rows.front()[0] || !head.rows.front()[1]
                || *head.rows.front()[0]!=std::to_string(currentVersion))
                co_return foundation::fail(E::FailedPrecondition);
            auto fingerprint=foundation::fromHex(*head.rows.front()[1]);
            if (!fingerprint || fingerprint->size()!=currentFingerprint.size() ||
                !security::constantTimeEquals(std::span<const std::byte>{fingerprint->data(),fingerprint->size()},
                    std::span<const std::byte>{currentFingerprint.data(),currentFingerprint.size()}))
                co_return foundation::fail(E::FailedPrecondition);
        }
        // All statements are constant, offline-only and return one count
        // regardless of the number of deleted records.
        const auto remove=[&](std::string table)->asio::awaitable<std::size_t>{
            const auto rows=co_await execute("WITH removed AS (DELETE FROM openproof."+table+
                " RETURNING 1) SELECT count(*)::text FROM removed",{});
            if (rows.rows.size()!=1U || rows.rows.front().size()!=1U || !rows.rows.front()[0])
                throw std::runtime_error{"Invalid rotation count"};
            std::size_t count{};
            const auto& value=*rows.rows.front()[0];
            const auto [end,error]=std::from_chars(value.data(),value.data()+value.size(),count);
            if (error!=std::errc{} || end!=value.data()+value.size())
                throw std::runtime_error{"Invalid rotation count"};
            co_return count;
        };
        NativeMasterRotationReport report;
        report.dryRun=dryRun;
        report.authenticationTransactions=co_await remove("authentication_transactions");
        report.sessions=co_await remove("sessions");
        report.accountChallenges=co_await remove("account_verification_challenges");
        report.passkeyRegistrations=co_await remove("passkey_registration_ceremonies");
        report.authorizationCodes=co_await remove("oauth_authorization_codes");
        report.tokenFamilies=co_await remove("oauth_token_families");
        report.deviceAuthorizations=co_await remove("oauth_device_authorizations");
        report.pushedRequests=co_await remove("oauth_pushed_authorization_requests");
        if (dryRun) {
            const auto rolledBack=co_await execute("ROLLBACK",{});
            if (rolledBack.commandTag!="ROLLBACK" || !connection->reusable()) co_return foundation::fail(E::Unavailable);
            co_return report;
        }
        Params args{std::to_string(currentVersion),std::to_string(replacementVersion),
            foundation::toHex(currentFingerprint),foundation::toHex(replacementFingerprint),
            std::to_string(report.authenticationTransactions),std::to_string(report.sessions),
            std::to_string(report.accountChallenges),std::to_string(report.passkeyRegistrations),
            std::to_string(report.authorizationCodes),std::to_string(report.tokenFamilies),
            std::to_string(report.deviceAuthorizations),std::to_string(report.pushedRequests)};
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.master_key_rotations"
            "(from_version,to_version,from_fingerprint,to_fingerprint,authentication_transactions,sessions,account_challenges,"
            "passkey_registrations,authorization_codes,token_families,device_authorizations,pushed_requests,rotated_at_ms) "
            "VALUES($1,$2,decode($3,'hex'),decode($4,'hex'),$5,$6,$7,$8,$9,$10,$11,$12,"
            "(extract(epoch FROM clock_timestamp())*1000)::bigint)",std::move(args)));
        const auto committed=co_await execute("COMMIT",{});
        if (committed.commandTag!="COMMIT" || !connection->reusable()) co_return foundation::fail(E::Unavailable);
        co_return report;
    } catch (const std::exception&) {co_return foundation::fail(E::Unavailable,"Native master key rotation failed.");}
}
}
foundation::Result<NativeMasterRotationReport> rotateMasterKeyOffline(
    foundation::SecretString dsn,unsigned int currentVersion,security::Sha256Digest currentFingerprint,
    unsigned int replacementVersion,security::Sha256Digest replacementFingerprint,bool dryRun)
{
    try {
        asio::io_context io;
        auto result=asio::co_spawn(io,rotateMasterAsync(std::move(dsn),currentVersion,currentFingerprint,
            replacementVersion,replacementFingerprint,dryRun),asio::use_future);
        io.run();return result.get();
    } catch (const std::exception&) {return foundation::fail(E::Unavailable,"Master key rotation failed.");}
}
namespace {
asio::awaitable<foundation::Result<NativeCredentialRekeyReport>> rekeyTotpAsync(
    foundation::SecretString dsn,const security::AeadKey& currentKey,unsigned int currentVersion,
    const security::AeadKey& replacementKey,unsigned int replacementVersion,bool dryRun)
{
    if (currentVersion==0U || replacementVersion<=currentVersion || replacementVersion>2147483647U ||
        currentKey.matches(replacementKey)) co_return foundation::fail(E::InvalidArgument);
    try {
        const auto deadline=Clock::now()+std::chrono::minutes{5};
        auto connection=co_await pg::AsyncConnection::connect(std::string{dsn.expose()},remaining(deadline));
        const auto execute=[&](std::string sql,Params args){
            return connection->query(std::move(sql),std::move(args),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL SERIALIZABLE",{}));
        static_cast<void>(co_await execute("SELECT pg_advisory_xact_lock(7299730475761673316)",{}));
        static_cast<void>(co_await execute("LOCK TABLE openproof.totp_credentials IN ACCESS EXCLUSIVE MODE",{}));
        Params duplicateArgs{std::to_string(replacementVersion)};
        const auto duplicate=co_await execute(
            "SELECT 1 FROM openproof.credential_key_rotations WHERE purpose='totp' AND to_version=$1",
            std::move(duplicateArgs));
        if (!duplicate.rows.empty()) co_return foundation::fail(E::AlreadyExists);
        NativeCredentialRekeyReport report{0U,0U,dryRun};
        std::optional<std::string> cursor;
        // Keyset pagination bounds ciphertext materialization without weakening
        // the table lock or the all-or-nothing transaction.
        for (;;) {
            Params pageArgs{cursor};
            const auto page=co_await execute(
                "SELECT identity_id,encode(encrypted_seed,'hex'),key_version FROM openproof.totp_credentials "
                "WHERE $1::text IS NULL OR identity_id COLLATE \"C\">$1::text COLLATE \"C\" "
                "ORDER BY identity_id COLLATE \"C\" LIMIT 128 FOR UPDATE",std::move(pageArgs));
            if (page.rows.empty()) break;
            for (const auto& row:page.rows) {
                if (row.size()!=3U || !row[0] || !row[1] || !row[2])
                    co_return foundation::fail(E::FailedPrecondition);
                const auto& id=*row[0];
                const auto& encryptedHex=*row[1];
                const auto& version=*row[2];
                if (id.empty() || (cursor && *cursor>=id))
                    co_return foundation::fail(E::FailedPrecondition);
                auto envelope=foundation::fromHex(encryptedHex);
                if (!envelope) co_return foundation::fail(envelope.error());
                const std::string aad="openproof/totp/v1:"+id;
                if (version==std::to_string(replacementVersion)) {
                    auto validated=security::openAes256Gcm(replacementKey,envelope.value(),aad);
                    if (!validated) co_return foundation::fail(validated.error());
                    ++report.alreadyCurrent;
                } else {
                    if (version!=std::to_string(currentVersion)) co_return foundation::fail(E::FailedPrecondition);
                    auto plaintext=security::openAes256Gcm(currentKey,envelope.value(),aad);
                    if (!plaintext) co_return foundation::fail(plaintext.error());
                    auto encrypted=security::sealAes256Gcm(replacementKey,plaintext.value(),aad);
                    if (!encrypted) co_return foundation::fail(encrypted.error());
                    Params args{id,foundation::toHex(encrypted.value()),std::to_string(replacementVersion),
                        std::to_string(currentVersion),encryptedHex};
                    const auto updated=co_await execute(
                        "UPDATE openproof.totp_credentials SET encrypted_seed=decode($2,'hex'),key_version=$3 "
                        "WHERE identity_id=$1 AND key_version=$4 AND encrypted_seed=decode($5,'hex') RETURNING identity_id",
                        std::move(args));
                    if (updated.rows.size()!=1U || updated.rows.front().size()!=1U || updated.rows.front()[0]!=row[0])
                        co_return foundation::fail(E::Conflict);
                    ++report.rekeyed;
                }
                cursor=id;
            }
        }
        if (dryRun) {
            const auto rolledBack=co_await execute("ROLLBACK",{});
            if (rolledBack.commandTag!="ROLLBACK" || !connection->reusable()) co_return foundation::fail(E::Unavailable);
            co_return report;
        }
        Params journalArgs{std::to_string(currentVersion),std::to_string(replacementVersion),
            std::to_string(report.rekeyed),std::to_string(report.alreadyCurrent)};
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.credential_key_rotations(purpose,from_version,to_version,rekeyed_rows,unchanged_rows,rotated_at_ms) "
            "VALUES('totp',$1,$2,$3,$4,(extract(epoch FROM clock_timestamp())*1000)::bigint)",std::move(journalArgs)));
        const auto committed=co_await execute("COMMIT",{});
        if (committed.commandTag!="COMMIT" || !connection->reusable()) co_return foundation::fail(E::Unavailable);
        co_return report;
    } catch (const std::exception&) {co_return foundation::fail(E::Unavailable,"Native TOTP rekey failed.");}
}
}
foundation::Result<NativeCredentialRekeyReport> rekeyTotpOffline(
    foundation::SecretString dsn,const security::AeadKey& currentKey,unsigned int currentVersion,
    const security::AeadKey& replacementKey,unsigned int replacementVersion,bool dryRun)
{
    try {
        asio::io_context io;
        auto result=asio::co_spawn(io,rekeyTotpAsync(std::move(dsn),currentKey,currentVersion,
            replacementKey,replacementVersion,dryRun),asio::use_future);
        io.run();return result.get();
    } catch (const std::exception&) {return foundation::fail(E::Unavailable,"TOTP rekey failed.");}
}
foundation::Status nativeDatabasePreflight(foundation::SecretString dsn,std::filesystem::path directory,
    identity::core::OrganizationId tenant,unsigned int masterVersion,security::Sha256Digest fingerprint)
{
    try {
        auto result=migrateSchemaBeforeListener(dsn.clone(),std::move(directory));
        if (!result) return foundation::fail(result.error());
        asio::io_context io;
        auto checked=asio::co_spawn(io,validateAsync(std::move(dsn),std::move(tenant),masterVersion,fingerprint),asio::use_future);
        io.run();
        return checked.get();
    } catch (const std::exception&) {return foundation::fail(E::Unavailable,"Database preflight failed.");}
}
}

#include "../../src/gateway/asio_service_ids_extern.hpp"
#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <span>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <libpq-fe.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include "../../src/storage/postgres/coroutine_session_repository.hpp"
#include "../../src/storage/postgres/coroutine_auth_transaction_store.hpp"
#include "../../src/storage/postgres/coroutine_recovery_code_repository.hpp"
#include "../../src/storage/postgres/coroutine_startup.hpp"
#include "../../src/storage/postgres/coroutine_admin_store.hpp"
#include "../../src/storage/postgres/coroutine_canonical_finalizer.hpp"
#include "../../src/storage/postgres/coroutine_authorization_audit.hpp"
#include "../../src/storage/postgres/coroutine_local_proof_verifier.hpp"

import openproof.foundation;
import openproof.administration;
import openproof.application;
import openproof.client;
import openproof.audit;
import openproof.credentials;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.identity.profile;
import openproof.oauth;
import openproof.organization;
import openproof.policy;
import openproof.provider.local;
import openproof.provider.passkey;
import openproof.security;
import openproof.session;
import openproof.token;

namespace {

namespace asio = boost::asio;
using namespace std::chrono_literals;
namespace app = openproof::application;
namespace cli = openproof::client;
namespace core = openproof::identity::core;
namespace admin = openproof::administration;
namespace audit = openproof::audit;
namespace cred = openproof::credentials;
namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace profile = openproof::identity::profile;
namespace oauth = openproof::oauth;
namespace pg = openproof::storage::postgres;
namespace pol = openproof::policy;
namespace org = openproof::organization;
namespace local = openproof::provider::local;
namespace passkey = openproof::provider::passkey;
namespace sec = openproof::security;
namespace sess = openproof::session;
namespace tok = openproof::token;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

class PostgresIntegrationTest : public testing::Test {
protected:
    void SetUp() override
    {
        const char* configured=std::getenv("OPENPROOF_TEST_POSTGRES_INTEGRATION");
        const char* ack=std::getenv("OPENPROOF_TEST_POSTGRES_INTEGRATION_ACK");
        if (!configured && !ack) GTEST_SKIP()<<"Run the private integration fixture.";
        ASSERT_NE(configured,nullptr);
        ASSERT_NE(ack,nullptr);
        ASSERT_STREQ(ack,"YES_EXCLUSIVE_DISPOSABLE_DATABASE");
        constexpr std::string_view prefix="host=/tmp/openproof-integration-pg.";
        constexpr std::string_view suffix=" port=55419 user=postgres dbname=openproof_integration_ci";
        const std::string_view value{configured};
        ASSERT_TRUE(value.starts_with(prefix) && value.ends_with(suffix));
        ASSERT_EQ(value.size(),prefix.size()+8U+suffix.size());
        for (const char c:value.substr(prefix.size(),8U)) {
            ASSERT_TRUE((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9'));
        }
        // libpq environment defaults must not redirect a private socket DSN.
        ASSERT_EQ(std::getenv("PGHOSTADDR"),nullptr);
        ASSERT_EQ(std::getenv("PGSERVICE"),nullptr);
        ASSERT_EQ(std::getenv("PGOPTIONS"),nullptr);
        connectionString=configured;
        auto migrated = pg::migrateSchemaBeforeListener(fnd::SecretString{connectionString},
            std::filesystem::path{OPENPROOF_SOURCE_DIR} / "migrations");
        ASSERT_TRUE(migrated)
            << (migrated ? "" : std::string{migrated.error().internalDetail()});

        direct.reset(PQconnectdb(connectionString.c_str()));
        ASSERT_NE(direct.get(), nullptr);
        ASSERT_EQ(PQstatus(direct.get()), CONNECTION_OK);
        execute("TRUNCATE openproof.master_key_rotations, "
                "openproof.credential_key_rotations, "
                "openproof.audit_events, "
                "openproof.security_event_outbox, "
                "openproof.authentication_transactions, "
                "openproof.organizations CASCADE");
        execute("INSERT INTO openproof.organizations(id,name,state,created_at_ms) "
                "VALUES('org','Test',0,1770000000000)");
        execute("INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) "
                "VALUES('identity-1','org',0,0,1770000000000)");
    }

    struct ConnectionDeleter final {
        void operator()(PGconn* connection) const noexcept { if (connection != nullptr) PQfinish(connection); }
    };
    struct ResultDeleter final {
        void operator()(PGresult* result) const noexcept { if (result != nullptr) PQclear(result); }
    };

    void execute(const char* sql)
    {
        std::unique_ptr<PGresult, ResultDeleter> result{PQexec(direct.get(), sql)};
        ASSERT_NE(result.get(), nullptr);
        ASSERT_EQ(PQresultStatus(result.get()), PGRES_COMMAND_OK)
            << PQresultErrorMessage(result.get());
    }

    template<typename T>
    T run(asio::awaitable<T> operation)
    {
        io.restart();
        std::optional<T> value;
        const auto capture=[](asio::awaitable<T> task,std::optional<T>& out)->asio::awaitable<void>{
            out.emplace(co_await std::move(task));
        };
        auto done=asio::co_spawn(io,capture(std::move(operation),value),asio::use_future);
        io.run();
        done.get();
        return std::move(value).value();
    }

    std::string scalar(const char* sql)
    {
        std::unique_ptr<PGresult,ResultDeleter> result{PQexec(direct.get(),sql)};
        if (!result || PQresultStatus(result.get())!=PGRES_TUPLES_OK ||
            PQntuples(result.get())!=1 || PQnfields(result.get())!=1 || PQgetisnull(result.get(),0,0))
            throw std::runtime_error{"Invalid PostgreSQL test scalar"};
        return PQgetvalue(result.get(),0,0);
    }

    void seedRecoveryEligibility()
    {
        execute("INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) "
            "VALUES('local','fixture-owner','identity-1',1770000000000)");
        execute("INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
            "VALUES('identity-1','fixture-hash',1770000000000)");
        execute("INSERT INTO openproof.totp_credentials(identity_id,encrypted_seed,key_version,last_accepted_step,enrolled_at_ms) "
            "VALUES('identity-1',decode('00','hex'),1,NULL,1770000000000)");
    }

    void seedLocalCredentials(const idp::ExternalSubject& subject,const cred::PasswordHasher& hasher,
        const fnd::SecretString& password,const sec::AeadKey& key,const cred::TotpSecret* seed=nullptr)
    {
        auto hash=hasher.hash(password);
        ASSERT_TRUE(hash);
        const std::string subjectValue{subject.value()},encoded{hash->encoded()};
        const char* values[]{subjectValue.c_str(),encoded.c_str()};
        std::unique_ptr<PGresult,ResultDeleter> link{PQexecParams(direct.get(),
            "INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) "
            "VALUES('local',$1,'identity-1',1770000000000)",1,nullptr,values,nullptr,nullptr,0)};
        ASSERT_TRUE(link && PQresultStatus(link.get())==PGRES_COMMAND_OK);
        std::unique_ptr<PGresult,ResultDeleter> stored{PQexecParams(direct.get(),
            "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
            "VALUES('identity-1',$1,1770000000000)",1,nullptr,values+1,nullptr,nullptr,0)};
        ASSERT_TRUE(stored && PQresultStatus(stored.get())==PGRES_COMMAND_OK);
        if(seed){
            auto envelope=sec::sealAes256Gcm(key,seed->bytes(),"openproof/totp/v1:identity-1");
            ASSERT_TRUE(envelope);
            const auto hex=fnd::toHex(envelope.value());
            const char* ciphertext[]{hex.c_str()};
            std::unique_ptr<PGresult,ResultDeleter> enrolled{PQexecParams(direct.get(),
                "INSERT INTO openproof.totp_credentials(identity_id,encrypted_seed,key_version,last_accepted_step,enrolled_at_ms) "
                "VALUES('identity-1',decode($1,'hex'),1,NULL,1770000000000)",1,nullptr,ciphertext,nullptr,nullptr,0)};
            ASSERT_TRUE(enrolled && PQresultStatus(enrolled.get())==PGRES_COMMAND_OK);
        }
    }

    asio::io_context io;
    std::string connectionString;
    std::unique_ptr<PGconn, ConnectionDeleter> direct;
};

[[nodiscard]] sess::Session sessionValue(
    std::string_view token, std::string_view sessionId = "session-1",
    std::string_view identityId = "identity-1")
{
    return sess::Session::create(
        sess::SessionId{std::string{sessionId}},
        core::IdentityId{std::string{identityId}},
        idp::ProviderId{"provider"}, idp::AssuranceLevel::Ial2,
        idp::AuthenticationStrength{idp::AuthenticationFactor::Knowledge
                                        | idp::AuthenticationFactor::Possession,
                                    false},
        kNow, sess::TokenDigest{sec::sha256(token).value()}, kNow,
        std::chrono::hours{1}, std::chrono::minutes{10}).value();
}

TEST_F(PostgresIntegrationTest, MigrationIsIdempotentAndPoolIsHealthy)
{
    auto result = pg::migrateSchemaBeforeListener(fnd::SecretString{connectionString},
        std::filesystem::path{OPENPROOF_SOURCE_DIR} / "migrations");
    ASSERT_TRUE(result);
    EXPECT_EQ(result->applied, 0U);
    EXPECT_GE(result->alreadyApplied, 1U);
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{connectionString},
        core::OrganizationId{"org"},2U,2s,2s,4s};
    EXPECT_TRUE(run(native.healthCheckAsync()));
}


TEST_F(PostgresIntegrationTest, HistoricalTenantSeedsNeverAutoApply)
{
    // Customer provisioning is never a schema migration: even an organization
    // matching a historical vendor seed must not trigger creation of clients.
    execute("DELETE FROM openproof.schema_migrations "
            "WHERE version IN ('0020_genycaster_native_client.sql',"
            "'0021_genycaster_production_environment.sql',"
            "'0022_tegra_cms_browser_client.sql')");
    execute("INSERT INTO openproof.organizations(id,name,state,created_at_ms) "
            "VALUES('genyleap','Historical tenant',0,1770000000000)");
    auto result = pg::migrateSchemaBeforeListener(fnd::SecretString{connectionString},
        std::filesystem::path{OPENPROOF_SOURCE_DIR} / "migrations");
    ASSERT_TRUE(result)
        << (result ? "" : std::string{result.error().internalDetail()});
    EXPECT_EQ(result->applied, 0U);

    std::unique_ptr<PGresult, ResultDeleter> seeded{PQexec(direct.get(),
        "SELECT count(*) FROM openproof.applications "
        "WHERE organization_id='genyleap' "
        "AND identifier IN ('genycaster', 'tegra-cms')")};
    ASSERT_NE(seeded.get(), nullptr);
    ASSERT_EQ(PQresultStatus(seeded.get()), PGRES_TUPLES_OK);
    EXPECT_STREQ(PQgetvalue(seeded.get(), 0, 0), "0");

    // Only the three archived tenant-provisioning files are forbidden.
    // A legitimate provider-neutral schema migration also starts with 0020:
    // 0020_active_session_recency.sql. A numeric prefix is not a tenant ID.
    std::unique_ptr<PGresult, ResultDeleter> recorded{PQexec(direct.get(),
        "SELECT count(*) FROM openproof.schema_migrations "
        "WHERE version IN ('0020_genycaster_native_client.sql',"
        "'0021_genycaster_production_environment.sql',"
        "'0022_tegra_cms_browser_client.sql')")};
    ASSERT_NE(recorded.get(), nullptr);
    ASSERT_EQ(PQresultStatus(recorded.get()), PGRES_TUPLES_OK);
    EXPECT_STREQ(PQgetvalue(recorded.get(), 0, 0), "0");

    // Check the positive invariant as well: tenant-neutral migrations still
    // apply on fresh installs and must not be hidden by this regression.
    std::unique_ptr<PGresult, ResultDeleter> current{PQexec(direct.get(),
        "SELECT count(*) FROM openproof.schema_migrations "
        "WHERE version='0020_active_session_recency.sql'")};
    ASSERT_NE(current.get(), nullptr);
    ASSERT_EQ(PQresultStatus(current.get()), PGRES_TUPLES_OK);
    EXPECT_STREQ(PQgetvalue(current.get(), 0, 0), "1");

    auto repeated = pg::migrateSchemaBeforeListener(fnd::SecretString{connectionString},
        std::filesystem::path{OPENPROOF_SOURCE_DIR} / "migrations");
    ASSERT_TRUE(repeated);
    EXPECT_EQ(repeated->applied, 0U);

    // Previously applied records keep their exact historical checksum.
    // An invalid archived checksum must prevent startup, not be rewritten.
    execute("INSERT INTO openproof.schema_migrations(version,checksum) VALUES "
            "('0020_genycaster_native_client.sql', "
            "decode('b94bd75abaf5b1afc0ea740804d04a5c7518358321df5734b3e6084d4af97fa1','hex'))");
    auto historical = pg::migrateSchemaBeforeListener(fnd::SecretString{connectionString},
        std::filesystem::path{OPENPROOF_SOURCE_DIR} / "migrations");
    ASSERT_TRUE(historical);
    EXPECT_EQ(historical->applied, 0U);
    execute("UPDATE openproof.schema_migrations "
            "SET checksum=decode(repeat('00',32),'hex') "
            "WHERE version='0020_genycaster_native_client.sql'");
    auto mismatched = pg::migrateSchemaBeforeListener(fnd::SecretString{connectionString},
        std::filesystem::path{OPENPROOF_SOURCE_DIR} / "migrations");
    EXPECT_FALSE(mismatched);
    execute("DELETE FROM openproof.schema_migrations "
            "WHERE version='0020_genycaster_native_client.sql'");
}

TEST_F(PostgresIntegrationTest, MigrationRejectsUnknownLedgerBeforeNewSql)
{
    // A newer database cannot be silently opened by an older package.
    execute("INSERT INTO openproof.schema_migrations(version,checksum) VALUES "
            "('9999_future_schema.sql',decode(repeat('ab',32),'hex'))");
    auto result = pg::migrateSchemaBeforeListener(fnd::SecretString{connectionString},
        std::filesystem::path{OPENPROOF_SOURCE_DIR} / "migrations");
    execute("DELETE FROM openproof.schema_migrations WHERE version='9999_future_schema.sql'");
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), fnd::ErrorCode::FailedPrecondition);
    EXPECT_EQ(scalar("SELECT 1"),"1");
}

TEST_F(PostgresIntegrationTest, MigrationBatchRollsBackEarlierSqlAndLedgerOnLaterFailure)
{
    const auto suffix = sec::randomTokenBase64Url(18U);
    ASSERT_TRUE(suffix);
    const auto directory = std::filesystem::temp_directory_path()
        / ("openproof-migration-test-" + suffix.value());
    ASSERT_TRUE(std::filesystem::create_directory(directory));
    struct Cleanup final {
        std::filesystem::path directory;
        ~Cleanup() {
            std::error_code error;
            std::filesystem::remove_all(directory, error);
        }
    } cleanup{directory};
    std::filesystem::copy(std::filesystem::path{OPENPROOF_SOURCE_DIR} / "migrations",
                          directory, std::filesystem::copy_options::recursive);
    {
        std::ofstream first{directory / "9997_fixture_first.sql"};
        first << "UPDATE openproof.organizations SET name='must roll back' WHERE id='org';";
        ASSERT_TRUE(first);
        std::ofstream second{directory / "9998_fixture_failure.sql"};
        second << "SELECT * FROM openproof.nonexistent_migration_fixture;";
        ASSERT_TRUE(second);
    }
    const auto result = pg::migrateSchemaBeforeListener(fnd::SecretString{connectionString},directory);
    // Read and clean any unexpected writes before assertions, so a failing
    // regression cannot poison subsequent tests on the disposable database.
    std::unique_ptr<PGresult, ResultDeleter> name{PQexec(direct.get(),
        "SELECT name FROM openproof.organizations WHERE id='org'")};
    std::unique_ptr<PGresult, ResultDeleter> ledger{PQexec(direct.get(),
        "SELECT count(*) FROM openproof.schema_migrations "
        "WHERE version IN ('9997_fixture_first.sql','9998_fixture_failure.sql')")};
    execute("UPDATE openproof.organizations SET name='Test' WHERE id='org'");
    execute("DELETE FROM openproof.schema_migrations "
            "WHERE version IN ('9997_fixture_first.sql','9998_fixture_failure.sql')");
    ASSERT_FALSE(result);
    ASSERT_NE(name.get(), nullptr);
    ASSERT_EQ(PQresultStatus(name.get()), PGRES_TUPLES_OK);
    ASSERT_EQ(PQntuples(name.get()), 1);
    EXPECT_STREQ(PQgetvalue(name.get(), 0, 0), "Test");
    ASSERT_NE(ledger.get(), nullptr);
    ASSERT_EQ(PQresultStatus(ledger.get()), PGRES_TUPLES_OK);
    ASSERT_EQ(PQntuples(ledger.get()), 1);
    EXPECT_STREQ(PQgetvalue(ledger.get(), 0, 0), "0");
    EXPECT_EQ(scalar("SELECT 1"),"1");
    EXPECT_TRUE(pg::migrateSchemaBeforeListener(fnd::SecretString{connectionString},
        std::filesystem::path{OPENPROOF_SOURCE_DIR} / "migrations"));
}

TEST_F(PostgresIntegrationTest, ConcurrentMigrationChecksShareOneLedger)
{
    std::atomic<int> success{0};
    const auto directory = std::filesystem::path{OPENPROOF_SOURCE_DIR} / "migrations";
    const auto check = [&] {
        const auto result = pg::migrateSchemaBeforeListener(fnd::SecretString{connectionString},directory);
        if (result && result->applied == 0U && result->alreadyApplied > 0U)
            success.fetch_add(1, std::memory_order_relaxed);
    };
    std::thread first(check);
    std::thread second(check);
    first.join();
    second.join();
    EXPECT_EQ(success.load(std::memory_order_relaxed), 2);
    EXPECT_EQ(scalar("SELECT 1"),"1");
}

TEST(PostgresMigrationBaselineTest, FreshSnapshotRecordsHistoricalChecksumsAndIsIdempotent)
{
    const char* dsn = std::getenv("OPENPROOF_TEST_BASELINE_POSTGRES");
    const char* path = std::getenv("OPENPROOF_TEST_BASELINE_DIRECTORY");
    const char* ack = std::getenv("OPENPROOF_TEST_BASELINE_ACK");
    if (dsn == nullptr && path == nullptr && ack == nullptr)
        GTEST_SKIP() << "Only the dedicated disposable baseline CI fixture is supported.";
    ASSERT_NE(dsn, nullptr);
    ASSERT_NE(path, nullptr);
    ASSERT_NE(ack, nullptr);
    ASSERT_STREQ(ack, "YES_EXCLUSIVE_DISPOSABLE_DATABASE");
    auto first = pg::migrateSchemaBeforeListener(fnd::SecretString{dsn},std::filesystem::path{path});
    ASSERT_TRUE(first) << (first ? "" : std::string{first.error().internalDetail()});
    EXPECT_TRUE(first->usedBaseline);
    EXPECT_GT(first->applied, 0U);
    EXPECT_EQ(first->alreadyApplied, 0U);
    auto repeat = pg::migrateSchemaBeforeListener(fnd::SecretString{dsn},std::filesystem::path{OPENPROOF_SOURCE_DIR} / "migrations");
    ASSERT_TRUE(repeat);
    EXPECT_FALSE(repeat->usedBaseline);
    EXPECT_EQ(repeat->applied, 0U);
    EXPECT_EQ(repeat->alreadyApplied, first->applied);
    auto again = pg::migrateSchemaBeforeListener(fnd::SecretString{dsn},std::filesystem::path{path});
    ASSERT_TRUE(again);
    EXPECT_FALSE(again->usedBaseline);
    EXPECT_EQ(again->applied, 0U);
    EXPECT_EQ(again->alreadyApplied, first->applied);
}

TEST(PostgresMigrationBaselineTest, HistoricalReleaseUpgrade)
{
    const char* dsn = std::getenv("OPENPROOF_TEST_HISTORICAL_POSTGRES");
    const char* directory = std::getenv("OPENPROOF_TEST_HISTORICAL_DIRECTORY");
    const char* pending = std::getenv("OPENPROOF_TEST_HISTORICAL_PENDING");
    const char* ack = std::getenv("OPENPROOF_TEST_HISTORICAL_ACK");
    if (!dsn && !directory && !pending && !ack)
        GTEST_SKIP() << "Requires a private historical upgrade fixture.";
    ASSERT_NE(dsn, nullptr);
    ASSERT_NE(directory, nullptr);
    ASSERT_NE(pending, nullptr);
    ASSERT_NE(ack, nullptr);
    ASSERT_STREQ(ack, "YES_EXCLUSIVE_DISPOSABLE_DATABASE");
    ASSERT_TRUE(std::string_view{dsn}.starts_with("host=/tmp/openproof-baseline-pg."));
    auto result = pg::migrateSchemaBeforeListener(fnd::SecretString{dsn},std::filesystem::path{directory});
    ASSERT_TRUE(result) << (result ? "" : std::string{result.error().internalDetail()});
    EXPECT_FALSE(result->usedBaseline);
    EXPECT_EQ(result->applied, std::stoull(pending));
    EXPECT_GT(result->alreadyApplied, 0U);
    auto again = pg::migrateSchemaBeforeListener(fnd::SecretString{dsn},std::filesystem::path{directory});
    ASSERT_TRUE(again);
    EXPECT_FALSE(again->usedBaseline);
    EXPECT_EQ(again->applied, 0U);
    EXPECT_EQ(again->alreadyApplied, result->alreadyApplied + result->applied);
}

TEST_F(PostgresIntegrationTest, ExistingSchemaNeverRestoresSnapshot)
{
    const char* path = std::getenv("OPENPROOF_TEST_BASELINE_DIRECTORY");
    if (path == nullptr)
        GTEST_SKIP() << "No generated runtime baseline fixture.";
    const auto result = pg::migrateSchemaBeforeListener(fnd::SecretString{connectionString},std::filesystem::path{path});
    ASSERT_TRUE(result);
    EXPECT_FALSE(result->usedBaseline);
    EXPECT_EQ(result->applied, 0U);
    EXPECT_GT(result->alreadyApplied, 0U);
}

TEST_F(PostgresIntegrationTest, PasskeyConcurrentRemovalPreservesFinalCredential)
{
    const core::IdentityId identity{"identity-1"};
    pg::CoroutinePostgresSessionRepository sessions{io.get_executor(),fnd::SecretString{connectionString},1U,2s,2s,4s};
    ASSERT_TRUE(run(sessions.add(sessionValue("passkey-test-token"))));
    execute("INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) "
        "VALUES('passkey','identity-1','identity-1',1770000000000)");
    execute("INSERT INTO openproof.passkey_credentials(credential_id,identity_id,public_key_x,public_key_y,sign_count,created_at_ms,last_used_at_ms) "
        "VALUES('passkey-a','identity-1','x','y',0,1770000000000,1770000000000),"
        "('passkey-b','identity-1','x','y',0,1770000000000,1770000000000)");
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{connectionString},
        core::OrganizationId{"org"},1U,2s,2s,4s};
    pg::CoroutinePostgresCanonicalFinalizer peer{io.get_executor(),fnd::SecretString{connectionString},
        core::OrganizationId{"org"},1U,2s,2s,4s};
    const sess::SessionId sessionId{"session-1"};
    io.restart();
    auto first=asio::co_spawn(io,native.mutatePasskeyAccountAsync(identity,sessionId,kNow+1s,
        "passkey-a",std::nullopt,std::nullopt),asio::use_future);
    auto second=asio::co_spawn(io,peer.mutatePasskeyAccountAsync(identity,sessionId,kNow+1s,
        "passkey-b",std::nullopt,std::nullopt),asio::use_future);
    io.run();
    const auto a=first.get(),b=second.get();
    ASSERT_NE(a.has_value(),b.has_value());
    EXPECT_EQ((a?b:a).error().code(),fnd::ErrorCode::FailedPrecondition);
    auto remaining=run(native.readPasskeyAccountAsync(identity,sessionId,kNow+2s));
    ASSERT_TRUE(remaining);
    ASSERT_EQ(remaining->size(),1U);
    EXPECT_EQ(scalar("SELECT count(*)::text FROM openproof.external_identities WHERE provider='passkey' AND identity_id='identity-1'"),"1");
}

TEST_F(PostgresIntegrationTest, SessionUseRotationAndRevocationAreImmediate)
{
    pg::CoroutinePostgresSessionRepository repository{io.get_executor(),fnd::SecretString{connectionString},2U,2s,2s,4s};
    pg::CoroutinePostgresSessionRepository peer{io.get_executor(),fnd::SecretString{connectionString},1U,2s,2s,4s};
    ASSERT_TRUE(run(repository.add(sessionValue("old-token"))));
    const sess::TokenDigest oldToken{sec::sha256("old-token").value()},newToken{sec::sha256("new-token").value()};
    auto used=run(peer.use(oldToken,kNow+1min));
    ASSERT_TRUE(used);
    EXPECT_EQ(used->identity(),core::IdentityId{"identity-1"});
    ASSERT_TRUE(run(repository.rotate(sess::SessionId{"session-1"},oldToken,newToken,kNow+2min)));
    EXPECT_FALSE(run(peer.use(oldToken,kNow+2min)));
    EXPECT_TRUE(run(peer.use(newToken,kNow+2min)));
    ASSERT_TRUE(run(peer.revoke(sess::SessionId{"session-1"},kNow+3min)));
    EXPECT_FALSE(run(repository.use(newToken,kNow+3min)));
}

TEST_F(PostgresIntegrationTest, TransactionCanBeConsumedExactlyOnceAcrossThreads)
{
    pg::CoroutinePostgresAuthenticationTransactionStore store{io.get_executor(),fnd::SecretString{connectionString},2U,2s,2s,4s};
    pg::CoroutinePostgresAuthenticationTransactionStore peer{io.get_executor(),fnd::SecretString{connectionString},1U,2s,2s,4s};
    const fnd::SecretString nonce{"single-use-nonce"};
    const idp::BindingDigest binding = sec::sha256("binding").value();
    auto transaction = idp::AuthenticationTransaction::create(
        idp::TransactionId{"transaction-1"}, idp::ProviderId{"provider"},
        idp::InteractionModel::ChallengeResponse, nonce.clone(), binding,
        fnd::CorrelationId{"correlation"}, kNow, std::chrono::minutes{5}).value();
    transaction.setMetadata("challenge_id", "challenge");
    ASSERT_TRUE(run(store.beginAsync(std::move(transaction))));
    const auto redeem=[&](pg::CoroutinePostgresAuthenticationTransactionStore& target)->asio::awaitable<bool>{
        auto result=co_await target.consumeAsync(idp::TransactionId{"transaction-1"},nonce.clone(),binding,kNow+1s);
        co_return result && result->metadata().at("challenge_id")=="challenge";
    };
    io.restart();
    auto first=asio::co_spawn(io,redeem(store),asio::use_future);
    auto second=asio::co_spawn(io,redeem(peer),asio::use_future);
    io.run();
    EXPECT_NE(first.get(),second.get());
    EXPECT_EQ(scalar("SELECT state::text FROM openproof.authentication_transactions WHERE id='transaction-1'"),"1");
    EXPECT_EQ(scalar("SELECT value FROM openproof.authentication_transaction_metadata WHERE transaction_id='transaction-1' AND key='challenge_id'"),"challenge");
}

TEST_F(PostgresIntegrationTest, FailedNonceBurnsTransactionAtomically)
{
    pg::CoroutinePostgresAuthenticationTransactionStore store{io.get_executor(),fnd::SecretString{connectionString},2U,2s,2s,4s};
    const idp::BindingDigest binding = sec::sha256("binding").value();
    auto transaction = idp::AuthenticationTransaction::create(
        idp::TransactionId{"transaction-1"}, idp::ProviderId{"provider"},
        idp::InteractionModel::ChallengeResponse, fnd::SecretString{"right-nonce"},
        binding, fnd::CorrelationId{"correlation"}, kNow,
        std::chrono::minutes{5}).value();
    ASSERT_TRUE(run(store.beginAsync(std::move(transaction))));
    EXPECT_FALSE(run(store.consumeAsync(idp::TransactionId{"transaction-1"},fnd::SecretString{"wrong-nonce"},binding,kNow+1s)));
    EXPECT_FALSE(run(store.consumeAsync(idp::TransactionId{"transaction-1"},fnd::SecretString{"right-nonce"},binding,kNow+2s)));
    EXPECT_EQ(scalar("SELECT state::text FROM openproof.authentication_transactions WHERE id='transaction-1'"),"2");
}

TEST_F(PostgresIntegrationTest, RecoveryCodeIsConsumedExactlyOnceAcrossNodes)
{
    seedRecoveryEligibility();
    pg::CoroutinePostgresRecoveryCodeRepository firstRepository{io.get_executor(),fnd::SecretString{connectionString},
        2U,2s,2s,4s,core::OrganizationId{"org"},idp::ProviderId{"local"}};
    pg::CoroutinePostgresRecoveryCodeRepository secondRepository{io.get_executor(),fnd::SecretString{connectionString},
        1U,2s,2s,4s,core::OrganizationId{"org"},idp::ProviderId{"local"}};
    const core::IdentityId identity{"identity-1"};
    std::vector<cred::RecoveryCodeDigest> batch(4U);
    for (std::size_t index=0;index<batch.size();++index)
        batch[index].fill(static_cast<std::byte>(index+1U));
    const auto presented=batch.front();
    auto fence=run(firstRepository.captureIssuanceAsync(identity));
    ASSERT_TRUE(fence);
    ASSERT_TRUE(run(firstRepository.replaceFencedAsync(identity,std::move(batch),fence.value())));
    ASSERT_EQ(run(firstRepository.remainingAsync(identity)).value(),4U);
    io.restart();
    auto first=asio::co_spawn(io,firstRepository.consumeAsync(identity,presented),asio::use_future);
    auto second=asio::co_spawn(io,secondRepository.consumeAsync(identity,presented),asio::use_future);
    io.run();
    EXPECT_NE(first.get().has_value(),second.get().has_value());
    EXPECT_EQ(run(secondRepository.remainingAsync(identity)).value(),3U);
}

TEST_F(PostgresIntegrationTest, RecoveryRotationWaitsForNativeTransactionLock)
{
    // The fixture already applies the real schema in the exclusive
    // integration database. Hold the exact advisory transaction lock
    // used by AsyncRecoveryCodeSql::replace on a separate connection.
    seedRecoveryEligibility();
    pg::CoroutinePostgresRecoveryCodeRepository repository{io.get_executor(),fnd::SecretString{connectionString},
        2U,2s,2s,6s,core::OrganizationId{"org"},idp::ProviderId{"local"}};
    const core::IdentityId identity{"identity-1"};
    auto fence=run(repository.captureIssuanceAsync(identity));
    ASSERT_TRUE(fence);
    cred::RecoveryCodeDigest prior{};
    prior.fill(std::byte{0x11});
    cred::RecoveryCodeDigest next{};
    next.fill(std::byte{0x22});
    ASSERT_TRUE(run(repository.replaceFencedAsync(identity,{prior},fence.value())));
    execute("BEGIN");
    std::unique_ptr<PGresult, ResultDeleter> locked{PQexec(direct.get(),
        "SELECT pg_advisory_xact_lock(hashtextextended('identity-1',0))")};
    ASSERT_TRUE(locked && PQresultStatus(locked.get()) == PGRES_TUPLES_OK);
    // Emulate the intervening native transaction with its real shared
    // lock key and disjoint code batch, not an in-memory repository.
    execute("DELETE FROM openproof.recovery_codes WHERE identity_id='identity-1'");
    execute("INSERT INTO openproof.recovery_codes(identity_id,code_digest,issued_at_ms) "
            "VALUES('identity-1',decode(repeat('33',32),'hex'),1770000000000)");

    bool replaced = false;
    std::jthread rotate{[&] {
        replaced = run(repository.replaceFencedAsync(identity,{next},fence.value())).has_value();
    }};
    // Observe a real ungranted advisory lock on our lock key rather
    // than guessing from a thread's sleep or scheduling delay.
    bool waited = false;
    bool observerFailed = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
    while (std::chrono::steady_clock::now() < deadline && !waited) {
        std::unique_ptr<PGresult, ResultDeleter> observed{PQexec(direct.get(),
            "SELECT EXISTS(SELECT 1 FROM pg_locks h JOIN pg_locks w "
            "ON h.locktype=w.locktype AND h.database=w.database "
            "AND h.classid=w.classid AND h.objid=w.objid AND h.objsubid=w.objsubid "
            "WHERE h.locktype='advisory' AND h.pid=pg_backend_pid() "
            "AND h.granted AND NOT w.granted AND w.pid<>h.pid)")};
        if (!observed || PQresultStatus(observed.get()) != PGRES_TUPLES_OK
            || PQntuples(observed.get()) != 1) {
            observerFailed = true;
            break;
        }
        waited = std::string_view{PQgetvalue(observed.get(), 0, 0)} == "t";
        if (!waited) std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    // Always release before joining, including a failed observation.
    std::unique_ptr<PGresult, ResultDeleter> committed{PQexec(direct.get(), "COMMIT")};
    if (!committed || PQresultStatus(committed.get()) != PGRES_COMMAND_OK) {
        std::unique_ptr<PGresult, ResultDeleter> rollbackResult{PQexec(direct.get(), "ROLLBACK")};
        static_cast<void>(rollbackResult);
    }
    rotate.join();
    ASSERT_TRUE(committed && PQresultStatus(committed.get()) == PGRES_COMMAND_OK);
    ASSERT_FALSE(observerFailed);
    EXPECT_TRUE(waited);
    ASSERT_TRUE(replaced);
    auto count=run(repository.remainingAsync(identity));
    ASSERT_TRUE(count);
    EXPECT_EQ(count.value(),1U);
    cred::RecoveryCodeDigest intervening{};
    intervening.fill(std::byte{0x33});
    EXPECT_FALSE(run(repository.consumeAsync(identity,prior)));
    EXPECT_FALSE(run(repository.consumeAsync(identity,intervening)));
    EXPECT_TRUE(run(repository.consumeAsync(identity,next)));
    EXPECT_FALSE(run(repository.consumeAsync(identity,next)));
}

TEST_F(PostgresIntegrationTest, IdentityOrganizationMembershipAndExternalLinksRoundTrip)
{
    const core::OrganizationId tenant{"org"};
    const core::IdentityId owner{"identity-1"};
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{connectionString},tenant,2U,2s,2s,4s};
    EXPECT_TRUE(run(native.healthCheckAsync()));
    EXPECT_TRUE(run(native.authorizeConnectionTargetAsync(owner)));
    execute("INSERT INTO openproof.memberships(organization_id,identity_id,state,invited_at_ms) "
        "VALUES('org','identity-1',1,1770000000000)");
    execute("INSERT INTO openproof.membership_roles(organization_id,identity_id,role) VALUES('org','identity-1','member')");
    auto member=run(native.readAuthorizationMembershipAsync(owner,tenant));
    ASSERT_TRUE(member);
    EXPECT_TRUE(member->hasRole(org::Role{"member"}));
    EXPECT_FALSE(run(native.readAuthorizationMembershipAsync(owner,core::OrganizationId{"foreign"})));
    auto outcome=idp::AuthenticationOutcome::create(idp::ProviderId{"fixture-oidc"},idp::ExternalSubject{"alice"},
        idp::VerifiedClaims{},idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{idp::AuthenticationFactor::Possession,false},idp::ProviderEvidence{},kNow);
    ASSERT_TRUE(outcome);
    auto linked=run(native.finishConnectionAsync(outcome.value(),owner,kNow));
    ASSERT_TRUE(linked);
    EXPECT_EQ(linked->subject().value(),"alice");
    auto login=run(native.finishLoginAsync(outcome.value(),kNow));
    ASSERT_TRUE(login);
    EXPECT_EQ(login.value(),owner);
    auto connections=run(native.readConnectionsAsync(owner));
    ASSERT_TRUE(connections);
    EXPECT_EQ(connections->first,owner);
    ASSERT_EQ(connections->second.size(),1U);
    EXPECT_EQ(connections->second.front(),linked.value());
    execute("UPDATE openproof.organizations SET state=1 WHERE id='org'");
    EXPECT_FALSE(run(native.finishLoginAsync(outcome.value(),kNow)));
    EXPECT_FALSE(run(native.readAuthorizationMembershipAsync(owner,tenant)));
}

TEST_F(PostgresIntegrationTest, RejectedAuthorizationIsChainedAndPublished)
{
    fnd::ManualClockSource clock{kNow};
    const fnd::SecretString sessionSecret{
        "0123456789abcdef0123456789abcdef"};
    auto digest = sec::hmacSha256(sessionSecret, "denied-token").value();
    sess::InMemorySessionRepository sessionRepository;
    ASSERT_TRUE(sessionRepository.add(sess::Session::create(
        sess::SessionId{"denied-session"}, core::IdentityId{"identity-1"},
        idp::ProviderId{"local"}, idp::AssuranceLevel::Ial2,
        idp::AuthenticationStrength{
            idp::AuthenticationFactor::Knowledge
                | idp::AuthenticationFactor::Possession,
            false},
        kNow, sess::TokenDigest{digest}, kNow, std::chrono::hours{1},
        std::chrono::minutes{10}).value()));
    sess::SessionService sessions{
        sessionRepository, clock,
        sess::SessionKey::create(sessionSecret.clone()).value(),
        sess::SessionPolicy::create(std::chrono::hours{1},
                                    std::chrono::minutes{10}).value()};
    auto authenticated = sessions.authenticate(
        fnd::SecretString{"denied-token"});
    ASSERT_TRUE(authenticated);

    pg::CoroutineAuthorizationDecisionSink sink{
        io.get_executor(),fnd::SecretString{connectionString},
        audit::AuditKey::create(fnd::SecretString{
            "abcdef0123456789abcdef0123456789"}).value(),
        clock,1U,2s,2s,4s};
    ASSERT_TRUE(run(sink.recordAsync(
        authenticated.value(),core::OrganizationId{"org"},
        pol::Action{"proxy.GET:/api"},pol::Resource{"upstream:/api"},
        pol::AuthorizationDecision::deny("required role is absent"),
        fnd::CorrelationId{"authorization-request"})));

    std::unique_ptr<PGresult, ResultDeleter> evidence{PQexec(
        direct.get(),
        "SELECT (SELECT count(*) FROM openproof.audit_events WHERE "
        "category='authorization' AND action='protected-route.evaluate' "
        "AND outcome='deny' AND encode(event_hash,'hex')<>repeat('0',64)),"
        "(SELECT count(*) FROM openproof.security_event_outbox WHERE "
        "payload->>'type'='authorization.protected-route.denied')")};
    ASSERT_NE(evidence.get(), nullptr);
    ASSERT_EQ(PQresultStatus(evidence.get()), PGRES_TUPLES_OK);
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 0), "1");
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 1), "1");
}


TEST_F(PostgresIntegrationTest, PasswordKdfPolicySwitchPreservesAndUpgradesLogin)
{
    if (!cred::PasswordHasher::supportsArgon2id()) {
        GTEST_SKIP() << "libsodium Argon2id is unavailable";
    }
    const idp::ExternalSubject subject{"kdf-switch-user"};
    const core::IdentityId owner{"identity-1"};
    const fnd::SecretString password{"correct-password"};
    auto policy=cred::PasswordPolicy::create(1024U,8U,1U,16U,32U,2U*1024U*1024U).value();
    const auto makeHasher=[&](std::string algorithm){
        return cred::PasswordHasher::create(fnd::SecretString{std::string(32U,'p')},policy,std::move(algorithm)).value();
    };
    const auto makeKey=[](){return sec::AeadKey::create(fnd::SecretString{std::string(32U,'k')}).value();};
    auto initialHasher=makeHasher("scrypt");
    auto fixtureKey=makeKey();
    ASSERT_NO_FATAL_FAILURE(seedLocalCredentials(subject,initialHasher,password,fixtureKey));
    auto oldWorker=cred::BoundedPasswordExecutor::create(makeHasher("scrypt"),1U);
    auto modernWorker=cred::BoundedPasswordExecutor::create(makeHasher("argon2id"),1U);
    ASSERT_TRUE(oldWorker && modernWorker);
    pg::CoroutineLocalCredentialStore store{io.get_executor(),fnd::SecretString{connectionString},
        core::OrganizationId{"org"},idp::ProviderId{"local"},2U,2s,2s,4s};
    pg::CoroutinePostgresLocalProofVerifier modern{store,*modernWorker.value(),cred::TotpPolicy::recommended(),
        makeKey(),1U,fnd::SecretString{std::string(32U,'r')}};
    pg::CoroutinePostgresLocalProofVerifier old{store,*oldWorker.value(),cred::TotpPolicy::recommended(),
        makeKey(),1U,fnd::SecretString{std::string(32U,'r')}};
    const auto readStored=[&](){
        return std::pair{scalar("SELECT password_hash FROM openproof.password_credentials WHERE identity_id='identity-1'"),
            scalar("SELECT changed_at_ms::text FROM openproof.password_credentials WHERE identity_id='identity-1'")};
    };
    const auto previous=readStored();
    ASSERT_TRUE(previous.first.starts_with("scrypt$v1$"));
    auto oldStatus=run(store.readPasswordUpgradeStatusAsync(owner,*oldWorker.value()));
    ASSERT_TRUE(oldStatus && oldStatus->second.has_value());
    EXPECT_FALSE(*oldStatus->second);
    auto modernStatus=run(store.readPasswordUpgradeStatusAsync(owner,*modernWorker.value()));
    ASSERT_TRUE(modernStatus && modernStatus->second.has_value());
    EXPECT_TRUE(*modernStatus->second);
    EXPECT_FALSE(run(store.confirmPasswordUpgradeAsync(owner,fnd::SecretString{"wrong-password"},*modernWorker.value())));
    EXPECT_EQ(readStored(),previous);
    auto upgraded=run(store.confirmPasswordUpgradeAsync(owner,password.clone(),*modernWorker.value()));
    ASSERT_TRUE(upgraded);
    EXPECT_TRUE(upgraded->second);
    auto current=run(store.readPasswordUpgradeStatusAsync(owner,*modernWorker.value()));
    ASSERT_TRUE(current && current->second.has_value());
    EXPECT_FALSE(*current->second);
    auto repeated=run(store.confirmPasswordUpgradeAsync(owner,password.clone(),*modernWorker.value()));
    ASSERT_TRUE(repeated);
    EXPECT_FALSE(repeated->second);
    auto verified=run(modern.verifyAsync(subject,password.clone(),std::nullopt,std::nullopt,kNow));
    ASSERT_TRUE(verified);
    EXPECT_EQ(verified->verification,local::LocalVerification::Password);
    EXPECT_TRUE(readStored().first.starts_with("$argon2id$v=19$"));
    EXPECT_EQ(readStored().second,previous.second);
    ASSERT_TRUE(run(old.verifyAsync(subject,password.clone(),std::nullopt,std::nullopt,kNow)));
    EXPECT_TRUE(readStored().first.starts_with("scrypt$v1$"));
    EXPECT_EQ(readStored().second,previous.second);
    // Complete login also upgrades a valid old hash without an explicit request.
    ASSERT_TRUE(run(modern.verifyAsync(subject,password.clone(),std::nullopt,std::nullopt,kNow)));
    EXPECT_TRUE(readStored().first.starts_with("$argon2id$v=19$"));
    EXPECT_EQ(readStored().second,previous.second);
}

TEST_F(PostgresIntegrationTest, PersistentLocalTotpIsEncryptedAndConsumedOnce)
{
    const idp::ExternalSubject subject{"alice"};
    const core::IdentityId owner{"identity-1"};
    const fnd::SecretString password{"correct-password"};
    const auto policy=cred::PasswordPolicy::create(1024U,8U,1U,16U,32U,2U*1024U*1024U).value();
    const auto makeHasher=[&](){return cred::PasswordHasher::create(fnd::SecretString{std::string(32U,'p')},policy).value();};
    const auto makeKey=[](){return sec::AeadKey::create(fnd::SecretString{std::string(32U,'k')}).value();};
    auto hasher=makeHasher();
    auto key=makeKey();
    auto secret=cred::TotpSecret::create(fnd::SecretString{"12345678901234567890"}).value();
    const auto code=cred::totpAt(secret,cred::TotpPolicy::recommended(),kNow).value();
    ASSERT_NO_FATAL_FAILURE(seedLocalCredentials(subject,hasher,password,key,&secret));
    EXPECT_EQ(scalar("SELECT (encrypted_seed=convert_to('12345678901234567890','UTF8'))::text FROM openproof.totp_credentials WHERE identity_id='identity-1'"),"false");
    auto workers=cred::BoundedPasswordExecutor::create(makeHasher(),2U);
    ASSERT_TRUE(workers);
    pg::CoroutineLocalCredentialStore store{io.get_executor(),fnd::SecretString{connectionString},
        core::OrganizationId{"org"},idp::ProviderId{"local"},2U,2s,2s,4s};
    pg::CoroutineLocalCredentialStore peer{io.get_executor(),fnd::SecretString{connectionString},
        core::OrganizationId{"org"},idp::ProviderId{"local"},1U,2s,2s,4s};
    pg::CoroutinePostgresLocalProofVerifier firstVerifier{store,*workers.value(),cred::TotpPolicy::recommended(),
        makeKey(),1U,fnd::SecretString{std::string(32U,'r')}};
    pg::CoroutinePostgresLocalProofVerifier secondVerifier{peer,*workers.value(),cred::TotpPolicy::recommended(),
        makeKey(),1U,fnd::SecretString{std::string(32U,'r')}};
    auto verify=[&](pg::CoroutinePostgresLocalProofVerifier& verifier)->asio::awaitable<bool>{
        auto result=co_await verifier.verifyAsync(subject,password.clone(),
            std::optional<fnd::SecretString>{fnd::SecretString{code}},std::nullopt,kNow);
        co_return result && result->verification==local::LocalVerification::PasswordAndTotp;
    };
    io.restart();
    auto first=asio::co_spawn(io,verify(firstVerifier),asio::use_future);
    auto second=asio::co_spawn(io,verify(secondVerifier),asio::use_future);
    io.run();
    EXPECT_NE(first.get(),second.get());
    EXPECT_FALSE(run(verify(firstVerifier)));
    EXPECT_FALSE(run(firstVerifier.verifyAsync(subject,password.clone(),std::nullopt,std::nullopt,kNow)));
    fnd::ManualClockSource clock{kNow+1s};
    pg::CoroutineTotpEnrollment ceremony{store,*workers.value(),makeKey(),1U,clock};
    EXPECT_FALSE(run(ceremony.disableAsync(owner,password.clone(),idp::AssuranceLevel::Ial1)));
    ASSERT_TRUE(run(ceremony.disableAsync(owner,password.clone(),idp::AssuranceLevel::Ial2)));
    EXPECT_EQ(scalar("SELECT count(*)::text FROM openproof.totp_credentials WHERE identity_id='identity-1'"),"0");
    auto passwordOnly=run(firstVerifier.verifyAsync(subject,password.clone(),std::nullopt,std::nullopt,kNow+1s));
    ASSERT_TRUE(passwordOnly);
    EXPECT_EQ(passwordOnly->verification,local::LocalVerification::Password);
    auto removedAgain=run(ceremony.disableAsync(owner,password.clone(),idp::AssuranceLevel::Ial2));
    ASSERT_FALSE(removedAgain);
    EXPECT_EQ(removedAgain.error().code(),fnd::ErrorCode::FailedPrecondition);
}

TEST_F(PostgresIntegrationTest, TotpCredentialRekeyIsAtomicVersionedAndDryRunnable)
{
    const idp::ExternalSubject subject{"rekey-user"};
    const fnd::SecretString password{"correct-password"};
    const auto passwordPolicy=cred::PasswordPolicy::create(1024U,8U,1U,16U,32U,2U*1024U*1024U).value();
    const auto makeHasher=[&](){return cred::PasswordHasher::create(fnd::SecretString{std::string(32U,'p')},passwordPolicy).value();};
    auto oldHasher=makeHasher();
    auto oldDirectoryKey=sec::AeadKey::create(fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto seed=cred::TotpSecret::create(fnd::SecretString{"12345678901234567890"}).value();
    const auto firstCode=cred::totpAt(seed,cred::TotpPolicy::recommended(),kNow).value();
    ASSERT_NO_FATAL_FAILURE(seedLocalCredentials(subject,oldHasher,password,oldDirectoryKey,&seed));
    auto worker=cred::BoundedPasswordExecutor::create(makeHasher(),1U);
    ASSERT_TRUE(worker);
    pg::CoroutineLocalCredentialStore store{io.get_executor(),fnd::SecretString{connectionString},
        core::OrganizationId{"org"},idp::ProviderId{"local"},2U,2s,2s,4s};
    pg::CoroutinePostgresLocalProofVerifier oldVerifier{store,*worker.value(),cred::TotpPolicy::recommended(),
        std::move(oldDirectoryKey),1U,fnd::SecretString{std::string(32U,'r')}};
    ASSERT_TRUE(run(oldVerifier.verifyAsync(subject,password.clone(),
        std::optional<fnd::SecretString>{fnd::SecretString{firstCode}},std::nullopt,kNow)));

    std::unique_ptr<PGresult, ResultDeleter> before{PQexec(
        direct.get(),
        "SELECT encode(encrypted_seed,'hex'),key_version,last_accepted_step "
        "FROM openproof.totp_credentials WHERE identity_id='identity-1'")};
    ASSERT_NE(before.get(), nullptr);
    ASSERT_EQ(PQresultStatus(before.get()), PGRES_TUPLES_OK);
    ASSERT_EQ(PQntuples(before.get()), 1);
    const std::string oldCiphertext = PQgetvalue(before.get(), 0, 0);
    const std::string acceptedStep = PQgetvalue(before.get(), 0, 2);

    auto unchangedOldKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto unchangedNewKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto unchanged = pg::rekeyTotpOffline(fnd::SecretString{connectionString},
        unchangedOldKey, 1U, unchangedNewKey, 2U, true);
    ASSERT_FALSE(unchanged);
    EXPECT_EQ(unchanged.error().code(), fnd::ErrorCode::InvalidArgument);

    auto oldDryKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto newDryKey = sec::AeadKey::create(
        fnd::SecretString{"fedcba9876543210fedcba9876543210"}).value();
    auto dryRun = pg::rekeyTotpOffline(fnd::SecretString{connectionString},oldDryKey, 1U, newDryKey, 2U, true);
    ASSERT_TRUE(dryRun);
    EXPECT_EQ(dryRun->rekeyed, 1U);
    EXPECT_EQ(dryRun->alreadyCurrent, 0U);
    EXPECT_TRUE(dryRun->dryRun);

    std::unique_ptr<PGresult, ResultDeleter> afterDryRun{PQexec(
        direct.get(),
        "SELECT key_version,encode(encrypted_seed,'hex'),"
        "(SELECT count(*) FROM openproof.credential_key_rotations) "
        "FROM openproof.totp_credentials WHERE identity_id='identity-1'")};
    ASSERT_NE(afterDryRun.get(), nullptr);
    ASSERT_EQ(PQresultStatus(afterDryRun.get()), PGRES_TUPLES_OK);
    EXPECT_STREQ(PQgetvalue(afterDryRun.get(), 0, 0), "1");
    EXPECT_EQ(PQgetvalue(afterDryRun.get(), 0, 1), oldCiphertext);
    EXPECT_STREQ(PQgetvalue(afterDryRun.get(), 0, 2), "0");

    auto wrongOldKey = sec::AeadKey::create(
        fnd::SecretString{std::string(32U, 'x')}).value();
    auto newAttemptKey = sec::AeadKey::create(
        fnd::SecretString{"fedcba9876543210fedcba9876543210"}).value();
    auto refused = pg::rekeyTotpOffline(fnd::SecretString{connectionString},
        wrongOldKey, 1U, newAttemptKey, 2U, false);
    ASSERT_FALSE(refused);
    EXPECT_EQ(refused.error().code(), fnd::ErrorCode::AuthenticationFailed);

    auto oldKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto newKey = sec::AeadKey::create(
        fnd::SecretString{"fedcba9876543210fedcba9876543210"}).value();
    auto rotated = pg::rekeyTotpOffline(fnd::SecretString{connectionString},oldKey, 1U, newKey, 2U, false);
    ASSERT_TRUE(rotated) << rotated.error().internalDetail();
    EXPECT_EQ(rotated->rekeyed, 1U);
    EXPECT_FALSE(rotated->dryRun);

    std::unique_ptr<PGresult, ResultDeleter> after{PQexec(
        direct.get(),
        "SELECT key_version,encode(encrypted_seed,'hex'),last_accepted_step,"
        "(SELECT count(*) FROM openproof.credential_key_rotations "
        "WHERE purpose='totp' AND from_version=1 AND to_version=2 "
        "AND rekeyed_rows=1) FROM openproof.totp_credentials "
        "WHERE identity_id='identity-1'")};
    ASSERT_NE(after.get(), nullptr);
    ASSERT_EQ(PQresultStatus(after.get()), PGRES_TUPLES_OK);
    ASSERT_EQ(PQntuples(after.get()), 1);
    EXPECT_STREQ(PQgetvalue(after.get(), 0, 0), "2");
    EXPECT_NE(PQgetvalue(after.get(), 0, 1), oldCiphertext);
    EXPECT_EQ(PQgetvalue(after.get(), 0, 2), acceptedStep);
    EXPECT_STREQ(PQgetvalue(after.get(), 0, 3), "1");

    auto newDirectoryKey=sec::AeadKey::create(
        fnd::SecretString{"fedcba9876543210fedcba9876543210"}).value();
    pg::CoroutinePostgresLocalProofVerifier newVerifier{store,*worker.value(),cred::TotpPolicy::recommended(),
        std::move(newDirectoryKey),2U,fnd::SecretString{std::string(32U,'r')}};
    EXPECT_FALSE(run(newVerifier.verifyAsync(subject,password.clone(),
        std::optional<fnd::SecretString>{fnd::SecretString{firstCode}},std::nullopt,kNow)));
    const auto nextInstant=kNow+30s;
    const auto nextCode=cred::totpAt(seed,cred::TotpPolicy::recommended(),nextInstant).value();
    EXPECT_FALSE(run(oldVerifier.verifyAsync(subject,password.clone(),
        std::optional<fnd::SecretString>{fnd::SecretString{nextCode}},std::nullopt,nextInstant)));
    auto verified=run(newVerifier.verifyAsync(subject,password.clone(),
        std::optional<fnd::SecretString>{fnd::SecretString{nextCode}},std::nullopt,nextInstant));
    ASSERT_TRUE(verified);
    EXPECT_EQ(verified->verification,local::LocalVerification::PasswordAndTotp);
}

TEST_F(PostgresIntegrationTest, MasterKeyRotationAtomicallyInvalidatesOnlyDerivedState)
{
    pg::CoroutinePostgresAuthenticationTransactionStore transactions{io.get_executor(),fnd::SecretString{connectionString},1U,2s,2s,4s};
    auto transaction = idp::AuthenticationTransaction::create(
        idp::TransactionId{"master-rotation-transaction"},
        idp::ProviderId{"local"}, idp::InteractionModel::ChallengeResponse,
        fnd::SecretString{"master-rotation-nonce"}, sec::sha256("binding").value(),
        fnd::CorrelationId{"master-rotation"}, kNow,
        std::chrono::minutes{5}).value();
    ASSERT_TRUE(run(transactions.beginAsync(std::move(transaction))));

    pg::CoroutinePostgresSessionRepository sessions{io.get_executor(),fnd::SecretString{connectionString},1U,2s,2s,4s};
    ASSERT_TRUE(run(sessions.add(sessionValue(
        "master-rotation-session", "master-rotation-session"))));

    execute("INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
            "VALUES('identity-1','scrypt$v1$1024$8$1$2097152$c2FsdHNhbHRzYWx0c2FsdA$"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',1770000000000)");
    execute("INSERT INTO openproof.totp_credentials"
            "(identity_id,encrypted_seed,key_version,last_accepted_step,enrolled_at_ms) "
            "VALUES('identity-1',decode('00','hex'),1,NULL,1770000000000)");
    execute("INSERT INTO openproof.recovery_codes(identity_id,code_digest,issued_at_ms) "
            "VALUES('identity-1',decode(repeat('11',32),'hex'),1770000000000)");
    execute("INSERT INTO openproof.audit_events"
            "(event_id,occurred_at_ms,correlation_id,category,action,outcome,detail,event_hash) "
            "VALUES('master-rotation-audit',1770000000000,'master-rotation',"
            "'security','master.rotate','planned','{}',decode(repeat('22',32),'hex'))");
    execute("INSERT INTO openproof.applications"
            "(id,organization_id,identifier,display_name,environment,status,created_at_ms,updated_at_ms) "
            "VALUES('master-app','org','master-app','Master App',2,0,1770000000000,1770000000000)");
    execute("INSERT INTO openproof.oauth_clients"
            "(id,application_id,display_name,kind,status,secret_digest,created_at_ms,updated_at_ms) "
            "VALUES('master-client','master-app','Master Client',0,0,"
            "decode(repeat('33',32),'hex'),1770000000000,1770000000000)");
    execute("INSERT INTO openproof.account_verification_challenges"
            "(id,identity_id,purpose,channel,destination,secret_digest,attempts,created_at_ms,expires_at_ms) "
            "VALUES('master-account-challenge','identity-1',0,0,'user@example.test',"
            "decode(repeat('44',32),'hex'),0,1770000000000,1770003600000)");
    execute("INSERT INTO openproof.passkey_registration_ceremonies"
            "(id,identity_id,expires_at_ms,consumed_at_ms) "
            "VALUES('master-passkey-registration','identity-1',1770003600000,NULL)");
    execute("INSERT INTO openproof.oauth_authorization_codes"
            "(code_digest,client_id,identity_id,redirect_uri,code_challenge,provider,"
            "assurance,factors,phishing_resistant,authenticated_at_ms,issued_at_ms,expires_at_ms) "
            "VALUES(decode(repeat('55',32),'hex'),'master-client','identity-1',"
            "'https://client.example/callback',repeat('a',43),'local',2,3,false,"
            "1770000000000,1770000000000,1770000300000)");
    execute("INSERT INTO openproof.oauth_token_families"
            "(id,client_id,identity_id,provider,assurance,factors,phishing_resistant,"
            "authenticated_at_ms,revoked_at_ms) VALUES('master-family','master-client',"
            "'identity-1','local',2,3,false,1770000000000,NULL)");
    execute("INSERT INTO openproof.oauth_device_authorizations"
            "(device_digest,user_code_digest,client_id,status,issued_at_ms,expires_at_ms,poll_interval_ms) "
            "VALUES(decode(repeat('66',32),'hex'),decode(repeat('77',32),'hex'),"
            "'master-client',0,1770000000000,1770000600000,5000)");
    execute("INSERT INTO openproof.oauth_pushed_authorization_requests"
            "(request_digest,client_id,redirect_uri,code_challenge,response_mode,issued_at_ms,expires_at_ms) "
            "VALUES(decode(repeat('88',32),'hex'),'master-client',"
            "'https://client.example/callback',repeat('b',43),0,1770000000000,1770000090000)");

    const auto oldFingerprint = sec::hmacSha256(
        fnd::SecretString{std::string(32U, 'm')},
        "openproof/master-key-fingerprint/v1").value();
    const auto newFingerprint = sec::hmacSha256(
        fnd::SecretString{std::string(32U, 'n')},
        "openproof/master-key-fingerprint/v1").value();
    const auto* dsn=connectionString.c_str();
    EXPECT_TRUE(pg::verifyMasterKeyBeforeListener(fnd::SecretString{dsn},1U,oldFingerprint));
    EXPECT_FALSE(pg::verifyMasterKeyBeforeListener(fnd::SecretString{dsn},2U,newFingerprint));
    auto dryRun=pg::rotateMasterKeyOffline(fnd::SecretString{dsn},1U,oldFingerprint,2U,newFingerprint,true);
    ASSERT_TRUE(dryRun) << dryRun.error().internalDetail();
    EXPECT_TRUE(dryRun->dryRun);
    EXPECT_EQ(dryRun->invalidated(), 8U);

    std::unique_ptr<PGresult, ResultDeleter> afterDryRun{PQexec(
        direct.get(),
        "SELECT (SELECT count(*) FROM openproof.authentication_transactions)+"
        "(SELECT count(*) FROM openproof.sessions)+"
        "(SELECT count(*) FROM openproof.account_verification_challenges)+"
        "(SELECT count(*) FROM openproof.passkey_registration_ceremonies)+"
        "(SELECT count(*) FROM openproof.oauth_authorization_codes)+"
        "(SELECT count(*) FROM openproof.oauth_token_families)+"
        "(SELECT count(*) FROM openproof.oauth_device_authorizations)+"
        "(SELECT count(*) FROM openproof.oauth_pushed_authorization_requests),"
        "(SELECT count(*) FROM openproof.master_key_rotations)")};
    ASSERT_NE(afterDryRun.get(), nullptr);
    ASSERT_EQ(PQresultStatus(afterDryRun.get()), PGRES_TUPLES_OK);
    EXPECT_STREQ(PQgetvalue(afterDryRun.get(), 0, 0), "8");
    EXPECT_STREQ(PQgetvalue(afterDryRun.get(), 0, 1), "0");

    auto committed=pg::rotateMasterKeyOffline(fnd::SecretString{dsn},1U,oldFingerprint,2U,newFingerprint,false);
    ASSERT_TRUE(committed) << committed.error().internalDetail();
    EXPECT_FALSE(committed->dryRun);
    EXPECT_EQ(committed->invalidated(), 8U);
    EXPECT_FALSE(pg::verifyMasterKeyBeforeListener(fnd::SecretString{dsn},1U,oldFingerprint));
    EXPECT_TRUE(pg::verifyMasterKeyBeforeListener(fnd::SecretString{dsn},2U,newFingerprint));

    std::unique_ptr<PGresult, ResultDeleter> afterCommit{PQexec(
        direct.get(),
        "SELECT (SELECT count(*) FROM openproof.authentication_transactions)+"
        "(SELECT count(*) FROM openproof.sessions)+"
        "(SELECT count(*) FROM openproof.account_verification_challenges)+"
        "(SELECT count(*) FROM openproof.passkey_registration_ceremonies)+"
        "(SELECT count(*) FROM openproof.oauth_authorization_codes)+"
        "(SELECT count(*) FROM openproof.oauth_token_families)+"
        "(SELECT count(*) FROM openproof.oauth_device_authorizations)+"
        "(SELECT count(*) FROM openproof.oauth_pushed_authorization_requests),"
        "(SELECT count(*) FROM openproof.password_credentials),"
        "(SELECT count(*) FROM openproof.totp_credentials),"
        "(SELECT count(*) FROM openproof.recovery_codes),"
        "(SELECT count(*) FROM openproof.audit_events "
        "WHERE event_id='master-rotation-audit'),"
        "(SELECT count(*) FROM openproof.oauth_clients),"
        "(SELECT count(*) FROM openproof.master_key_rotations WHERE from_version=1 "
        "AND to_version=2 AND authentication_transactions=1 AND sessions=1 "
        "AND account_challenges=1 AND passkey_registrations=1 "
        "AND authorization_codes=1 AND token_families=1 "
        "AND device_authorizations=1 AND pushed_requests=1)")};
    ASSERT_NE(afterCommit.get(), nullptr);
    ASSERT_EQ(PQresultStatus(afterCommit.get()), PGRES_TUPLES_OK);
    EXPECT_STREQ(PQgetvalue(afterCommit.get(), 0, 0), "0");
    for (int column = 1; column <= 6; ++column) {
        EXPECT_STREQ(PQgetvalue(afterCommit.get(), 0, column), "1");
    }

    auto duplicate=pg::rotateMasterKeyOffline(fnd::SecretString{dsn},1U,oldFingerprint,2U,newFingerprint,false);
    ASSERT_FALSE(duplicate);
    EXPECT_EQ(duplicate.error().code(), fnd::ErrorCode::AlreadyExists);
    const auto wrongFingerprint = sec::hmacSha256(
        fnd::SecretString{std::string(32U, 'x')},
        "openproof/master-key-fingerprint/v1").value();
    const auto thirdFingerprint = sec::hmacSha256(
        fnd::SecretString{std::string(32U, 'z')},
        "openproof/master-key-fingerprint/v1").value();
    auto wrongHead=pg::rotateMasterKeyOffline(fnd::SecretString{dsn},
        2U,wrongFingerprint,3U,thirdFingerprint,true);
    ASSERT_FALSE(wrongHead);
    EXPECT_EQ(wrongHead.error().code(), fnd::ErrorCode::FailedPrecondition);
}

TEST_F(PostgresIntegrationTest, InitialAdministratorBootstrapIsAtomicAuditedAndOneTime)
{
    execute("TRUNCATE openproof.audit_events, openproof.security_event_outbox, "
            "openproof.organizations CASCADE");
    auto command = admin::InitialAdministrator::create(
        core::OrganizationId{"bootstrap-org"}, "Bootstrap Organization",
        core::IdentityId{"bootstrap-identity"}, idp::ProviderId{"local"},
        idp::ExternalSubject{"owner@example.test"},
        fnd::SecretString{"correct-bootstrap-password"},
        cred::TotpSecret::create(
            fnd::SecretString{"12345678901234567890"}).value(), kNow);
    ASSERT_TRUE(command);

    auto policy = cred::PasswordPolicy::create(
        1024U, 8U, 1U, 16U, 32U, 2U * 1024U * 1024U).value();
    auto hasher = cred::PasswordHasher::create(
        fnd::SecretString{std::string(32U, 'p')}, policy).value();
    auto encryptionKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto auditKey = audit::AuditKey::create(
        fnd::SecretString{"abcdef0123456789abcdef0123456789"}).value();
    ASSERT_TRUE(pg::initializeAdministratorOffline(fnd::SecretString{connectionString},
        command.value(),hasher,encryptionKey,1U,idp::ProviderId{"local"},auditKey));

    auto repeated=pg::initializeAdministratorOffline(fnd::SecretString{connectionString},
        command.value(),hasher,encryptionKey,1U,idp::ProviderId{"local"},auditKey);
    ASSERT_FALSE(repeated);
    EXPECT_EQ(repeated.error().code(), fnd::ErrorCode::AlreadyExists);

    EXPECT_EQ(scalar("SELECT count(*)::text FROM openproof.organizations WHERE id='bootstrap-org' AND state=0"),"1");
    EXPECT_EQ(scalar("SELECT count(*)::text FROM openproof.identities WHERE id='bootstrap-identity' AND organization_id='bootstrap-org' AND kind=0 AND status=0"),"1");
    EXPECT_EQ(scalar("SELECT count(*)::text FROM openproof.memberships WHERE organization_id='bootstrap-org' AND identity_id='bootstrap-identity' AND state=1"),"1");
    EXPECT_EQ(scalar("SELECT count(*)::text FROM openproof.membership_roles WHERE organization_id='bootstrap-org' AND identity_id='bootstrap-identity' AND role='owner'"),"1");
    EXPECT_EQ(scalar("SELECT identity_id FROM openproof.external_identities WHERE provider='local' AND external_subject='owner@example.test'"),"bootstrap-identity");

    std::unique_ptr<PGresult, ResultDeleter> evidence{PQexec(
        direct.get(),
        "SELECT (SELECT count(*) FROM openproof.audit_events WHERE "
        "action='bootstrap.initial-owner' AND encode(event_hash,'hex')<>repeat('0',64)),"
        "(SELECT count(*) FROM openproof.security_event_outbox),"
        "(SELECT encrypted_seed=convert_to('12345678901234567890','UTF8') "
        "FROM openproof.totp_credentials WHERE identity_id='bootstrap-identity')")};
    ASSERT_NE(evidence.get(), nullptr);
    ASSERT_EQ(PQresultStatus(evidence.get()), PGRES_TUPLES_OK);
    ASSERT_EQ(PQntuples(evidence.get()), 1);
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 0), "1");
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 1), "1");
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 2), "f");

    auto verifierHasher = cred::PasswordHasher::create(
        fnd::SecretString{std::string(32U, 'p')}, policy).value();
    auto verifierKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto passwords=cred::BoundedPasswordExecutor::create(std::move(verifierHasher),1U);
    ASSERT_TRUE(passwords);
    pg::CoroutineLocalCredentialStore store{io.get_executor(),fnd::SecretString{connectionString},
        core::OrganizationId{"bootstrap-org"},idp::ProviderId{"local"},2U,2s,2s,4s};
    pg::CoroutinePostgresLocalProofVerifier verifier{store,*passwords.value(),cred::TotpPolicy::recommended(),
        std::move(verifierKey),1U,fnd::SecretString{std::string(32U,'r')}};
    const auto code=cred::totpAt(command->totp(),cred::TotpPolicy::recommended(),kNow).value();
    auto verified=run(verifier.verifyAsync(idp::ExternalSubject{"owner@example.test"},
        fnd::SecretString{"correct-bootstrap-password"},std::optional<fnd::SecretString>{fnd::SecretString{code}},std::nullopt,kNow));
    ASSERT_TRUE(verified);
    EXPECT_EQ(verified->verification,local::LocalVerification::PasswordAndTotp);
    EXPECT_EQ(verified->canonicalOwner,"bootstrap-identity");
}

TEST_F(PostgresIntegrationTest, NativeInitialOwnerRepairRequiresActiveIal2AndIsOneTime)
{
    auto auditKey=audit::AuditKey::create(fnd::SecretString{std::string(32U,'a')}).value();
    const auto repair=[&](){
        return pg::repairInitialOwnerOffline(fnd::SecretString{connectionString},
            core::OrganizationId{"org"},core::IdentityId{"identity-1"},idp::ProviderId{"local"},kNow,auditKey);
    };
    EXPECT_FALSE(repair());
    execute("INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) "
            "VALUES('local','repair-fixture','identity-1',1770000000000)");
    execute("INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
            "VALUES('identity-1','fixture-hash',1770000000000)");
    execute("INSERT INTO openproof.totp_credentials(identity_id,encrypted_seed,key_version,last_accepted_step,enrolled_at_ms) "
            "VALUES('identity-1',decode('00','hex'),1,NULL,1770000000000)");
    auto absent=repair();
    ASSERT_FALSE(absent);
    EXPECT_EQ(absent.error().code(),fnd::ErrorCode::AssuranceInsufficient);
    execute("INSERT INTO openproof.sessions(id,identity_id,provider,assurance,factors,phishing_resistant,state,"
            "token_digest,authenticated_at_ms,issued_at_ms,last_seen_at_ms,absolute_expires_at_ms,idle_timeout_ms) "
            "VALUES('repair-session','identity-1','local',2,3,false,0,decode(repeat('13',32),'hex'),"
            "1770000000000,1770000000000,1770000000000,1770003600000,600000)");
    ASSERT_TRUE(repair());
    EXPECT_FALSE(repair());
    std::unique_ptr<PGresult,ResultDeleter> result{PQexec(direct.get(),
        "SELECT (SELECT count(*) FROM openproof.membership_roles WHERE organization_id='org' AND identity_id='identity-1' AND role='owner'),"
        "(SELECT count(*) FROM openproof.audit_events WHERE action='bootstrap.initial-owner.repair' AND encode(event_hash,'hex')<>repeat('0',64)),"
        "(SELECT count(*) FROM openproof.security_event_outbox WHERE payload->>'type'='bootstrap.initial-owner.repaired')")};
    ASSERT_TRUE(result);
    ASSERT_EQ(PQresultStatus(result.get()),PGRES_TUPLES_OK);
    ASSERT_EQ(PQntuples(result.get()),1);
    for (int column=0;column<3;++column) EXPECT_STREQ(PQgetvalue(result.get(),0,column),"1");
}

TEST_F(PostgresIntegrationTest, OwnerProvisioningIsAtomicAuditedAndDeniedToMembers)
{
    execute("TRUNCATE openproof.audit_events, openproof.security_event_outbox");
    execute("INSERT INTO openproof.memberships"
            "(organization_id,identity_id,state,invited_at_ms) "
            "VALUES('org','identity-1',1,1770000000000)");
    execute("INSERT INTO openproof.membership_roles"
            "(organization_id,identity_id,role) "
            "VALUES('org','identity-1','owner')");
    execute("INSERT INTO openproof.external_identities"
            "(provider,external_subject,identity_id,linked_at_ms) "
            "VALUES('local','owner@example.test','identity-1',1770000000000)");

    auto policy = cred::PasswordPolicy::create(
        1024U, 8U, 1U, 16U, 32U, 2U * 1024U * 1024U).value();
    auto hasher = cred::PasswordHasher::create(
        fnd::SecretString{std::string(32U, 'p')}, policy).value();
    auto encryptionKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto auditKey = audit::AuditKey::create(
        fnd::SecretString{"abcdef0123456789abcdef0123456789"}).value();
    auto passwords=cred::BoundedPasswordExecutor::create(std::move(hasher),1U);
    ASSERT_TRUE(passwords);
    pg::CoroutineAdminStore administration{io.get_executor(),fnd::SecretString{connectionString},
        core::OrganizationId{"org"},idp::ProviderId{"local"},*passwords.value(),std::move(encryptionKey),
        1U,std::move(auditKey),2U,2s,2s,4s};
    const auto mutate=[&](std::string actor,auto&& command){
        const pg::CoroutineAdminStore::Command owned{std::move(command)};
        return run(administration.mutateAsync(core::IdentityId{std::move(actor)},owned));
    };

    const fnd::SecretString password{"generated-member-password-123456"};
    auto memberTotp = cred::TotpSecret::create(
        fnd::SecretString{"12345678901234567890"}).value();
    auto enrollment = admin::LocalMemberEnrollment::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        idp::ProviderId{"local"}, idp::ExternalSubject{"bob@example.test"},
        std::vector<org::Role>{org::Role{"viewer"}, org::Role{"member"}},
        password.clone(), std::move(memberTotp), kNow);
    ASSERT_TRUE(enrollment);
    ASSERT_TRUE(mutate("identity-1",enrollment.value()));

    EXPECT_EQ(scalar("SELECT count(*)::text FROM openproof.identities WHERE id='identity-2' AND organization_id='org' AND status=0"),"1");
    EXPECT_EQ(scalar("SELECT count(*)::text FROM openproof.memberships WHERE organization_id='org' AND identity_id='identity-2' AND state=1"),"1");
    EXPECT_EQ(scalar("SELECT identity_id FROM openproof.external_identities WHERE provider='local' AND external_subject='bob@example.test'"),"identity-2");
    EXPECT_EQ(scalar("SELECT string_agg(role,',' ORDER BY role) FROM openproof.membership_roles WHERE identity_id='identity-2' AND organization_id='org'"),"member,viewer");

    auto verifierHasher = cred::PasswordHasher::create(
        fnd::SecretString{std::string(32U, 'p')}, policy).value();
    auto verifierKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto verifyPasswords=cred::BoundedPasswordExecutor::create(std::move(verifierHasher),1U);
    ASSERT_TRUE(verifyPasswords);
    pg::CoroutineLocalCredentialStore store{io.get_executor(),fnd::SecretString{connectionString},
        core::OrganizationId{"org"},idp::ProviderId{"local"},2U,2s,2s,4s};
    pg::CoroutinePostgresLocalProofVerifier verifier{store,*verifyPasswords.value(),cred::TotpPolicy::recommended(),
        std::move(verifierKey),1U,fnd::SecretString{std::string(32U,'r')}};
    const auto verify=[&](const fnd::SecretString& candidate,const std::string& otp,fnd::Instant when){
        return run(verifier.verifyAsync(idp::ExternalSubject{"bob@example.test"},candidate.clone(),
            std::optional<fnd::SecretString>{fnd::SecretString{otp}},std::nullopt,when));
    };
    auto verifierTotp = cred::TotpSecret::create(
        fnd::SecretString{"12345678901234567890"}).value();
    const std::string code = cred::totpAt(
        verifierTotp, cred::TotpPolicy::recommended(), kNow).value();
    ASSERT_TRUE(verify(password,code,kNow));

    auto refused = admin::LocalMemberEnrollment::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-3"},
        idp::ProviderId{"local"}, idp::ExternalSubject{"mallory@example.test"},
        std::vector<org::Role>{org::Role{"member"}},
        fnd::SecretString{"another-generated-password-12345"},
        cred::TotpSecret::create(
            fnd::SecretString{"abcdefghijabcdefghij"}).value(), kNow);
    ASSERT_TRUE(refused);
    const auto denied=mutate("identity-2",refused.value());
    ASSERT_FALSE(denied);
    EXPECT_EQ(denied.error().code(), fnd::ErrorCode::PermissionDenied);
    EXPECT_EQ(scalar("SELECT count(*)::text FROM openproof.identities WHERE id='identity-3'"),"0");

    std::unique_ptr<PGresult, ResultDeleter> evidence{PQexec(
        direct.get(),
        "SELECT (SELECT count(*) FROM openproof.audit_events WHERE "
        "action='local-member.create' AND encode(event_hash,'hex')<>repeat('0',64)),"
        "(SELECT count(*) FROM openproof.security_event_outbox),"
        "(SELECT count(*) FROM openproof.identities WHERE id='identity-3')")};
    ASSERT_NE(evidence.get(), nullptr);
    ASSERT_EQ(PQresultStatus(evidence.get()), PGRES_TUPLES_OK);
    ASSERT_EQ(PQntuples(evidence.get()), 1);
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 0), "1");
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 1), "1");
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 2), "0");

    auto finalOwnerRoles = admin::MemberRoleReplacement::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-1"},
        std::vector<org::Role>{org::Role{"member"}},
        kNow + std::chrono::minutes{1}).value();
    auto refusedLastOwner = mutate("identity-1",finalOwnerRoles);
    ASSERT_FALSE(refusedLastOwner);
    EXPECT_EQ(refusedLastOwner.error().code(), fnd::ErrorCode::FailedPrecondition);
    auto suspendFinalOwner = admin::MemberLifecycleChange::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-1"},
        admin::MemberLifecycleAction::Suspend,
        kNow + std::chrono::minutes{1}).value();
    auto refusedSuspension = mutate("identity-1",suspendFinalOwner);
    ASSERT_FALSE(refusedSuspension);
    EXPECT_EQ(refusedSuspension.error().code(), fnd::ErrorCode::FailedPrecondition);

    pg::CoroutinePostgresSessionRepository sessions{io.get_executor(),fnd::SecretString{connectionString},2U,2s,2s,4s};
    ASSERT_TRUE(run(sessions.add(sessionValue(
        "member-role-token", "member-role-session", "identity-2"))));
    auto promote = admin::MemberRoleReplacement::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        std::vector<org::Role>{org::Role{"member"}, org::Role{"owner"}},
        kNow + std::chrono::minutes{2}).value();
    ASSERT_TRUE(mutate("identity-1",promote));
    EXPECT_FALSE(run(sessions.use(
        sess::TokenDigest{sec::sha256("member-role-token").value()},
        kNow + std::chrono::minutes{2})));
    EXPECT_EQ(scalar("SELECT count(*)::text FROM openproof.membership_roles WHERE organization_id='org' AND identity_id='identity-2' AND role='owner'"),"1");

    ASSERT_TRUE(run(sessions.add(sessionValue(
        "owner-lifecycle-token", "owner-lifecycle-session", "identity-1"))));
    auto suspendOwner = admin::MemberLifecycleChange::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-1"},
        admin::MemberLifecycleAction::Suspend,
        kNow + std::chrono::minutes{3}).value();
    ASSERT_TRUE(mutate("identity-2",suspendOwner));
    EXPECT_FALSE(run(sessions.use(
        sess::TokenDigest{sec::sha256("owner-lifecycle-token").value()},
        kNow + std::chrono::minutes{3})));
    EXPECT_EQ(scalar("SELECT state::text FROM openproof.memberships WHERE organization_id='org' AND identity_id='identity-1'"),"2");
    EXPECT_EQ(scalar("SELECT count(*)::text FROM openproof.memberships m JOIN openproof.membership_roles r USING(organization_id,identity_id) WHERE m.organization_id='org' AND m.identity_id='identity-1' AND m.state=1 AND r.role='owner'"),"0");

    auto reinstateOwner = admin::MemberLifecycleChange::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-1"},
        admin::MemberLifecycleAction::Reinstate,
        kNow + std::chrono::minutes{4}).value();
    ASSERT_TRUE(mutate("identity-2",reinstateOwner));
    EXPECT_EQ(scalar("SELECT count(*)::text FROM openproof.memberships m JOIN openproof.membership_roles r USING(organization_id,identity_id) WHERE m.organization_id='org' AND m.identity_id='identity-1' AND m.state=1 AND r.role='owner'"),"1");

    ASSERT_TRUE(run(sessions.add(sessionValue(
        "member-reset-token", "member-reset-session", "identity-2"))));
    execute("INSERT INTO openproof.recovery_codes"
            "(identity_id,code_digest,issued_at_ms) "
            "VALUES('identity-2',decode(repeat('ab',32),'hex'),1770000000000)");
    const fnd::SecretString resetPassword{"reset-generated-password-12345678"};
    auto reset = admin::LocalCredentialReset::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        resetPassword.clone(),
        cred::TotpSecret::create(
            fnd::SecretString{"abcdefghijabcdefghij"}).value(),
        kNow + std::chrono::minutes{5}).value();
    ASSERT_TRUE(mutate("identity-1",reset));
    EXPECT_FALSE(run(sessions.use(
        sess::TokenDigest{sec::sha256("member-reset-token").value()},
        kNow + std::chrono::minutes{5})));
    auto resetTotp = cred::TotpSecret::create(
        fnd::SecretString{"abcdefghijabcdefghij"}).value();
    const std::string resetCode = cred::totpAt(
        resetTotp, cred::TotpPolicy::recommended(),
        kNow + std::chrono::minutes{5}).value();
    EXPECT_FALSE(verify(password,resetCode,kNow+5min));
    ASSERT_TRUE(verify(resetPassword,resetCode,kNow+5min));

    auto removeMember = admin::MemberLifecycleChange::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        admin::MemberLifecycleAction::Remove,
        kNow + std::chrono::minutes{6}).value();
    ASSERT_TRUE(mutate("identity-1",removeMember));
    EXPECT_EQ(scalar("SELECT state::text FROM openproof.memberships WHERE organization_id='org' AND identity_id='identity-2'"),"3");
    EXPECT_EQ(scalar("SELECT count(*)::text FROM openproof.membership_roles WHERE organization_id='org' AND identity_id='identity-2'"),"0");

    auto removeFinalOwner = admin::MemberLifecycleChange::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-1"},
        admin::MemberLifecycleAction::Remove,
        kNow + std::chrono::minutes{7}).value();
    auto finalRemoval = mutate("identity-1",removeFinalOwner);
    ASSERT_FALSE(finalRemoval);
    EXPECT_EQ(finalRemoval.error().code(), fnd::ErrorCode::FailedPrecondition);

    std::unique_ptr<PGresult, ResultDeleter> lifecycleEvidence{PQexec(
        direct.get(),
        "SELECT (SELECT count(*) FROM openproof.audit_events),"
        "(SELECT count(*) FROM openproof.security_event_outbox),"
        "(SELECT count(*) FROM openproof.recovery_codes WHERE identity_id='identity-2'),"
        "(SELECT count(*) FROM openproof.sessions WHERE identity_id IN "
        "('identity-1','identity-2') AND state=0)")};
    ASSERT_NE(lifecycleEvidence.get(), nullptr);
    ASSERT_EQ(PQresultStatus(lifecycleEvidence.get()), PGRES_TUPLES_OK);
    EXPECT_STREQ(PQgetvalue(lifecycleEvidence.get(), 0, 0), "6");
    EXPECT_STREQ(PQgetvalue(lifecycleEvidence.get(), 0, 1), "6");
    EXPECT_STREQ(PQgetvalue(lifecycleEvidence.get(), 0, 2), "0");
    EXPECT_STREQ(PQgetvalue(lifecycleEvidence.get(), 0, 3), "0");
}


TEST_F(PostgresIntegrationTest, IdentityPlatformPersistenceAndOneTimeOAuthStateAreTransactional)
{
    const core::IdentityId owner{"identity-1"};
    const sess::SessionId sessionId{"session-1"};
    execute("INSERT INTO openproof.memberships(organization_id,identity_id,state,invited_at_ms) VALUES('org','identity-1',1,1770000000000)");
    execute("INSERT INTO openproof.membership_roles(organization_id,identity_id,role) VALUES('org','identity-1','owner')");
    pg::CoroutinePostgresSessionRepository sessions{io.get_executor(),fnd::SecretString{connectionString},1U,2s,2s,4s};
    ASSERT_TRUE(run(sessions.add(sessionValue("platform-session"))));
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{connectionString},
        core::OrganizationId{"org"},2U,2s,2s,4s};
    const app::ApplicationId applicationId{"ride-app"};
    auto application=run(native.mutateApplicationAsync(
        app::ApplicationMutationCommand{app::ApplicationMutation::Create,applicationId,"ride","Ride",app::Environment::Production},
        owner,sessionId,kNow));
    ASSERT_TRUE(application);
    EXPECT_EQ(application->identifier(),"ride");
    EXPECT_EQ(application->environment(),app::Environment::Production);
    auto loadedApplication=run(native.readApplicationManagementAsync(app::ManagementRead::Applications,owner,sessionId,std::nullopt,kNow));
    ASSERT_TRUE(loadedApplication);
    EXPECT_NE(loadedApplication->find("ride-app"),std::string::npos);

    auto redirect = cli::RedirectUri::create(
        "http://127.0.0.1:49152/callback", cli::ClientKind::Native);
    auto openid = cli::Scope::create("openid");
    auto profileScope = cli::Scope::create("profile");
    ASSERT_TRUE(redirect && openid && profileScope);

    const cli::ClientId clientId{"ride-native"};
    auto client=run(native.mutateOAuthClientAsync(cli::ManagementMutationCommand{
        cli::ManagementMutation::Create,clientId,applicationId,"Ride Native",cli::ClientKind::Native,
        {redirect.value()},{openid.value(),profileScope.value()},std::nullopt},owner,sessionId,kNow));
    ASSERT_TRUE(client);
    EXPECT_TRUE(client->isPublic());
    EXPECT_TRUE(client->permitsRedirect("http://127.0.0.1:55001/callback"));
    auto loadedClient=run(native.readApplicationManagementAsync(app::ManagementRead::Clients,owner,sessionId,
        std::string{"ride-app"},kNow));
    ASSERT_TRUE(loadedClient);
    EXPECT_NE(loadedClient->find("ride-native"),std::string::npos);

    execute("INSERT INTO openproof.identity_profiles(identity_id,email,email_verified,created_at_ms,updated_at_ms) "
        "VALUES('identity-1','rider@example.test',true,1770000000000,1770000000000)");
    ASSERT_TRUE(run(native.updateProfileAsync(owner,std::string{"Rider One"},std::string{"rider-one"},
        std::string{"fa-IR"},std::nullopt,std::nullopt,kNow)));
    auto loadedProfile=run(native.readProfileAsync(owner));
    ASSERT_TRUE(loadedProfile && loadedProfile->email().has_value());
    EXPECT_EQ(loadedProfile->email().value(),"rider@example.test");
    EXPECT_TRUE(loadedProfile->emailVerified());

    constexpr std::string_view verifier="0123456789012345678901234567890123456789012";
    const auto digest=[](std::string_view label){return fnd::toHex(sec::sha256(label).value());};
    const auto code=digest("stored-code");
    const auto challenge=fnd::toBase64Url(sec::sha256(verifier).value());
    const char* values[]{code.c_str(),challenge.c_str()};
    std::unique_ptr<PGresult,ResultDeleter> grant{PQexecParams(direct.get(),
        "INSERT INTO openproof.oauth_authorization_codes(code_digest,client_id,identity_id,redirect_uri,code_challenge,"
        "nonce,provider,assurance,factors,phishing_resistant,authenticated_at_ms,issued_at_ms,expires_at_ms) "
        "VALUES(decode($1,'hex'),'ride-native','identity-1','http://127.0.0.1:55001/callback',$2,"
        "'nonce-pg','local',2,3,false,1770000000000,1770000000000,1770000120000)",2,nullptr,values,nullptr,nullptr,0)};
    ASSERT_TRUE(grant && PQresultStatus(grant.get())==PGRES_COMMAND_OK);
    std::unique_ptr<PGresult,ResultDeleter> scopes{PQexecParams(direct.get(),
        "INSERT INTO openproof.oauth_authorization_code_scopes(code_digest,scope) "
        "VALUES(decode($1,'hex'),'openid'),(decode($1,'hex'),'profile')",1,nullptr,values,nullptr,nullptr,0)};
    ASSERT_TRUE(scopes && PQresultStatus(scopes.get())==PGRES_COMMAND_OK);
    int signCalls=0;
    const auto signer=[&](const oauth::AuthorizationCode& accepted)->fnd::Result<std::string>{
        ++signCalls;
        EXPECT_EQ(accepted.identity(),owner);
        EXPECT_EQ(accepted.nonce(),std::optional<std::string>{"nonce-pg"});
        return std::string{"fixture-signed-id-token"};
    };
    const auto exchange=[&](std::string pkce,fnd::Instant when){
        return run(native.exchangeOAuthCodeAsync("ride-native",std::nullopt,code,
            "http://127.0.0.1:55001/callback",std::move(pkce),"family-pg",digest("access-pg-0"),
            digest("refresh-pg-0"),std::nullopt,when,15min,24h*30,signer));
    };
    const auto wrong=fnd::toBase64Url(sec::sha256("1123456789012345678901234567890123456789012").value());
    EXPECT_FALSE(exchange(wrong,kNow+10s));
    EXPECT_EQ(signCalls,0);
    auto consumed=exchange(challenge,kNow+11s);
    ASSERT_TRUE(consumed);
    EXPECT_EQ(consumed->scopes,(std::vector<std::string>{"openid","profile"}));
    EXPECT_TRUE(consumed->idToken.has_value());
    EXPECT_FALSE(exchange(challenge,kNow+12s));
    EXPECT_EQ(signCalls,1);
    auto access=run(native.readDelegatedAccessAsync(digest("access-pg-0"),kNow+12s));
    ASSERT_TRUE(access);
    const auto refreshState=[&](std::string_view label){
        const auto hex=digest(label);
        return scalar(("SELECT state::text FROM openproof.oauth_refresh_tokens WHERE token_digest=decode('"+hex+"','hex')").c_str());
    };
    EXPECT_EQ(refreshState("refresh-pg-0"),"0");
    const auto absolute=scalar("SELECT expires_at_ms::text FROM openproof.oauth_refresh_tokens WHERE family_id='family-pg'");
    auto rotated=run(native.rotateOAuthRefreshAsync("ride-native",std::nullopt,digest("refresh-pg-0"),
        digest("access-pg-1"),digest("refresh-pg-1"),std::nullopt,kNow+1min,15min));
    ASSERT_TRUE(rotated);
    EXPECT_EQ(rotated.value(),(std::vector<std::string>{"openid","profile"}));
    EXPECT_EQ(refreshState("refresh-pg-0"),"1");
    EXPECT_EQ(refreshState("refresh-pg-1"),"0");
    EXPECT_EQ(scalar("SELECT expires_at_ms::text FROM openproof.oauth_refresh_tokens WHERE family_id='family-pg' AND sequence=1"),absolute);
    EXPECT_FALSE(run(native.rotateOAuthRefreshAsync("ride-native",std::nullopt,digest("refresh-pg-0"),
        digest("access-pg-replay"),digest("refresh-pg-replay"),std::nullopt,kNow+2min,15min)));
    EXPECT_EQ(refreshState("refresh-pg-1"),"2");
    EXPECT_FALSE(run(native.readDelegatedAccessAsync(digest("access-pg-1"),kNow+2min)));
}


TEST_F(PostgresIntegrationTest, PasskeyZeroCounterUseUpdatesLastUsedAt)
{
    // Exercise a real ES256 assertion rather than bypassing proof validation
    // with the retired repository's raw counter update.
    std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key{
        EVP_PKEY_Q_keygen(nullptr,nullptr,"EC","prime256v1"),EVP_PKEY_free};
    ASSERT_TRUE(key);
    const auto coordinate=[&](const char* name){
        BIGNUM* raw=nullptr;
        if(EVP_PKEY_get_bn_param(key.get(),name,&raw)!=1)
            throw std::runtime_error{"Fixture EC coordinate unavailable"};
        std::unique_ptr<BIGNUM,decltype(&BN_free)> number{raw,BN_free};
        std::array<std::byte,32U> bytes{};
        if(BN_bn2binpad(number.get(),reinterpret_cast<unsigned char*>(bytes.data()),32)!=32)
            throw std::runtime_error{"Invalid fixture EC coordinate"};
        return fnd::toBase64Url(bytes);
    };
    const auto x=coordinate(OSSL_PKEY_PARAM_EC_PUB_X),y=coordinate(OSSL_PKEY_PARAM_EC_PUB_Y);
    const auto credentialId=fnd::toBase64Url(sec::sha256("zero-counter-credential").value());
    const char* values[]{credentialId.c_str(),x.c_str(),y.c_str()};
    execute("INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) "
        "VALUES('passkey','identity-1','identity-1',1770000000000)");
    std::unique_ptr<PGresult,ResultDeleter> inserted{PQexecParams(direct.get(),
        "INSERT INTO openproof.passkey_credentials(credential_id,identity_id,public_key_x,public_key_y,sign_count,created_at_ms,last_used_at_ms) "
        "VALUES($1,'identity-1',$2,$3,0,1770000000000,1770000000000)",3,nullptr,values,nullptr,nullptr,0)};
    ASSERT_TRUE(inserted && PQresultStatus(inserted.get())==PGRES_COMMAND_OK);
    auto config=passkey::PasskeyConfig::create("identity.example.test","Fixture","https://identity.example.test",
        fnd::SecretString{std::string(32U,'k')},5min);
    ASSERT_TRUE(config);
    pg::CoroutinePostgresCanonicalFinalizer native{io.get_executor(),fnd::SecretString{connectionString},
        core::OrganizationId{"org"},2U,2s,2s,4s};
    const auto assertion=[&](const idp::ChallengeId& ceremony,std::uint32_t counter){
        const auto challenge=fnd::toBase64Url(sec::hmacSha256(
            fnd::SecretString{std::string(32U,'k')},"authenticate:"+std::string{ceremony.value()}).value());
        const std::string client="{\"type\":\"webauthn.get\",\"challenge\":\""+challenge+
            "\",\"origin\":\"https://identity.example.test\",\"crossOrigin\":false}";
        const auto rp=sec::sha256("identity.example.test").value();
        std::vector<std::byte> auth(rp.begin(),rp.end());
        auth.push_back(std::byte{0x05}); // user presence + user verification
        for(unsigned shift:{24U,16U,8U,0U}) auth.push_back(static_cast<std::byte>((counter>>shift)&0xffU));
        const auto hash=sec::sha256(client).value();
        std::vector<std::byte> payload=auth;
        payload.insert(payload.end(),hash.begin(),hash.end());
        std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> context{EVP_MD_CTX_new(),EVP_MD_CTX_free};
        if(!context || EVP_DigestSignInit(context.get(),nullptr,EVP_sha256(),nullptr,key.get())!=1)
            throw std::runtime_error{"Fixture signature initialization failed"};
        std::size_t size{};
        const auto* message=reinterpret_cast<const unsigned char*>(payload.data());
        if(EVP_DigestSign(context.get(),nullptr,&size,message,payload.size())!=1)
            throw std::runtime_error{"Fixture signature sizing failed"};
        std::vector<std::byte> signature(size);
        if(EVP_DigestSign(context.get(),reinterpret_cast<unsigned char*>(signature.data()),&size,message,payload.size())!=1)
            throw std::runtime_error{"Fixture signature failed"};
        signature.resize(size);
        return passkey::AssertionResponse{credentialId,
            fnd::toBase64Url(std::as_bytes(std::span{client.data(),client.size()})),
            fnd::toBase64Url(auth),fnd::toBase64Url(signature),std::nullopt};
    };
    const auto prove=[&](fnd::Instant when,std::uint32_t counter){
        auto options=passkey::assertionOptions(config.value(),when);
        if(!options) throw std::runtime_error{"Fixture assertion options failed"};
        return run(native.verifyPasskeyAssertionAsync(config.value(),options->id(),assertion(options->id(),counter),when));
    };
    const auto usedAt=kNow+5min;
    auto accepted=prove(usedAt,0U);
    ASSERT_TRUE(accepted);
    EXPECT_EQ(accepted->value(),"identity-1");
    EXPECT_EQ(scalar("SELECT sign_count::text||':'||last_used_at_ms::text FROM openproof.passkey_credentials WHERE identity_id='identity-1'"),"0:1770000300000");
    ASSERT_TRUE(prove(kNow,0U));
    EXPECT_EQ(scalar("SELECT sign_count::text||':'||last_used_at_ms::text FROM openproof.passkey_credentials WHERE identity_id='identity-1'"),"0:1770000300000");
    ASSERT_TRUE(prove(usedAt+1s,1U));
    EXPECT_FALSE(prove(usedAt+2s,1U));
    EXPECT_FALSE(prove(usedAt+2s,0U));
    EXPECT_EQ(scalar("SELECT sign_count::text||':'||last_used_at_ms::text FROM openproof.passkey_credentials WHERE identity_id='identity-1'"),"1:1770000301000");
}

}

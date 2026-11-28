import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {cppExecutableText} from "./cpp-lexical-scan.mjs";
const root=path.resolve(import.meta.dirname,"..");
const read=file=>fs.readFileSync(path.join(root,file),"utf8");
const app=read("apps/opp/main.cpp");
const http=read("src/operations/http/coroutine_health_http.cpp");
const store=read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
test("production health routes exclusively use strict native dispatch",()=>{
  assert.match(app,/operationsHttp::CoroutineHealthAdapter nativeHealth/);
  assert.match(app,/reader->healthCheckAsync\(\)/);
  assert.match(app,/nativePaths.emplace_back\("\/health\/live"\)/);
  assert.match(app,/nativePaths.emplace_back\("\/health\/ready"\)/);
  assert.match(app,/CoroutineRouteOverlay nativeRoutes\{\s*fallback, nativeHealth,/);
  assert.doesNotMatch(app,/operationsHttp::PostgresReadinessCheck\s+\w+\s*\{/);
  assert.doesNotMatch(app,/operationsHttp::HealthHttpApi\s+\w+\s*\{/);
  assert.doesNotMatch(cppExecutableText(http),/m_fallback->handle\(|PQexec|condition_variable|\.wait_for\(/);
});
test("server preflight and listener use no blocking PostgreSQL repository",()=>{
  const serve=app.slice(app.indexOf("ExitCode runGatewayServer("),app.indexOf("int main("));
  const preflight=serve.indexOf("postgres::nativeDatabasePreflight(");
  assert.ok(preflight>=0);
  assert.doesNotMatch(cppExecutableText(serve),/\bpostgres::(?:ConnectionPool|PoolConfig|Migrator|Postgres\w+Repository|Postgres\w+Store)\b/);
  assert.ok(serve.indexOf("nativeIo = std::make_unique<boost::asio::thread_pool>",preflight)>preflight);
  const startup=read("src/storage/postgres/coroutine_startup.cpp");
  const migrate=startup.slice(startup.indexOf("migrateSchemaAsync("),startup.indexOf("migrateSchemaBeforeListener("));
  const ordered=["migration::loadPackage(directory)","co_await pg::AsyncConnection::connect",
    "BEGIN ISOLATION LEVEL READ COMMITTED","pg_advisory_xact_lock(1827364512)",
    "SELECT version,encode(checksum,'hex')","existing->checksum!=*row[1]",
    "if (baselineSql && ledger.rows.empty())","if (migration.archived || migration.recorded) continue;",
    "executeMigrationScript(migration.sql","INSERT INTO openproof.schema_migrations",
    'execute("COMMIT",{})','committed.commandTag!="COMMIT"'];
  let previous=-1;
  for(const term of ordered){
    const index=migrate.indexOf(term,previous+1);
    assert.ok(index>previous,term);previous=index;
  }
  assert.match(startup,/security::constantTimeEquals/);
  const validate=startup.slice(startup.indexOf("validateAsync("),startup.indexOf("migrateSchemaAsync("));
  assert.match(validate,/storedVersion!=version/);
  assert.match(validate,/E::FailedPrecondition,"Configured master key does not match the committed rotation journal\."/);
  const e2e=read("scripts/e2e-identity-platform.mjs");
  assert.match(e2e,/assert.equal\(retiredMasterStart.status, 3,/);
  assert.match(e2e,/does not match the committed rotation journal\.\*FAILED_PRECONDITION/);
  assert.match(startup,/WHERE id=\$1 AND state=0/);
  assert.doesNotMatch(cppExecutableText(startup),/PQexec|PQconnectdb|PQreset|condition_variable/);
  const transport=read("src/storage/postgres/async_connection.cpp");
  assert.match(transport,/migrationScript\?PQsendQuery\(connection,sql.c_str\(\)\):/);
  assert.match(transport,/migrationScript && \(!params.empty\(\) \|\| !inTransaction\(\)/);
  assert.match(transport,/migrationScript && !inTransaction\(\)/);
  assert.match(read("tests/storage/postgres_async_test.cpp"),/MigrationScriptUsesExplicitTransactionAndKeepsRequestQueriesSingleStatement/);
  assert.match(read("tests/storage/postgres_integration_test.cpp"),/pg::migrateSchemaBeforeListener\(fnd::SecretString\{dsn\}/);
  for(const file of ["session_domain.cpp","coroutine_session_repository.cpp"])
    assert.doesNotMatch(read("src/storage/postgres/"+file),/import openproof.storage.postgres;/);
  const cmake=read("src/storage/postgres/CMakeLists.txt");
  const native=cmake.slice(cmake.indexOf("target_link_libraries(openproof_postgres_async_repository"),
      cmake.indexOf("# GCC 16.2 misidentifies",cmake.indexOf("target_link_libraries(openproof_postgres_async_repository")));
  assert.match(native,/PUBLIC openproof_postgres_async_io/);
  assert.doesNotMatch(native,/openproof_storage_postgres/);
  const tests=read("tests/CMakeLists.txt");
  const isolated=tests.slice(tests.indexOf("target_link_libraries(openproof_postgres_native_only_tests"),
      tests.indexOf("# OIDC's native discovery"));
  assert.match(isolated,/openproof_postgres_async_repository/);
  assert.doesNotMatch(isolated,/openproof_storage_postgres/);
  assert.match(read(".github/workflows/ci.yml"),/tests\/openproof_postgres_native_only_tests/);
  assert.match(read(".github/workflows/native-coroutine.yml"),/tests\/openproof_postgres_native_only_tests/);
});
test("offline master key rotation and all CLI schema checks use native libpq",()=>{
  const cli=app.slice(app.indexOf("ExitCode runTotpRekey("),app.indexOf("ExitCode runListener("));
  assert.equal([...cli.matchAll(/postgres::migrateSchemaBeforeListener\(/g)].length,4);
  assert.doesNotMatch(cli,/postgres::Migrator|PostgresMasterKeyRotator/);
  const master=cli.slice(cli.indexOf("ExitCode runMasterKeyRotation("),cli.indexOf("ExitCode runBootstrapAdmin("));
  assert.match(master,/postgres::verifyMasterKeyBeforeListener\(/);
  assert.match(master,/postgres::rotateMasterKeyOffline\(/);
  assert.doesNotMatch(master,/postgres::ConnectionPool|postgres::PoolConfig/);
  const startup=read("src/storage/postgres/coroutine_startup.cpp");
  const rotation=startup.slice(startup.indexOf("rotateMasterAsync("),startup.indexOf("foundation::Result<NativeMasterRotationReport> rotateMasterKeyOffline("));
  const order=["BEGIN ISOLATION LEVEL SERIALIZABLE","pg_advisory_xact_lock(7299730475761673317)",
    "IN ACCESS EXCLUSIVE MODE","WHERE to_version=$1","ORDER BY sequence DESC LIMIT 1",
    "security::constantTimeEquals(std::span","WITH removed AS (DELETE FROM openproof.",
    'remove("authentication_transactions")','remove("sessions")','remove("account_verification_challenges")',
    'remove("passkey_registration_ceremonies")','remove("oauth_authorization_codes")',
    'remove("oauth_token_families")','remove("oauth_device_authorizations")',
    'remove("oauth_pushed_authorization_requests")','execute("ROLLBACK",{})',
    "INSERT INTO openproof.master_key_rotations",'execute("COMMIT",{})','committed.commandTag!="COMMIT"'];
  let previous=-1;
  for(const term of order){
    const index=rotation.indexOf(term,previous+1);
    assert.ok(index>previous,term);previous=index;
  }
  assert.doesNotMatch(cppExecutableText(rotation),/PQexec|PQconnectdb|PQreset|condition_variable/);
  const integration=read("tests/storage/postgres_integration_test.cpp");
  assert.match(integration,/MasterKeyRotationAtomicallyInvalidatesOnlyDerivedState/);
  assert.match(integration,/pg::rotateMasterKeyOffline\(fnd::SecretString\{dsn\}/);
});
test("all offline CLI mutations and production linking are independent of blocking storage",()=>{
  const cli=app.slice(app.indexOf("ExitCode runTotpRekey("),app.indexOf("ExitCode runListener("));
  for(const call of ["rekeyTotpOffline","rotateMasterKeyOffline","initializeAdministratorOffline","repairInitialOwnerOffline"])
    assert.ok(cli.includes("postgres::"+call+"("),call);
  assert.doesNotMatch(cppExecutableText(app),/\bpostgres::(?:ConnectionPool|PoolConfig|Migrator|Postgres\w+Repository|Postgres\w+Store|PostgresCredentialRekeyer|PostgresMasterKeyRotator)\b/);
  assert.doesNotMatch(app,/import openproof.storage.postgres;/);
  for(const file of ["apps/opp/CMakeLists.txt","src/operations/http/CMakeLists.txt"])
    assert.doesNotMatch(read(file),/\bopenproof_storage_postgres\b/);
  assert.doesNotMatch(read("src/operations/http/http.cppm"),/import openproof.storage.postgres;/);
  assert.doesNotMatch(read("src/storage/postgres/CMakeLists.txt"),/\bopenproof_storage_postgres\b/);
  for(const file of ["postgres.cpp","postgres.cppm"])
    assert.equal(fs.existsSync(path.join(root,"src/storage/postgres",file)),false,file);
  assert.doesNotMatch(read("tests/CMakeLists.txt"),/\bopenproof_storage_postgres\b/);
  const startup=read("src/storage/postgres/coroutine_startup.cpp");
  const rekey=startup.slice(startup.indexOf("rekeyTotpAsync("),startup.indexOf("foundation::Result<NativeCredentialRekeyReport> rekeyTotpOffline("));
  for(const term of ["BEGIN ISOLATION LEVEL SERIALIZABLE","pg_advisory_xact_lock(7299730475761673316)",
    "LOCK TABLE openproof.totp_credentials IN ACCESS EXCLUSIVE MODE","LIMIT 128 FOR UPDATE",
    "openAes256Gcm(replacementKey","openAes256Gcm(currentKey","sealAes256Gcm(replacementKey",
    "AND encrypted_seed=decode($5,'hex') RETURNING identity_id",'execute("ROLLBACK",{})',
    "INSERT INTO openproof.credential_key_rotations",'execute("COMMIT",{})'])
    assert.ok(rekey.includes(term),term);
  const admin=read("src/storage/postgres/coroutine_admin_store.cpp");
  const bootstrap=admin.slice(admin.indexOf("initializeAdministratorAsync("),admin.indexOf("repairInitialOwnerAsync("));
  const repair=admin.slice(admin.indexOf("repairInitialOwnerAsync("),admin.indexOf("foundation::Status initializeAdministratorOffline("));
  for(const section of [bootstrap,repair]){
    assert.match(section,/BEGIN ISOLATION LEVEL SERIALIZABLE/);
    assert.match(section,/pg_advisory_xact_lock\(7299730475761673313\)/);
    assert.match(section,/co_await appendRecords/);
    assert.ok(section.indexOf("co_await appendRecords")<section.indexOf('execute("COMMIT",{})'));
    assert.doesNotMatch(cppExecutableText(section),/PQexec|PQconnectdb/);
  }
  for(const term of ["SELECT count(*) FROM openproof.memberships","SELECT count(*) FROM openproof.membership_roles WHERE role='owner'",
    "bootstrap.initial-owner.repair","AND i.kind=0 AND i.status=0","assurance>=2","issued_at_ms<=$2::bigint",
    "E::AssuranceInsufficient"]) assert.ok(repair.includes(term),term);
  const integration=read("tests/storage/postgres_integration_test.cpp");
  for(const call of ["rekeyTotpOffline","initializeAdministratorOffline","repairInitialOwnerOffline"])
    assert.ok(integration.includes("pg::"+call+"("),call);
});
test("native migration and session regression suites exercise production SQL without the old module",()=>{
  const migration=read("tests/storage/postgres_integration_test.cpp");
  assert.doesNotMatch(migration,/import openproof.storage.postgres;|\bpg::(?:PoolConfig|ConnectionPool|Migrator|Postgres\w+Repository|Postgres\w+Store)\b|migrator\.applyDirectory/);
  for(const name of ["HistoricalTenantSeedsNeverAutoApply","MigrationRejectsUnknownLedgerBeforeNewSql",
    "MigrationBatchRollsBackEarlierSqlAndLedgerOnLaterFailure","ConcurrentMigrationChecksShareOneLedger",
    "FreshSnapshotRecordsHistoricalChecksumsAndIsIdempotent","HistoricalReleaseUpgrade"]){
    const start=migration.indexOf(name);
    assert.ok(start>=0,name);
    const end=migration.indexOf("\nTEST",start);
    assert.match(migration.slice(start,end<0?undefined:end),/pg::migrateSchemaBeforeListener/);
  }
  const nativeCases=[
    ["PasskeyConcurrentRemovalPreservesFinalCredential",["mutatePasskeyAccountAsync","readPasskeyAccountAsync","ASSERT_NE(a.has_value(),b.has_value())"]],
    ["SessionUseRotationAndRevocationAreImmediate",["peer.use","repository.rotate","peer.revoke"]],
    ["TransactionCanBeConsumedExactlyOnceAcrossThreads",["consumeAsync","redeem(peer)","authentication_transaction_metadata"]],
    ["FailedNonceBurnsTransactionAtomically",["consumeAsync","wrong-nonce","right-nonce","state::text"]],
    ["RecoveryCodeIsConsumedExactlyOnceAcrossNodes",["captureIssuanceAsync","replaceFencedAsync","consumeAsync","remainingAsync"]],
    ["RecoveryRotationWaitsForNativeTransactionLock",["replaceFencedAsync","pg_locks","consumeAsync"]],
    ["RejectedAuthorizationIsChainedAndPublished",["CoroutineAuthorizationDecisionSink","recordAsync","security_event_outbox"]],
    ["MasterKeyRotationAtomicallyInvalidatesOnlyDerivedState",["beginAsync","CoroutinePostgresSessionRepository","rotateMasterKeyOffline"]],
    ["IdentityOrganizationMembershipAndExternalLinksRoundTrip",["readAuthorizationMembershipAsync","finishConnectionAsync","finishLoginAsync","readConnectionsAsync"]],
    ["PasswordKdfPolicySwitchPreservesAndUpgradesLogin",["confirmPasswordUpgradeAsync","readPasswordUpgradeStatusAsync","modern.verifyAsync","changed_at_ms"]],
    ["PersistentLocalTotpIsEncryptedAndConsumedOnce",["CoroutinePostgresLocalProofVerifier","EXPECT_NE(first.get(),second.get())","disableAsync","encrypted_seed"]],
    ["TotpCredentialRekeyIsAtomicVersionedAndDryRunnable",["rekeyTotpOffline","oldVerifier.verifyAsync","newVerifier.verifyAsync","last_accepted_step"]],
    ["InitialAdministratorBootstrapIsAtomicAuditedAndOneTime",["initializeAdministratorOffline","CoroutinePostgresLocalProofVerifier","canonicalOwner"]],
    ["OwnerProvisioningIsAtomicAuditedAndDeniedToMembers",["CoroutineAdminStore","mutateAsync","refusedLastOwner","finalRemoval","security_event_outbox"]],
    ["IdentityPlatformPersistenceAndOneTimeOAuthStateAreTransactional",["mutateApplicationAsync","mutateOAuthClientAsync","readProfileAsync","exchangeOAuthCodeAsync","rotateOAuthRefreshAsync","readDelegatedAccessAsync"]],
    ["PasskeyZeroCounterUseUpdatesLastUsedAt",["EVP_PKEY_Q_keygen","EVP_DigestSign","verifyPasskeyAssertionAsync","prove(kNow,0U)","last_used_at_ms"]]
  ];
  for(const [name,required] of nativeCases){
    const start=migration.indexOf("TEST_F(PostgresIntegrationTest, "+name+")");
    assert.ok(start>=0,name);
    const end=migration.indexOf("\nTEST",start+1);
    const section=migration.slice(start,end<0?undefined:end);
    assert.doesNotMatch(section,/pg::Postgres\w+\b/);
    for(const token of required) assert.ok(section.includes(token),name+": "+token);
  }
  const session=read("tests/storage/postgres_coroutine_repository_integration_test.cpp");
  assert.doesNotMatch(session,/import openproof.storage.postgres;|pg::(?:PoolConfig|ConnectionPool|Migrator|PostgresSessionRepository)\b/);
  assert.match(session,/pg::CoroutinePostgresSessionRepository peer\{/);
  assert.match(session,/INSERT INTO openproof.sessions/);
  assert.match(session,/run\(peer.use\(digestOf\(0x51\)/);
  assert.match(session,/run\(peer.revoke\(/);
  const cmake=read("tests/CMakeLists.txt");
  for(const target of ["openproof_postgres_domain_tests","openproof_postgres_network_tests","openproof_postgres_async_canonical_tests"]){
    const start=cmake.indexOf("target_link_libraries("+target);
    const end=cmake.indexOf(")\n",start);
    assert.ok(start>=0 && end>start,target);
    assert.doesNotMatch(cmake.slice(start,end),/openproof_storage_postgres/);
  }
  const canonical=read("tests/storage/postgres_async_canonical_test.cpp");
  assert.match(canonical,/IndependentNativeTransactionsShareOneTimeFederationState/);
  assert.match(canonical,/IndependentNativeAuthorizationAuditSharesChainAndRollsBack/);
  assert.match(canonical,/co_spawn\(io,peer.rotateOAuthRefreshAsync/);
  assert.doesNotMatch(canonical,/import openproof.storage.postgres;|pg::(?:PoolConfig|ConnectionPool|Postgres\w+Repository|Postgres\w+Store|PostgresAuthorizationDecisionSink)\b/);
  const verification=canonical.slice(canonical.indexOf("TEST(PostgresCanonicalCoroutineTest, VerificationReplacementAndCompensation"),
    canonical.indexOf("TEST(PostgresCanonicalCoroutineTest, NativeLocalCredentialsRejectStaleProofsAndTotpReplay)"));
  assert.match(verification,/co_spawn\(io,peer.replaceAsync/);
  assert.match(verification,/peer.verifyPhoneAsync/);
  assert.match(verification,/foreign.changeEmailAsync/);
  assert.match(verification,/SELECT attempts::text FROM openproof.account_verification_challenges/);
  assert.match(verification,/EXPECT_EQ\(generation\(\),renewedId\)/);
  assert.match(verification,/peer.changeEmailAsync\(localProvider,ownerId,acc::VerificationId\{orphanId\}/);
  assert.match(verification,/WHERE provider=\$1 AND verification_id IS NULL/);
  assert.match(verification,/untagged.error\(\).code\(\)==fnd::ErrorCode::AlreadyExists/);
});
test("liveness has no SQL dependency and readiness is bounded and fail-closed",()=>{
  const body=http.slice(http.indexOf("CoroutineHealthAdapter::handleAsync("));
  const ordered=["scrub(request);","method!=gateway::HttpMethod::Get","if (live) co_return response(200,true)",
    "if (!m_check) co_return response(503,false)","co_await m_check()","checked?response(200,true):response(503,false)"];
  let previous=-1;
  for(const term of ordered){
    const index=body.indexOf(term,previous+1);
    assert.ok(index>previous,term);
    previous=index;
  }
  const probe=store.slice(store.indexOf("CoroutinePostgresCanonicalFinalizer::healthCheckAsync("));
  assert.match(probe,/Clock::now\(\)\+m_impl->queryTimeout/);
  assert.match(probe,/co_await m_impl->pool.probeReadiness\(deadline\)/);
  const pool=read("src/storage/postgres/async_pool.cpp");
  const ready=pool.slice(pool.indexOf("AsyncConnectionPool::probeReadiness("),pool.indexOf("AsyncConnectionPool::acquireImpl("));
  assert.match(ready,/co_await acquireImpl\(deadline, &resetConfirmed\)/);
  assert.match(ready,/if \(resetConfirmed\)\s+co_return lease.connection\(\).reusable\(\) && std::chrono::steady_clock::now\(\) < deadline;/);
  assert.match(ready,/co_await lease.connection\(\).query\("SELECT 1", \{\}, remaining\)/);
  assert.match(ready,/rows.rows.front\(\).front\(\) == std::optional<std::string>\{"1"\}/);
  const acquire=pool.slice(pool.indexOf("AsyncConnectionPool::acquireImpl("));
  const reset=acquire.indexOf('"DISCARD ALL", {}, bounded(state->connectTimeout)');
  assert.ok(reset>=0);
  assert.ok(acquire.indexOf('reset.commandTag != "DISCARD ALL"',reset)>reset);
  assert.ok(acquire.indexOf('*resetConfirmed = true',reset)>reset);
  assert.match(acquire,/lease.m_connection.reset\(\);/);
  assert.doesNotMatch(cppExecutableText(probe),/PQexec|PQconnectdb|PQreset|wait_for\(/);
  assert.match(read("tests/operations/coroutine_health_test.cpp"),/ReadinessAwaitsDependencyAndLivenessNeverTouchesStorage/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/RealDatabaseNativeReadinessChecksActualPool/);
  assert.match(read(".github/workflows/ci.yml"),/openproof_native_health_tests/);
});

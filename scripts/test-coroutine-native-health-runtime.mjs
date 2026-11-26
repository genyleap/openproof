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
  assert.match(probe,/co_await m_impl->pool.acquire\(deadline\)/);
  assert.match(probe,/co_await lease.connection\(\).query\("SELECT 1",\{\},remaining\(deadline\)\)/);
  assert.match(probe,/rows.rows.front\(\).front\(\)!=std::optional<std::string>\{"1"\}/);
  assert.doesNotMatch(cppExecutableText(probe),/PQexec|PQconnectdb|PQreset|wait_for\(/);
  assert.match(read("tests/operations/coroutine_health_test.cpp"),/ReadinessAwaitsDependencyAndLivenessNeverTouchesStorage/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/RealDatabaseNativeReadinessChecksActualPool/);
  assert.match(read(".github/workflows/ci.yml"),/openproof_native_health_tests/);
});

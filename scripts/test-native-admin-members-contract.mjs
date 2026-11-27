import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
const root = path.resolve(import.meta.dirname, "..");
const read = p => fs.readFileSync(path.join(root,p), "utf8");
test("owner and active tenant authorization are in the same bounded native SQL snapshot", () => {
  const source = read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
  const body = source.slice(source.indexOf("CoroutinePostgresCanonicalFinalizer::readMembersAsync("),
    source.indexOf("\n}\n", source.indexOf("CoroutinePostgresCanonicalFinalizer::readMembersAsync(")));
  for (const term of ["a.identity_id=$1 AND a.organization_id=$2", "a.state=1 AND ai.status=0 AND o.state=0",
    "ar.organization_id=a.organization_id AND ar.identity_id=a.identity_id",
    "AND ar.role='owner'", "m.organization_id=$2", "i.organization_id=m.organization_id",
    "r.organization_id=m.organization_id", "LIMIT 4097", "ownerSeen",
    "co_await m_impl->pool.acquire(deadline)", "remaining(deadline)"])
    assert.ok(body.includes(term), term);
  assert.equal((body.match(/co_await lease\.connection\(\)\.query\(/g) ?? []).length, 1);
  assert.doesNotMatch(body, /PQexec|password_hash|encrypted_seed|DELETE FROM|INSERT INTO|UPDATE openproof/);
});
test("all local member routes are mandatory native and owner identity and IAL2 are rechecked", () => {
  const app = read("apps/opp/main.cpp");
  const http = read("src/authentication/http/coroutine_admin_read_http.cpp");
  assert.match(app, /nativeAdminReadFlag && \*nativeAdminReadFlag == "1"/);
  assert.match(app, /nativeAdminReadEnabled && \(!nativeAuthSessionEnabled \|\| !platform\.auth\(\)\.enabled\(\)\)/);
  assert.match(app, /const bool nativeAdminReadEnabled = platform\.auth\(\)\.enabled\(\)\s*\|\|/);
  assert.match(app, /platform\.auth\(\)\.enabled\(\) && nativeAdminReadFlag && \*nativeAdminReadFlag == "0"/);
  const routes=app.slice(app.indexOf('for (const auto* path : {"/admin/local-members"'),
    app.indexOf("nativePaths.emplace_back(path);",app.indexOf('for (const auto* path : {"/admin/local-members"')));
  for (const route of ["/admin/local-members","/admin/local-members/roles","/admin/local-members/suspend",
    "/admin/local-members/reinstate","/admin/local-members/remove","/admin/local-members/credentials/reset"])
    assert.ok(routes.includes('"'+route+'"'),route);
  assert.match(app,/store->mutateAsync\(std::move\(actor\),command\)/);
  assert.doesNotMatch(app.slice(app.indexOf("ExitCode runGatewayServer(")),/AdministrationHttpApi administrationApi|PostgresAdministrationRepository::create\(/);
  assert.match(http, /idp::AssuranceLevel::Ial2/);
  assert.match(http, /listing->actor != actor/);
  assert.match(http, /role\.value\(\) == "owner"/);
  assert.match(http, /m_fallback->nativeEnabledFor\(request\)/);
  assert.doesNotMatch(http, /m_fallback->handle\(/);
});
test("native mutation authorizes twice around bounded KDF and commits audit/outbox with domain changes", () => {
  const sql=read("src/storage/postgres/coroutine_admin_store.cpp");
  const http=read("src/authentication/http/coroutine_admin_read_http.cpp");
  const m=sql.slice(sql.indexOf("CoroutineAdminStore::mutateAsync("));
  const ordered=(text,terms)=>{
    let previous=-1;
    for(const term of terms) {
      const index=text.indexOf(term,previous+1);
      assert.ok(index>previous,term);
      previous=index;
    }
  };
  ordered(m,["lease.connection().query(ownerSql","authorized.rows.size()!=1U",
    "co_await m_impl->passwords->hashAsync",'execute("BEGIN ISOLATION LEVEL READ COMMITTED"',
    "pg_advisory_xact_lock(7299730475761673315)","FOR UPDATE OF o,i,m,r",
    "co_await appendRecords(",'execute("COMMIT"']);
  for (const term of ["i.organization_id=o.id","m.organization_id=o.id","r.role='owner'",
    "m.identity_id<>$2 AND m.state=1 AND i.status=0","FOR UPDATE OF m,i,r",
    "DELETE FROM openproof.membership_roles","UPDATE openproof.memberships SET state",
    "GREATEST(changed_at_ms+1,$3::bigint)","DELETE FROM openproof.recovery_codes",
    "UPDATE openproof.sessions SET state=1","ON CONFLICT DO NOTHING RETURNING id"])
    assert.ok(m.includes(term),term);
  ordered(sql,["pg_advisory_xact_lock(7299730475761673314)","ORDER BY sequence DESC LIMIT 1",
    "INSERT INTO openproof.audit_events","audit::computeAuditRecordHash","UPDATE openproof.audit_events",
    "INSERT INTO openproof.security_event_outbox"]);
  ordered(http,["co_await m_authenticate(","idp::AssuranceLevel::Ial2","co_await mutate(",
    "co_await m_mutation->mutate(","if (!result)","credentialResponse(201"]);
  assert.doesNotMatch(sql,/\bPQ(?:exec|execParams|connectdb|reset)\s*\(|m_passwordHasher\.hash\(/);
  const legacy=read("src/authentication/http/admin.cpp");
  assert.match(legacy,/ErrorCode::Unavailable/);
  assert.doesNotMatch(legacy,/m_sessions->|m_members->|m_memberships->|m_identities->/);
  const tests=read("tests/administration/http_test.cpp");
  for (const name of ["RetiredSynchronousAbiNeverInvokesStorage","DoesNotReturnGeneratedSecretsWhenOwnerCheckFails",
    "CredentialResetReturnsSecretsOnlyAfterSuccess","DispatchesEachExplicitLifecycleTransition"])
    assert.ok(tests.includes(name),name);
  const e2e=read("scripts/e2e-identity-platform.mjs");
  for (const term of ["native administration: role/lifecycle/reset","m.membership_state === \"removed\"",
    "a.event_hash<>decode(repeat('00',32),'hex')",'assert.equal(auditCount, "6")'])
    assert.ok(e2e.includes(term),term);
});
test("actual C++ and real PostgreSQL/HTTP regressions remain scheduled", () => {
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"), /RealDatabaseAdminListingRequiresActiveTenantOwner/);
  assert.match(read("tests/authentication/coroutine_admin_read_http_test.cpp"), /Ial2AndOwnerAreRequiredBeforeSerialization/);
  assert.match(read("scripts/run-disposable-postgres-canonical-tests.sh"), /0002_memberships.sql/);
  assert.match(read("scripts/e2e-identity-platform.mjs"), /edgeRequest\("\/admin\/local-members", \{ jar: dispatcherJar \}\), 403/);
  assert.equal((read(".github/workflows/ci.yml").match(/OPENPROOF_EXPERIMENTAL_NATIVE_ADMIN_MEMBERS: "1"/g) ?? []).length, 2);
});

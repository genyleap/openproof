import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
const root = path.resolve(import.meta.dirname, "..");
const read = p => fs.readFileSync(path.join(root,p), "utf8");
test("owner and active tenant authorization are in the same bounded native SQL snapshot", () => {
  const source = read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
  const body = source.slice(source.indexOf("CoroutinePostgresCanonicalFinalizer::readMembersAsync("),
    source.indexOf("CoroutinePostgresCanonicalFinalizer::authorizeConnectionTargetAsync("));
  for (const term of ["a.identity_id=$1 AND a.organization_id=$2", "a.state=1 AND ai.status=0 AND o.state=0",
    "ar.organization_id=a.organization_id AND ar.identity_id=a.identity_id",
    "AND ar.role='owner'", "m.organization_id=$2", "i.organization_id=m.organization_id",
    "r.organization_id=m.organization_id", "LIMIT 4097", "ownerSeen",
    "co_await m_impl->pool.acquire(deadline)", "remaining(deadline)"])
    assert.ok(body.includes(term), term);
  assert.equal((body.match(/co_await lease\.connection\(\)\.query\(/g) ?? []).length, 1);
  assert.doesNotMatch(body, /PQexec|password_hash|encrypted_seed|DELETE FROM|INSERT INTO|UPDATE openproof/);
});
test("only opted-in GET is native, owner identity and IAL2 are rechecked", () => {
  const app = read("apps/opp/main.cpp");
  const http = read("src/authentication/http/coroutine_admin_read_http.cpp");
  assert.match(app, /nativeAdminReadFlag && \*nativeAdminReadFlag == "1"/);
  assert.match(app, /nativeAdminReadEnabled && \(!nativeAuthSessionEnabled \|\| !platform\.auth\(\)\.enabled\(\)\)/);
  assert.match(app, /nativeMethods\.emplace_back\("\/admin\/local-members", gateway::HttpMethod::Get\)/);
  assert.match(http, /idp::AssuranceLevel::Ial2/);
  assert.match(http, /listing->actor != actor/);
  assert.match(http, /role\.value\(\) == "owner"/);
  assert.match(http, /m_fallback->nativeEnabledFor\(request\)/);
  assert.doesNotMatch(http, /m_fallback->handle\(/);
});
test("actual C++ and real PostgreSQL/HTTP regressions remain scheduled", () => {
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"), /RealDatabaseAdminListingRequiresActiveTenantOwner/);
  assert.match(read("tests/authentication/coroutine_admin_read_http_test.cpp"), /Ial2AndOwnerAreRequiredBeforeSerialization/);
  assert.match(read("scripts/run-disposable-postgres-canonical-tests.sh"), /0002_memberships.sql/);
  assert.match(read("scripts/e2e-identity-platform.mjs"), /edgeRequest\("\/admin\/local-members", \{ jar: dispatcherJar \}\), 403/);
  assert.equal((read(".github/workflows/ci.yml").match(/OPENPROOF_EXPERIMENTAL_NATIVE_ADMIN_MEMBERS: "1"/g) ?? []).length, 2);
});

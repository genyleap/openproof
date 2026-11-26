import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
const root = path.resolve(import.meta.dirname, "..");
const read = p => fs.readFileSync(path.join(root, p), "utf8");
const app = read("apps/opp/main.cpp");
const http = read("src/account/http/coroutine_session_http.cpp");
const sql = read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
test("TOTP status is separately gated, read-only and preserves compatibility", () => {
  assert.match(app, /nativeAccountTotpStatusFlag && \*nativeAccountTotpStatusFlag == "1"/);
  assert.match(app, /nativeAccountTotpStatusEnabled\s*&& \(!nativeAccountEnabled \|\| !platform\.account\(\)\.enabled\(\)\)/);
  assert.match(app, /nativeMethods\.emplace_back\("\/account\/totp", gateway::HttpMethod::Get\)/);
  assert.match(app, /reader->readTotpStatusAsync\(std::move\(owner\), providerId\)/);
  assert.match(http, /if \(totpStatusReadRoute\(request\)\) \{\s*return !request\.header\("authorization"\)\.has_value\(\)/);
});
test("status SQL is one tenant-scoped coroutine read and does not select secrets", () => {
  const start = sql.indexOf("CoroutinePostgresCanonicalFinalizer::readTotpStatusAsync(");
  const end = sql.indexOf("CoroutinePostgresCanonicalFinalizer::authorizeConnectionTargetAsync(", start);
  assert.ok(start >= 0 && end > start);
  const body = sql.slice(start, end);
  for (const term of ["co_await m_impl->pool.acquire(deadline)", "co_await lease.connection().query(", "i.organization_id=$2", "i.status=0 AND o.state=0", "e.provider=$3", "e.identity_id=i.id", "remaining(deadline)"])
    assert.ok(body.includes(term), term);
  assert.doesNotMatch(body, /p\.password_hash|t\.encrypted_seed|INSERT INTO|DELETE FROM|UPDATE openproof|PQexec/);
  assert.equal((body.match(/co_await lease\.connection\(\)\.query\(/g) ?? []).length, 1);
});
test("native status authorizes before lookup, validates owner and runs actual regressions", () => {
  const body = http.slice(http.indexOf("CoroutineAccountSessionAdapter::totpStatusRead("));
  const authenticate = body.indexOf("co_await m_authenticate(");
  const lookup = body.indexOf("co_await m_readTotpStatus(authenticated->identity())");
  const owner = body.indexOf("status->first != authenticated->identity()");
  const response = body.indexOf("co_return jsonResponse");
  assert.ok(authenticate >= 0 && authenticate < lookup && lookup < owner && owner < response);
  assert.match(read("tests/account/session_coroutine_http_test.cpp"), /TotpStatusIsOptInCookieOnlyAndOwnerBound/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"), /RealDatabaseTotpStatusOnlyReadsOwnedBooleans/);
  assert.equal((read(".github/workflows/ci.yml").match(/OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_TOTP_STATUS: "1"/g) ?? []).length, 2);
  assert.match(read("scripts/e2e-identity-platform.mjs"), /available: true, enabled: true, assurance: "ial2"/);
});

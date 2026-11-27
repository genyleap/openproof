#!/usr/bin/env node
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const read = file => fs.readFileSync(path.join(root, file), "utf8");

test("admin HTTP requires tenant-scoped owner role before enumeration", () => {
  const raw = read("src/authentication/http/coroutine_admin_read_http.cpp");
  const storage=read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
  const start=storage.indexOf("CoroutinePostgresCanonicalFinalizer::readMembersAsync(");
  const end=storage.indexOf("CoroutinePostgresCanonicalFinalizer::readAuthorizationContextAsync(",start);
  const listing=storage.slice(start,end);
  assert.match(listing,/a.identity_id=\$1 AND a.organization_id=\$2/);
  assert.match(listing,/a.state=1 AND ai.status=0 AND o.state=0/);
  assert.match(listing,/AND ar.role='owner'/);
  assert.match(listing,/ErrorCode::PermissionDenied/);
  assert.match(raw,/listing->actor != actor/);
  assert.match(raw,/role\.value\(\) == "owner"/);
  assert.ok(raw.indexOf("co_await m_authenticate(")<raw.indexOf("co_await m_read(actor)"));
});

test("admin HTTP tests cover denied and authorized member enumeration", () => {
  const tests = read("tests/administration/http_test.cpp");
  assert.match(tests, /TEST\(AdministrationHttpApiTest, MemberEnumerationRequiresActiveOwner\)/);
  assert.match(tests, /TEST\(AdministrationHttpApiTest, MemberEnumerationIsTenantScopedToActiveOwner\)/);
  for(const part of ['suspendedOwner', 'Role{"viewer"}',
                     'Role{"owner"}', 'OrganizationId{"different-org"}',
                     "EXPECT_EQ(denied.status(), 403)"]) {
    assert.ok(tests.includes(part), "Missing regression coverage for " + part);
  }
  assert.match(tests, /ASSERT_EQ\(permitted.status\(\), 200\)/);
});

test("pure admin domain has no transport I/O; gate scans native HTTP, SQL and retired ABI", () => {
  const domain = cppExecutableText(read("src/administration/administration.cpp"));
  assert.doesNotMatch(domain,
    /\b(?:PQexec|PQconnectdb|ldap_sasl_bind_s|curl_easy_perform|read|write|connect)\s*\(/);
  const gate = read("scripts/verify-coroutine-coverage.mjs");
  assert.match(gate, /\["HTTP administration API", "src\/authentication\/http\/admin\.cpp"\]/);
  assert.doesNotMatch(gate,
    /\["HTTP administration API", "src\/administration\/administration\.cpp"\]/);
  assert.match(gate,/src\/authentication\/http\/coroutine_admin_read_http\.cpp/);
  assert.match(gate,/src\/storage\/postgres\/coroutine_admin_store\.cpp/);
  assert.match(gate,/admin HTTP lifecycle has incomplete native authorization/);
});

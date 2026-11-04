#!/usr/bin/env node
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const read = file => fs.readFileSync(path.join(root, file), "utf8");

test("admin HTTP requires tenant-scoped owner role before enumeration", () => {
  const raw = read("src/authentication/http/admin.cpp");
  const start = raw.indexOf("AdministrationHttpApi::handle(");
  const end = raw.indexOf("AdministrationHttpApi::listLocalMembers(", start);
  assert.ok(start >= 0 && end > start);
  const handle = raw.slice(start, end);
  assert.match(handle, /m_memberships->find\s*\(\s*m_organization\s*,\s*actor\s*\)/);
  assert.match(handle, /membership->value\(\)\.hasRole\(organization::Role\{"owner"\}\)/);
  assert.match(handle, /ErrorCode::PermissionDenied/);
  assert.ok(handle.indexOf("m_memberships->find(m_organization, actor)")
            < handle.indexOf("return listLocalMembers(std::move(request))"));
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

test("pure admin domain has no transport I/O; real HTTP stays a migration blocker", () => {
  const domain = cppExecutableText(read("src/administration/administration.cpp"));
  assert.doesNotMatch(domain,
    /\b(?:PQexec|PQconnectdb|ldap_sasl_bind_s|curl_easy_perform|read|write|connect)\s*\(/);
  const gate = read("scripts/verify-coroutine-coverage.mjs");
  assert.match(gate, /\["HTTP administration API", "src\/authentication\/http\/admin\.cpp"\]/);
  assert.doesNotMatch(gate,
    /\["HTTP administration API", "src\/administration\/administration\.cpp"\]/);
});

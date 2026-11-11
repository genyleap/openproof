#!/usr/bin/env node
// Source contract for the native PostgreSQL session issuer's single-owner
// bearer transfer. The new C++ test verifies moved-from emptiness and
// buffer identity; compiled coverage is still required for acceptance.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
const root = path.resolve(import.meta.dirname, "..");
const read = file => fs.readFileSync(path.join(root, file), "utf8");
const service = read("src/storage/postgres/coroutine_session_service.cpp");
const header = read("src/storage/postgres/coroutine_session_service.hpp");
const domain = read("tests/storage/postgres_coroutine_repository_integration_test.cpp");

test("native session grant exposes explicit rvalue-only token transfer", () => {
  assert.match(header, /foundation::SecretString takeToken\(\) && noexcept/);
  assert.match(service, /CoroutineSessionGrant::takeToken\(\) && noexcept\s*\{\s*return std::move\(m_bearer\);\s*\}/);
  assert.match(domain, /TEST\(PostgresCoroutineDomainTest, NativeSessionGrantTransfersBearerWithoutCloning\)/);
  assert.match(domain, /std::move\(grant\).takeToken\(\)/);
});
test("both native issuers move the persisted bearer without cloning", () => {
  for (const [name, end] of [
    ["CoroutinePostgresSessionService::issueAsync(", "CoroutinePostgresSessionService::issueReplacingAsync("],
    ["CoroutinePostgresSessionService::issueReplacingAsync(", "CoroutinePostgresSessionService::issue("]
  ]) {
    const begin = service.indexOf(name);
    const finish = service.indexOf(end, begin + name.length);
    assert.ok(begin >= 0 && finish > begin, "missing native method " + name);
    const method = service.slice(begin, finish);
    assert.match(method, /std::move\(\*issued\).takeToken\(\)/);
    assert.doesNotMatch(method, /issued->token\(\).clone\(\)/);
    assert.match(method, /if \(!issued\) co_return foundation::fail\(issued.error\(\)\)/);
  }
});

#!/usr/bin/env node
// Source regression only: native SQL semantics also require disposable-DB C++ tests.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const read = name => fs.readFileSync(path.join(root, name), "utf8");
const native = read("src/storage/postgres/async_session.cpp");
const legacy = read("src/storage/postgres/postgres.cpp");

for (const [name, source, useStart, rotateStart, revokeStart] of [
  ["native", native, "AsyncSessionSql::useToken(", "AsyncSessionSql::rotateToken(", "AsyncSessionSql::revoke("],
  ["compatibility", legacy, "PostgresSessionRepository::use(", "PostgresSessionRepository::rotate(", "PostgresSessionRepository::revoke("],
]) {
  test(name + " session usage cannot roll back last-seen time", () => {
    const use = source.slice(source.indexOf(useStart), source.indexOf(rotateStart));
    assert.match(use, /GREATEST\(last_seen_at_ms,\$2::bigint\)/);
    assert.match(use, /\$2::bigint>=absolute_expires_at_ms/);
    assert.match(use, /\$2::bigint>=last_seen_at_ms\+idle_timeout_ms/);
  });
  test(name + " token rotation cannot roll back last-seen time", () => {
    const rotate = source.slice(source.indexOf(rotateStart), source.indexOf(revokeStart));
    assert.match(rotate, /GREATEST\(last_seen_at_ms,\$4::bigint\)/);
    assert.match(rotate, /\$4::bigint<absolute_expires_at_ms/);
    assert.match(rotate, /\$4::bigint<last_seen_at_ms\+idle_timeout_ms/);
  });
}

test("disposable C++ session regression covers stale use, stale rotate, and expiry", () => {
  const source = read("tests/storage/postgres_async_session_test.cpp");
  assert.match(source, /TEST\(PostgresAsyncSessionSqlTest, StaleConcurrentClocksNeverRegressLastSeen\)/);
  assert.match(source, /sql\.useToken\(\*conn, kDigestA, 1800, 3s\)/);
  assert.match(source, /sql\.useToken\(\*conn, kDigestA, 1300, 3s\)/);
  assert.match(source, /sql\.rotateToken\([\s\S]*?kDigestA, kDigestB, 1200, 3s\)/);
  assert.match(source, /sql\.useToken\(\*conn, kDigestB, 3500, 3s\)/);
});

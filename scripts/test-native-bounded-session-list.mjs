#!/usr/bin/env node
// Static contract only. Disposable PostgreSQL integration is independently required.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const read = file => fs.readFileSync(path.join(root, file), "utf8");
const sql = read("src/storage/postgres/async_session.cpp");
const header = read("src/storage/postgres/async_session.hpp");
const regression = read("tests/storage/postgres_async_session_test.cpp");
const list = sql.slice(
  sql.indexOf("AsyncSessionSql::list("),
  sql.indexOf("AsyncSessionSql::purgeExpired("));

test("the native session listing cap is declared once", () => {
  assert.match(header, /kMaximumListedSessions\s*=\s*256U/);
});
test("the query enforces the bound before receiving rows", () => {
  assert.match(list, /WHERE identity_id=\$1 ORDER BY last_seen_at_ms DESC, id ASC LIMIT/);
  assert.match(list, /std::to_string\(kMaximumListedSessions \+ 1U\)/);
  assert.ok(list.indexOf("LIMIT") < list.indexOf("co_await connection.query"));
});
test("overflow cannot produce a deceptively truncated account response", () => {
  assert.match(list, /rows\.rows\.size\(\) > kMaximumListedSessions/);
  assert.match(list, /throw std::length_error/);
  assert.ok(list.indexOf("throw std::length_error") < list.indexOf("co_return std::move(rows.rows)"));
});
test("the disposable C++ regression exercises exact bound and extra row", () => {
  assert.match(regression, /TEST\(PostgresAsyncSessionSqlTest, BoundedIdentityListingRejectsOverflow\)/);
  assert.match(regression, /addStressSessions\(1U, pg::AsyncSessionSql::kMaximumListedSessions - 1U\)/);
  assert.match(regression, /addStressSessions\(pg::AsyncSessionSql::kMaximumListedSessions,[\s\S]*?pg::AsyncSessionSql::kMaximumListedSessions\)/);
});
test("regression asserts stable sort, identity isolation and reusable connection", () => {
  assert.match(regression, /deterministic = first == second/);
  assert.match(regression, /fields\[1\] == "test-identity"/);
  assert.match(regression, /catch \(const std::length_error&\)/);
  assert.match(regression, /overflowRejected = overflowRejected && present\.has_value\(\) && conn->reusable\(\)/);
});

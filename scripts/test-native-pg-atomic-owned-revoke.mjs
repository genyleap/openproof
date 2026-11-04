#!/usr/bin/env node
// Source-level invariant only; disposable PostgreSQL C++ integration must
// execute separately to establish actual SQL semantics and concurrency.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const read = file => fs.readFileSync(path.join(root, file), "utf8");
const raw = read("src/storage/postgres/async_session.cpp");
const code = cppExecutableText(raw);
const start = code.indexOf("AsyncSessionSql::revokeOwned(");
const end = code.indexOf("AsyncSessionSql::revokeAll(", start);
const body = code.slice(start, end);

test("owned session revocation SQL fences its UPDATE and state lookup by identity", () => {
  assert.ok(start > 0 && end > start);
  assert.match(raw.slice(raw.indexOf("AsyncSessionSql::revokeOwned("),
                          raw.indexOf("AsyncSessionSql::revokeAll(", raw.indexOf("AsyncSessionSql::revokeOwned("))),
    /WHERE id=\$1 AND identity_id=\$2 AND state=0 RETURNING id/);
  assert.match(raw.slice(raw.indexOf("AsyncSessionSql::revokeOwned("),
                          raw.indexOf("AsyncSessionSql::revokeAll(", raw.indexOf("AsyncSessionSql::revokeOwned("))),
    /WHERE id=\$1 AND identity_id=\$2"/);
  assert.match(body, /connection\.query\(update/);
  assert.match(body, /connection\.query\(\s*query,/);
  assert.match(body, /co_return RevokeStatus::NotFound/);
  assert.match(body, /co_return RevokeStatus::AlreadyRevoked/);
  assert.match(body, /co_return RevokeStatus::Expired/);
  assert.match(body, /expiresAt - std::chrono::steady_clock::now\(\)/);
  assert.doesNotMatch(body, /co_await\s+connection\.query\(\s*"SELECT/);
});

test("coroutine repository exposes atomic owner-scoped operation, never checks then revokes", () => {
  const repository = read("src/storage/postgres/coroutine_session_repository.cpp");
  const begin = repository.indexOf("CoroutinePostgresSessionRepository::revokeOwned(");
  const finish = repository.indexOf("CoroutinePostgresSessionRepository::revokeAll(", begin);
  assert.ok(begin > 0 && finish > begin);
  const implementation = repository.slice(begin, finish);
  assert.match(implementation, /co_await m_impl->sql\.revokeOwned\(/);
  assert.doesNotMatch(implementation, /co_await\s+(?:find|revoke)\(/);
  assert.match(implementation, /ErrorCode::NotFound/);
  assert.match(implementation, /ErrorCode::Unavailable/);
  const service = read("src/storage/postgres/coroutine_session_service.cpp");
  assert.match(service, /return m_repository->revokeOwned\(/);
  assert.doesNotMatch(service, /revokeOwnedSession\(/);
});

test("disposable SQL test includes owner change, wrong owner, idempotence, expiry", () => {
  const testSource = read("tests/storage/postgres_async_session_test.cpp");
  assert.match(testSource, /TEST\(PostgresAsyncSessionSqlTest, OwnedRevokeNeverMutatesOrDisclosesForeignSession\)/);
  assert.match(testSource, /auto wrongOwner = co_await sql\.revokeOwned\(/);
  assert.match(testSource, /SET identity_id='another-identity'/);
  assert.match(testSource, /auto formerOwner = co_await sql\.revokeOwned\(/);
  assert.match(testSource, /auto repeat = co_await sql\.revokeOwned\(/);
  assert.match(testSource, /auto expired = co_await sql\.revokeOwned\(/);
  assert.match(testSource, /OPENPROOF_TEST_POSTGRES/);
});

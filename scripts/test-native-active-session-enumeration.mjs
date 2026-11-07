#!/usr/bin/env node
// Source-contract test. Real SQL behavior requires disposable PostgreSQL.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const read = name => fs.readFileSync(path.join(root,name), "utf8");
const sql = read("src/storage/postgres/async_session.cpp");
const header = read("src/storage/postgres/async_session.hpp");
const repository = read("src/storage/postgres/coroutine_session_repository.cpp");
const service = read("src/storage/postgres/coroutine_session_service.cpp");
const regression = read("tests/storage/postgres_async_session_test.cpp");
const from = (source,begin,end) => {
  const start = source.indexOf(begin);
  const stop = source.indexOf(end,start+begin.length);
  assert.ok(start >= 0 && stop > start, "missing method boundary: "+begin);
  return source.slice(start,stop);
};

test("all-state list retains complete historical semantics and the cardinality guard",()=>{
  const list=from(sql,"AsyncSessionSql::list(","AsyncSessionSql::listActive(");
  assert.match(list,/WHERE identity_id=\$1 ORDER BY last_seen_at_ms DESC, id ASC LIMIT/);
  assert.match(list,/kMaximumListedSessions \+ 1U/);
  assert.match(list,/throw std::length_error/);
  assert.doesNotMatch(list,/\bstate=0\b/);
});

test("active-only listing filters historical rows in SQL before bounding result",()=>{
  assert.match(header,/AsyncConnection& connection, std::string identityId,\s*std::int64_t nowMilliseconds/);
  const body=from(sql,"AsyncSessionSql::listActive(","AsyncSessionSql::purgeExpired(");
  for(const expression of [
    /WHERE identity_id=\$1 AND state=0/,
    /absolute_expires_at_ms>\$2::bigint/,
    /last_seen_at_ms\+idle_timeout_ms>\$2::bigint/,
    /ORDER BY last_seen_at_ms DESC, id ASC LIMIT/,
    /kMaximumListedSessions \+ 1U/,
    /rows\.rows\.size\(\) > kMaximumListedSessions/,
    /throw std::length_error/,
    /rows\.rows\.size/,
  ]) assert.match(body,expression);
  const query = body.slice(body.indexOf("const std::string sql ="),
    body.indexOf("auto rows ="));
  assert.ok(query.indexOf("AND state=0") < query.indexOf("LIMIT"));
  assert.ok(query.indexOf("LIMIT") > query.indexOf("WHERE identity_id=$1"));
  assert.ok(body.indexOf("co_await connection.query") > body.indexOf("auto rows ="));
  assert.match(body,/\{std::move\(identityId\), std::to_string\(nowMilliseconds\)\}/);
});

test("repository applies scoped active-only SQL with a shared deadline and defense-in-depth",()=>{
  const body=from(repository,"CoroutinePostgresSessionRepository::listActive(","CoroutinePostgresSessionRepository::purgeExpired(");
  assert.match(body,/pool\.acquire\(deadline\)/);
  assert.match(body,/m_impl->sql\.listActive\(/);
  assert.match(body,/now\.time_since_epoch\(\)\.count\(\), remaining\(deadline\)/);
  assert.match(body,/restored->identity\(\) != identity/);
  assert.match(body,/restored->state\(\) != session::SessionState::Active/);
  assert.match(body,/restored->isExpiredAt\(now\)/);
});

test("account-facing native session service no longer pre-limits historical sessions",()=>{
  const body=from(service,"listActiveSessions(","CoroutineSessionGrant::CoroutineSessionGrant(");
  assert.match(body,/repo\.listActive\(std::move\(identity\), now\)/);
  assert.doesNotMatch(body,/repo\.list\s*\(/);
  assert.match(body,/value\.state\(\) != session::SessionState::Active/);
  assert.match(body,/return left\.id\(\)\.value\(\) < right\.id\(\)\.value\(\)/);
});

test("disposable PostgreSQL test exercises historic 600 rows plus 256/257 active boundary",()=>{
  assert.match(regression,/HistoricalSessionsCannotEvictActiveListing/);
  assert.match(regression,/generate_series\(1,300\)/);
  assert.match(regression,/sql\.listActive\(\*conn, "test-identity", 1500, 3s\)/);
  assert.match(regression,/addActive\(1U, pg::AsyncSessionSql::kMaximumListedSessions - 1U\)/);
  assert.match(regression,/catch \(const std::length_error&\)/);
  assert.match(regression,/sql\.listActive\(\*conn, "test-identity", 2000, 3s\)/);
});

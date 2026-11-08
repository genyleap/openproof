#!/usr/bin/env node
// SQL shape guard. Plan quality must ultimately be EXPLAIN ANALYZE'd on a
// disposable PostgreSQL instance with representative active/revoked history.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname,"..");
const load = x=>fs.readFileSync(path.join(root,x),"utf8");
const migration = load("migrations/0020_active_session_recency.sql")
  .replace(/--[^\n]*\n/g,"\n").trim();
const native=load("src/storage/postgres/async_session.cpp");
const list=native.slice(native.indexOf("AsyncSessionSql::listActive("),
  native.indexOf("AsyncSessionSql::purgeExpired("));

test("migration matches the native active-session ORDER BY and filters revoked sessions",()=>{
  assert.match(migration,
    /CREATE INDEX IF NOT EXISTS sessions_active_identity_recency\s+ON openproof\.sessions\s*\(\s*identity_id,\s*last_seen_at_ms DESC,\s*id ASC\s*\)\s*WHERE state = 0;/);
  assert.match(list,/WHERE identity_id=\$1 AND state=0/);
  assert.match(list,/ORDER BY last_seen_at_ms DESC, id ASC LIMIT/);
  assert.match(list,/kMaximumListedSessions \+ 1U/);
  assert.match(list,/rows\.rows\.size\(\) > kMaximumListedSessions/);
});

test("migration remains additive, transaction safe and protocol neutral",()=>{
  assert.doesNotMatch(migration,/\bDROP\b|\bALTER TABLE\b|\bCONCURRENTLY\b|\bTRUNCATE\b|\bDELETE\b|\bUPDATE\b|\bINSERT\b/i);
  assert.doesNotMatch(migration,/\bgenyleap\b|\bgenycaster\b/i);
  assert.match(load("migrations/0001_identity_auth_gateway.sql"),
    /CREATE INDEX IF NOT EXISTS sessions_by_identity_state/);
});

test("revoked and expired session history cannot replace live bounded rows",()=>{
  assert.match(list,/absolute_expires_at_ms>\$2::bigint/);
  assert.match(list,/last_seen_at_ms\+idle_timeout_ms>\$2::bigint/);
  assert.match(list,/length_error/);
});

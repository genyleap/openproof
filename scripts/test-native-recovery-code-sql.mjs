#!/usr/bin/env node
// Structural guard, not a substitute for disposable PostgreSQL integration.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const raw = fs.readFileSync(path.join(root,
  "src/storage/postgres/async_recovery_code.cpp"),"utf8");
const source = cppExecutableText(raw);
const header = fs.readFileSync(path.join(root,
  "src/storage/postgres/async_recovery_code.hpp"),"utf8");
const cppTest = fs.readFileSync(path.join(root,
  "tests/storage/postgres_async_recovery_code_test.cpp"),"utf8");
const body = (begin,end, from=raw) => {
  const first=from.indexOf(begin), last=from.indexOf(end,first+begin.length);
  assert.ok(first>0 && last>first,"missing native SQL method");
  return from.slice(first,last);
};

test("native recovery adapter bounds all inputs and never uses blocking libpq",()=>{
  assert.match(header,/kMaximumRecoveryCodes = 64U/);
  assert.match(source,/digestsHex\.size\(\) > kMaximumRecoveryCodes/);
  assert.match(source,/validIdentity\(identityId\)/);
  assert.match(source,/digest\.size\(\) == 64U|text\.size\(\) == 64U/);
  assert.doesNotMatch(source,/\b(?:PQexec|PQexecParams|PQconnectdb|PQreset|io\.run)\s*\(/);
});

test("recovery-code replacement validates/normalizes before changing any rows",()=>{
  const replace=body("AsyncRecoveryCodeSql::replace(","AsyncRecoveryCodeSql::consume(");
  assert.match(replace,/canonicalDigest\(std::move\(digest\)\)/);
  assert.match(replace,/std::sort\(digestsHex\.begin\(\), digestsHex\.end\(\)\)/);
  assert.match(replace,/std::adjacent_find/);
  assert.match(replace,/throw std::invalid_argument/);
  assert.ok(replace.indexOf("std::adjacent_find") < replace.indexOf('"BEGIN"'));
  assert.match(replace,/const Deadline deadline = Clock::now\(\) \+ timeout/);
});

test("recovery-code replacement commits DELETE and one parameterized batch INSERT atomically",()=>{
  const replace=body("AsyncRecoveryCodeSql::replace(","AsyncRecoveryCodeSql::consume(");
  for(const q of [
    /co_await conn\.query\(\s*"BEGIN", \{\}, remainingBudget\(deadline\)\)/,
    /SELECT pg_advisory_xact_lock\(hashtextextended\(\$1, 0\)\)/,
    /co_await conn\.query\(\s*"DELETE FROM "/,
    /parameters\.emplace_back\(digest\)/,
    /sql \+= "\(\$1,decode\(\$" \+ std::to_string\(index\)/,
    /std::move\(sql\), std::move\(parameters\), remainingBudget\(deadline\)/,
    /co_await conn\.query\(\s*"COMMIT", \{\}, remainingBudget\(deadline\)\)/,
  ]) assert.match(replace,q);
  assert.equal((replace.match(/\bco_await\b/g)||[]).length,5);
  assert.ok(replace.indexOf("pg_advisory_xact_lock") < replace.indexOf('"DELETE FROM "'));
  assert.match(replace, /\{identityId\}, remainingBudget\(deadline\)/);
  assert.doesNotMatch(replace,/INSERT[^;]+(?:\+\s*identityId|\+\s*digest)/);
});

test("single-use recovery digest is atomically consumed with identity fence",()=>{
  const consume=body("AsyncRecoveryCodeSql::consume(","AsyncRecoveryCodeSql::remaining(");
  assert.match(consume,/DELETE FROM/);
  assert.match(consume,/WHERE identity_id=\$1 AND code_digest=decode\(\$2,'hex'\)/);
  assert.match(consume,/RETURNING identity_id/);
  assert.match(consume,/co_await conn\.query\(/);
  assert.match(consume,/rows\.rows\.size\(\) > 1U/);
  assert.match(consume,/co_return !rows\.rows\.empty\(\)/);
  assert.doesNotMatch(consume,/\bSELECT\b/);
});

test("count validates exactly one bounded integer without identity disclosure",()=>{
  const count=raw.slice(raw.indexOf("std::size_t countRows("),
    raw.indexOf("AsyncRecoveryCodeSql::replace("));
  assert.match(count,/rows\.rows\.size\(\) != 1U/);
  assert.match(count,/std::from_chars/);
  assert.match(count,/number > AsyncRecoveryCodeSql::kMaximumRecoveryCodes/);
  const remaining=raw.slice(raw.indexOf("AsyncRecoveryCodeSql::remaining("));
  assert.match(remaining,/SELECT count\(\*\)::text/);
  assert.match(remaining,/WHERE identity_id=\$1/);
});

test("disposable PostgreSQL regressions cover replay, tenant scope, bound and failed transactions",()=>{
  for(const item of [
    /AtomicReplacementAndOneTimeUseOnDisposablePg/,
    /SixtyFourCodeBoundAndDuplicatesFailBeforeBegin/,
    /FailedInsertPoisonsLeaseInsteadOfCommitting/,
    /replayDenied = !replay/,
    /tenantDenied = !\(co_await sql\.consume/,
    /const char\* dsn = std::getenv\("OPENPROOF_TEST_POSTGRES"\)/,
    /GTEST_SKIP\(\)/,
    /poisonedBeforeRollback = !conn->reusable\(\)/,
  ]) assert.match(cppTest,item);
});

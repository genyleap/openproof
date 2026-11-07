#!/usr/bin/env node
// Static gate complements C++/disposable DB; no claim of database execution.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const rawSource = fs.readFileSync(path.join(
  root, "src/storage/postgres/coroutine_auth_transaction_store.cpp"), "utf8");
const source = cppExecutableText(rawSource);
const rawSql = fs.readFileSync(path.join(
  root, "src/storage/postgres/async_auth_transaction.cpp"), "utf8");
const sql = cppExecutableText(rawSql);
const methods = [
  ["begin", "beginAsync(", "consumeAsync("],
  ["consume", "consumeAsync(", "CoroutinePostgresAuthenticationTransactionStore::begin("]
];

test("transaction repository carries one wall-clock budget to each operation", () => {
  assert.match(source, /using Clock = std::chrono::steady_clock/);
  const helper = source.slice(source.indexOf("remaining(Deadline deadline)"),
    source.indexOf("using Snapshot"));
  assert.match(helper, /deadline - Clock::now\(\)/);
  assert.match(helper, /budget <= std::chrono::milliseconds::zero\(\)/);
  assert.match(helper, /throw std::runtime_error/);
});

for (const [name, suffix, next] of methods) {
  test("native " + name + " uses the same deadline for pool and SQL", () => {
    const start = source.indexOf("CoroutinePostgresAuthenticationTransactionStore::" + suffix);
    assert.ok(start > 0);
    const end = source.indexOf(next, start + suffix.length);
    assert.ok(end > start);
    const fragment = source.slice(start, end);
    assert.match(fragment, /const Deadline deadline = Clock::now\(\) \+ m_impl->queryTimeout/);
    assert.match(fragment, /pool\.acquire\(deadline\)/);
    assert.match(fragment, /remaining\(deadline\)/);
    assert.ok(fragment.indexOf("pool.acquire(deadline)") <
              fragment.indexOf("remaining(deadline)"));
    assert.doesNotMatch(fragment, /pool\.acquire\(\)/);
  });
}

test("transaction SQL budgets all BEGIN/metadata/COMMIT stages rather than resetting", () => {
  for (const name of ["begin", "consume"]) {
    const start = sql.indexOf("AsyncAuthenticationTransactionSql::" + name + "(");
    const end = sql.indexOf("AsyncAuthenticationTransactionSql::",
      start + ("AsyncAuthenticationTransactionSql::" + name).length);
    const method = sql.slice(start, end > start ? end : undefined);
    assert.match(method, /const auto deadline = Clock::now\(\) \+ timeout/);
    assert.match(method, /connection\.query\([\s\S]*?remaining\(deadline\)/);
    assert.match(rawSql, /"BEGIN"/);
    assert.match(rawSql, /"COMMIT"/);
  }
});

test("native store never falls back to blocking PostgreSQL through its sync SPI", () => {
  assert.match(source, /CoroutinePostgresAuthenticationTransactionStore::begin\(/);
  assert.match(rawSource, /Native PostgreSQL transaction store requires coroutine authentication/);
  assert.doesNotMatch(source, /\bPQexec\s*\(|\bPQexecParams\s*\(|\bio\.run\s*\(/);
});

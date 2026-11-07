#!/usr/bin/env node
// Contract tests cannot substitute for native C++/PostgreSQL integration.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const raw = fs.readFileSync(path.join(root,
  "src/storage/postgres/coroutine_session_repository.cpp"), "utf8");
const code = cppExecutableText(raw);
const methods = [
  "use", "find", "replace", "rotate", "revoke", "revokeOwned",
  "revokeAll", "list", "purgeExpired", "size",
];

test("native session repository enforces an operation-wide steady-clock deadline", () => {
  assert.match(code, /using Clock = std::chrono::steady_clock/);
  const helper = code.slice(
    code.indexOf("std::chrono::milliseconds remaining("),
    code.indexOf("captureSessionRecord("));
  assert.match(helper, /deadline - Clock::now\(\)/);
  assert.match(helper, /if \(budget <= std::chrono::milliseconds::zero\(\)\)/);
  assert.match(helper, /throw std::runtime_error/);
  assert.match(helper, /return budget/);
});

test("new session insertion also shares the pool and SQL budget", () => {
  const helper = code.slice(
    code.indexOf("insertCapturedSession("),
    code.indexOf("class CoroutinePostgresSessionRepository::Impl"));
  assert.match(helper, /const Deadline deadline = Clock::now\(\) \+ timeout/);
  assert.match(helper, /pool\.acquire\(deadline\)/);
  assert.match(helper, /sql\.add\([\s\S]*?remaining\(deadline\)\)/);
  assert.ok(helper.indexOf("pool.acquire(deadline)") <
            helper.indexOf("remaining(deadline)"));
});

for (const method of methods) {
  test(method + " preserves one deadline through admission and SQL execution", () => {
    const start = code.indexOf("CoroutinePostgresSessionRepository::" + method + "(");
    assert.ok(start >= 0);
    const next = code.indexOf("CoroutinePostgresSessionRepository::", start + 30);
    const body = code.slice(start, next === -1 ? undefined : next);
    assert.match(body, /const Deadline deadline = Clock::now\(\) \+ m_impl->queryTimeout/);
    assert.match(body, /co_await m_impl->pool\.acquire\(deadline\)/);
    assert.match(body, /remaining\(deadline\)/);
    assert.ok(body.indexOf("pool.acquire(deadline)") < body.indexOf("remaining(deadline)"));
    assert.doesNotMatch(body, /m_impl->pool\.acquire\(\)/);
    assert.doesNotMatch(body, /, m_impl->queryTimeout\)/);
  });
}

test("canonical finalization follows the same deadline model", () => {
  const canon = fs.readFileSync(path.join(root,
    "src/storage/postgres/coroutine_canonical_finalizer.cpp"), "utf8");
  assert.match(canon, /pool\.acquire\(deadline\)/);
  assert.match(canon, /remaining\(deadline\)/);
});

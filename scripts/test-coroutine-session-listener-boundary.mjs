#!/usr/bin/env node
// Source-only guard. Real loopback C++ tests remain mandatory for acceptance.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const source = fs.readFileSync(
  path.join(root, "src/storage/postgres/coroutine_session_listener.cpp"), "utf8");
const tests = fs.readFileSync(
  path.join(root, "tests/storage/postgres_coroutine_network_test.cpp"), "utf8");

test("session listener rejects disabled native fallback at composition", () => {
  const body = source.slice(source.indexOf("CoroutineSessionListenerStack::CoroutineSessionListenerStack"));
  assert.match(body, /if\s*\(\s*!allowCompatibilityFallback\s*&&\s*!fallback\.nativeEnabled\(\)\s*\)/);
  assert.match(body, /throw\s+std::invalid_argument/);
  assert.match(tests, /TEST\(PostgresCoroutineNetworkTest, DisabledFallbackIsRejectedAtComposition\)/);
});

test("session listener rechecks dynamic capability and never invokes sync fallback", () => {
  const start = source.indexOf("[&fallback](gateway::HttpRequest request)");
  const end = source.indexOf("m_network(m_application, fallback", start);
  assert.ok(start >= 0 && end > start);
  const coroutine = source.slice(start, end);
  assert.match(coroutine, /if\s*\(\s*!fallback\.nativeEnabledFor\(request\)\s*\)/);
  assert.match(coroutine, /foundation::ErrorCode::Unavailable/);
  assert.match(coroutine, /co_return\s+co_await\s+fallback\.handleAsync\s*\(/);
  assert.doesNotMatch(coroutine, /\bfallback\.handle\s*\(/);
  assert.match(tests, /TEST\(PostgresCoroutineNetworkTest, DisabledFallbackFailsClosedOnLiveSocket\)/);
  assert.match(tests, /TEST\(PostgresCoroutineNetworkTest, DisabledRequestSpecificFallbackFailsClosed\)/);
  assert.match(tests, /denySelectedRoute\.store\(true/);
  assert.match(tests, /TEST\(PostgresCoroutineNetworkTest, ExplicitHybridCompatibilityRoutesSafely\)/);
  assert.match(tests, /TEST\(PostgresCoroutineNetworkTest, ExplicitCompatibilityCanComposePartialFallback\)/);
  assert.match(source, /m_allowCompatibilityFallback\s*&&\s*!CoroutineSessionHttpHandler::isSessionRoute\(request\.path\(\)\)/);
  assert.match(source, /return\s+m_fallback->handle\(std::move\(request\)\)/);
  assert.match(source, /CoroutineSessionHttpHandler::isSessionRoute\(request\.path\(\)\)/);
  assert.match(tests, /EXPECT_EQ\(f\.fallback\.blockingCalls\.load\(\), 0\)/);
});

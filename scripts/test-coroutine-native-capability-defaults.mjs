#!/usr/bin/env node
// Source-only native dispatch invariants; no substitute for C++ wire tests.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");
const gateway = read("src/gateway/http.cppm");
const listener = read("src/storage/postgres/coroutine_session_listener.hpp");
const web3 = read("src/authentication/http/web3.cppm");
const gatewayTests = read("tests/gateway/http_integration_test.cpp");

test("native gateway capability defaults to fail closed", () => {
  assert.match(gateway, /virtual\s+bool\s+nativeEnabled\s*\(\)\s*const\s*noexcept\s*\{\s*return\s+false;\s*\}/);
  assert.match(gatewayTests, /class\s+UnconfiguredCoroutineHandler\s+final/);
  assert.match(gatewayTests, /TEST\(BeastHttpIntegrationTest, NativeDispatchRequiresExplicitOptIn\)/);
  assert.match(gatewayTests, /EXPECT_FALSE\(handler\.nativeEnabled\(\)\)/);
  assert.match(gatewayTests, /EXPECT_EQ\(handler\.asynchronousCalls\.load\(std::memory_order_relaxed\), 0\)/);
});

test("known native handlers explicitly opt in; conditional Web3 remains gated", () => {
  assert.match(gateway, /class CoroutineGatewayAdapter[\s\S]*?nativeEnabled\(\) const noexcept override \{ return true; \}/);
  assert.match(listener, /class CoroutineSessionListenerAdapter[\s\S]*?nativeEnabled\(\) const noexcept override \{ return true; \}/);
  assert.match(gateway, /return m_fallback->nativeEnabled\(\);/);
  assert.match(web3, /return m_asyncSessions != nullptr\s*&&\s*m_authentication->nativeCanonicalCompletionEnabled\(\);/);
});

test("loopback-native test implementations explicitly opt in", () => {
  for (const name of ["CoroutineWaitingHandler", "CoroutineProxyHandler", "CoroutineThrowingHandler"]) {
    const start = gatewayTests.indexOf("class " + name + " final");
    assert.ok(start >= 0);
    const tail = gatewayTests.slice(start, gatewayTests.indexOf("\n};", start));
    assert.match(tail, /nativeEnabled\(\) const noexcept override \{ return true; \}/);
  }
});

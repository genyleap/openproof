#!/usr/bin/env node
// Source-contract guard; real loopback C++ tests are independent and mandatory.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const read = file => fs.readFileSync(path.join(root,file), "utf8");
const rawSource = read("src/storage/postgres/coroutine_session_listener.cpp");
const source = cppExecutableText(rawSource);
const header = read("src/storage/postgres/coroutine_session_listener.hpp");
const tests = read("tests/storage/postgres_coroutine_network_test.cpp");

test("disabled global native capability requires explicit partial-native opt-in", () => {
  const body = source.slice(source.indexOf("CoroutineSessionListenerStack::CoroutineSessionListenerStack"));
  assert.match(body, /if\s*\(\s*!allowPartialNativeFallback\s*&&\s*!fallback\.nativeEnabled\(\)\s*\)/);
  assert.match(body, /throw\s+std::invalid_argument/);
  assert.match(tests, /TEST\(PostgresCoroutineNetworkTest, DisabledFallbackIsRejectedAtComposition\)/);
});

test("listener forces every request through an awaitable and rejects all sync entry", () => {
  const native = source.slice(
    source.indexOf("CoroutineSessionListenerAdapter::nativeEnabledFor("),
    source.indexOf("CoroutineSessionListenerAdapter::handle("));
  const sync = source.slice(
    source.indexOf("CoroutineSessionListenerAdapter::handle("),
    source.indexOf("CoroutineSessionListenerAdapter::handleAsync("));
  assert.match(native, /return true;/);
  assert.doesNotMatch(native, /m_fallback|allowCompatibilityFallback/);
  assert.match(sync, /foundation::ErrorCode::Unavailable/);
  assert.match(rawSource, /rejected\.setHeader\("cache-control", "no-store"\)/);
  assert.doesNotMatch(source, /m_fallback->handle\s*\(|\bfallback\.handle\s*\(/);
  assert.doesNotMatch(header, /allowCompatibilityFallback|m_allowCompatibilityFallback/);
  assert.match(source, /m_network\(m_application\)/);
});

test("partial-native fallback rechecks capability per request and fails closed", () => {
  const start = source.indexOf("[&fallback](gateway::HttpRequest request)");
  const end = source.indexOf("m_network(m_application)", start);
  assert.ok(start >= 0 && end > start);
  const coroutine = source.slice(start,end);
  assert.match(coroutine, /if\s*\(\s*!fallback\.nativeEnabledFor\(request\)\s*\)/);
  assert.match(coroutine, /foundation::ErrorCode::Unavailable/);
  assert.match(coroutine, /co_return\s+co_await\s+fallback\.handleAsync\s*\(/);
  assert.doesNotMatch(coroutine, /\bfallback\.handle\s*\(/);
  for (const name of [
    "DisabledFallbackFailsClosedOnLiveSocket",
    "DisabledRequestSpecificFallbackFailsClosed",
    "ExplicitPartialNativeRefusesBlockingCompatibility",
    "ExplicitPartialNativeCanComposeDisabledGlobalFallback",
    "PartialNativeRunsSelectedRouteWithGlobalNativeDisabled",
    "RevokedCapabilityBetweenChecksFailsClosed",
  ]) assert.ok(tests.includes("TEST(PostgresCoroutineNetworkTest, " + name + ")"));
  assert.match(tests, /revokeCapabilityAfterFirstCheck\.exchange\(/);
  assert.match(tests, /if\s*\(!nativeEnabledFor\(request\)\)/);
  assert.match(tests, /TEST\(PostgresCoroutineNetworkTest, SynchronousCompatibilityEntryFailsClosed\)/);
  assert.match(tests, /f\.stack\.handler\(\)\.handle\(std::move\(unsupported\)\.value\(\)\)/);
  assert.match(tests, /EXPECT_EQ\(f\.fallback\.blockingCalls\.load\(\), 0\)/);
  assert.doesNotMatch(tests, /EXPECT_EQ\(f\.fallback\.blockingCalls\.load\(\), 1\)/);
});

test("native session mutations remain protected when other routes are disabled", () => {
  const routes = read("src/storage/postgres/coroutine_session_http.cpp");
  const predicate = routes.slice(
    routes.indexOf("bool CoroutineSessionHttpHandler::isSessionRoute("),
    routes.indexOf("CoroutineSessionHttpHandler::handleAsync("));
  for (const pathValue of ["/auth/session/rotate", "/auth/logout", "/auth/logout-all"]) {
    assert.ok(predicate.includes('"' + pathValue + '"'));
  }
  assert.match(tests, /for \(const std::string_view route : \{"\/auth\/logout", "\/auth\/logout-all"\}\)/);
});

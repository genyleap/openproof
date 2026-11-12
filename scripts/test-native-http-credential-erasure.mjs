#!/usr/bin/env node
// Source-contract tests for request-owned credentials on rejection paths.
// C++/HTTP runtime tests are required separately for release acceptance.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const read = p => fs.readFileSync(path.join(root, p), "utf8");
const accountRaw = read("src/account/http/coroutine_session_http.cpp");
const nativeSession = cppExecutableText(read("src/storage/postgres/coroutine_session_http.cpp"));
const legacyAccountRaw = read("src/account/http/http.cpp");
const account = cppExecutableText(accountRaw);
const recovery = cppExecutableText(read("src/authentication/http/coroutine_recovery_code_http.cpp"));

const method = (src, first, last) => {
  const start = src.indexOf(first);
  const end = last ? src.indexOf(last, start + first.length) : src.length;
  assert.ok(start >= 0 && end > start, "Missing " + first);
  return src.slice(start, end);
};

test("native account and recovery handlers securely wipe both request header classes", () => {
  for (const source of [account, recovery]) {
    const guard = method(source, "class SensitiveSessionHeadersGuard final",
      "[[nodiscard]] bool");
    assert.match(guard, /~SensitiveSessionHeadersGuard\(\)/);
    assert.match(guard, /m_request\.wipeAuthorizationHeader\(\)/);
    assert.match(guard, /m_request\.wipeCookieHeader\(\)/);
    assert.match(guard, /SensitiveSessionHeadersGuard\(const SensitiveSessionHeadersGuard&\) = delete/);
  }
  const methods = [
    [account, "CoroutineAccountSessionAdapter::handleAsync(", "CoroutineAccountSessionAdapter::sessionList("],
    [account, "CoroutineAccountSessionAdapter::sessionList(", "CoroutineAccountSessionAdapter::sessionRevoke("],
    [account, "CoroutineAccountSessionAdapter::sessionRevoke(", null],
    [recovery, "CoroutineRecoveryCodeHttpAdapter::handle(", "CoroutineRecoveryCodeHttpAdapter::handleAsync("],
    [recovery, "CoroutineRecoveryCodeHttpAdapter::handleAsync(", "CoroutineRecoveryCodeHttpAdapter::issue("],
    [recovery, "CoroutineRecoveryCodeHttpAdapter::issue(", null],
  ];
  for (const [source, start, end] of methods) {
    const body = method(source, start, end);
    assert.match(body, /SensitiveSessionHeadersGuard wipeHeadersOnExit\{request\}/);
    const guard = body.indexOf("SensitiveSessionHeadersGuard wipeHeadersOnExit{request}");
    const gate = body.indexOf("m_rateLimiter->allow(");
    const credential = body.indexOf("gateway::takeSessionCredential(request)");
    if (gate >= 0) assert.ok(guard < gate);
    if (credential >= 0) assert.ok(guard < credential);
  }
});

test("native PostgreSQL rotate/logout deny paths erase request credential headers", () => {
  const guard = method(nativeSession, "class SensitiveSessionHeadersGuard final",
    "[[nodiscard]] gateway::HttpResponse safeResponse(");
  assert.match(guard, /~SensitiveSessionHeadersGuard\(\)/);
  assert.match(guard, /m_request\.wipeAuthorizationHeader\(\)/);
  assert.match(guard, /m_request\.wipeCookieHeader\(\)/);
  const mutation = method(nativeSession, "sessionMutation(",
    "CoroutineSessionHttpHandler::CoroutineSessionHttpHandler(");
  assert.match(mutation, /SensitiveSessionHeadersGuard wipeHeadersOnExit\{request\}/);
  assert.ok(mutation.indexOf("SensitiveSessionHeadersGuard wipeHeadersOnExit{request}") <
    mutation.indexOf("limiter.allow("));
  assert.ok(mutation.indexOf("SensitiveSessionHeadersGuard wipeHeadersOnExit{request}") <
    mutation.indexOf("gateway::takeSessionCredential(request)"));
});

test("native and legacy account JSON handlers reject MIME prefix confusion", () => {
  // The executable-only scanner erases string literal contents, so read
  // the raw method bodies for exact MIME-token validation.
  const native = method(accountRaw, "revokeTarget(", "CoroutineAccountSessionAdapter::CoroutineAccountSessionAdapter(");
  const legacy = method(legacyAccountRaw, "objectBody(", "trustedPasswordUpgradeOrigin(");
  for (const source of [native, legacy]) {
    assert.match(source, /\*contentType != "application\/json"/);
    assert.match(source, /contentType->starts_with\("application\/json;"\)/);
    assert.doesNotMatch(source, /!contentType->starts_with\("application\/json"\)/);
  }
  const cpp = read("tests/account/session_coroutine_http_test.cpp");
  assert.match(cpp, /TEST\(AccountCoroutineSessionHttpTest, RevokeRejectsLookalikeJsonMimeTypes\)/);
  assert.match(cpp, /"application\/json-invalid"/);
  assert.match(cpp, /"application\/jsonp"/);
  assert.match(cpp, /"application\/json; charset=utf-8"/);
});

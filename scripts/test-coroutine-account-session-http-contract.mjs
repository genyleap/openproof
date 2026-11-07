#!/usr/bin/env node
// Source-level guards complement, not replace, the GCC16 C++ socket tests.
// The legacy AccountHttpApi remains a migration blocker until all routes
// and persistence services are truly nonblocking.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const read = value => fs.readFileSync(path.join(root, value), "utf8");
const implementation = read("src/account/http/coroutine_session_http.cpp");
const executable = cppExecutableText(implementation);
const start = executable.indexOf("CoroutineAccountSessionAdapter::handleAsync(");
const end = executable.indexOf("CoroutineAccountSessionAdapter::sessionList(", start);
const native = executable.slice(start, end);

test("Account HTTP opts in only native authenticated list and revoke", () => {
  const code = read("src/account/http/coroutine_session_http.hpp");
  assert.match(code, /nativeEnabled\(\)\s*const noexcept override\s*\{\s*return false;/);
  assert.match(implementation, /request\.path\(\)\s*==\s*"\/account\/sessions"/);
  assert.match(implementation, /request\.path\(\)\s*==\s*"\/account\/sessions\/revoke"/);
  assert.match(implementation, /m_asyncFallback->nativeEnabledFor\(request\)/);
  assert.match(implementation, /static_cast<bool>\(m_authenticate\)/);
  assert.match(implementation, /static_cast<bool>\(m_list\)/);
  assert.match(implementation, /static_cast<bool>\(m_revokeOwned\)/);
  assert.match(native, /if\s*\(!nativeEnabledFor\(request\)\)/);
  assert.doesNotMatch(native, /m_legacyAccount->handle\s*\(/);
  assert.doesNotMatch(native, /m_sessions->(?:authenticate|list|revokeOwned)\s*\(/);
  assert.match(native, /co_await\s+m_asyncFallback->handleAsync\(/);
});

test("native session routes preserve bearer and operation authorization", () => {
  assert.match(executable, /gateway::takeSessionCredential\(request\)/);
  assert.match(executable, /co_await\s+m_authenticate\(std::move\(credential->value\(\)\)\)/);
  assert.match(executable, /co_await\s+m_list\(current->identity\(\)\)/);
  assert.match(executable, /target\.value\(\)\s*==\s*authenticated->id\(\)/);
  assert.match(executable, /co_await\s+m_revokeOwned\(/);
  assert.match(implementation, /"current"\]\s*=\s*value\.id\(\)\s*==\s*current->id\(\)/);
  assert.match(implementation, /response\.setHeader\("cache-control", "no-store"\)/);
  assert.match(implementation, /"session_id"/);
  assert.match(implementation, /"revoked"/);
});

test("native Account listing checks all returned session identities before disclosure", () => {
  const start = executable.indexOf("CoroutineAccountSessionAdapter::sessionList(");
  const end = executable.indexOf("CoroutineAccountSessionAdapter::sessionRevoke(", start);
  assert.ok(start > 0 && end > start);
  const listing = executable.slice(start, end);
  assert.match(listing, /std::ranges::any_of\(values\.value\(\)/);
  assert.match(listing, /value\.identity\(\)\s*!=\s*current->identity\(\)/);
  assert.match(listing, /ErrorCode::Unavailable/);
  assert.ok(listing.indexOf("value.identity()") < listing.indexOf("json::array sessions;"));
  const cppTests = read("tests/account/session_coroutine_http_test.cpp");
  assert.match(cppTests, /TEST\(AccountCoroutineSessionHttpTest, ForeignIdentityRowsFailClosedBeforeSerialization\)/);
  assert.match(cppTests, /validSession\("foreign-session-internal", "identity-foreign"\)/);
});

test("native Account list refuses oversized provider results before JSON", () => {
  const begin = executable.indexOf("CoroutineAccountSessionAdapter::sessionList(");
  const end = executable.indexOf("CoroutineAccountSessionAdapter::sessionRevoke(", begin);
  const listing = executable.slice(begin, end);
  assert.match(executable, /kMaximumSessionResponseRows\s*=\s*256U/);
  assert.match(listing, /values->size\(\)\s*>\s*kMaximumSessionResponseRows/);
  assert.ok(listing.indexOf("values->size()") < listing.indexOf("json::array sessions;"));
  const cpp = read("tests/account/session_coroutine_http_test.cpp");
  assert.match(cpp, /TEST\(AccountCoroutineSessionHttpTest, SessionListExactLimitAndOverflow\)/);
  assert.match(cpp, /exact\.generatedSessionCount\s*=\s*256U/);
  assert.match(cpp, /overflow\.generatedSessionCount\s*=\s*257U/);
});

test("storage-specific bridge binds real native PostgreSQL session operations", () => {
  const source = read("src/storage/postgres/coroutine_account_session_bridge.cpp");
  assert.match(source, /makeCoroutinePostgresAccountSessionAdapter\s*\(/);
  assert.match(source, /sessions\.authenticate\(std::move\(bearer\)\)/);
  assert.match(source, /sessions\.list\(std::move\(identity\)\)/);
  assert.match(source, /sessions\.revokeOwned\(std::move\(identity\), std::move\(id\)\)/);
  assert.doesNotMatch(source, /io\.run\s*\(|m_sessions->|PQexec\s*\(/);
  const cmake = read("src/storage/postgres/CMakeLists.txt");
  assert.match(cmake, /add_library\(openproof_postgres_async_account_bridge STATIC/);
  assert.match(cmake, /openproof_postgres_async_repository openproof_account_async_http/);
});

test("native path has independent C++ security regression and strict acceptance guard", () => {
  const tests = read("tests/account/session_coroutine_http_test.cpp");
  for (const name of [
    "RequestSpecificCapabilityAndNativeFallback",
    "ListNativeSessionsPreservesExistingJson",
    "MissingAndInvalidBearerNeverEnumerate",
    "RevokeRejectsCurrentAndMalformedRequests",
  ]) {
    assert.ok(tests.includes("TEST(AccountCoroutineSessionHttpTest, " + name + ")"));
  }
  const checker = read("scripts/verify-coroutine-coverage.mjs");
  assert.match(checker, /"src\/account\/http\/coroutine_session_http\.cpp"/);
  assert.match(checker, /"src\/account\/http\/http\.cpp"/);
  const cmake = read("tests/CMakeLists.txt");
  assert.match(cmake, /add_executable\(openproof_account_coroutine_http_tests/);
});

#!/usr/bin/env node
// Static security invariants for opt-in native /auth login and verification.
// This is not a C++ compilation or HTTP integration test.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const read = file => fs.readFileSync(path.join(root, file), "utf8");
const http = cppExecutableText(read("src/authentication/http/http.cpp"));
const api = read("src/authentication/http/http.cppm");
const coordinator = read("src/authentication/service.cpp");
const port = read("src/session/coroutine.cppm");
const repository = cppExecutableText(
  read("src/storage/postgres/coroutine_session_service.cpp"));
const repositoryInterface =
  read("src/storage/postgres/coroutine_session_service.hpp");

const method = (source, startToken, nextToken) => {
  const start = source.indexOf(startToken);
  const end = source.indexOf(nextToken, start + startToken.length);
  assert.ok(start >= 0 && end > start, "Cannot locate " + startToken);
  return source.slice(start, end);
};

test("native authentication requires the provider and every durable dependency", () => {
  assert.match(api, /nativeProviderAuthenticationEnabled\(m_provider\)/);
  assert.match(api, /static constexpr bool kAllAuthRoutesNative = false/);
  assert.match(api, /return kAllAuthRoutesNative && m_asyncSessions != nullptr/);
  const nativeRoute = method(http,
    "AuthenticationHttpApi::nativeEnabledFor(", "AuthenticationHttpApi::handleAsync(");
  const raw = read("src/authentication/http/http.cpp");
  assert.match(raw, /path == "\/auth\/login" \|\| path == "\/auth\/mfa\/verify"/);
  assert.match(nativeRoute, /m_asyncSessions != nullptr/);
  assert.match(nativeRoute, /nativeProviderAuthenticationEnabled\(m_provider\)/);
  assert.match(raw, /path == "\/auth" \|\| path\.starts_with\("\/auth\/"\)\) return false/);
  assert.match(nativeRoute, /native->nativeEnabledFor\(request\)/);
  const native = method(coordinator,
    "bool AuthenticationService::nativeProviderAuthenticationEnabled",
    "foundation::Result<AuthenticationStart> AuthenticationService::begin");
  assert.match(native, /m_asyncCanonical\s*==\s*nullptr/);
  assert.match(native, /CoroutineAuthenticationTransactionStore/);
  assert.match(native, /CoroutineAuthenticationProvider/);
  assert.match(native, /effectiveMaximum\(/);
  assert.match(native, /catch\s*\(\s*\.\.\.\s*\)/);
});

test("native HTTP dispatch cannot invoke legacy fallback or session APIs", () => {
  const native = method(http,
    "AuthenticationHttpApi::handleAsync(", "AuthenticationHttpApi::loginAsync(");
  assert.match(native, /native->nativeEnabledFor\(request\)/);
  assert.match(native, /co_await\s+native->handleAsync\(/);
  assert.match(native, /co_await\s+loginAsync\(/);
  assert.match(native, /co_await\s+verifyAsync\(/);
  assert.match(native, /ErrorCode::Unavailable/);
  assert.doesNotMatch(native, /\bm_fallback->handle\s*\(/);
  assert.doesNotMatch(native, /\bm_sessions->/);
});

test("native login awaits trusted challenge creation", () => {
  const login = method(http,
    "AuthenticationHttpApi::loginAsync(", "AuthenticationHttpApi::verifyAsync(");
  assert.match(login, /co_await\s+m_authentication->beginAsync\(/);
  assert.match(read("src/authentication/http/http.cpp"), /"auth-subject:"/);
  assert.match(login, /kPreauthCookie/);
  assert.match(login, /kBindingCookie/);
  assert.match(login, /kSubjectCookie/);
  assert.doesNotMatch(login, /m_authentication->begin\s*\(/);
});

test("native verification atomically replaces prior session after the proof", () => {
  const verify = method(http,
    "AuthenticationHttpApi::verifyAsync(", "gateway::HttpResponse AuthenticationHttpApi::login(");
  assert.match(verify, /co_await\s+m_authentication->completeAsync\(/);
  assert.match(verify, /co_await\s+m_asyncSessions->issueReplacingAsync\(/);
  assert.match(verify, /clearPreauth\(output\)/);
  assert.match(verify, /setSessionCookie\(output,\s*issued->token\)/);
  assert.doesNotMatch(verify, /\bm_sessions->/);
  assert.doesNotMatch(verify, /m_authentication->complete\s*\(/);
  assert.doesNotMatch(verify, /m_asyncSessions->issueAsync\s*\(/);
});

test("provider-neutral native session port is backed by atomic SQL repository", () => {
  assert.match(port, /class CoroutineReplacingSessionIssuer\s*:\s*public CoroutineSessionIssuer/);
  const originalPort = port.slice(
    port.indexOf("class CoroutineSessionIssuer {"),
    port.indexOf("class CoroutineReplacingSessionIssuer :"));
  assert.doesNotMatch(originalPort, /issueReplacingAsync\s*\(/);
  assert.match(port, /virtual\s+boost::asio::awaitable<[\s\S]*?issueReplacingAsync\(/);
  assert.match(api, /session::CoroutineReplacingSessionIssuer\* asyncSessions/);
  assert.match(repositoryInterface, /issueReplacingAsync\([\s\S]*?override/);
  const implementation = method(repository,
    "CoroutinePostgresSessionService::issueReplacingAsync(",
    "CoroutinePostgresSessionService::issue(");
  assert.match(implementation, /co_await\s+issueReplacing\(/);
  assert.match(implementation, /CoroutineIssuedSession/);
  assert.doesNotMatch(implementation, /m_sessions->/);
});

test("subject continuation cookie supports the full validated base64url length", () => {
  const matches = http.match(/cookieValue\(request,\s*kSubjectCookie,\s*512U\)/g);
  assert.equal(matches?.length, 2);
  assert.match(http, /value\.size\(\)\s*>\s*maximumLength/);
});

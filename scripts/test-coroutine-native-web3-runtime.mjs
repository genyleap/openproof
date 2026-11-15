#!/usr/bin/env node
// Runtime composition contract for the experimental native Web3 login
// slice. These checks are NOT a replacement for compiled C++/HTTP/SQL E2E.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const read = file => fs.readFileSync(path.join(root, file), "utf8");
const app = read("apps/opp/main.cpp");
const web3 = read("src/authentication/http/web3.cpp");
const web3Api = read("src/authentication/http/web3.cppm");

test("Web3 opt-in is validated before database operations and is off by default", () => {
  assert.match(app, /environment\.get\("OPENPROOF_EXPERIMENTAL_NATIVE_WEB3_LOGIN"\)/);
  assert.match(app, /nativeWeb3Flag && \*nativeWeb3Flag != "0"/);
  assert.match(app, /nativeWeb3Flag && \*nativeWeb3Flag == "1"/);
  assert.match(app, /nativeWeb3Enabled && !platform\.auth\(\)\.enabled\(\)/);
  const start = app.indexOf("OPENPROOF_EXPERIMENTAL_NATIVE_WEB3_LOGIN");
  const migrator = app.indexOf("postgres::Migrator migrator{*pool.value()}", start);
  assert.ok(start >= 0 && migrator > start);
});

test("Web3 login gets async transaction, canonical and session services without LDAP opt-in", () => {
  assert.match(app, /if \(nativeLdapEnabled \|\| nativeAccountEnabled \|\| nativeWeb3Enabled\s*\|\| nativeAuthSessionEnabled\)\s*nativeSessionSecret\.emplace\(sessionSecret->clone\(\)\)/);
  assert.match(app, /if \(nativeLdapEnabled \|\| nativeAccountEnabled \|\| nativeWeb3Enabled\s*\|\| nativeAuthSessionEnabled\) \{/);
  assert.match(app, /if \(nativeLdapEnabled \|\| nativeWeb3Enabled\) \{/);
  const runtime = app.slice(app.indexOf("nativeIo = std::make_unique<boost::asio::thread_pool>"),
    app.indexOf("std::optional<passkey::PasskeyService>"));
  assert.match(runtime, /CoroutinePostgresSessionRepository/);
  assert.match(runtime, /CoroutinePostgresSessionService/);
  assert.match(runtime, /CoroutinePostgresAuthenticationTransactionStore/);
  assert.match(runtime, /CoroutinePostgresCanonicalFinalizer/);
  assert.match(runtime, /nativeCanonical\.get\(\)/);
  assert.match(app, /authHttp::Web3AuthenticationHttpApi nativeWeb3Api\{\s*\*nativeAuthentication, providers, sessions, limiter\.value\(\),\s*enterpriseApi, nullptr, nativeSessions\.get\(\)\}/);
  assert.match(app, /runWithScim\(enterpriseApi, nativeWeb3Api\)/);
  assert.match(app, /runWithScim\(enterpriseApi, enterpriseApi\)/);
});

test("native route overlay has exact opt-in path gates, never implicit LDAP or Account activation", () => {
  const start = app.indexOf("std::vector<std::string> nativePaths;");
  const end = app.indexOf("gatewayHttp::CoroutineRouteOverlay nativeRoutes{", start);
  assert.ok(start >= 0 && end > start);
  const routing = app.slice(start,end);
  const ldapStart = routing.indexOf("if (nativeLdapEnabled)");
  const web3Start = routing.indexOf("if (nativeWeb3Enabled)");
  const accountStart = routing.indexOf("if (platform.account().enabled() && nativeAccountEnabled && nativeSessions)");
  assert.ok(ldapStart >= 0 && web3Start > ldapStart && accountStart > web3Start);
  const ldap = routing.slice(ldapStart,web3Start);
  const web3Routes = routing.slice(web3Start,accountStart);
  const account = routing.slice(accountStart);
  assert.match(ldap, /nativePaths\.emplace_back\("\/auth\/ldap\/start"\)/);
  assert.match(ldap, /nativePaths\.emplace_back\("\/auth\/ldap\/complete"\)/);
  assert.match(web3Routes, /nativePaths\.emplace_back\("\/auth\/web3\/start"\)/);
  assert.match(web3Routes, /nativePaths\.emplace_back\("\/auth\/web3\/complete"\)/);
  assert.doesNotMatch(web3Routes,/\/auth\/web3\/handoff|\/account\/connections/);
  assert.match(account, /nativePaths\.emplace_back\("\/account\/sessions"\)/);
  assert.match(account, /nativePaths\.emplace_back\("\/account\/sessions\/revoke"\)/);
});

test("native Web3 entry awaits verification and session issuance but cannot redeem handoffs", () => {
  assert.match(web3Api,/session::CoroutineSessionIssuer\* asyncSessions = nullptr/);
  const start = web3.slice(web3.indexOf("Web3AuthenticationHttpApi::nativeEnabledFor("));
  const cap = start.slice(0,start.indexOf("Web3AuthenticationHttpApi::handleAsync("));
  assert.match(cap,/path == "\/auth\/web3\/start" \|\| path == "\/auth\/web3\/complete"/);
  assert.match(cap,/m_asyncSessions != nullptr/);
  assert.match(cap,/m_authentication->nativeCanonicalCompletionEnabled\(\)/);
  assert.match(cap,/path\.starts_with\("\/auth\/web3\/"\)/);
  const begin = start.slice(start.indexOf("Web3AuthenticationHttpApi::startAsync("),
    start.indexOf("Web3AuthenticationHttpApi::completeAsync("));
  const complete = start.slice(start.indexOf("Web3AuthenticationHttpApi::completeAsync("));
  assert.match(begin,/co_await m_authentication->beginAsync\(/);
  assert.match(begin,/if \(handoffTicket\)/);
  assert.match(complete,/co_await m_authentication->completeAsync\(/);
  assert.match(complete,/co_await m_asyncSessions->issueAsync\(/);
  assert.match(complete,/if \(authenticationHandoff\)/);
  assert.doesNotMatch(complete,/m_sessions->issue\(/);
});

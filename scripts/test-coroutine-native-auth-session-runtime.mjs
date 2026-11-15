#!/usr/bin/env node
// Native session rotate/logout cutover contract. Source tests complement,
// never replace, fresh compiled C++ and isolated SQL/HTTP acceptance.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const root=path.resolve(import.meta.dirname,"..");
const read=f=>fs.readFileSync(path.join(root,f),"utf8");
const app=read("apps/opp/main.cpp");
const listener=read("src/storage/postgres/coroutine_session_listener.cpp");
const handler=read("src/storage/postgres/coroutine_session_http.cpp");
const ctest=read("tests/storage/postgres_coroutine_network_test.cpp");
const cmake=read("apps/opp/CMakeLists.txt");

test("auth session cutover is independently opt-in and rejected before DB migration when malformed",()=>{
  assert.match(app,/environment\.get\("OPENPROOF_EXPERIMENTAL_NATIVE_AUTH_SESSIONS"\)/);
  assert.match(app,/nativeAuthSessionFlag && \*nativeAuthSessionFlag != "0"/);
  assert.match(app,/nativeAuthSessionFlag && \*nativeAuthSessionFlag == "1"/);
  assert.match(app,/nativeAuthSessionEnabled && !platform\.auth\(\)\.enabled\(\)/);
  const begin=app.indexOf("OPENPROOF_EXPERIMENTAL_NATIVE_AUTH_SESSIONS");
  const migrate=app.indexOf("postgres::Migrator migrator{*pool.value()}",begin);
  assert.ok(begin>=0 && migrate>begin);
});

test("session-only runtime builds async SQL session service without identity canonical/LDAP",()=>{
  assert.match(app,/if \(nativeLdapEnabled \|\| nativeAccountEnabled \|\| nativeWeb3Enabled\s*\|\| nativeAuthSessionEnabled\)\s*nativeSessionSecret\.emplace/);
  assert.match(app,/if \(nativeLdapEnabled \|\| nativeAccountEnabled \|\| nativeWeb3Enabled\s*\|\| nativeAuthSessionEnabled\)\s*\{/);
  const start=app.indexOf("nativeIo = std::make_unique<boost::asio::thread_pool>");
  const repo=app.indexOf("nativeSessionRepository = std::make_unique<",start);
  const sessions=app.indexOf("nativeSessions = std::make_unique<",repo);
  const canonicalGate=app.indexOf("if (nativeLdapEnabled || nativeWeb3Enabled)",sessions);
  const canonical=app.indexOf("nativeCanonical = std::make_unique<",canonicalGate);
  assert.ok(start>=0 && repo>start && sessions>repo && canonicalGate>sessions && canonical>canonicalGate);
  assert.match(cmake,/openproof_postgres_async_listener/);
  assert.match(cmake,/openproof_postgres_async_repository/);
});

test("only the three auth session mutations are overlaid; middleware chain cannot call a sync fallback",()=>{
  const section=app.slice(app.indexOf("std::vector<std::string> nativePaths;"),
    app.indexOf("gatewayHttp::CoroutineRouteOverlay nativeRoutes{"));
  const pos=section.indexOf("if (nativeAuthSessionEnabled && nativeSessions)");
  const account=section.indexOf("if (platform.account().enabled() && nativeAccountEnabled && nativeSessions)");
  assert.ok(pos>=0 && account>pos);
  const native=section.slice(pos,account);
  assert.match(native,/CoroutineSessionListenerStack/);
  assert.match(native,/\*nativeSessions, limiter\.value\(\), \*nativeHandler, true/);
  assert.match(native,/nativeHandler = &asyncAuthSessions->handler\(\)/);
  for(const route of ["/auth/session/rotate","/auth/logout","/auth/logout-all"])
    assert.ok(native.includes('nativePaths.emplace_back("'+route+'")'));
  assert.doesNotMatch(native,/\/auth\/login|\/auth\/mfa\/verify|\/auth\/recovery-codes/);
  assert.match(section.slice(account),/healthApi, \*nativeHandler, limiter\.value\(\)/);
  assert.match(app,/std::unique_ptr<postgres::CoroutineSessionListenerStack> asyncAuthSessions;/);
});

test("native handler dispatches actual nonblocking session mutations with no sync repo calls",()=>{
  assert.match(handler,/CoroutineSessionHttpHandler::isSessionRoute\(/);
  assert.match(handler,/co_await service\.rotate\(/);
  assert.match(handler,/co_await service\.authenticate\(/);
  assert.match(handler,/co_await service\.revokeAll\(/);
  assert.match(handler,/co_await service\.revoke\(/);
  assert.match(listener,/co_return co_await m_handler->handleAsync\(std::move\(request\)\)/);
  assert.match(listener,/fallback\.nativeEnabledFor\(request\)/);
  assert.match(listener,/co_return co_await fallback\.handleAsync\(std::move\(request\)\)/);
  assert.doesNotMatch(listener,/m_sessions->authenticate\(|m_fallback->handle\(/);
});

test("real compiled listener suite covers rotate and logout wire methods under private loopback",()=>{
  assert.match(ctest,/CoroutineSessionListenerStack hybrid/);
  assert.match(ctest,/gwHttp::BeastHttpServer listener/);
  assert.match(ctest,/"\/auth\/session\/rotate"/);
  assert.match(ctest,/"\/auth\/logout"/);
  assert.match(ctest,/"\/auth\/logout-all"/);
  assert.match(ctest,/EXPECT_EQ\(f\.fallback\.blockingCalls\.load\(\), 0\)/);
});

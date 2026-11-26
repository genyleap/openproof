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
  assert.match(gateway, /nativeEnabledFor\([\s\S]*?return nativeEnabled\(\);/);
  assert.match(read("src/gateway/http.cpp"), /asyncHandler->nativeEnabledFor\(operation\)/);
  assert.match(gatewayTests, /TEST\(BeastHttpIntegrationTest, SelectiveNativeDispatchPreservesLegacyRoutes\)/);
});

test("known native handlers explicitly opt in; conditional Web3 remains gated", () => {
  assert.match(gateway, /class CoroutineGatewayAdapter[\s\S]*?nativeEnabled\(\) const noexcept override \{ return true; \}/);
  assert.match(listener, /class CoroutineSessionListenerAdapter[\s\S]*?nativeEnabled\(\) const noexcept override \{ return true; \}/);
  assert.match(gateway, /return m_fallback->nativeEnabled\(\);/);
  assert.match(gateway, /request\.path\(\) != "\/metrics"\s*&& m_fallback->nativeEnabledFor\(request\)/);
  assert.match(web3, /nativeEnabled\(\) const noexcept override \{[\s\S]*?return false;/);
  assert.match(web3, /bool nativeEnabledFor\(/);
  assert.match(read("src/authentication/http/web3.cpp"),
    /Web3AuthenticationHttpApi::nativeEnabledFor\([\s\S]*?m_asyncSessions != nullptr\s*&&\s*m_authentication->nativeCanonicalCompletionEnabled\(\)/);
});

test("metrics asynchronous entry rejects direct sync and revoked fallback calls", () => {
  const implementation = read("src/gateway/http_coroutine.cpp");
  const start = implementation.indexOf("CoroutineMetricsAdapter::handleAsync(");
  const end = implementation.indexOf("CoroutineGatewayAdapter::CoroutineGatewayAdapter(", start);
  assert.ok(start >= 0 && end > start);
  const native = implementation.slice(start, end);
  assert.match(native, /request\.path\(\) == "\/metrics"/);
  assert.match(native, /!m_fallback->nativeEnabledFor\(request\)/);
  assert.doesNotMatch(native, /m_metricsFacade->handle\s*\(/);
  assert.match(native, /ErrorCode::Unavailable/);
  const denied = native.slice(0, native.indexOf("const HttpMethod method"));
  for (const scrub of ["wipeBody", "wipeAuthorizationHeader", "wipeCookieHeader"])
    assert.ok(denied.includes("request." + scrub + "()"),
      "disabled native metrics requests must scrub " + scrub);
  assert.match(native, /cache-control", "no-store"/);
  assert.match(gatewayTests,
    /TEST\(BeastHttpIntegrationTest, DirectMetricsCoroutineCallFailsClosed\)/);
  assert.match(gatewayTests,
    /EXPECT_EQ\(disabled\.synchronousCalls\.load\(\), 0\)/);
  assert.match(gatewayTests,
    /EXPECT_EQ\(disabled\.asynchronousCalls\.load\(\), 0\)/);
});

test("partially migrated runtime overlays LDAP and opted-in account sessions with fail-closed readiness", () => {
  const app=read("apps/opp/main.cpp");
  const implementation=read("src/gateway/http_coroutine.cpp");
  const overlayStart=implementation.indexOf("CoroutineRouteOverlay::CoroutineRouteOverlay(");
  const overlayEnd=implementation.indexOf("CoroutineMetricsAdapter::CoroutineMetricsAdapter(", overlayStart);
  assert.ok(overlayStart >= 0 && overlayEnd > overlayStart);
  const overlay=implementation.slice(overlayStart, overlayEnd);
  assert.match(gateway, /class CoroutineRouteOverlay final : public CoroutineHttpHandler/);
  assert.match(gateway, /m_exactNativePaths/);
  assert.match(overlay, /m_native->nativeEnabledFor\(request\)/);
  assert.match(overlay, /m_native->handleAsync\(std::move\(request\)\)/);
  assert.match(overlay, /if \(!overlays\(request\)\) return false;/);
  const syncReject=overlay.slice(
    overlay.indexOf("CoroutineRouteOverlay::handle(HttpRequest request)"),
    overlay.indexOf("CoroutineRouteOverlay::handleAsync(HttpRequest request)"));
  const asyncReject=overlay.slice(overlay.indexOf(
    "CoroutineRouteOverlay::handleAsync(HttpRequest request)"));
  for (const denied of [syncReject, asyncReject]) {
    assert.match(denied, /request.wipeBody\(\)/);
    assert.match(denied, /request.wipeAuthorizationHeader\(\)/);
    assert.match(denied, /request.wipeCookieHeader\(\)/);
  }
  assert.match(overlay, /return unavailable\(request\)/);
  assert.doesNotMatch(overlay.slice(overlay.indexOf("CoroutineRouteOverlay::handleAsync(")), /m_compatibility->handle\(/);
  assert.match(app, /CoroutineRouteOverlay nativeRoutes\{[\s\S]*?healthApi, \*nativeHandler, std::move\(nativePaths\)/);
  assert.match(app, /nativeHandler = &nativeEnterprise/);
  assert.match(app, /if \(nativeLdapEnabled\)\s*\{\s*nativePaths\.emplace_back\("\/auth\/ldap\/start"\);\s*nativePaths\.emplace_back\("\/auth\/ldap\/complete"\)/);
  assert.match(app, /if \(nativeWeb3Enabled\)\s*\{\s*nativePaths\.emplace_back\("\/auth\/web3\/start"\);\s*nativePaths\.emplace_back\("\/auth\/web3\/complete"\)/);
  assert.match(app, /if \(platform.account\(\).enabled\(\) && nativeAccountEnabled && nativeSessions\)/);
  assert.match(app, /nativeHandler = asyncAccount.get\(\)/);
  assert.match(app, /nativePaths.emplace_back\("\/account\/sessions"\)/);
  assert.match(app, /nativePaths.emplace_back\("\/account\/sessions\/revoke"\)/);
  assert.match(app, /runListener\(platform, nativeRoutes, logger\)/);
  assert.match(app, /runWithScim\(enterpriseApi, enterpriseApi\)/);
  assert.match(gatewayTests, /TEST\(BeastHttpIntegrationTest, RouteOverlayPreservesCompatibilityAndDeniesUnreadySecrets\)/);
  assert.match(gatewayTests, /TEST\(BeastHttpIntegrationTest, DirectRouteOverlayAsyncCannotCallLegacyHandler\)/);
});
test("native account-session runtime remains independent of LDAP and profile reads", () => {
  const app = read("apps/opp/main.cpp");
  assert.match(app, /environment\.get\("OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_SESSIONS"\)/);
  assert.match(app, /nativeAccountFlag && \*nativeAccountFlag != "0"/);
  assert.match(app, /nativeAccountFlag && \*nativeAccountFlag == "1"/);
  assert.match(app, /nativeAccountEnabled && !platform\.account\(\)\.enabled\(\)/);

  // Account session management must not allocate an OAuth transaction store,
  // canonical finalizer, or another key on its own. Profile reads have a
  // second explicit flag and can initialize only their canonical SQL reader.
  const nativeIo = app.indexOf("nativeIo = std::make_unique<boost::asio::thread_pool>");
  const setup = app.lastIndexOf(
    "if (nativeLdapEnabled || nativeAccountEnabled || nativeWeb3Enabled", nativeIo);
  const sessionRepo = app.indexOf("nativeSessionRepository = std::make_unique<", nativeIo);
  const sessionIssuer = app.indexOf("nativeSessions = std::make_unique<", sessionRepo);
  const canonicalGate = app.indexOf(
    "if (nativeLdapEnabled || nativeWeb3Enabled || nativeFederatedStartEnabled\n            || nativeAccountProfileEnabled || nativeAccountConnectionsEnabled\n            || nativeAccountTotpStatusEnabled || nativeAdminReadEnabled || nativeRecoveryEnabled) {", sessionIssuer);
  const canonical = app.indexOf("nativeCanonical = std::make_unique<", canonicalGate);
  const authGate = app.indexOf(
    "if (nativeLdapEnabled || nativeWeb3Enabled || nativeFederatedStartEnabled) {", canonical);
  const transactions = app.indexOf("nativeTransactions = std::make_unique<", authGate);
  const nativeAuthentication = app.indexOf(
    "nativeAuthentication = std::make_unique<auth::AuthenticationService>", transactions);
  assert.ok(setup >= 0 && setup < nativeIo);
  assert.ok(nativeIo < sessionRepo && sessionRepo < sessionIssuer
    && sessionIssuer < canonicalGate && canonicalGate < canonical);
  assert.ok(canonical < authGate && authGate < transactions
    && transactions < nativeAuthentication);
  assert.match(app, /if \(platform\.account\(\)\.enabled\(\) && nativeAccountEnabled && nativeSessions\)/);
  assert.match(app, /if \(nativeLdapEnabled \|\| nativeAccountEnabled \|\| nativeWeb3Enabled[\s\S]*?\|\| nativeAuthSessionEnabled \|\| nativeFederatedStartEnabled\)[\s\S]*?nativeSessionSecret\.emplace\(sessionSecret->clone\(\)\)/);
  assert.match(app, /OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_PROFILE/);
  assert.match(app, /nativeAccountProfileEnabled[\s\S]*?!nativeAccountEnabled/);
  assert.match(app, /OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_CONNECTIONS/);
  assert.match(app, /nativeAccountConnectionsEnabled[\s\S]*?!nativeAccountEnabled/);
  assert.match(app, /if \(nativeAccountProfileEnabled\) \{\s*nativeMethods\.emplace_back\("\/account\/profile", gateway::HttpMethod::Get\)/);
});

test("loopback-native test implementations explicitly opt in", () => {
  for (const name of ["CoroutineWaitingHandler", "CoroutineProxyHandler", "CoroutineThrowingHandler"]) {
    const start = gatewayTests.indexOf("class " + name + " final");
    assert.ok(start >= 0);
    const tail = gatewayTests.slice(start, gatewayTests.indexOf("\n};", start));
    assert.match(tail, /nativeEnabled\(\) const noexcept override \{ return true; \}/);
  }
});

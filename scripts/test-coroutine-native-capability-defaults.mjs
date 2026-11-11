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
  const implementation = read("src/gateway/http.cpp");
  const start = implementation.indexOf("CoroutineMetricsAdapter::handleAsync(");
  const end = implementation.indexOf("CoroutineGatewayAdapter::CoroutineGatewayAdapter(", start);
  assert.ok(start >= 0 && end > start);
  const native = implementation.slice(start, end);
  assert.match(native, /request\.path\(\) == "\/metrics"/);
  assert.match(native, /!m_fallback->nativeEnabledFor\(request\)/);
  assert.doesNotMatch(native, /m_metricsFacade->handle\s*\(/);
  assert.match(native, /ErrorCode::Unavailable/);
  assert.match(native, /cache-control", "no-store"/);
  assert.match(gatewayTests,
    /TEST\(BeastHttpIntegrationTest, DirectMetricsCoroutineCallFailsClosed\)/);
  assert.match(gatewayTests,
    /EXPECT_EQ\(disabled\.synchronousCalls\.load\(\), 0\)/);
  assert.match(gatewayTests,
    /EXPECT_EQ\(disabled\.asynchronousCalls\.load\(\), 0\)/);
});

test("partially migrated runtime overlays only LDAP with fail-closed native readiness", () => {
  const app=read("apps/opp/main.cpp");
  const implementation=read("src/gateway/http.cpp");
  const overlayStart=implementation.indexOf("CoroutineRouteOverlay::CoroutineRouteOverlay(");
  const overlayEnd=implementation.indexOf("CoroutineMetricsAdapter::CoroutineMetricsAdapter(", overlayStart);
  assert.ok(overlayStart >= 0 && overlayEnd > overlayStart);
  const overlay=implementation.slice(overlayStart, overlayEnd);
  assert.match(gateway, /class CoroutineRouteOverlay final : public CoroutineHttpHandler/);
  assert.match(gateway, /m_exactNativePaths/);
  assert.match(overlay, /m_native->nativeEnabledFor\(request\)/);
  assert.match(overlay, /m_native->handleAsync\(std::move\(request\)\)/);
  assert.match(overlay, /if \(overlays\(request.path\(\)\)\)/);
  assert.match(overlay, /request.wipeBody\(\)/);
  assert.match(overlay, /return unavailable\(request\)/);
  assert.doesNotMatch(overlay.slice(overlay.indexOf("CoroutineRouteOverlay::handleAsync(")), /m_compatibility->handle\(/);
  assert.match(app, /CoroutineRouteOverlay nativeRoutes\{[\s\S]*?healthApi, nativeEnterprise/);
  assert.match(app, /\{"\/auth\/ldap\/start", "\/auth\/ldap\/complete"\}/);
  assert.match(app, /runListener\(platform, nativeRoutes, logger\)/);
  assert.match(app, /runWithScim\(enterpriseApi, enterpriseApi\)/);
  assert.match(gatewayTests, /TEST\(BeastHttpIntegrationTest, RouteOverlayPreservesCompatibilityAndDeniesUnreadySecrets\)/);
  assert.match(gatewayTests, /TEST\(BeastHttpIntegrationTest, DirectRouteOverlayAsyncCannotCallLegacyHandler\)/);
});
test("loopback-native test implementations explicitly opt in", () => {
  for (const name of ["CoroutineWaitingHandler", "CoroutineProxyHandler", "CoroutineThrowingHandler"]) {
    const start = gatewayTests.indexOf("class " + name + " final");
    assert.ok(start >= 0);
    const tail = gatewayTests.slice(start, gatewayTests.indexOf("\n};", start));
    assert.match(tail, /nativeEnabled\(\) const noexcept override \{ return true; \}/);
  }
});

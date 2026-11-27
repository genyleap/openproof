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
  assert.match(app, /CoroutineRouteOverlay nativeRoutes\{[\s\S]*?fallback, nativeHealth, std::move\(nativePaths\)/);
  assert.match(app, /CoroutineHealthAdapter nativeHealth\{\*nativeHandler,/);
  assert.match(app, /nativeHandler = &nativeEnterprise/);
  assert.match(app, /if \(nativeLdapEnabled\)\s*\{\s*nativePaths\.emplace_back\("\/auth\/ldap\/start"\);\s*nativePaths\.emplace_back\("\/auth\/ldap\/complete"\)/);
  assert.match(app, /if \(nativeWeb3Enabled\)\s*\{\s*nativePaths\.emplace_back\("\/auth\/web3\/start"\);\s*nativePaths\.emplace_back\("\/auth\/web3\/complete"\)/);
  assert.match(app, /if \(platform.account\(\).enabled\(\) && nativeAccountEnabled && nativeSessions\)/);
  assert.match(app, /nativeHandler = asyncAccount.get\(\)/);
  assert.match(app, /nativePaths.emplace_back\("\/account\/sessions"\)/);
  assert.match(app, /nativePaths.emplace_back\("\/account\/sessions\/revoke"\)/);
  assert.match(app, /runListener\(platform, nativeRoutes, logger\)/);
  assert.match(app, /runWithEvidence\(fallback,localEnterpriseApi\)/);
  assert.match(gatewayTests, /TEST\(BeastHttpIntegrationTest, RouteOverlayPreservesCompatibilityAndDeniesUnreadySecrets\)/);
  assert.match(gatewayTests, /TEST\(BeastHttpIntegrationTest, DirectRouteOverlayAsyncCannotCallLegacyHandler\)/);
});
test("native account lifecycle is mandatory and independent of LDAP", () => {
  const app = read("apps/opp/main.cpp");
  assert.match(app, /environment\.get\("OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_SESSIONS"\)/);
  assert.match(app, /nativeAccountFlag && \*nativeAccountFlag != "0"/);
  assert.match(app, /nativeAccountFlag && \*nativeAccountFlag == "1"/);
  assert.match(app, /nativeAccountEnabled && !platform\.account\(\)\.enabled\(\)/);
  const runtime=app.indexOf("ExitCode runGatewayServer(");
  const migrator=app.indexOf("postgres::nativeDatabasePreflight(",runtime);
  assert.ok(runtime>=0 && migrator>runtime);
  for (const [flag,capability] of [
    ["nativeAccountFlag","nativeAccountEnabled"],
    ["nativeAccountProfileFlag","nativeAccountProfileEnabled"],
    ["nativeAccountConnectionsFlag","nativeAccountConnectionsEnabled"],
    ["nativeAccountTotpStatusFlag","nativeAccountTotpStatusEnabled"],
    ["nativeSignupFlag","nativeSignupEnabled"]
  ]) {
    const declaration=new RegExp("const bool "+capability+"\\s*=\\s*platform\\.account\\(\\)\\.enabled\\(\\)\\s*\\|\\|\\s*\\("+flag+" && \\*"+flag+"\\s*==\\s*\"1\"\\)");
    const refuse=new RegExp("if \\(platform\\.account\\(\\)\\.enabled\\(\\) && "+flag+" && \\*"+flag+"\\s*==\\s*\"0\"\\) \\{[\\s\\S]*?return ExitCode::ConfigurationError;");
    assert.match(app,declaration);
    assert.match(app.slice(0,migrator),refuse);
  }
  assert.match(app,/if \(!nativeContactIssuer \|\| !nativeSignup \|\| !nativeVerifySignup[\s\S]*?!nativeTotp\) \{[\s\S]*?return ExitCode::ConfigurationError;/);
  const exact=app.slice(app.indexOf('for (const auto* path : {"/account/signup"'),app.indexOf("nativePaths.emplace_back(path);"));
  for (const route of ["/account/signup","/account/email/verify","/account/email/change","/account/email/change/verify","/account/email/resend","/account/phone","/account/phone/verify","/account/password/forgot","/account/password/reset","/account/totp/start","/account/totp/complete","/account/totp/disable"])
    assert.ok(exact.includes('"'+route+'"'),route);

  // Keep the session and tenant readers independent of provider transaction
  // initialization even though the account feature now requires both readers.
  const nativeIo = app.indexOf("nativeIo = std::make_unique<boost::asio::thread_pool>");
  const setup = app.lastIndexOf(
    "if (nativeLdapEnabled || nativeAccountEnabled || nativeWeb3Enabled", nativeIo);
  const sessionRepo = app.indexOf("nativeSessionRepository = std::make_unique<", nativeIo);
  const sessionIssuer = app.indexOf("nativeSessions = std::make_unique<", sessionRepo);
  const canonicalGate = app.indexOf(
    "if (nativeLdapEnabled || nativeWeb3Enabled || nativeFederatedStartEnabled\n            || nativeAccountProfileEnabled || nativeAccountConnectionsEnabled\n            || nativeAccountTotpStatusEnabled || nativeAdminReadEnabled || nativeRecoveryEnabled || nativeProtectedGatewayEnabled || nativeLocalEnabled) {", sessionIssuer);
  const canonical = app.indexOf("nativeCanonical = std::make_unique<", canonicalGate);
  const authGate = app.indexOf(
    "if (nativeLdapEnabled || nativeWeb3Enabled || nativeFederatedStartEnabled || nativeLocalEnabled) {", canonical);
  const transactions = app.indexOf("nativeTransactions = std::make_unique<", authGate);
  const nativeAuthentication = app.indexOf(
    "nativeAuthentication = std::make_unique<auth::AuthenticationService>", transactions);
  assert.ok(setup >= 0 && setup < nativeIo);
  assert.ok(nativeIo < sessionRepo && sessionRepo < sessionIssuer
    && sessionIssuer < canonicalGate && canonicalGate < canonical);
  assert.ok(canonical < authGate && authGate < transactions
    && transactions < nativeAuthentication);
  assert.match(app, /if \(platform\.account\(\)\.enabled\(\) && nativeAccountEnabled && nativeSessions\)/);
  assert.match(app, /if \(nativeLdapEnabled \|\| nativeAccountEnabled \|\| nativeWeb3Enabled[\s\S]*?\|\| nativeAuthSessionEnabled \|\| nativeFederatedStartEnabled\s*\|\| nativeProtectedGatewayEnabled\s*\|\|\s*nativeLocalEnabled\)[\s\S]*?nativeSessionSecret\.emplace\(sessionSecret->clone\(\)\)/);
  assert.match(app, /OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_PROFILE/);
  assert.match(app, /nativeAccountProfileEnabled[\s\S]*?!nativeAccountEnabled/);
  assert.match(app, /OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_CONNECTIONS/);
  assert.match(app, /nativeAccountConnectionsEnabled[\s\S]*?!nativeAccountEnabled/);
  assert.match(app, /if \(nativeAccountProfileEnabled\) \{\s*nativePaths\.emplace_back\("\/account\/profile"\)/);
});

test("loopback-native test implementations explicitly opt in", () => {
  for (const name of ["CoroutineWaitingHandler", "CoroutineProxyHandler", "CoroutineThrowingHandler"]) {
    const start = gatewayTests.indexOf("class " + name + " final");
    assert.ok(start >= 0);
    const tail = gatewayTests.slice(start, gatewayTests.indexOf("\n};", start));
    assert.match(tail, /nativeEnabled\(\) const noexcept override \{ return true; \}/);
  }
});

test("native protected proxy is mandatory for authenticated and OIDC runtimes", () => {
  const app = read("apps/opp/main.cpp");
  const domain = read("src/gateway/gateway.cpp");
  const implementation = read("src/gateway/http_coroutine.cpp");
  const start = domain.indexOf("bool GatewayNativePreparationSource::eligible(");
  const end = domain.indexOf("HttpResponse GatewayNativePreparationSource::reject(", start);
  assert.ok(start >= 0 && end > start);
  const gate = domain.slice(start, end);
  assert.match(gate, /localProtocolPath\(request\.path\(\)\)/);
  assert.match(gate, /route && route->isProtected\(\)/);
  const local=domain.slice(domain.indexOf("bool localProtocolPath("),start);
  for(const prefix of ["/auth","/admin","/account","/oauth","/login","/.well-known","/evidence","/trust","/scim","/health","/metrics"])
    assert.ok(local.includes('"'+prefix+'"'),prefix);
  assert.match(local,/path\[prefix.size\(\)\] == '\/'/);
  const begin=domain.slice(domain.indexOf("GatewayNativePreparationSource::begin("),domain.indexOf("GatewayNativePreparationSource::admitIdentity("));
  assert.match(begin,/!delegated && \(gateway.m_delegatedAccess != nullptr/);
  assert.match(begin,/gateway.m_senderConstraintVerifier != nullptr/);
  const native = implementation.slice(implementation.indexOf("auto started = begin(*m_gateway"));
  assert.ok(native.includes("co_await m_verify"));
  assert.ok(native.includes("co_await m_authorize"));
  assert.ok(native.includes("co_await m_transport->sendAsync"));
  assert.ok(native.indexOf("co_await m_verify") < native.indexOf("co_await m_authorize"));
  assert.ok(native.indexOf("co_await m_authorize") < native.indexOf("co_await m_transport->sendAsync"));
  assert.doesNotMatch(native, /m_gateway->handle\(|m_fallback->handle\(|m_transport->send\(/);
  assert.match(app, /environment\.get\("OPENPROOF_EXPERIMENTAL_NATIVE_PROTECTED_GATEWAY"\)/);
  assert.match(app, /nativeProtectedGatewayEnabled = platform\.auth\(\)\.enabled\(\)\s*\|\| \(nativeProtectedGatewayFlag && \*nativeProtectedGatewayFlag == "1"\)/);
  assert.match(app, /platform\.auth\(\)\.enabled\(\) && nativeProtectedGatewayFlag && \*nativeProtectedGatewayFlag == "0"/);
  assert.match(native,/!delegated \|\| !delegated->permits\(pending.route.requiredScope\(\)\)/);
  assert.match(app, /nativeProtectedGatewayEnabled\s*&& !platform\.auth\(\)\.enabled\(\)/);
  assert.match(app, /co_await reader->readAuthorizationContextAsync/);
  assert.match(app, /co_await sink->recordAsync/);
  assert.match(app, /runListener\(platform, nativeGateway, logger\)/);
  assert.match(gatewayTests, /TEST\(BeastHttpIntegrationTest, NativeProtectedGatewayForwardsOnlyVerifiedPermittedRequests\)/);
});

test("native local login is mandatory in authenticated runtime with owner-bound proof verification", () => {
  const app = read("apps/opp/main.cpp");
  const cmake = read("apps/opp/CMakeLists.txt");
  assert.match(app, /environment\.get\("OPENPROOF_EXPERIMENTAL_NATIVE_LOCAL_LOGIN"\)/);
  assert.match(app, /nativeLocalFlag && \*nativeLocalFlag != "0" && \*nativeLocalFlag != "1"/);
  assert.match(app, /const bool nativeLocalEnabled = platform\.auth\(\)\.enabled\(\)\s*\|\| \(nativeLocalFlag && \*nativeLocalFlag == "1"\)/);
  assert.match(app, /platform\.auth\(\)\.enabled\(\) && nativeLocalFlag && \*nativeLocalFlag == "0"/);
  assert.match(app, /nativeLocalEnabled && !platform\.auth\(\)\.enabled\(\)/);
  const flag = app.indexOf("OPENPROOF_EXPERIMENTAL_NATIVE_LOCAL_LOGIN");
  assert.ok(flag < app.indexOf("postgres::nativeDatabasePreflight(", flag));
  assert.match(app, /BoundedPasswordExecutor::create\(std::move\(hasher\)\.value\(\), 1U\)/);
  assert.match(app, /nativeLocalProviders->registerProvider\(\s*std::make_unique<local::CoroutineLocalAuthenticationProvider>/);
  assert.match(app, /catalogStatus=providers.registerProvider\(\s*std::make_unique<local::CoroutineLocalAuthenticationProvider>/);
  assert.doesNotMatch(app, /\bpostgres::(?:PostgresLocalAccountDirectory::create|PostgresSessionRepository\s+\w+\s*\{|PostgresAuthenticationTransactionStore\s+\w+\s*\{|PostgresRecoveryCodeRepository\s+\w+\s*\{)/);
  assert.doesNotMatch(app, /\b(?:auth::AuthenticationService authentication|local::LocalAuthenticationProvider\s+\w+)\s*\{/);
  assert.doesNotMatch(app, /std::make_unique<local::LocalAuthenticationProvider>/);
  assert.match(app, /\*nativeLocalProviders,\*nativeTransactions,clock,\s*std::move\(nativeLocalTrust\),std::chrono::minutes\{5\},\*nativeCanonical/);
  assert.match(app, /nativeLocalAuthentication->nativeProviderAuthenticationEnabled\(providerId\)/);
  assert.match(app, /if \(nativeLocalEnabled\) \{\s*nativePaths\.emplace_back\("\/auth\/login"\);\s*nativePaths\.emplace_back\("\/auth\/mfa\/verify"\);\s*\}/);
  assert.match(app, /authHttp::AuthenticationHttpApi nativeLocalApi\{\s*\*nativeLocalAuthentication,\*nativeSessions,limiter\.value\(\),providerId,fallback\}/);
  const constructors = [...app.matchAll(/authHttp::AuthenticationHttpApi \w+\{([\s\S]*?)\};/g)];
  assert.equal(constructors.length, 1);
  for (const [, args] of constructors) {
    assert.match(args, /^\s*\*nativeLocalAuthentication,\s*\*nativeSessions,/);
    assert.doesNotMatch(args, /recoveryCodes|accounts\.value\(\)/);
  }
  const authHttp = read("src/authentication/http/http.cpp");
  assert.match(authHttp, /m_authentication\(&authentication\), m_asyncSessions\(&sessions\)/);
  assert.doesNotMatch(authHttp, /\b(?:m_sessions|m_recoveryCodes|m_localAccounts)\b/);
  const sync = authHttp.slice(authHttp.indexOf("AuthenticationHttpApi::handle("),
    authHttp.indexOf("AuthenticationHttpApi::nativeEnabledFor("));
  assert.match(sync, /SensitiveAuthRequestGuard wipeRequestOnExit\{request\};\s*return error\(foundation::Error\{foundation::ErrorCode::Unavailable\}, request\)/);
  assert.match(app, /runWithEvidence\(fallback,localEnterpriseApi\)/);
  assert.match(app, /runWithEvidence\(fallback,localWeb3Api\)/);
  assert.match(cmake, /openproof_postgres_async_local_credentials/);
});

test("OIDC requires native tenant-bound consent management with no synchronous downgrade",()=> {
  const app=read("apps/opp/main.cpp");
  const http=read("src/oauth/http/coroutine_consent_http.cpp");
  const store=read("src/storage/postgres/coroutine_consent_store.cpp");
  assert.match(app,/const bool nativeConsentEnabled = platform\.oidc\(\)\.enabled\(\)\s*\|\| \(nativeConsentFlag && \*nativeConsentFlag == "1"\)/);
  assert.match(app,/platform\.oidc\(\)\.enabled\(\) && nativeConsentFlag && \*nativeConsentFlag == "0"[\s\S]*?return ExitCode::ConfigurationError;/);
  const flag=app.indexOf('environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_OAUTH_CONSENTS")');
  assert.ok(flag>=0 && flag<app.indexOf("postgres::nativeDatabasePreflight(",flag));
  assert.match(app,/if \(nativeConsentEnabled\) \{\s*nativePaths\.emplace_back\("\/oauth\/consents"\);\s*nativePaths\.emplace_back\("\/oauth\/consents\/revoke"\);/);
  assert.match(app,/std::make_unique<postgres::CoroutineConsentStore>/);
  assert.match(app,/std::make_unique<oauthHttp::CoroutineConsentAdapter>/);
  assert.match(app,/return store->listAsync\(std::move\(owner\)\)/);
  assert.match(app,/return store->revokeAsync\(std::move\(id\), std::move\(owner\), now\)/);
  assert.match(http,/co_await m_authenticate\(std::move\(\*credential\)\)/);
  assert.match(http,/co_await m_list\(current->identity\(\)\)/);
  assert.match(http,/co_await m_revoke\(std::move\(target\).value\(\), current->identity\(\), m_clock->now\(\)\)/);
  assert.doesNotMatch(http,/m_fallback->handle\(/);
  assert.match(store,/i\.id=\$1 AND i\.organization_id=\$2 AND i\.status=0 AND o\.state=0/);
  assert.match(store,/c\.id=\$1 AND c\.identity_id=\$2/);
  assert.match(store,/app\.organization_id=\$4/);
  assert.match(store,/COALESCE\(c\.revoked_at_ms,\$3\)/);
});

test("authenticated runtimes dispatch explicitly public proxy routes without invoking protected authentication",()=>{
  const app=read("apps/opp/main.cpp");
  const domain=read("src/gateway/gateway.cpp");
  const implementation=read("src/gateway/http_coroutine.cpp");
  const gate=domain.slice(domain.indexOf("bool GatewayNativePreparationSource::eligiblePublic("),
    domain.indexOf("HttpResponse GatewayNativePreparationSource::reject("));
  assert.match(gate,/route && !route->isProtected\(\)/);
  assert.match(gate,/if \(!route \|\| route->isProtected\(\)/);
  assert.match(gate,/stripTrustedIdentityHeaders\(request\)/);
  assert.match(gate,/stripHopByHop\(request\)/);
  assert.match(gate,/gateway.completeForward\(/);
  assert.doesNotMatch(gate,/m_sessions->|m_delegatedAccess->|m_access->/);
  assert.match(app,/CoroutineProtectedGatewayAdapter nativePublicGateway\{/);
  assert.match(app,/runListener\(platform,nativePublicGateway,logger\)/);
  assert.equal([...app.matchAll(/nativeGatewayCore = &gatewayCore;/g)].length,2);
  assert.equal([...app.matchAll(/gateway::Gateway gatewayCore\{\s*router, limiter.value\(\), discovery, loadBalancer,/g)].length,2);
  assert.doesNotMatch(app,/\bpostgres::PostgresAuthorizationDecisionSink\s+authorizationAudit/);
  assert.doesNotMatch(app,/\bgateway::PolicyAccessController\s+access\{/);
  assert.match(domain,/if \(!m_sessions \|\| !m_access \|\| !m_proxy\)/);
  const native=implementation.slice(implementation.indexOf("CoroutineProtectedGatewayAdapter::handleAsync("),
    implementation.indexOf("auto started = begin(*m_gateway"));
  assert.match(native,/eligiblePublic\(/);
  assert.match(native,/co_await m_transport->sendAsync\(/);
  assert.doesNotMatch(native,/m_gateway->handle\(|m_transport->send\(/);
});

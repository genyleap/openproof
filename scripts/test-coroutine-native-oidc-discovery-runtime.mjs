#!/usr/bin/env node
// Exact-path, independently opted-in native OIDC discovery/JWKS cutover.
// Source contract only; compiled HTTP integration is a separate release gate.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const root=path.resolve(import.meta.dirname,"..");
const read=f=>fs.readFileSync(path.join(root,f),"utf8");
const app=read("apps/opp/main.cpp");
const header=read("src/oauth/http/coroutine_discovery_http.hpp");
const source=read("src/oauth/http/coroutine_discovery_http.cpp");
const cmake=read("src/oauth/http/CMakeLists.txt");
const legacy=read("src/oauth/http/http.cpp");

test("native public OIDC discovery is mandatory whenever OIDC is enabled",()=>{
  assert.match(app,/environment\.get\("OPENPROOF_EXPERIMENTAL_NATIVE_OIDC_DISCOVERY"\)/);
  assert.match(app,/nativeOidcDiscoveryFlag && \*nativeOidcDiscoveryFlag != "0"/);
  assert.match(app,/const bool nativeOidcDiscoveryEnabled = platform\.oidc\(\)\.enabled\(\)\s*\|\| \(nativeOidcDiscoveryFlag && \*nativeOidcDiscoveryFlag == "1"\)/);
  assert.match(app,/platform\.oidc\(\)\.enabled\(\) && nativeOidcDiscoveryFlag && \*nativeOidcDiscoveryFlag == "0"[\s\S]*?return ExitCode::ConfigurationError;/);
  assert.match(app,/nativeOidcDiscoveryEnabled && !platform\.oidc\(\)\.enabled\(\)/);
  const flag=app.indexOf("OPENPROOF_EXPERIMENTAL_NATIVE_OIDC_DISCOVERY");
  const migrate=app.indexOf("postgres::nativeDatabasePreflight(",flag);
  assert.ok(flag>=0 && migrate>flag,"reject invalid flag before SQL migrations");
  assert.match(app,/const oidc::OpenIdProvider\* nativeOidcProvider = nullptr;/);
  assert.match(app,/nativeOidcProvider = &openIdProvider;/);
});

test("only public discovery/JWKS URLs join the native OAuth slice",()=>{
  const point=app.indexOf("if (nativeOidcDiscoveryEnabled) {",
    app.indexOf("std::vector<std::string> nativePaths;"));
  assert.ok(point>=0);
  const code=app.slice(point,app.indexOf("gatewayHttp::CoroutineRouteOverlay nativeRoutes{",point));
  assert.match(code,/nativeOidcProvider->jwksDocument\(\)/);
  assert.match(code,/nativeOidcProvider->discoveryDocument\(\)/);
  assert.match(code,/if \(!jwks\) \{/);
  assert.match(code,/std::make_unique<oauthHttp::CoroutineOidcDiscoveryAdapter>/);
  assert.match(code,/nativeHandler = asyncOidc\.get\(\)/);
  assert.match(code,/nativePaths\.emplace_back\("\/.well-known\/openid-configuration"\)/);
  assert.match(code,/nativePaths\.emplace_back\("\/.well-known\/jwks.json"\)/);
  assert.doesNotMatch(code,/nativePaths\.emplace_back\("\/oauth\/(?:token|authorize|par|introspect|revoke|device_authorization)"/);
  const init=app.indexOf("nativeOidcProvider = &openIdProvider;");
  assert.ok(init>point,"provider pointer is assigned after setup, before runListener invocation");
});

test("native adapter never calls the synchronous OAuth facade or starts DB I/O",()=>{
  assert.match(header,/class CoroutineOidcDiscoveryAdapter final/);
  assert.match(header,/public gateway::http::CoroutineHttpHandler/);
  assert.match(header,/nativeEnabled\(\) const noexcept override \{ return false; \}/);
  assert.match(source,/CoroutineOidcDiscoveryAdapter::handleAsync\(/);
  assert.match(source,/co_return co_await m_fallback->handleAsync\(std::move\(request\)\)/);
  assert.doesNotMatch(source,/m_fallback->handle\(|m_sessions->|m_tokens->|m_oidc->/);
  assert.match(cmake,/coroutine_discovery_http.cpp/);
  assert.match(cmake,/openproof_gateway_http/);
  assert.match(app,/#include "\.\.\/\.\.\/src\/oauth\/http\/coroutine_discovery_http\.hpp"/);
});

test("native discovery preserves legacy GET and OPTIONS response policy",()=>{
  assert.match(source,/HttpMethod::Get/);
  assert.match(source,/HttpMethod::Options/);
  assert.match(source,/request\.path\(\) == "\/.well-known\/openid-configuration"/);
  assert.match(source,/request\.path\(\) == "\/.well-known\/jwks.json"/);
  for(const name of ["cache-control","pragma","x-content-type-options","referrer-policy",
                     "access-control-allow-origin","access-control-allow-methods",
                     "access-control-allow-headers","access-control-max-age"])
    assert.ok(source.includes('response.setHeader("'+name+'"'));
  assert.match(source,/options \? 204 : 200/);
  assert.match(source,/"content-type", "application\/json"/);
  assert.match(legacy,/m_oidc->discoveryDocument\(\)/);
  assert.match(legacy,/m_oidc->jwksDocument\(\)/);
});

test("credentials are wiped only on discovery and failure, never before native fallback",()=>{
  const route=source.slice(source.indexOf("CoroutineOidcDiscoveryAdapter::handleAsync("));
  const publicBranch=route.slice(route.indexOf("if (readOnlyRoute(request)) {"),
    route.indexOf("co_return response;"));
  for(const method of ["wipeBody","wipeAuthorizationHeader","wipeCookieHeader","wipeTargetQuery"])
    assert.ok(publicBranch.includes("request."+method+"()"));
  const fallback=route.slice(route.indexOf("if (!m_fallback->nativeEnabledFor(request))"));
  for(const method of ["wipeBody","wipeAuthorizationHeader","wipeCookieHeader","wipeTargetQuery"])
    assert.ok(fallback.includes("request."+method+"()"));
  assert.match(fallback,/co_return co_await m_fallback->handleAsync\(std::move\(request\)\)/);
  assert.doesNotMatch(source,/co_return co_await m_fallback->handle\(/);
});

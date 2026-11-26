#!/usr/bin/env node
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const root=path.resolve(import.meta.dirname,"..");
const read=f=>fs.readFileSync(path.join(root,f),"utf8");
const app=read("apps/opp/main.cpp");
const header=read("src/authentication/http/coroutine_provider_catalog_http.hpp");
const code=read("src/authentication/http/coroutine_provider_catalog_http.cpp");
const cmake=read("src/authentication/http/CMakeLists.txt");
const old=read("src/authentication/http/federated.cpp");

test("catalog is mandatory for enabled authentication and validated before database setup",()=>{
  const flag=app.indexOf('environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_PROVIDER_CATALOG")');
  const migrations=app.indexOf("postgres::nativeDatabasePreflight(",flag);
  assert.ok(flag>0 && migrations>flag);
  assert.match(app,/nativeCatalogFlag && \*nativeCatalogFlag != "0"/);
  assert.match(app,/const bool nativeCatalogEnabled = platform\.auth\(\)\.enabled\(\)\s*\|\| \(nativeCatalogFlag && \*nativeCatalogFlag == "1"\)/);
  assert.match(app,/platform\.auth\(\)\.enabled\(\) && nativeCatalogFlag && \*nativeCatalogFlag == "0"[\s\S]*?return ExitCode::ConfigurationError;/);
  assert.match(app,/nativeCatalogEnabled && !platform\.auth\(\)\.enabled\(\)/);
  assert.match(app,/if \(nativeCatalogEnabled\) \{/);
});

test("public catalog snapshots the same registered provider projection",()=>{
  const i=app.indexOf("if (nativeCatalogEnabled) {",app.indexOf("std::vector<std::string> nativePaths;"));
  assert.ok(i>=0);
  const sub=app.slice(i,app.indexOf("gatewayHttp::CoroutineRouteOverlay nativeRoutes",i));
  for (const part of [
    "providers.ids()", "providers.find(registeredProvider)",
    "idp::InteractionModel::Redirect",
    "idp::InteractionModel::ChallengeResponse",
    'catalog["providers"]',
    'catalog["challenge_providers"]',
    "boost::json::serialize(catalog)",
    "nativePaths.emplace_back(\"/auth/providers\")"
  ]) assert.ok(sub.includes(part),part);
  assert.match(sub,/std::make_unique<authHttp::CoroutineProviderCatalogAdapter>/);
  assert.match(sub,/nativeHandler = asyncCatalog\.get\(\)/);
  const oldStart=old.indexOf("FederatedAuthenticationHttpApi::providers()");
  const oldBody=old.slice(oldStart,old.indexOf("FederatedAuthenticationHttpApi::connectionComplete()",oldStart));
  assert.match(oldBody,/m_providers->ids\(\)/);
  assert.match(oldBody,/"providers"/);
  assert.match(oldBody,/"challenge_providers"/);
});

test("the new adapter never runs provider auth or blocked database IO",()=>{
  assert.match(header,/class CoroutineProviderCatalogAdapter final/);
  assert.match(header,/nativeEnabled\(\) const noexcept override \{ return false; \}/);
  assert.match(code,/asio::awaitable<gateway::HttpResponse>/);
  assert.match(code,/co_return co_await m_fallback->handleAsync\(std::move\(request\)\)/);
  assert.doesNotMatch(code,/\.run\(\)|PQexec|PQconnectdb|m_fallback->handle\(/);
  assert.match(cmake,/add_library\(openproof_authentication_async_catalog_http STATIC/);
  assert.match(read("apps/opp/CMakeLists.txt"),/openproof_authentication_async_catalog_http/);
});

test("native catalog is exact GET-only and scrubs ignored request secrets",()=>{
  assert.match(code,/request\.method\(\) == gateway::HttpMethod::Get/);
  assert.match(code,/request\.path\(\) == "\/auth\/providers"/);
  assert.match(code,/"content-type", "application\/json"/);
  assert.match(code,/cache-control/);
  assert.match(code,/x-content-type-options/);
  const branch=code.slice(code.indexOf("if (isCatalogRoute(request)) {"));
  for(const name of ["wipeBody","wipeAuthorizationHeader","wipeCookieHeader","wipeTargetQuery"])
    assert.match(branch,new RegExp("request\\."+name+"\\(\\)"));
  assert.match(code,/if \(!m_fallback->nativeEnabledFor\(request\)\)/);
  assert.match(code,/co_return co_await m_fallback->handleAsync\(std::move\(request\)\)/);
});

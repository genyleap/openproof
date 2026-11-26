import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {cppExecutableText} from "./cpp-lexical-scan.mjs";
const root=path.resolve(import.meta.dirname,"..");
const read=file=>fs.readFileSync(path.join(root,file),"utf8");
const app=read("apps/opp/main.cpp");
const http=read("src/operations/http/coroutine_health_http.cpp");
const store=read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
test("production health routes exclusively use strict native dispatch",()=>{
  assert.match(app,/operationsHttp::CoroutineHealthAdapter nativeHealth/);
  assert.match(app,/reader->healthCheckAsync\(\)/);
  assert.match(app,/nativePaths.emplace_back\("\/health\/live"\)/);
  assert.match(app,/nativePaths.emplace_back\("\/health\/ready"\)/);
  assert.match(app,/CoroutineRouteOverlay nativeRoutes\{\s*evidenceApi, nativeHealth,/);
  assert.doesNotMatch(app,/operationsHttp::PostgresReadinessCheck\s+\w+\s*\{/);
  assert.doesNotMatch(app,/operationsHttp::HealthHttpApi\s+\w+\s*\{/);
  assert.doesNotMatch(cppExecutableText(http),/m_fallback->handle\(|PQexec|condition_variable|\.wait_for\(/);
});
test("liveness has no SQL dependency and readiness is bounded and fail-closed",()=>{
  const body=http.slice(http.indexOf("CoroutineHealthAdapter::handleAsync("));
  const ordered=["scrub(request);","method!=gateway::HttpMethod::Get","if (live) co_return response(200,true)",
    "if (!m_check) co_return response(503,false)","co_await m_check()","checked?response(200,true):response(503,false)"];
  let previous=-1;
  for(const term of ordered){
    const index=body.indexOf(term,previous+1);
    assert.ok(index>previous,term);
    previous=index;
  }
  const probe=store.slice(store.indexOf("CoroutinePostgresCanonicalFinalizer::healthCheckAsync("));
  assert.match(probe,/Clock::now\(\)\+m_impl->queryTimeout/);
  assert.match(probe,/co_await m_impl->pool.acquire\(deadline\)/);
  assert.match(probe,/co_await lease.connection\(\).query\("SELECT 1",\{\},remaining\(deadline\)\)/);
  assert.match(probe,/rows.rows.front\(\).front\(\)!=std::optional<std::string>\{"1"\}/);
  assert.doesNotMatch(cppExecutableText(probe),/PQexec|PQconnectdb|PQreset|wait_for\(/);
  assert.match(read("tests/operations/coroutine_health_test.cpp"),/ReadinessAwaitsDependencyAndLivenessNeverTouchesStorage/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/RealDatabaseNativeReadinessChecksActualPool/);
  assert.match(read(".github/workflows/ci.yml"),/openproof_native_health_tests/);
});

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {cppExecutableText} from "./cpp-lexical-scan.mjs";
const root=path.resolve(import.meta.dirname,"..");
const read=file=>fs.readFileSync(path.join(root,file),"utf8");
const app=read("apps/opp/main.cpp");
const http=read("src/enterprise/scim/http/coroutine_read_http.cpp");
const wire=read("src/enterprise/scim/http/http.cpp");
const source=read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
const sql=source.slice(source.indexOf("CoroutinePostgresCanonicalFinalizer::readScimAsync("));
test("SCIM read ownership preserves write dispatch and fails closed if native reads are unavailable",()=>{
  assert.match(app,/strictMethodPrefixes.emplace_back\("\/scim\/v2\/",gateway::HttpMethod::Get\)/);
  assert.match(app,/reader->readScimAsync/);
  assert.match(app,/scimBearerToken->clone\(\)/);
  assert.match(http,/r.method\(\)==gateway::HttpMethod::Get && r.path\(\).starts_with\("\/scim\/v2\/"\)/);
  const order=["m_limiter->allow","security::constantTimeEquals","r.wipeAuthorizationHeader();",
    "renderDiscovery(r)","parseReadRequest(r)","co_await m_read","renderReadResult"];
  let previous=http.indexOf("CoroutineReadAdapter::handleAsync(");
  for(const term of order){
    const index=http.indexOf(term,previous+1);
    assert.ok(index>previous,term);previous=index;
  }
  assert.doesNotMatch(cppExecutableText(http),/m_fallback->handle\(|PQexec/);
  const overlay=read("src/gateway/http_coroutine.cpp");
  assert.match(overlay,/method==request.method\(\) && !prefix.empty\(\) && prefix.back\(\)=='\/'/);
  assert.match(overlay,/overlays\(request.path\(\)\) \|\| strictMethodOverlay\(request\) \|\| nativeEnabledFor\(request\)/);
  assert.match(read("tests/gateway/http_integration_test.cpp"),/StrictMethodPrefixNeverFallsBackForReads/);
});
test("SCIM user and group reads are tenant-scoped consistent bounded projections",()=>{
  for(const term of ["BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
    "SELECT id FROM openproof.organizations WHERE id=$1 AND state=0",
    "i.organization_id=u.organization_id","WHERE u.organization_id=$1 AND i.kind=0",
    "LEFT JOIN openproof.identity_profiles p ON p.identity_id=i.id",
    "'active',i.status=0","WHERE organization_id=g.organization_id",
    "AND group_id=g.id","WHERE g.organization_id=$1",
    "u.identity_id=$2","g.id=$2","u.user_name=$2","g.display_name=$2",
    "LIMIT 10001","children.total<=10000","count(value)=count(*)",
    "COALESCE(sum(octet_length(value)),0)<=8380000","NULL::text,NULL::text,NULL::text,NULL::bigint",
    'execute("COMMIT",{})'])
    assert.ok(sql.includes(term),term);
  assert.doesNotMatch(cppExecutableText(sql),/PQexec|PQconnectdb/);
  assert.match(wire,/filter->first!=\(kind==ReadKind::Users\?"userName":"displayName"\)/);
  assert.match(wire,/response.setHeader\("etag",versionTag\(result.rows.front\(\).updatedAt\)\)/);
  assert.match(wire,/renderDiscovery\(const gateway::HttpRequest& request\)/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/NativeScimReadsPreserveTenantAndCanonicalState/);
});
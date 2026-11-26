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
const sql=source.slice(source.indexOf("std::string scimProjection("),
  source.indexOf("CoroutinePostgresCanonicalFinalizer::mutateScimAsync("));
test("SCIM read and mutation ownership fails closed if native storage is unavailable",()=>{
  assert.match(app,/strictNativePrefixes.emplace_back\("\/scim\/v2\/"\)/);
  assert.match(app,/reader->mutateScimAsync/);
  assert.doesNotMatch(app,/\b(?:PostgresScimDirectoryRepository|scim::Service|scimHttp::Api)\s+\w+\s*\{/);
  assert.match(app,/reader->readScimAsync/);
  assert.match(app,/scimBearerToken->clone\(\)/);
  assert.match(http,/r.path\(\)=="\/scim\/v2" \|\| r.path\(\).starts_with\("\/scim\/v2\/"\)/);
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
test("SCIM native writes serialize owner, identity and metadata changes, preserving tenant and version invariants",()=>{
  const store=source.slice(source.indexOf("CoroutinePostgresCanonicalFinalizer::mutateScimAsync("));
  const order=["BEGIN ISOLATION LEVEL READ COMMITTED","pg_advisory_xact_lock(7299730475761673315)",
    "WHERE id=$1 AND state=0 FOR SHARE","pg_advisory_xact_lock(hashtextextended($1::text, 684271993))",
    "WHERE u.organization_id=$1 AND u.identity_id=$2 AND i.kind=0 FOR UPDATE OF u,i,m",
    "request.expectedVersion","timestamp=std::max(timestamp,previous+1)","INSERT INTO openproof.identities",
    "INSERT INTO openproof.memberships","INSERT INTO openproof.identity_profiles","INSERT INTO openproof.scim_users",
    "FOR UPDATE OF m,i,r","UPDATE openproof.sessions SET state=1","UPDATE openproof.oauth_token_families SET revoked_at_ms",
    "DELETE FROM openproof.scim_users","scimProjection(users,scim::ReadSelector::Id)",'execute("COMMIT",{})'];
  let previous=-1;
  for(const term of order){
    const index=store.indexOf(term,previous+1);
    assert.ok(index>previous,term);previous=index;
  }
  for(const term of ["status>=4","status==2 || membership==0","WHERE organization_id=$1 AND identity_id=$2",
    "UPDATE openproof.scim_groups g SET updated_at_ms=GREATEST(g.updated_at_ms+1",
    "JOIN openproof.scim_users u ON u.organization_id=$1 AND u.identity_id=v.id",
    "DELETE FROM openproof.scim_group_members WHERE organization_id=$1 AND group_id=$2",
    "INSERT INTO openproof.scim_group_members(organization_id,group_id,identity_id)"])
    assert.ok(store.includes(term),term);
  assert.doesNotMatch(cppExecutableText(store),/PQexec|PQconnectdb/);
  assert.match(http,/parseMutationRequest\(r\);\s*scrub\(r\)/);
  assert.match(http,/co_await m_mutate\(std::move\(command\).value\(\)\)/);
  assert.match(wire,/command.expectedVersion=foundation::Instant/);
  assert.match(wire,/MemberAction::Remove/);
  assert.match(wire,/response.setHeader\("location"/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/NativeScimMutationsAreAtomicAndVersioned/);
});
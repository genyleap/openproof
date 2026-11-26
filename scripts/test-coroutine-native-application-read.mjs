import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {cppExecutableText} from "./cpp-lexical-scan.mjs";
const root=path.resolve(import.meta.dirname,"..");
const read=file=>fs.readFileSync(path.join(root,file),"utf8");
const app=read("apps/opp/main.cpp");
const http=read("src/application/http/coroutine_management_read_http.cpp");
const source=read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
const sql=source.slice(source.indexOf("CoroutinePostgresCanonicalFinalizer::readApplicationManagementAsync("),
  source.indexOf("CoroutinePostgresCanonicalFinalizer::mutateApplicationAsync("));
test("five management reads exclusively use native first-party IAL2 authentication",()=>{
  for(const route of ["/admin/applications","/admin/clients","/admin/clients/jar-key","/admin/resources","/admin/service-identities"])
    assert.ok(http.includes('r.path()=="'+route+'"'),route);
  assert.match(http,/r.method\(\)!=Method::Get/);
  assert.match(app,/nativeMethods.emplace_back\(route,gateway::HttpMethod::Get\)/);
  assert.match(app,/reader->readApplicationManagementAsync/);
  assert.match(http,/starts_with\("DPoP "\)/);
  const ordered=["gateway::takeSessionCredential(r)","scrub(r);","co_await m_authenticate","AssuranceLevel::Ial2","co_await m_read"];
  let previous=-1;
  for(const term of ordered){
    const index=http.indexOf(term,previous+1);
    assert.ok(index>previous,term); previous=index;
  }
  assert.doesNotMatch(cppExecutableText(http),/m_fallback->handle\(|PQexec/);
});
test("management projection is bounded, owner and session checked in a consistent read-only snapshot",()=>{
  for(const term of ["BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
    "s.id=$3 AND s.state=0","i.status=0 AND o.state=0 AND m.state=1","r.role='owner'",
    "s.last_seen_at_ms+s.idle_timeout_ms>$4","assurance<2 || assurance>4",
    "WHERE organization_id=$1 ORDER BY id","c.application_id=$1 AND a.organization_id=$2",
    "WHERE c.id=$1 AND a.organization_id=$2","s.client_id=$1 AND a.organization_id=$2 AND i.kind=1",
    "cardinality(redirects)<=256","count(value)=count(*)",
    "COALESCE(sum(octet_length(value)),0)<=2096000","NULL::text FROM bounds WHERE NOT ok"])
    assert.ok(sql.includes(term),term);
  assert.doesNotMatch(cppExecutableText(sql),/secret_digest|PQexec|INSERT INTO|UPDATE openproof|DELETE FROM/);
  assert.ok(sql.indexOf("if (assurance<2")<sql.indexOf("switch(operation)"));
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/NativeApplicationReadsRequireCurrentOwnerSessionAndNeverProjectSecrets/);
});
test("application lifecycle owns exact routes and commits valid domain transitions under owner and row locks",()=>{
  const store=source.slice(source.indexOf("CoroutinePostgresCanonicalFinalizer::mutateApplicationAsync("));
  for(const route of ["/admin/applications","/admin/applications/suspend","/admin/applications/activate","/admin/applications/revoke"])
    assert.ok(http.includes('r.path()=="'+route+'"'),route);
  assert.match(app,/nativePaths.emplace_back\(route\)/);
  assert.match(app,/reader->mutateApplicationAsync/);
  assert.match(http,/r.method\(\)!=Method::Post/);
  assert.match(http,/r.wipeBody\(\);[\s\S]*?ApplicationMutationCommand/);
  assert.match(http,/object.size\(\)!=1U/);
  assert.match(http,/object.size\(\)!=3U/);
  assert.match(http,/security::randomTokenBase64Url\(24U\)/);
  assert.match(http,/co_await m_mutate\(std::move\(\*command\),actor->identity\(\),actor->id\(\)\)/);
  const ordered=["BEGIN ISOLATION LEVEL READ COMMITTED","pg_advisory_xact_lock(7299730475761673315)",
    "r.role='owner'","s.id=$3 AND s.state=0","FOR SHARE OF o,i,m,r,s","assurance<2 || assurance>4"];
  // Check the session and role predicates independently, then ordering of authorization.
  for(const term of ordered) assert.ok(store.includes(term),term);
  assert.ok(store.indexOf("pg_advisory_xact_lock")<store.indexOf("FOR SHARE OF o,i,m,r,s"));
  assert.ok(store.indexOf("assurance<2")<store.indexOf("INSERT INTO openproof.applications"));
  assert.match(store,/application::Application::create/);
  assert.match(store,/ON CONFLICT DO NOTHING RETURNING id/);
  assert.match(store,/WHERE id=\$1 AND organization_id=\$2 FOR UPDATE/);
  assert.match(store,/application::Application::restore/);
  assert.match(store,/restored->suspend\(now\)[\s\S]*?restored->activate\(now\):restored->revoke\(now\)/);
  assert.ok(store.indexOf("UPDATE openproof.applications")<store.lastIndexOf('execute("COMMIT",{})'));
  assert.doesNotMatch(cppExecutableText(store),/PQexec|PQconnectdb/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/ASSERT_NE\(a.has_value\(\),b.has_value\(\)\)/);
});

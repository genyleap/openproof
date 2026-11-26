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
  const store=source.slice(source.indexOf("CoroutinePostgresCanonicalFinalizer::mutateApplicationAsync("),
    source.indexOf("CoroutinePostgresCanonicalFinalizer::mutateOAuthClientAsync("));
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
test("native client lifecycle and secret rotation preserve domain checks and expose raw secrets only after commit",()=>{
  for(const route of ["/admin/clients","/admin/clients/suspend","/admin/clients/activate","/admin/clients/revoke","/admin/clients/rotate-secret"])
    assert.ok(http.includes('r.path()=="'+route+'"'),route);
  assert.match(app,/reader->mutateOAuthClientAsync/);
  assert.match(app,/nativeOAuthClientKey->clone\(\)/);
  const ordered=["parseClientMutation(r,*clientWrite)","gateway::takeSessionCredential(r)",
    "co_await m_authenticate","AssuranceLevel::Ial2","secret.emplace(\"ops_\"+raw.value())",
    "security::hmacSha256(m_clients->key,secret->expose())","clientCommand->digest.emplace",
    "co_await m_clients->mutate","if (!changed)","body[\"client_secret_returned_once\"]","append(secret->expose())"];
  let previous=-1;
  for(const term of ordered){
    const index=http.indexOf(term,previous+1);
    assert.ok(index>previous,term); previous=index;
  }
  const store=source.slice(source.indexOf("CoroutinePostgresCanonicalFinalizer::mutateOAuthClientAsync("),
    source.indexOf("CoroutinePostgresCanonicalFinalizer::mutateOAuthJarKeyAsync("));
  for(const term of ["pg_advisory_xact_lock(7299730475761673315)","FOR SHARE OF o,i,m,r,s",
    "assurance<2 || assurance>4","WHERE id=$1 AND organization_id=$2 FOR SHARE",
    "client::Client::create","INSERT INTO openproof.oauth_clients","INSERT INTO openproof.oauth_client_redirect_uris",
    "INSERT INTO openproof.oauth_client_scopes","WHERE c.id=$1 AND a.organization_id=$2 FOR UPDATE OF c FOR SHARE OF a",
    "client::Client::restore","restored->replaceSecret(*command.digest,now)",
    "UPDATE openproof.oauth_clients SET status=$3,secret_digest=decode($4,'hex')"])
    assert.ok(store.includes(term),term);
  assert.ok(store.indexOf("assurance<2")<store.indexOf("INSERT INTO openproof.oauth_clients"));
  assert.ok(store.indexOf("UPDATE openproof.oauth_clients")<store.lastIndexOf('execute("COMMIT",{})'));
  assert.doesNotMatch(cppExecutableText(store),/PQexec|SecretString|randomTokenBase64Url/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/ASSERT_NE\(ca.has_value\(\),cb.has_value\(\)\)/);
});
test("JAR key management validates one RSA public envelope and preserves durable replay protection",()=>{
  const store=source.slice(source.indexOf("CoroutinePostgresCanonicalFinalizer::mutateOAuthJarKeyAsync("),
    source.indexOf("CoroutinePostgresCanonicalFinalizer::mutateOAuthResourceAsync("));
  assert.match(http,/r.path\(\)=="\/admin\/clients\/jar-key"\s*&& \(r.method\(\)==Method::Post \|\| r.method\(\)==Method::Delete\)/);
  assert.match(http,/parseJarMutation\(r\)/);
  assert.match(http,/co_await m_clients->mutateJarKey/);
  assert.match(app,/reader->mutateOAuthJarKeyAsync/);
  assert.match(app,/nativePaths.emplace_back\(route\)/);
  for(const term of ["pem.starts_with(begin)","pem.ends_with(end)","pem.find(\"-----BEGIN \",begin.size())",
    "security::validateRs256PublicKey(pem)","oauth::ClientRequestSigningKey::create",
    "pg_advisory_xact_lock(7299730475761673315)","FOR SHARE OF o,i,m,r,s","assurance<2 || assurance>4",
    "WHERE c.id=$1 AND a.organization_id=$2 FOR UPDATE OF c FOR SHARE OF a",
    "if (key && milliseconds(parent.rows.front()[1])==2)",
    "INSERT INTO openproof.oauth_client_request_signing_keys","ON CONFLICT(client_id) DO UPDATE",
    "updated_at_ms<=EXCLUDED.updated_at_ms","DELETE FROM openproof.oauth_client_request_signing_keys"])
    assert.ok(store.includes(term),term);
  assert.ok(store.indexOf("assurance<2")<store.indexOf("INSERT INTO openproof.oauth_client_request_signing_keys"));
  assert.ok(store.indexOf("DELETE FROM openproof.oauth_client_request_signing_keys")<store.lastIndexOf('execute("COMMIT",{})'));
  assert.doesNotMatch(store,/DELETE FROM openproof.oauth_jar_replays/);
  assert.doesNotMatch(cppExecutableText(store),/PQexec|PQconnectdb/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/keyTask\(client,"stale",pem/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/keyTask\(client,"bad",pem\+pem\)/);
});
test("resource lifecycle locks grant admission rows and preserves existing scopes",()=>{
  const store=source.slice(source.indexOf("CoroutinePostgresCanonicalFinalizer::mutateOAuthResourceAsync("));
  for(const route of ["/admin/resources","/admin/resources/suspend","/admin/resources/activate","/admin/resources/revoke"])
    assert.ok(http.includes('r.path()=="'+route+'"'),route);
  assert.match(http,/parseResourceMutation\(r,\*resourceWrite\)/);
  assert.match(http,/co_await m_resources\(std::move\(\*resourceCommand\),actor->identity\(\),actor->id\(\)\)/);
  assert.match(app,/reader->mutateOAuthResourceAsync/);
  assert.match(app,/nativePaths.emplace_back\(route\)/);
  for(const term of ["resource::ResourceServer::create","pg_advisory_xact_lock(7299730475761673315)",
    "FOR SHARE OF o,i,m,r,s","assurance<2 || assurance>4","INSERT INTO openproof.oauth_resources",
    "ON CONFLICT DO NOTHING RETURNING id","INSERT INTO openproof.oauth_resource_scopes",
    "FROM openproof.oauth_resources WHERE audience=$1 FOR UPDATE",
    "resource::ResourceServer::restore","now<updatedAt","restored->setStatus(target,now)",
    "UPDATE openproof.oauth_resources SET status=$3,updated_at_ms=$4"])
    assert.ok(store.includes(term),term);
  assert.ok(store.indexOf("assurance<2")<store.indexOf("INSERT INTO openproof.oauth_resources"));
  assert.ok(store.indexOf("UPDATE openproof.oauth_resources")<store.lastIndexOf('execute("COMMIT",{})'));
  assert.doesNotMatch(store,/DELETE FROM openproof.oauth_resource_scopes/);
  assert.doesNotMatch(cppExecutableText(store),/PQexec|PQconnectdb/);
  const fixture=read("tests/storage/postgres_async_canonical_test.cpp");
  assert.match(fixture,/resourceChange\(ROp::Revoke\)/);
  assert.match(fixture,/resourceChange\(ROp::Activate\)/);
  assert.match(fixture,/staleResource.error\(\).code\(\),fnd::ErrorCode::Conflict/);
});

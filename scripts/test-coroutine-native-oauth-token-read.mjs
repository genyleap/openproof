import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import {cppExecutableText} from "./cpp-lexical-scan.mjs";
const root=path.resolve(import.meta.dirname,"..");
const read=file=>fs.readFileSync(path.join(root,file),"utf8");
const http=read("src/oauth/http/coroutine_token_read_http.cpp");
const sql=read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
const app=read("apps/opp/main.cpp");
test("OIDC token reads are strict native and use durable sender replay",()=>{
  for(const route of ["/oauth/userinfo","/oauth/introspect","/oauth/revoke"])
    assert.ok(app.includes('nativePaths.emplace_back("'+route+'")'));
  for(const call of ["reader->readDelegatedAccessAsync(","reader->authenticateConfidentialClientAsync(",
    "reader->readProfileAsync(","sender->verifyAsync(","reader->consumeSenderReplayAsync("])
    assert.ok(app.includes(call),call);
  assert.doesNotMatch(cppExecutableText(http),/m_fallback->handle\(|PQexec|m_tokens->|m_clients->|m_oidc->/);
});
test("UserInfo validates token and sender before scoped owner projection",()=>{
  const body=http.slice(http.indexOf("CoroutineTokenReadAdapter::userInfo("),
    http.indexOf("CoroutineTokenReadAdapter::introspect("));
  const ordered=["r.wipeAuthorizationHeader()","security::hmacSha256(m_tokenKey",
    "co_await m_access(","access->permits(\"openid\")","m_sender(","co_await std::move(verification)",
    "credential=foundation::SecretString{}","co_await m_profile(owner)","profile->identity()!=owner"];
  let previous=-1;
  for(const term of ordered) {
    const index=body.indexOf(term,previous+1);
    assert.ok(index>previous,term);
    previous=index;
  }
  assert.match(body,/access->permits\("profile"\)/);
  assert.match(body,/access->permits\("email"\) && profile->email\(\)/);
  assert.match(body,/else if \(dpop\) co_return invalidBearer\(\)/);
});
test("introspection requires confidential client and erases raw form credentials before native lookup",()=>{
  const body=http.slice(http.indexOf("CoroutineTokenReadAdapter::introspect("));
  const ordered=["security::hmacSha256(m_clientKey","security::hmacSha256(m_tokenKey",
    "input->secret=foundation::SecretString{}","input->token=foundation::SecretString{}",
    "co_await m_client(","if (!caller)","co_await m_access("];
  let previous=-1;
  for(const term of ordered){
    const index=body.indexOf(term,previous+1);
    assert.ok(index>previous,term);
    previous=index;
  }
  assert.match(body,/E::AuthenticationFailed && access.error\(\).code\(\)!=E::NotFound/);
  assert.match(body,/body.add\("active",false\)/);
  assert.match(body,/\.add\("iat",seconds\(issued\)\)/);
  const client=sql.slice(sql.indexOf("CoroutinePostgresCanonicalFinalizer::authenticateConfidentialClientAsync("));
  for(const term of ["co_await m_impl->pool.acquire","a.organization_id=$2","o.state=0",
    "c.status=0 AND a.status=0 AND c.kind IN (0,3)","security::constantTimeEquals"])
    assert.ok(client.includes(term),term);
  assert.match(sql,/g.kind,g.value,t.issued_at_ms/);
  assert.match(sql,/if \(issuedAt\) \*issuedAt=issued/);
  assert.match(read("tests/oauth_native_consent_test.cpp"),/ScopedUserInfoAndAuthenticatedIntrospectionNeverUseLegacy/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/authenticateClient\(foreign,clientProof\)/);
  assert.match(read("scripts/e2e-identity-platform.mjs"),/claims.exp>claims.iat/);
});
test("native revocation binds caller and tenant, serializes family mutation and is idempotent",()=>{
  const body=http.slice(http.indexOf("CoroutineTokenReadAdapter::revoke("));
  assert.match(body,/form\(r,false\)/);
  const ordered=["security::hmacSha256(m_tokenKey","input->secret=foundation::SecretString{}",
    "input->token=foundation::SecretString{}","co_await m_revoke(","if (!result)","response{200"];
  let previous=-1;
  for(const term of ordered) {
    const index=body.indexOf(term,previous+1);
    assert.ok(index>previous,term);
    previous=index;
  }
  const store=sql.slice(sql.indexOf("CoroutinePostgresCanonicalFinalizer::revokeOAuthTokenAsync("));
  for(const term of ["FOR SHARE OF c,a,o","security::constantTimeEquals","!clientDigest",
    "WHERE f.client_id=$2 AND i.organization_id=$3","FOR UPDATE OF f",
    "WHERE token_digest=decode($1,'hex') AND family_id=$2",
    "UPDATE openproof.oauth_token_families SET revoked_at_ms=COALESCE",
    "UPDATE openproof.oauth_refresh_tokens SET state=2","WHERE family_id=$1 AND state<>2"])
    assert.ok(store.includes(term),term);
  assert.ok(store.indexOf("if (!authenticated)")<store.indexOf("FOR UPDATE OF f"));
  assert.ok(store.indexOf("FOR UPDATE OF f")<store.indexOf("UPDATE openproof.oauth_access_tokens"));
  assert.match(store,/if \(found.rows.empty\(\)\) \{[\s\S]*?execute\("COMMIT",\{\}\)[\s\S]*?co_return foundation::ok\(\)/);
  assert.match(app,/reader->revokeOAuthTokenAsync/);
  const legacy=read("src/oauth/http/http.cpp");
  assert.match(legacy,/m_nativeTokenReadsRequired && \(path=="\/oauth\/userinfo"\s*\|\| path=="\/oauth\/introspect" \|\| path=="\/oauth\/revoke"\)/);
  const pg=read("src/storage/postgres/postgres.cpp");
  const rotate=pg.slice(pg.indexOf("PostgresIdentityProviderStore::rotateRefresh("),pg.indexOf("PostgresIdentityProviderStore::revokeFamily("));
  assert.ok(rotate.indexOf("FOR UPDATE OF f")<rotate.indexOf("ResultPointer current="));
  assert.ok(rotate.indexOf("!PQgetisnull(familyLock.get(),0,1)")<rotate.indexOf("INSERT INTO openproof.oauth_access_tokens"));
  const revoke=pg.slice(pg.indexOf("PostgresIdentityProviderStore::revokeToken("));
  assert.equal((revoke.match(/FOR UPDATE OF f/g)??[]).length,2);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/Race native family revocation against the still-legacy rotation/);
  assert.match(read("scripts/e2e-identity-platform.mjs"),/another client's token: no-op/);
});

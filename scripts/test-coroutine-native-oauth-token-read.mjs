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
  for(const route of ["/oauth/userinfo","/oauth/introspect"])
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

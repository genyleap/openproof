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
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/co_spawn\(io,peer.rotateOAuthRefreshAsync[\s\S]*?co_spawn\(io,native.revokeOAuthTokenAsync/);
  assert.match(read("scripts/e2e-identity-platform.mjs"),/another client's token: no-op/);
});
test("native refresh uses grant-scoped routing, durable proof and atomic family rotation",()=>{
  const refresh=http.slice(http.indexOf("CoroutineTokenReadAdapter::refresh("));
  const ordered=["form(r,false,true)","security::hmacSha256(m_tokenKey,input->token.expose())",
    "input->secret=foundation::SecretString{}","input->token=foundation::SecretString{}",
    "m_prepareSender(r)","co_await std::move(proof)","co_await m_rotate(",
    "if (!scopes)",'body.add("access_token",access.expose())'];
  let previous=-1;
  for(const term of ordered){
    const index=refresh.indexOf(term,previous+1);
    assert.ok(index>previous,term); previous=index;
  }
  assert.match(http,/value->expose\(\)==grantType/);
  assert.match(http,/grantRoute\(r,"refresh_token"\)/);
  assert.match(app,/nativePaths.emplace_back\("\/oauth\/token"\)/);
  assert.match(app,/reader->rotateOAuthRefreshAsync/);
  assert.match(app,/sender->tokenEndpointConstraintAsync/);
  assert.match(app,/nativeOAuthAccessLifetime=tokenPolicy->accessLifetime\(\)/);
  const legacy=read("src/oauth/http/http.cpp");
  const token=legacy.slice(legacy.indexOf("OAuthHttpApi::tokenEndpoint("));
  assert.ok(token.indexOf('m_nativeTokenReadsRequired && grantType.value()=="refresh_token"')>=0);
  assert.ok(token.indexOf('m_nativeTokenReadsRequired && grantType.value()=="refresh_token"')<token.indexOf("m_clients->authenticate("));
  const store=sql.slice(sql.indexOf("CoroutinePostgresCanonicalFinalizer::rotateOAuthRefreshAsync("),
    sql.indexOf("CoroutinePostgresCanonicalFinalizer::exchangeOAuthCodeAsync("));
  for(const term of ["FOR SHARE OF c,a,o","security::constantTimeEquals",
    "f.client_id=$2 AND i.organization_id=$3","FOR UPDATE OF f","senderMatches",
    "WHERE token_digest=decode($1,'hex') AND family_id=$2 FOR UPDATE",
    "state!=0 || expires<=observed","UPDATE openproof.oauth_token_families SET revoked_at_ms",
    "sequence==std::numeric_limits","std::to_string(sequence+1),timestamp,std::to_string(expires)"])
    assert.ok(store.includes(term),term);
  assert.ok(store.indexOf("FOR UPDATE OF f")<store.indexOf("family_id=$2 FOR UPDATE"));
  assert.ok(store.indexOf("UPDATE openproof.oauth_token_families SET revoked_at_ms")<store.indexOf('execute("COMMIT",{})'));
  assert.ok(store.lastIndexOf('execute("COMMIT",{})')<store.indexOf("co_return scopes"));
  const sender=read("src/oauth/http/sender.cpp");
  const proof=sender.slice(sender.indexOf("SenderProofVerifier::tokenEndpointConstraintAsync("),sender.indexOf("SenderProofVerifier::tokenEndpointConstraint("));
  assert.match(proof,/prepareDpop\(request,nullptr\):prepareMtlsForwarding\(request\)/);
  assert.match(proof,/co_await consume\(/);
  assert.doesNotMatch(proof,/m_dpop->consume|m_mtlsReplays->|verifyDpop\(/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/Fresh family for native\/native rotation/);
  assert.match(read("tests/oauth_native_consent_test.cpp"),/grant_type=refresh%5Ftoken/);
});
test("native code exchange validates PKCE and atomically issues the initial family before responding",()=>{
  const exchange=http.slice(http.indexOf("CoroutineTokenReadAdapter::exchangeCode("));
  const ordered=["codeForm(r)","security::sha256(verifier)",
    "security::hmacSha256(m_codeExchange->codeKey","input->code=foundation::SecretString{}",
    "input->verifier=foundation::SecretString{}","input->secret=foundation::SecretString{}",
    "m_prepareSender(r)","co_await std::move(proof)","co_await m_codeExchange->exchange(",
    "if (!exchanged)",'body.add("access_token",access.expose())'];
  let previous=-1;
  for(const term of ordered){
    const index=exchange.indexOf(term,previous+1);
    assert.ok(index>previous,term); previous=index;
  }
  assert.match(http,/grantRoute\(r,"authorization_code"\)/);
  assert.match(exchange,/verifier.size\(\)<43U \|\| verifier.size\(\)>128U/);
  assert.match(exchange,/foundation::toBase64Url\(pkce.value\(\)\)/);
  assert.match(app,/reader->exchangeOAuthCodeAsync/);
  assert.match(app,/oidc->issueIdTokenForNativeExchange\(code\)/);
  assert.match(app,/nativeOAuthCodeKey.emplace\(authorizationCodeMaterial->clone\(\)\)/);
  assert.match(app,/nativeOAuthRefreshLifetime=tokenPolicy->refreshLifetime\(\)/);
  const store=sql.slice(sql.indexOf("CoroutinePostgresCanonicalFinalizer::exchangeOAuthCodeAsync("));
  const transaction=['execute("BEGIN ISOLATION LEVEL READ COMMITTED"', "FOR SHARE OF c,a,o",
    "if (!authenticated)","g.client_id=$2 AND i.organization_id=$3",
    "g.redirect_uri=$4 AND g.code_challenge=$5","g.issued_at_ms<=$6 AND g.expires_at_ms>$6 AND i.status=0",
    "FOR UPDATE OF g","oauth::AuthorizationCode::restore","signIdToken(code.value())",
    "INSERT INTO openproof.oauth_token_families","INSERT INTO openproof.oauth_access_tokens",
    "INSERT INTO openproof.oauth_refresh_tokens","DELETE FROM openproof.oauth_authorization_codes",
    'execute("COMMIT",{})',"co_return std::move(result)"];
  previous=-1;
  for(const term of transaction){
    const index=store.indexOf(term,previous+1);
    assert.ok(index>previous,term); previous=index;
  }
  assert.match(store,/INSERT INTO openproof.oauth_token_family_audiences/);
  assert.match(store,/INSERT INTO openproof.oauth_token_family_scopes/);
  const legacy=read("src/oauth/http/http.cpp");
  const token=legacy.slice(legacy.indexOf("OAuthHttpApi::tokenEndpoint("));
  const guard=token.indexOf('m_nativeTokenReadsRequired && grantType.value()=="authorization_code"');
  assert.ok(guard>=0 && guard<token.indexOf("m_clients->authenticate("));
  assert.match(read("src/oidc/service.cpp"),/OpenIdProvider::issueIdTokenForNativeExchange\([\s\S]*?return signIdToken\(/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/NativeCodeExchangeConsumesExactlyOnceAndRollsBackFailedSigning/);
  assert.match(read("scripts/e2e-identity-platform.mjs"),/invalid.set\("code_verifier", "a".repeat\(43\)\)/);
});
test("machine grants authenticate and enforce resource, scope and subject lifetime atomically",()=>{
  const issue=http.slice(http.indexOf("CoroutineTokenReadAdapter::issueMachine("),
    http.indexOf("CoroutineTokenReadAdapter::pollDevice("));
  assert.match(http,/grantRoute\(r,"client_credentials"\) \|\| grantRoute\(r,kExchangeGrant\)/);
  assert.match(http,/subjectType->expose\(\)!=kAccessType/);
  assert.match(issue,/input->secret=foundation::SecretString\{\};\s*input->subject.reset\(\);\s*auto proof=m_prepareSender\(r\)/);
  assert.ok(issue.indexOf("co_await m_issueMachine(")<issue.indexOf('body.add("access_token",access.expose())'));
  assert.doesNotMatch(issue,/body.add\("refresh_token"/);
  assert.match(app,/reader->issueOAuthMachineGrantAsync/);
  const store=sql.slice(sql.indexOf("CoroutinePostgresCanonicalFinalizer::issueOAuthMachineGrantAsync("),
    sql.indexOf("CoroutinePostgresCanonicalFinalizer::pollOAuthDeviceAsync("));
  for(const term of ["FOR SHARE OF c,a,o","security::constantTimeEquals","!subjectDigest && kind!=3",
    "WHERE audience=$1 AND status=0 FOR SHARE","f.client_id=$2 AND i.organization_id=$3",
    "FOR SHARE OF f,i","senderMatches","family_id=$2 AND state=0 AND revoked_at_ms IS NULL",
    "expires=std::min(expires,milliseconds(live.rows.front()[0]))",
    "family_id=$1 AND audience=$2 FOR SHARE","s.active AND i.kind=1 AND i.status=0",
    "FOR SHARE OF s,i","client_id=$1 AND audience=$2 FOR SHARE",
    "const bool defaultScopes=requestedScopes.empty()",
    "std::ranges::find(allowedResource,scope)!=allowedResource.end()",
    "defaultScopes || std::ranges::find(sourceScopes,scope)!=sourceScopes.end()"])
    assert.ok(store.includes(term),term);
  assert.ok(store.indexOf("FOR SHARE OF f,i")<store.indexOf("family_id=$2 AND state=0"));
  assert.ok(store.indexOf("defaultScopes || std::ranges::find(sourceScopes")<store.indexOf("INSERT INTO openproof.oauth_token_families"));
  assert.ok(store.indexOf('execute("COMMIT",{})')<store.indexOf("co_return oauth::NativeMachineGrantResult"));
  assert.doesNotMatch(store,/INSERT INTO openproof.oauth_refresh_tokens/);
  const legacy=read("src/oauth/http/http.cpp");
  const token=legacy.slice(legacy.indexOf("OAuthHttpApi::tokenEndpoint("));
  const guard=token.indexOf('m_nativeTokenReadsRequired && (grantType.value()=="client_credentials"');
  assert.ok(guard>=0 && guard<token.indexOf("m_clients->authenticate("));
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/NativeMachineGrantsCannotWidenScopeAudienceOrLifetime/);
});
test("native device polling commits throttling and atomically consumes approval with token issuance",()=>{
  const body=http.slice(http.indexOf("CoroutineTokenReadAdapter::pollDevice("));
  assert.match(http,/grantRoute\(r,kDeviceGrant\)/);
  assert.match(body,/form\(r,false,false,true\)/);
  assert.match(body,/security::hmacSha256\(m_devicePoll->deviceKey,input->token.expose\(\)\)/);
  assert.match(body,/input->secret=foundation::SecretString\{\};\s*input->token=foundation::SecretString\{\}/);
  assert.ok(body.indexOf("co_await m_devicePoll->poll(")<body.indexOf('body.add("access_token",access.expose())'));
  for(const term of ["authorization_pending","slow_down","access_denied","expired_token","invalid_grant"])
    assert.ok(body.includes('"'+term+'"'),term);
  const store=sql.slice(sql.indexOf("CoroutinePostgresCanonicalFinalizer::pollOAuthDeviceAsync("),
    sql.indexOf("CoroutinePostgresCanonicalFinalizer::beginOAuthDeviceAsync("));
  for(const term of ["FOR SHARE OF c,a,o","if (!authenticated)",
    "WHERE device_digest=decode($1,'hex') AND client_id=$2 FOR UPDATE",
    "state==3","expires<=observed || state==2","observed-last<interval",
    "std::to_string(interval+5000)","State::SlowDown","State::Pending",
    "organization_id=$2 AND status=0 FOR SHARE",
    "INSERT INTO openproof.oauth_token_families","INSERT INTO openproof.oauth_access_tokens",
    "INSERT INTO openproof.oauth_refresh_tokens","SET status=3,last_poll_at_ms=$3",
    "AND client_id=$2 AND status=1 RETURNING client_id","State::Issued"])
    assert.ok(store.includes(term),term);
  assert.ok(store.indexOf("INSERT INTO openproof.oauth_refresh_tokens")<store.indexOf("SET status=3,last_poll_at_ms=$3"));
  assert.ok(store.lastIndexOf('execute("COMMIT",{})')<store.indexOf("State::Issued"));
  assert.match(app,/reader->pollOAuthDeviceAsync/);
  assert.match(app,/nativeOAuthDeviceKey.emplace\(deviceAuthorizationMaterial->clone\(\)\)/);
  const legacy=read("src/oauth/http/http.cpp");
  const token=legacy.slice(legacy.indexOf("OAuthHttpApi::tokenEndpoint("));
  const guard=token.indexOf('m_nativeTokenReadsRequired && grantType.value()=="urn:ietf:params:oauth:grant-type:device_code"');
  assert.ok(guard>=0 && guard<token.indexOf("m_clients->authenticate("));
  assert.ok(token.indexOf("if (m_nativeTokenReadsRequired) {",guard)<token.indexOf("m_clients->authenticate("));
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/NativeDevicePollingCommitsThrottleAndConsumesApprovedCodeExactlyOnce/);
});
test("device initiation authenticates and persists only hashed codes within bounded native transactions",()=>{
  const body=http.slice(http.indexOf("CoroutineTokenReadAdapter::beginDevice("),http.indexOf("CoroutineTokenReadAdapter::pollDevice("));
  for(const term of ["input->secret=foundation::SecretString{}","256U-(256U%alphabet.size())","attempt<3U",
    "security::hmacSha256(m_devicePoll->deviceKey,device.expose())",
    "security::hmacSha256(m_devicePoll->deviceKey,user.expose())","co_await m_devicePoll->begin(",
    "case E::Conflict: continue","body.add(\"device_code\",device.expose())"])
    assert.ok(body.includes(term),term);
  assert.ok(body.indexOf("co_await m_devicePoll->begin(")<body.indexOf('body.add("device_code",device.expose())'));
  const store=sql.slice(sql.indexOf("CoroutinePostgresCanonicalFinalizer::beginOAuthDeviceAsync("),
    sql.indexOf("CoroutinePostgresCanonicalFinalizer::readOAuthDeviceApprovalAsync("));
  for(const term of ["FOR SHARE OF c,a,o","if (!authenticated)","oauth_client_scopes",
    "std::ranges::find(allowed,scope)!=allowed.end()","!resource && !std::ranges::all_of(scopes,oidcOnly)",
    "WHERE audience=$1 AND status=0 FOR SHARE","oauth_resource_scopes","oidcOnly(scope) ||",
    "ON CONFLICT DO NOTHING RETURNING client_id","oauth_device_authorization_scopes"])
    assert.ok(store.includes(term),term);
  assert.ok(store.indexOf("if (!authenticated)")<store.indexOf("INSERT INTO openproof.oauth_device_authorizations"));
  assert.ok(store.indexOf("INSERT INTO openproof.oauth_device_authorization_scopes")<store.lastIndexOf('execute("COMMIT",{})'));
  assert.match(app,/reader->beginOAuthDeviceAsync/);
  assert.match(app,/nativePaths.emplace_back\("\/oauth\/device_authorization"\)/);
  assert.match(read("src/oauth/http/http.cpp"),/m_nativeTokenReadsRequired && \(path=="\/oauth\/device_authorization" \|\| path=="\/oauth\/device"\)/);
  assert.match(read("tests/oauth_native_consent_test.cpp"),/DeviceInitiationRetriesCollisionAndReturnsOnlyCommittedCodes/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/duplicate.error\(\).code\(\),fnd::ErrorCode::Conflict/);
});
test("device browser approval binds CSRF to first-party session and commits consent and approval together",()=>{
  const body=http.slice(http.indexOf("CoroutineTokenReadAdapter::deviceBrowser("),http.indexOf("CoroutineTokenReadAdapter::beginDevice("));
  for(const term of ['r.header("authorization")',"browserCookie(r,kBrowserSession)",
    "security::constantTimeEquals(expected->expose(),input->csrf->expose())",
    "co_await m_devicePoll->authenticate","deviceCsrf(m_devicePoll->deviceKey,actor.value(),digest",
    "input->csrf.reset(); input->code.reset();","co_await m_devicePoll->decide",
    "actor->identity(),actor->id()","co_await m_devicePoll->readApproval",
    "htmlEscape(grant->clientName)","deviceCsrfCookie(\"\",0)"])
    assert.ok(body.includes(term),term);
  assert.ok(body.indexOf("scrub(r);",body.indexOf("const auto login="))<body.indexOf("co_await m_devicePoll->authenticate"));
  assert.ok(body.indexOf("co_await m_devicePoll->decide")<body.indexOf('input->approve?"Device approved"'));
  assert.match(http,/device-browser:"\+std::string\{actor.id\(\).value\(\)\}/);
  assert.match(http,/frame-ancestors 'none'/);
  const store=sql.slice(sql.indexOf("CoroutinePostgresCanonicalFinalizer::decideOAuthDeviceAsync("));
  for(const term of ["a.organization_id=$2","FOR SHARE OF c,a,o",
    "AND client_id=$2 AND status=0","FOR UPDATE","s.id=$3 AND s.state=0",
    "s.absolute_expires_at_ms>$4","s.last_seen_at_ms+s.idle_timeout_ms>$4",
    "FOR UPDATE OF i FOR SHARE OF s","UPDATE openproof.oauth_consents",
    "INSERT INTO openproof.oauth_consent_scopes","SET status=1,identity_id=$2",
    "SET status=2"])
    assert.ok(store.includes(term),term);
  assert.ok(store.indexOf("INSERT INTO openproof.oauth_consent_scopes")<store.indexOf("SET status=1,identity_id=$2"));
  assert.ok(store.indexOf("SET status=2")<store.lastIndexOf('execute("COMMIT",{})'));
  assert.match(app,/reader->decideOAuthDeviceAsync/);
  assert.match(app,/reader->readOAuthDeviceApprovalAsync/);
  assert.match(app,/nativePaths.emplace_back\("\/oauth\/device"\)/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/Force a consent collision; the device must remain pending/);
});
test("PAR authenticates and validates request parameters and pinned JAR before atomic replay and storage",()=>{
  const body=http.slice(http.indexOf("CoroutineTokenReadAdapter::pushAuthorization("),http.indexOf("CoroutineTokenReadAdapter::deviceBrowser("));
  for(const term of ["clientSecret.reset()","parameters.size()!=1U","verifyNativeJar(",
    "*jwt=foundation::SecretString{}","parseParAuthorization(parameters)",
    "security::sha256(uri.expose())","co_await m_par->push(",'body.add("request_uri",uri.expose())'])
    assert.ok(body.includes(term),term);
  assert.ok(body.indexOf("clientSecret.reset()")<body.indexOf("co_await m_par->push("));
  assert.ok(body.indexOf("co_await m_par->push(")<body.indexOf('body.add("request_uri",uri.expose())'));
  const jar=http.slice(http.indexOf("verifyNativeJar("),http.indexOf("bool parRoute("));
  for(const term of ["security::verifyRs256Jwt(pem,compactJwt)",'{"RS256"}',
    "std::string{expectedKeyId}","std::string{expectedClient.value()}","audienceMatches",
    "expiresAt<=now","expiresAt-issuedAt>std::chrono::minutes{10}","parseParAuthorization(parameters)"])
    assert.ok(jar.includes(term),term);
  const store=sql.slice(sql.indexOf("CoroutinePostgresCanonicalFinalizer::pushOAuthAuthorizationAsync("),
    sql.indexOf("CoroutinePostgresCanonicalFinalizer::completeOAuthAuthorizationAsync("));
  const ordered=["FOR SHARE OF c,a,o","if (!authenticated)","oauth_client_request_signing_keys",
    "WHERE client_id=$1 FOR SHARE","verifyJar(required","client::matchesRegisteredRedirect",
    "oauth_client_scopes","oauth_resource_scopes","INSERT INTO openproof.oauth_jar_replays",
    "ON CONFLICT(client_id,jwt_id) DO UPDATE","WHERE openproof.oauth_jar_replays.expires_at_ms<=$4",
    "INSERT INTO openproof.oauth_pushed_authorization_requests",
    "INSERT INTO openproof.oauth_pushed_authorization_request_scopes",'execute("COMMIT",{})'];
  let previous=-1;
  for(const term of ordered){
    const index=store.indexOf(term,previous+1);
    assert.ok(index>previous,term); previous=index;
  }
  assert.match(store,/LIMIT 128 FOR UPDATE SKIP LOCKED/);
  assert.match(app,/reader->pushOAuthAuthorizationAsync/);
  assert.match(app,/nativePaths.emplace_back\("\/oauth\/par"\)/);
  assert.match(read("src/oauth/http/http.cpp"),/m_nativeTokenReadsRequired && path=="\/oauth\/par"/);
  assert.match(read("src/client/model.cpp"),/return matchesRegisteredRedirect\(m_state->kind,item.value\(\),redirectUri\)/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/NativeParPreservesLoopbackAndCommitsJarReplayAtomically/);
});
test("browser authorization revalidates session and consent and commits PAR consumption with code issuance",()=>{
  const body=http.slice(http.indexOf("CoroutineTokenReadAdapter::authorizeBrowser("),http.indexOf("CoroutineTokenReadAdapter::pushAuthorization("));
  for(const term of ["browserCookie(r,kBrowserSession)","browserCookie(r,\"__Host-openproof-consent-csrf\")",
    "security::constantTimeEquals(expected->expose(),*csrf)","co_await m_devicePoll->authenticate",
    "authorizationCsrf(m_codeExchange->codeKey,actor.value(),target","submittedCsrf.reset()",
    "co_await m_par->complete(","actor->identity(),actor->id(),decision",
    "security::hmacSha256(m_codeExchange->codeKey,code.expose())",
    "completed->consentRequired","htmlEscape(completed->clientName)","completed->signedResponse",
    "authorizationCookie(\"\",0)"])
    assert.ok(body.includes(term),term);
  assert.ok(body.indexOf("submittedCsrf.reset()")<body.indexOf("co_await m_par->complete("));
  assert.ok(body.indexOf("co_await m_par->complete(")<body.indexOf("completed->signedResponse"));
  assert.match(body,/std::nullopt,std::move\(verify\),true\)/);
  assert.match(http,/authorization-browser:"\+std::string\{actor.id\(\).value\(\)\}/);
  const store=sql.slice(sql.indexOf("CoroutinePostgresCanonicalFinalizer::completeOAuthAuthorizationAsync("));
  const ordered=["FOR SHARE OF c,a,o","FROM openproof.oauth_pushed_authorization_requests",
    "AND issued_at_ms<=$3 AND expires_at_ms>$3 FOR UPDATE","client::matchesRegisteredRedirect",
    "oauth_client_scopes","oauth_resource_scopes","s.id=$3 AND s.state=0",
    "FOR UPDATE OF i FOR SHARE OF s","observed-authenticatedAt>=request.maximumAuthenticationAge()->count()",
    "FROM openproof.oauth_consents","if (!covered)","signResponse(request,decision==Decision::Deny)",
    "INSERT INTO openproof.oauth_consents","INSERT INTO openproof.oauth_authorization_codes",
    "INSERT INTO openproof.oauth_authorization_code_scopes",
    "DELETE FROM openproof.oauth_pushed_authorization_requests","AND client_id=$2 RETURNING client_id",
    'execute("COMMIT",{})',"co_return std::move(result)"];
  let previous=-1;
  for(const term of ordered){
    const index=store.indexOf(term,previous+1);
    assert.ok(index>previous,term); previous=index;
  }
  assert.match(store,/co_return oauth::NativeAuthorizationResult\{request,clientName,true,std::nullopt\}/);
  assert.match(store,/if \(decision!=Decision::Deny\)/);
  assert.match(app,/reader->completeOAuthAuthorizationAsync/);
  assert.match(app,/nativePaths.emplace_back\("\/oauth\/authorize"\)/);
  assert.match(app,/nativePaths.emplace_back\("\/oauth\/consent"\)/);
  assert.match(read("src/oauth/http/http.cpp"),/m_nativeTokenReadsRequired && \(path=="\/oauth\/authorize" \|\| path=="\/oauth\/consent"\)/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/Exercise the actual PAR consumer, including consent and JARM failure/);
});
test("native browser login owns credentials, binds return target, replaces sessions and retires synchronous OAuth runtime",()=>{
  const body=http.slice(http.indexOf("CoroutineTokenReadAdapter::loginBrowser("),http.indexOf("CoroutineTokenReadAdapter::authorizeBrowser("));
  const ordered=["parseLoginForm(r)","browserCookie(r,kLoginCsrfCookie)",
    "loginCsrf(m_clientKey,input->target,token.substr(0,dot))",
    "input->csrf=foundation::SecretString{}","browserCookie(r,kBrowserSession)",
    "scrub(r);","co_await m_login(","std::move(input->password)",
    "std::move(input->totp),std::move(prior)","if (!issued)",
    "loginCookie(kBrowserSession,bearer,8*60*60)"];
  let previous=-1;
  for(const term of ordered){
    const index=body.indexOf(term,previous+1);
    assert.ok(index>previous,term); previous=index;
  }
  assert.match(http,/oauth-login:"\+foundation::toHex\(digest.value\(\)\)/);
  assert.match(app,/co_await service->beginAsync\(/);
  assert.match(app,/co_await service->completeAsync\(/);
  assert.match(app,/co_return co_await sessions->issueReplacingAsync\(/);
  assert.match(app,/nativePaths.emplace_back\("\/login"\)/);
  assert.match(app,/nativePaths.emplace_back\("\/oauth\/token"\)/);
  assert.doesNotMatch(app,/\bOAuthHttpApi\s+\w+\s*\{/);
  assert.match(http,/if \(tokenRoute\(r\)\) return true/);
  assert.match(http,/valid\?"unsupported_grant_type":"invalid_request"/);
  assert.match(read("tests/oauth_native_consent_test.cpp"),/LoginBindsReturnTargetAndReplacesPriorSessionNatively/);
});

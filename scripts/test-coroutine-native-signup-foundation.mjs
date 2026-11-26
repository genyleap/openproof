import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
const root=path.resolve(import.meta.dirname,"..");
const read=file=>fs.readFileSync(path.join(root,file),"utf8");
test("native enrollment shares the bounded KDF worker permit and owns plaintext",()=>{
  const source=read("src/credentials/bounded_password_executor.cpp");
  const worker=source.slice(source.indexOf("hashWorker("),source.indexOf("verifyWorker("));
  assert.match(worker,/Permit permit,foundation::SecretString password/);
  assert.match(worker,/permit.state->hasher.hash\(password\)/);
  const hash=source.slice(source.indexOf("BoundedPasswordExecutor::hashAsync("),
    source.indexOf("BoundedPasswordExecutor::verifyAsync("));
  assert.match(hash,/auto permit=admit\(m_impl->state\)/);
  assert.match(hash,/RateLimited/);
  assert.match(hash,/co_await asio::co_spawn\(m_impl->pool,/);
  assert.match(hash,/hashWorker\(std::move\(\*permit\),std::move\(password\)\)/);
  assert.doesNotMatch(hash,/hasher.hash\(/);
});
test("native memory and PostgreSQL share unknown/nonpending replay rejection",()=>{
  const memory=read("src/identity/provider/transaction.cpp");
  const body=memory.slice(memory.indexOf("InMemoryAuthenticationTransactionStore::consumeAsync("),
    memory.indexOf("InMemoryAuthenticationTransactionStore::find("));
  assert.match(body,/lock_guard<std::mutex>/);
  assert.match(body,/position->second.state\(\)!=TransactionState::Pending/);
  assert.match(body,/ErrorCode::AuthenticationFailed/);
  assert.match(body,/position->second.consume\(nonce,binding,now\)/);
  const pg=read("src/storage/postgres/coroutine_auth_transaction_store.cpp");
  assert.match(pg,/if \(!consumed\) \{\s*co_return foundation::fail\(foundation::ErrorCode::AuthenticationFailed/);
});

test("signup provisions identity, reservation, credential and digest in one transaction",()=>{
  const source=read("src/storage/postgres/coroutine_verification_challenge_store.cpp");
  const body=source.slice(source.indexOf("CoroutineVerificationChallengeStore::provisionSignupAsync("),
    source.indexOf("CoroutineVerificationChallengeStore::activateSignupAsync("));
  const ordered=["BEGIN ISOLATION LEVEL READ COMMITTED","pg_advisory_xact_lock",
    "SELECT id FROM openproof.organizations","p.email_verified=true","FOR UPDATE OF i",
    "INSERT INTO openproof.identities","INSERT INTO openproof.identity_profiles",
    "VerificationPreparation::prepare","INSERT INTO openproof.pending_external_identity_reservations",
    "INSERT INTO openproof.password_credentials","INSERT INTO openproof.account_verification_challenges",
    'connection.query("COMMIT"',"co_return PendingSignup"];
  let previous=-1;
  for (const marker of ordered) {
    const i=body.indexOf(marker);
    assert.ok(i>previous,marker);
    previous=i;
  }
  assert.match(body,/i.organization_id=\$1/);
  assert.match(body,/LIMIT 2 FOR UPDATE OF i/);
  assert.match(body,/WHERE r.expires_at_ms<=\$5 RETURNING identity_id/);
  assert.match(body,/ON CONFLICT\(identity_id\) DO NOTHING/);
  assert.match(body,/WHERE identity_id=\$1 AND purpose=0 RETURNING id,identity_id/);
  assert.match(body,/foundation::toHex\(challenge.digest\(\).bytes\(\)\)/);
  assert.doesNotMatch(body,/\.secret\(|->secret\(|->deliver\(|hasher.hash\(/);
  assert.match(body,/co_return foundation::fail\(foundation::ErrorCode::AlreadyExists\)/);
});

test("signup proof activation binds tenant, owner, purpose and reservation before an atomic promotion",()=>{
  const source=read("src/storage/postgres/coroutine_verification_challenge_store.cpp");
  const body=source.slice(source.indexOf("CoroutineVerificationChallengeStore::activateSignupAsync("),
    source.indexOf("CoroutineVerificationChallengeStore::replaceImpl("));
  const order=["BEGIN ISOLATION LEVEL READ COMMITTED","c.purpose=0 AND c.channel=0",
    "FOR UPDATE OF i FOR SHARE OF o","purpose=0 AND channel=0 FOR UPDATE",
    "security::constantTimeEquals","r.verification_id IS NULL",
    "INSERT INTO openproof.external_identities","UPDATE openproof.identity_profiles",
    "UPDATE openproof.identities SET status=0","const auto consumed=","const auto released=",
    'connection.query("COMMIT",{},remaining(deadline)));\n        co_return ActivatedSignup'];
  let previous=-1;
  for(const marker of order){
    const i=body.indexOf(marker);
    assert.ok(i>previous,marker);previous=i;
  }
  assert.match(body,/i.organization_id=\$2 AND i.kind=0 AND i.status IN \(0,3\) AND o.state=0/);
  assert.match(body,/r.expires_at_ms>\$4 AND r.verification_id IS NULL/);
  assert.match(body,/AND lower\(p.email\)=lower\(\$2\)/);
  assert.match(body,/expires<=time \|\| attempts>=maximumAttempts/);
  assert.match(body,/attempts=attempts\+1/);
  assert.match(body,/ON CONFLICT\(provider,external_subject\) DO NOTHING/);
  assert.doesNotMatch(body,/issueAsync\(|->issue\(|->deliver\(/);
});
test("signup delivery compensation leaves the untagged reservation available for resend",()=>{
  const source=read("src/storage/postgres/coroutine_verification_challenge_store.cpp");
  const body=source.slice(source.indexOf("CoroutineVerificationChallengeStore::discardAsync("));
  assert.match(body,/c.id=\$1 AND c.identity_id=\$2/);
  assert.match(body,/c.purpose=\$3 AND i.id=c.identity_id AND i.organization_id=\$4/);
  assert.match(body,/r.verification_id=c.id AND r.identity_id=c.identity_id/);
  assert.doesNotMatch(body,/DELETE FROM openproof.password_credentials|DELETE FROM openproof.identities/);
});

test("native signup pair shares bounded KDF and owner-bound verification before issuing session",()=>{
  const app=read("apps/opp/main.cpp");
  const auth=read("src/authentication/service.cpp");
  const http=read("src/account/http/coroutine_session_http.cpp");
  const signup=app.slice(app.indexOf("nativeSignup=[&]("),app.indexOf("nativeVerifySignup=[&]("));
  const verify=app.slice(app.indexOf("nativeVerifySignup=[&]("),app.indexOf("nativeContactIssuer=&contactIssuer;"));
  const order=(body,markers)=>{
    let previous=-1;
    for(const marker of markers){
      const index=body.indexOf(marker);
      assert.ok(index>previous,marker);previous=index;
    }
  };
  order(signup,["hashAsync(std::move(password))","provisionSignupAsync(","deliverAsync(","discardAsync(generation,owner"]);
  order(verify,["VerificationPreparation::digest(","secret=fnd::SecretString{}","activateSignupAsync(",
    "acceptVerifiedEmailAsync(","std::move(activated->first),std::move(activated->second)","nativeSessions->issueAsync("]);
  assert.match(auth,/authorizeHandoffOwnerAsync\(expectedOwner,external\)/);
  assert.match(app,/nativeSignupFlag && \*nativeSignupFlag=="1"/);
  assert.match(app,/nativeMethods.emplace_back\("\/account\/signup",gateway::HttpMethod::Post\)/);
  assert.match(app,/nativeMethods.emplace_back\("\/account\/email\/verify",gateway::HttpMethod::Post\)/);
  const body=http.slice(http.indexOf("CoroutineContactVerificationAdapter::signupOrVerify("));
  order(body,["ParsedPasswordGuard wipeParsed","request.wipeBody();","co_await m_signup(","co_await m_verifySignup(",
    "if (!safe(issued->id.value())","response.addHeader(\"set-cookie\""]);
  assert.doesNotMatch(body,/m_fallback->handle\(|m_accounts->/);
});

test("abandoned signup collection is bounded, tenant-scoped and refuses unrelated identity state",()=>{
  const source=read("src/storage/postgres/coroutine_verification_challenge_store.cpp");
  const gate=source.slice(source.indexOf("constexpr std::string_view abandonedSignupEligibility="),source.indexOf("bool exactRow("));
  for(const marker of ["i.organization_id=$1 AND i.kind=0 AND i.status=3",
    "starts_with(i.id,'opi_signup_')","p.updated_at_ms=i.created_at_ms",
    "c.changed_at_ms=i.created_at_ms","NOT p.email_verified","r.expires_at_ms>$3",
    "v.expires_at_ms>$3","external_identities","sessions","memberships","oauth_token_families",
    "passkey_credentials","scim_users","evidence","audit_events"])
    assert.ok(gate.includes(marker),marker);
  const body=source.slice(source.indexOf("CoroutineVerificationChallengeStore::reapExpiredSignupsAsync("),
    source.indexOf("CoroutineVerificationChallengeStore::provisionSignupAsync("));
  assert.match(body,/std::chrono::hours\{48\}/);
  assert.match(body,/LIMIT 8 FOR UPDATE OF i,p,c SKIP LOCKED/);
  assert.match(body,/pg_catalog.pg_constraint/);
  assert.equal([...body.matchAll(/std::string\{abandonedSignupEligibility\}/g)].length,2);
  assert.match(body,/WHERE identity_id=\$1 FOR UPDATE/);
  assert.match(body,/DELETE FROM openproof.identities target WHERE target.id=\$4/);
  assert.match(read("apps/opp/main.cpp"),/co_await contactStore.reapExpiredSignupsAsync\(clock.now\(\)\)/);
});

test("expired enrollment retry requires exact pending provenance and a locked hash generation",()=>{
  const source=read("src/storage/postgres/coroutine_verification_challenge_store.cpp");
  const body=source.slice(source.indexOf("CoroutineVerificationChallengeStore::provisionSignupAsync("),
    source.indexOf("CoroutineVerificationChallengeStore::activateSignupAsync("));
  assert.match(body,/SELECT changed_at_ms FROM openproof.password_credentials WHERE identity_id=\$1 FOR UPDATE/);
  assert.match(body,/r.provider=\$1 AND r.external_subject=\$2 AND r.identity_id=\$3/);
  assert.match(body,/r.verification_id IS NULL AND r.expires_at_ms<=\$4/);
  assert.match(body,/\$5::bigint<r.expires_at_ms/);
  assert.match(body,/other.identity_id=\$3 AND \(other.provider<>\$1 OR other.external_subject<>\$2\)/);
  assert.match(body,/OR v.destination<>\$2 OR v.expires_at_ms>\$4/);
  assert.match(body,/FOR UPDATE OF r/);
  assert.match(body,/if \(!exactRow\(expiredEnrollment,owner\)\)/);
  assert.match(body,/expiredCredentialGeneration=generation/);
  assert.match(body,/WHERE identity_id=\$1 AND changed_at_ms=\$4 RETURNING identity_id/);
  assert.match(body,/ON CONFLICT\(identity_id\) DO NOTHING/);
  assert.ok(body.indexOf("expiredCredentialGeneration=generation")<body.indexOf("const auto reserved="));
  assert.ok(body.indexOf("const auto credential=")<body.indexOf("const auto stored="));
});

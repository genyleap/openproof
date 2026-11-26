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
    source.indexOf("CoroutineVerificationChallengeStore::replaceImpl("));
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

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

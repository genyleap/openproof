#!/usr/bin/env node
// Structural release contracts: the real in-memory async GTest must also pass.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root=path.resolve(import.meta.dirname,"..");
const read=p=>fs.readFileSync(path.join(root,p),"utf8");
const iface=read("src/credentials/coroutine_recovery_codes.hpp");
const service=cppExecutableText(read("src/credentials/coroutine_recovery_codes.cpp"));
const bridge=cppExecutableText(read("src/storage/postgres/coroutine_recovery_code_repository.cpp"));
const tests=read("tests/credentials/coroutine_recovery_code_service_test.cpp");
const slice=(text,begin,end)=> {
  const a=text.indexOf(begin),b=text.indexOf(end,a+begin.length);
  assert.ok(a>=0 && b>a,"missing method boundary");
  return text.slice(a,b);
};

test("recovery coroutine repository interface is independent of PostgreSQL vendor",()=>{
  assert.match(iface,/class CoroutineRecoveryCodeRepository/);
  for(const operation of ["replaceAsync","consumeAsync","remainingAsync"]) {
    assert.match(iface,new RegExp(operation+"\\("));
  }
  assert.doesNotMatch(cppExecutableText(iface),/postgres|libpq|PQexec|ConnectionPool/i);
  assert.match(iface,/virtual ~CoroutineRecoveryCodeRepository\(\) = default/);
});

test("issue generates CSPRNG and keyed digests before awaiting atomic replacement",()=>{
  const issued=slice(service,"CoroutineRecoveryCodeService::issue(","CoroutineRecoveryCodeService::consume(");
  assert.match(issued,/security::randomTokenBase64Url\(20U\)/);
  assert.match(issued,/security::hmacSha256\(m_pepper, code\.expose\(\)\)/);
  assert.match(issued,/count > 32U/);
  assert.match(issued,/co_await m_repository->replaceAsync\(/);
  assert.match(issued,/if \(!saved\) co_return foundation::fail\(saved\.error\(\)\)/);
  assert.ok(issued.indexOf("co_await m_repository->replaceAsync") <
            issued.indexOf("co_return foundation::Result<std::vector<foundation::SecretString>>"));
  assert.doesNotMatch(issued,/m_repository->replace\s*\(|\.run\s*\(/);
});

test("consume is one keyed digest and a scoped awaitable atomic store redemption",()=>{
  const body=slice(service,"CoroutineRecoveryCodeService::consume(","CoroutineRecoveryCodeService::revoke(");
  assert.match(body,/security::hmacSha256\(m_pepper, presented\.expose\(\)\)/);
  assert.match(body,/co_await m_repository->consumeAsync\(/);
  assert.doesNotMatch(body,/m_repository->consume\s*\(|\.run\s*\(/);
});

test("native PostgreSQL adapter has one deadline across queue and all SQL",()=>{
  for(const name of ["replaceAsync","consumeAsync","remainingAsync"]) {
    const from=bridge.indexOf("CoroutinePostgresRecoveryCodeRepository::"+name+"(");
    const to=bridge.indexOf("CoroutinePostgresRecoveryCodeRepository::",from+name.length+3);
    const method=bridge.slice(from,to<0?undefined:to);
    assert.ok(from>=0);
    assert.match(method,/const Deadline deadline = Clock::now\(\) \+ m_impl->queryTimeout/);
    assert.match(method,/co_await m_impl->pool\.acquire\(deadline\)/);
    assert.match(method,/remaining\(deadline\)/);
  }
  assert.doesNotMatch(bridge,/\b(?:PQexec|PQexecParams|PQconnectdb|PQreset|io\.run)\s*\(/);
  assert.match(bridge,/foundation::ErrorCode::AuthenticationFailed/);
  assert.match(bridge,/foundation::ErrorCode::Unavailable/);
});

test("service GTests ensure fail-closed output and single-use consumed digests",()=>{
  for(const item of [
    "IssuanceCommitsHashedDigestsBeforeReturningSecrets",
    "PersistFailureNeverReturnsPlaintextCodes",
    "OneTimeConsumptionPreventsReplay",
    "RevokeInvalidatesEverything",
    "InvalidInputNeverReachesPersistence",
  ]) assert.match(tests,new RegExp("TEST\\(CoroutineRecoveryCodesTest, "+item+"\\)"));
  assert.match(tests,/sec::hmacSha256/);
  assert.match(tests,/std::find\(stored\.begin\(\), stored\.end\(\), digest\)/);
});

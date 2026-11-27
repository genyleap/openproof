#!/usr/bin/env node
// Native route authorization and persistence contract. The in-process C++
// GTests are still required for runtime assurance.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root=path.resolve(import.meta.dirname,"..");
const read=p=>fs.readFileSync(path.join(root,p),"utf8");
const header=read("src/authentication/http/coroutine_recovery_code_http.hpp");
const file=read("src/authentication/http/coroutine_recovery_code_http.cpp");
const code=cppExecutableText(file);
const fixture=read("tests/authentication/coroutine_recovery_code_http_test.cpp");
const eligibility=read("src/storage/postgres/async_recovery_code.cpp");
const repository=read("src/storage/postgres/coroutine_recovery_code_repository.cpp");

test("recovery-code native HTTP is a per-route Asio handler without sync fallback",()=>{
  assert.match(header,/public gateway::http::CoroutineHttpHandler/);
  assert.match(header,/using Authenticate = std::function<boost::asio::awaitable</);
  assert.match(header,/nativeEnabled\(\) const noexcept override \{ return false; \}/);
  assert.match(code,/request\.method\(\) == gateway::HttpMethod::Post/);
  assert.match(code,/request\.path\(\) ==/);
  assert.match(file,/request\.path\(\) == "\/auth\/recovery-codes"/);
  assert.doesNotMatch(code,/m_sessions->authenticate|m_localAccounts->hasTotp|io\.run\(/);
});

test("compatibility handle cannot execute synchronous authentication or TOTP checks",()=>{
  const handler=code.slice(code.indexOf("CoroutineRecoveryCodeHttpAdapter::handle("),
    code.indexOf("CoroutineRecoveryCodeHttpAdapter::handleAsync("));
  assert.match(handler,/return fail\(/);
  assert.doesNotMatch(handler,/m_nativeFallback->handle\(|m_authenticate\(|m_eligible\(/);
  const native=code.slice(code.indexOf("CoroutineRecoveryCodeHttpAdapter::handleAsync("),
    code.indexOf("CoroutineRecoveryCodeHttpAdapter::issue("));
  assert.match(native,/if \(!nativeEnabledFor\(request\)\)/);
  assert.match(native,/co_return co_await m_nativeFallback->handleAsync\(/);
  assert.doesNotMatch(native,/m_nativeFallback->handle\(/);
});

test("native route verifies bearer, IAL2 and DB TOTP eligibility before issuing plaintext",()=>{
  const issue=code.slice(code.indexOf("CoroutineRecoveryCodeHttpAdapter::issue("));
  for(const re of [
    /m_rateLimiter->allow\(limitKey\)/,
    /gateway::takeSessionCredential\(request\)/,
    /co_await m_authenticate\(/,
    /idp::meetsAssurance\(authenticated->assurance\(\)/,
    /idp::AssuranceLevel::Ial2/,
    /co_await m_recoveryCodes->issueFenced\(authenticated->identity\(\), 10U\)/,
    /codes\.emplace_back\(code\.expose\(\)\)/,
    /co_return jsonResponse\(201/,
  ]) assert.match(issue,re);
  const issueAt=issue.indexOf("co_await m_recoveryCodes->issueFenced");
  const denied=issue.indexOf("if (!issued)");
  const responseAt=issue.indexOf("co_return jsonResponse(201");
  assert.ok(issueAt>=0 && denied>issueAt && responseAt>denied);
  assert.match(file,/cache-control/);
  assert.match(file,/no-store/);
  assert.doesNotMatch(issue,/m_recoveryCodes->revoke|m_eligible/);
});

test("native SQL eligibility binds canonical active identity and configured local provider",()=>{
  const sql=eligibility.slice(eligibility.indexOf("AsyncRecoveryCodeSql::eligible("));
  for(const regex of [
    /SELECT EXISTS/,
    /external_identities e/,
    /identities i/,
    /i\.status=0/,
    /password_credentials p/,
    /totp_credentials t/,
    /e\.identity_id=\$1 AND e\.provider=\$2/,
    /co_await conn\.query\(/,
    /rows\.rows\.size\(\) != 1U/,
    /result != "true" && result != "false"/,
  ]) assert.match(sql, regex);
  const repo=repository.slice(repository.indexOf(
    "CoroutinePostgresRecoveryCodeRepository::eligibleAsync("));
  assert.match(repo,/m_impl->pool\.acquire\(deadline\)/);
  assert.match(repo,/co_await m_impl->sql\.eligible\(/);
  assert.match(repo,/remaining\(deadline\)/);
});

test("HTTP GTests cover negative and cross-check revocation before any secret returns",()=>{
  for(const name of [
    "OnlyOneAuthorizedRouteIsNative",
    "WeakOrMissingSessionNeverIssuesCode",
    "NativeIssueReturnsTenCodesOnlyAfterPersistence",
    "MissingTotpStopsBeforeAnyPersistence",
    "ChangedFactorDuringIssuePreservesNewerBatch",
    "FailedFencedWriteCannotLeakPlaintext",
    "PersistenceAndEligibilityErrorsFailClosed",
  ]) assert.match(fixture,new RegExp("TEST\\(CoroutineRecoveryHttpTest, "+name+"\\)"));
  assert.match(fixture,/fnd::SecretString\{std::string\(32U, 'P'\)\}/);
  assert.match(fixture,/sec::hmacSha256/);
  assert.match(fixture,/asyncCalls/);
});

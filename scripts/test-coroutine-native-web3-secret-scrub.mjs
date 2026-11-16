#!/usr/bin/env node
// Web3 proof/cookie lifetime contract across native coroutine suspension.
// The fresh C++ Web3 HTTP test bundle is an independent release requirement.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const source=fs.readFileSync(path.resolve(import.meta.dirname,"../src/authentication/http/web3.cpp"),"utf8");
const start=source.slice(source.indexOf("Web3AuthenticationHttpApi::startAsync("),
  source.indexOf("Web3AuthenticationHttpApi::completeAsync("));
const complete=source.slice(source.indexOf("Web3AuthenticationHttpApi::completeAsync("));
const guard=source.slice(source.indexOf("class SensitiveWeb3RequestGuard final"),
  source.indexOf("[[nodiscard]] std::string cookie("));

test("native Web3 request guard erases raw proof, authorization and cookie headers",()=>{
  for(const method of ["wipeBody","wipeAuthorizationHeader","wipeCookieHeader"])
    assert.ok(guard.includes("m_request."+method+"()"));
  assert.match(guard,/~SensitiveWeb3RequestGuard\(\) \{ wipe\(\); \}/);
  assert.match(start,/SensitiveWeb3RequestGuard wipeRequestOnExit\{request\}/);
  assert.match(complete,/SensitiveWeb3RequestGuard wipeRequestOnExit\{request\}/);
  assert.ok(start.indexOf("wipeRequestOnExit.wipe()") <
      start.indexOf("co_await m_authentication->beginAsync("));
  assert.ok(complete.indexOf("wipeRequestOnExit.wipe()") <
      complete.indexOf("co_await m_authentication->completeAsync("));
});

test("all parsed SIWE and handoff JSON copies are securely wiped",()=>{
  assert.match(guard,/class SensitiveWeb3ParsedGuard final/);
  assert.match(guard,/~SensitiveWeb3ParsedGuard\(\) \{ wipe\(\); \}/);
  assert.match(guard,/\{"handoff_ticket", "message", "signature"\}/);
  assert.match(guard,/foundation::secureWipe\(value\.data\(\), value\.size\(\)\)/);
  for(const fn of [start,complete]){
    assert.match(fn,/SensitiveWeb3ParsedGuard wipeParsedOnExit\{body \? &body\.value\(\) : nullptr\}/);
    const wipe=fn.indexOf("wipeParsedOnExit.wipe()");
    const awaitAt=fn.indexOf("co_await m_authentication->");
    assert.ok(wipe>=0 && awaitAt>wipe);
  }
});

test("start ceremony uses auto-wiping binding owner over native await",()=>{
  assert.match(start,/foundation::SecretString bindingSecret\{std::move\(bindingToken\)\.value\(\)\}/);
  assert.match(start,/security::sha256\(bindingSecret\.expose\(\)\)/);
  assert.match(start,/cookie\(kBindingCookie, bindingSecret\.expose\(\), 600\)/);
  assert.doesNotMatch(start,/cookie\(kBindingCookie, bindingToken\.value\(\)/);
});

test("verify ceremony moves proofs into secret owners before awaiting",()=>{
  const names=["message","signature","continuation","bindingToken","transaction",
    "challenge","mode","authenticationHandoff"];
  for(const n of names) {
    assert.match(complete,new RegExp("SensitiveWeb3CopyGuard wipe[A-Za-z]+OnExit\\{"+n+"\\}"));
  }
  assert.match(complete,/foundation::SecretString continuationSecret\{std::move\(\*continuation\)\}/);
  assert.match(complete,/idp::TransactionId transactionId\{std::move\(\*transaction\)\}/);
  assert.match(complete,/idp::ChallengeId challengeId\{std::move\(\*challenge\)\}/);
  assert.match(complete,/idp::CredentialValue\{std::move\(\*signature\)\}/);
  assert.match(complete,/idp::CredentialValue\{std::move\(\*message\)\}/);
  const awaitAt=complete.indexOf("co_await m_authentication->completeAsync(");
  for(const n of ["wipeBindingOnExit.wipe()","wipeContinuationOnExit.wipe()",
                   "wipeSignatureOnExit.wipe()","wipeMessageOnExit.wipe()",
                   "wipeParsedOnExit.wipe()","wipeRequestOnExit.wipe()"]) {
    assert.ok(complete.indexOf(n)>=0 && complete.indexOf(n)<awaitAt,n+" must occur before async verification");
  }
  assert.match(complete,/co_await m_asyncSessions->issueAsync\(\s*verified\.value\(\), std::move\(client\)\)/);
});

test("cookie parser makes only one copy after duplicate and format validation",()=>{
  const cookie=source.slice(source.indexOf("std::optional<std::string> cookieValue("),
    source.indexOf("[[nodiscard]] foundation::Result<json::object> parseObject"));
  assert.match(cookie,/std::optional<std::string_view> found/);
  assert.match(cookie,/if \(!safe \|\| found\) return std::nullopt/);
  assert.match(cookie,/found = value/);
  assert.match(cookie,/std::optional<std::string>\{std::string\{\*found\}\}/);
  assert.doesNotMatch(cookie,/found = std::string\{value\}/);
});

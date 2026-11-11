#!/usr/bin/env node
// Native enterprise LDAP HTTP must not accidentally call the old synchronous
// AuthenticationService or SessionService, even via disabled fallback routes.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root=path.resolve(import.meta.dirname,"..");
const read=p=>fs.readFileSync(path.join(root,p),"utf8");
const source=read("src/authentication/http/enterprise.cpp");
const executable=cppExecutableText(source);
const header=read("src/authentication/http/enterprise.cppm");
const block=(start,end)=>source.slice(source.indexOf(start),
    end ? source.indexOf(end,source.indexOf(start)) : undefined);
const compatibility=block("EnterpriseAuthenticationHttpApi::startLdap(",
    "EnterpriseAuthenticationHttpApi::nativeEnabledFor(");
const dispatch=block("EnterpriseAuthenticationHttpApi::handleAsync(",
    "EnterpriseAuthenticationHttpApi::startLdapAsync(");
const start=block("EnterpriseAuthenticationHttpApi::startLdapAsync(",
    "EnterpriseAuthenticationHttpApi::completeLdapAsync(");
const completion=block("EnterpriseAuthenticationHttpApi::completeLdapAsync(");
const allNative=dispatch+start+completion;

test("legacy LDAP HTTP cannot issue an unredeemable challenge or use blocking session IO",()=>{
  assert.match(compatibility,/ErrorCode::Unavailable/g);
  assert.match(compatibility,/request, true/g);
  assert.doesNotMatch(compatibility,/m_authentication->(?:begin|complete)\s*\(/);
  assert.doesNotMatch(compatibility,/m_sessions->(?:issue|authenticate)\s*\(/);
});
test("LDAP routes are request-gated on native transaction, identity and issuer readiness",()=>{
  assert.match(header,/public gateway::http::CoroutineHttpHandler/);
  assert.match(header,/nativeEnabled\(\) const noexcept override \{ return false; \}/);
  assert.match(header,/session::CoroutineSessionIssuer\* asyncSessions = nullptr/);
  const cap=block("EnterpriseAuthenticationHttpApi::nativeEnabledFor(",
    "EnterpriseAuthenticationHttpApi::handleAsync(");
  assert.match(cap,/m_asyncSessions == nullptr/);
  assert.match(cap,/m_authentication->nativeProviderAuthenticationEnabled/);
  assert.match(cap,/idp::ProviderId\{"ldap"\}/);
  assert.match(cap,/request.method\(\) != gateway::HttpMethod::Post/);
  assert.match(cap,/m_fallback\)/);
  assert.match(cap,/native->nativeEnabledFor\(request\)/);
  assert.match(cap,/catch \(\.\.\.\)/);
  assert.match(dispatch,/if \(!nativeEnabledFor\(request\)\)/);
  assert.match(dispatch,/co_await native->handleAsync/);
  assert.doesNotMatch(dispatch,/m_fallback->handle\s*\(/);
});
test("native LDAP challenge preserves bounded validated username and issuance cookies",()=>{
  assert.match(start,/co_await m_authentication->beginAsync/);
  assert.match(start,/onlyFields\(body\.value\(\), \{"username"\}\)/);
  assert.match(start,/required\(body\.value\(\), "username", 320U\)/);
  assert.match(start,/m_rateLimiter->allow/);
  assert.match(start,/m_authentication->nativeProviderAuthenticationEnabled|nativeEnabledFor\(request\)/);
  assert.match(start,/idp::ProviderId\{"ldap"\}/);
  assert.match(start,/username_binding/);
  assert.match(start,/cookie\(kContinuationCookie/);
  assert.match(start,/cookie\(kBindingCookie/);
  assert.doesNotMatch(start,/m_authentication->begin\s*\(/);
});
test("native LDAP completion awaits proof redemption and persisted bearer before returning cookie",()=>{
  const rules=[
    /onlyFields\(body\.value\(\),/,
    /"transaction_id"/,/"challenge_id"/,/"username"/,/"username_binding"/,/"password"/,
    /required\(body\.value\(\), "password", 4096U\)/,
    /cookieValue\(request, kContinuationCookie\)/,
    /cookieValue\(request, kBindingCookie\)/,
    /security::sha256\(\*bindingToken\)/,
    /idp::CredentialValue\{std::move\(password\)\.value\(\)\}/,
    /m_rateLimiter->allow\(/,
    /std::string\{"ldap-complete-ip:"\}/,
    /foundation::secureWipe\(parsedPassword\.data\(\), parsedPassword\.size\(\)\)/,
    /co_await m_authentication->completeAsync\(/,
    /co_await m_asyncSessions->issueAsync\(/,
    /if \(!grant\)/,
    /clearState\(response\)/,
    /cookie\("__Host-openproof-session", grant->token\.expose\(\)/,
  ];
  for(const regex of rules)assert.match(completion,regex);
  assert.ok(completion.indexOf("m_rateLimiter->allow(")
       < completion.indexOf("auto body = parseObject(request)"));
  assert.ok(completion.indexOf("foundation::secureWipe(parsedPassword.data()")
       < completion.indexOf("co_await m_authentication->completeAsync("));
  assert.ok(completion.indexOf("co_await m_authentication->completeAsync(")
       < completion.indexOf("co_await m_asyncSessions->issueAsync("));
  assert.ok(completion.indexOf("co_await m_asyncSessions->issueAsync(")
       <completion.indexOf('cookie("__Host-openproof-session"'));
  assert.doesNotMatch(allNative,/m_sessions->|m_authentication->(?:begin|complete)\s*\(/);
  assert.match(source,/SameSite=Strict/);
  assert.match(source,/HttpOnly/);
  assert.match(source,/Secure/);
  assert.match(source,/no-store/);
});

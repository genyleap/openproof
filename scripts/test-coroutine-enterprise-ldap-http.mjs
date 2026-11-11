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

test("LDAP request payload is scrubbed before asynchronous proof verification and on failure",()=>{
  const requestType=read("src/gateway/gateway.cppm");
  const gatewayImpl=read("src/gateway/gateway.cpp");
  assert.match(requestType,/void wipeBody\(\) noexcept/);
  assert.match(gatewayImpl,/void HttpRequest::wipeBody\(\) noexcept[\s\S]*?foundation::secureWipe\(m_body\.data\(\), m_body\.size\(\)\)/);
  assert.match(compatibility,/SensitiveRequestBodyGuard wipeOnExit\{request\}/);
  assert.match(completion,/SensitiveRequestBodyGuard wipeOnExit\{request\}/);
  assert.match(dispatch,/request\.wipeBody\(\)/);
  assert.ok(completion.indexOf("request.wipeBody();") < completion.indexOf("co_await m_authentication->completeAsync("));
});
test("LDAP invalid completion always scrubs parsed password, extracted copy and cookie secrets",()=>{
  const gatewayType=read("src/gateway/gateway.cppm");
  const gatewayImpl=read("src/gateway/gateway.cpp");
  const guards=block("class SensitiveRequestBodyGuard final",
    "[[nodiscard]] gateway::HttpResponse jsonResponse");
  assert.match(gatewayType,/void wipeCookieHeader\(\) noexcept/);
  assert.match(gatewayImpl,/HttpRequest::wipeCookieHeader\(\) noexcept[\s\S]*?foundation::secureWipe\(found->second\.data\(\), found->second\.size\(\)\)/);
  assert.match(guards,/class SensitiveParsedPasswordGuard final/);
  assert.match(guards,/~SensitiveParsedPasswordGuard\(\) \{ wipe\(\); \}/);
  assert.match(guards,/m_object->if_contains\("password"\)/);
  assert.match(guards,/foundation::secureWipe\(value\.data\(\), value\.size\(\)\)/);
  assert.match(guards,/class SensitiveCredentialCopyGuard final/);
  assert.match(guards,/~SensitiveCredentialCopyGuard\(\)/);
  assert.match(guards,/foundation::secureWipe\(m_value->data\(\), m_value->size\(\)\)/);
  assert.match(compatibility,/SensitiveRequestCookieGuard wipeCookieOnExit\{request\}/);
  assert.match(completion,/SensitiveRequestCookieGuard wipeCookieOnExit\{request\}/);
  assert.match(start,/SensitiveRequestCookieGuard wipeCookieOnExit\{request\}/);
  const parsedGuard=completion.indexOf("SensitiveParsedPasswordGuard wipeParsedOnExit");
  const invalidFields=completion.indexOf("!onlyFields(body.value()");
  const copyGuard=completion.indexOf("SensitiveCredentialCopyGuard wipePasswordCopyOnExit");
  const missingSecrets=completion.indexOf("if (!transaction || !challenge");
  assert.ok(parsedGuard >= 0 && parsedGuard < invalidFields);
  assert.ok(copyGuard >= 0 && copyGuard < missingSecrets);
  assert.match(completion,/SensitiveCredentialCopyGuard wipeContinuationOnExit/);
  assert.match(completion,/SensitiveCredentialCopyGuard wipeBindingOnExit/);
  assert.match(completion,/foundation::SecretString continuationSecret\{std::move\(\*continuation\)\}/);
  assert.match(completion,/request\.wipeCookieHeader\(\)/);
  assert.match(dispatch,/request\.wipeCookieHeader\(\)/);
  const awaitVerification=completion.indexOf("co_await m_authentication->completeAsync(");
  assert.ok(completion.indexOf("request.wipeCookieHeader();") < awaitVerification);
  assert.ok(completion.indexOf("request.wipeBody();") < awaitVerification);
  const cookieParser=block("cookieValue(const gateway::HttpRequest& request,",
    "[[nodiscard]] idp::ClientContext clientContext(");
  assert.match(cookieParser,/std::optional<std::string_view> found/);
  assert.match(cookieParser,/if \(found \|\| value\.empty\(\)/);
  assert.match(cookieParser,/found = value;/);
  assert.match(cookieParser,/return std::optional<std::string>\{std::in_place, \*found\}/);
  assert.doesNotMatch(cookieParser,/found = std::string\{value\}/);
  const gatewayTest=read("tests/gateway/gateway_test.cpp");
  assert.match(gatewayTest,/TEST\(HttpRequestTest, WipesPreAuthenticationCookiesWithoutDroppingOtherHeaders\)/);
});
test("LDAP JSON input rejects MIME prefix confusion",()=>{
  const parser=block("parseObject(const gateway::HttpRequest& request)", "[[nodiscard]] foundation::Result<std::string> required(");
  assert.match(parser,/\*contentType == "application\/json"/);
  assert.match(parser,/contentType->starts_with\("application\/json;"\)/);
  assert.doesNotMatch(parser,/!contentType->starts_with\("application\/json"\)/);
});
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

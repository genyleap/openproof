#!/usr/bin/env node
// Security invariants for the opt-in native local-password completion.
// This suite inspects executable C++ source; it is NOT an executable C++
// integration test and cannot substitute for the GCC16 module build.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const raw = fs.readFileSync(path.join(root, "src/authentication/http/http.cpp"), "utf8");
const executable = cppExecutableText(raw);

const block = (source, start, end) => {
  const first = source.indexOf(start);
  const last = end ? source.indexOf(end, first + start.length) : source.length;
  assert.ok(first >= 0 && last > first, "Missing method " + start);
  return source.slice(first, last);
};
const dispatch = block(executable,
  "AuthenticationHttpApi::handleAsync(", "AuthenticationHttpApi::loginAsync(");
const login = block(executable,
  "AuthenticationHttpApi::loginAsync(", "AuthenticationHttpApi::verifyAsync(");
const verify = block(executable,
  "AuthenticationHttpApi::verifyAsync(", "gateway::HttpResponse AuthenticationHttpApi::login(");

test("native auth rejection always erases raw body, authorization and cookies", () => {
  const guard = block(executable,
    "class SensitiveAuthRequestGuard final", "class SensitiveParsedAuthSecretsGuard final");
  for (const wipe of ["wipeBody", "wipeAuthorizationHeader", "wipeCookieHeader"]) {
    assert.ok(guard.includes("m_request." + wipe + "()"), wipe);
  }
  assert.match(guard, /~SensitiveAuthRequestGuard\(\) \{ wipe\(\); \}/);
  assert.match(guard, /SensitiveAuthRequestGuard\(const SensitiveAuthRequestGuard&\) = delete/);
  for (const method of [dispatch, login, verify]) {
    assert.match(method, /SensitiveAuthRequestGuard wipeRequestOnExit\{request\}/);
  }
  assert.ok(dispatch.indexOf("wipeRequestOnExit{request}") <
    dispatch.indexOf("nativeEnabledFor(request)"));
});

test("all parsed password, TOTP and recovery code fields are securely erased", () => {
  const guard = block(raw,
    "class SensitiveParsedAuthSecretsGuard final", "class SensitiveAuthCopyGuard final");
  for (const field of ["password", "totp", "recovery_code"])
    assert.ok(guard.includes('"' + field + '"'), field);
  assert.match(guard, /foundation::secureWipe\(value.data\(\), value.size\(\)\)/);
  assert.match(guard, /~SensitiveParsedAuthSecretsGuard\(\) \{ wipe\(\); \}/);
  assert.ok(verify.indexOf("auto body = parseObject(request)") <
    verify.indexOf("SensitiveParsedAuthSecretsGuard wipeParsedOnExit"));
  assert.ok(verify.indexOf("SensitiveParsedAuthSecretsGuard wipeParsedOnExit") <
    verify.indexOf("!onlyFields(body.value()"));
  const validation = verify.indexOf("if (!transaction || !challenge || !knowledgeSecret");
  for (const name of ["wipeKnowledgeOnExit", "wipeTotpOnExit", "wipeRecoveryOnExit",
                      "wipeContinuationOnExit", "wipeBindingOnExit", "wipeSubjectOnExit"]) {
    const offset = verify.indexOf(name);
    assert.ok(offset > 0 && offset < validation, "secret guard missing before early denial: " + name);
  }
});

test("native password verification clears unprotected copies before the first await", () => {
  const guard = block(raw,
    "class SensitiveAuthCopyGuard final", "[[nodiscard]] gateway::HttpResponse response(");
  assert.match(guard, /SensitiveAuthCopyGuard\(std::string\* value\)/);
  assert.match(guard, /SensitiveAuthCopyGuard\(std::optional<std::string>\* value\)/);
  assert.match(guard, /~SensitiveAuthCopyGuard\(\) \{ wipe\(\); \}/);
  assert.match(guard, /foundation::secureWipe\(value->data\(\), value->size\(\)\)/);
  const firstAwait = verify.indexOf("co_await m_authentication->completeAsync(");
  assert.ok(firstAwait > 0);
  for (const call of ["wipeParsedOnExit.wipe()", "wipeBindingOnExit.wipe()",
                     "wipeSubjectOnExit.wipe()", "wipeRequestOnExit.wipe()"]) {
    assert.ok(verify.indexOf(call) >= 0 && verify.indexOf(call) < firstAwait, call);
  }
  assert.match(verify, /foundation::SecretString continuationSecret\{std::move\(\*continuation\)\}/);
  assert.match(verify, /oldToken.emplace\(std::move\(\*previous\)\)/);
  assert.match(verify, /std::move\(continuationSecret\), binding.value\(\)/);
  assert.doesNotMatch(verify, /foundation::SecretString\{\*continuation\}/);
  assert.doesNotMatch(verify, /oldToken.emplace\(std::string\{\*previous\}\)/);
});

test("native preauthentication binds a wiping secret and erases old credentials before suspension", () => {
  assert.match(login, /foundation::SecretString bindingSecret\{std::move\(bindingToken\).value\(\)\}/);
  assert.match(login, /preauthBinding\(bindingSecret.expose\(\), subjectValue\)/);
  assert.match(login, /kBindingCookie, bindingSecret.expose\(\)/);
  assert.ok(login.indexOf("wipeRequestOnExit.wipe()") <
    login.indexOf("co_await m_authentication->beginAsync("));
});

test("shared parsed-string and cookie parsers do not create prevalidation copies", () => {
  const required = block(raw, "requiredString(", "optionalString(");
  assert.match(required, /const auto& text = value->as_string\(\)/);
  assert.doesNotMatch(required, /const auto text = value->as_string\(\)/);
  const cookie = block(raw, "cookieValue(", "clientContext(");
  assert.match(cookie, /std::optional<std::string_view> found/);
  assert.match(cookie, /if \(found.has_value\(\) \|\| value.empty\(\)/);
  assert.match(cookie, /found = value;/);
  assert.match(cookie, /return std::optional<std::string>\{std::in_place, \*found\}/);
  assert.doesNotMatch(cookie, /found = std::string\{value\}/);
});


test("native federated redirect rejects before SQL without exposing a Location header", () => {
  // Retain literal characters: the lexer intentionally blanks quoted C++ strings.
  const source = fs.readFileSync(
    path.join(root, "src/authentication/service.cpp"), "utf8");
  const helper = block(source,
    "safeNativeAuthorizationUrl(", "[[nodiscard]] std::string digestHex(");
  for (const guard of ["url.starts_with(scheme)", "url.size() > 8192U",
                       "authority.empty()", "authority.contains('@')",
                       "authority.contains('%')", "authority.contains('\\\\')",
                       "byte >= 0x21U", "byte <= 0x7EU", "c != '#'"]) {
    assert.ok(helper.includes(guard), "missing safe redirect constraint: " + guard);
  }
  const asyncStart = block(source,
    "AuthenticationService::beginInternalAsync(", "AuthenticationService::completeExchange(");
  const check = asyncStart.indexOf("safeNativeAuthorizationUrl(url->second)");
  const persist = asyncStart.indexOf("nativeTransactions->beginAsync(");
  assert.ok(check > 0 && persist > check,
    "Reject an unsafe provider redirect before allocating a durable transaction");

  const nativeStart = cppExecutableText(fs.readFileSync(
    path.join(root, "src/authentication/http/coroutine_federated_start_http.cpp"), "utf8"));
  const handler = block(nativeStart,
    "CoroutineFederatedStartAdapter::handleAsync(", null);
  assert.match(handler, /if \(!started\) co_return denied\(started.error\(\), request\)/);
  assert.ok(handler.indexOf("if (!started)") <
    handler.indexOf('gateway::HttpResponse response{'),
    "No Location or cookies may be built after a rejected start");
});

test("both native federation HTTP legs erase raw request secrets on early denial", () => {
  const configurations = [
    ["src/authentication/http/coroutine_federated_start_http.cpp",
     "SensitiveFederatedStartRequestGuard",
     "CoroutineFederatedStartAdapter::handleAsync(",
     "if (!m_limiter->allow("],
    ["src/authentication/http/coroutine_federated_callback_http.cpp",
     "SensitiveFederatedCallbackRequestGuard",
     "CoroutineFederatedCallbackAdapter::handleAsync(",
     "if (request.method() != gateway::HttpMethod::Get"],
  ];
  for (const [file, type, method, firstRejection] of configurations) {
    const source = cppExecutableText(fs.readFileSync(
      path.join(root, file), "utf8"));
    const guard = block(source, "class " + type + " final", "};");
    for (const wipe of ["wipeTargetQuery", "wipeBody",
                        "wipeAuthorizationHeader", "wipeCookieHeader"])
      assert.ok(guard.includes("m_request." + wipe + "()"),
        file + " must scrub " + wipe);
    assert.ok(guard.includes("~" + type + "() { wipe(); }"),
      file + " must scrub on all return paths");
    const handler = block(source, method, null);
    const entry = handler.indexOf(type + " wipeRequestOnExit{request}");
    assert.ok(entry > 0 && entry < handler.indexOf(firstRejection),
      file + " must install the wipe guard before validation");
  }
  const startSource = cppExecutableText(fs.readFileSync(
    path.join(root, configurations[0][0]), "utf8"));
  const start = block(startSource,
    "CoroutineFederatedStartAdapter::handleAsync(", null);
  assert.ok(start.indexOf("request.wipeTargetQuery();") <
    start.indexOf("co_await m_authentication->beginAsync("),
    "The raw URL query must be erased before the first native auth suspension");
  const source = fs.readFileSync(
    path.join(root, configurations[0][0]), "utf8");
  const nativeHandler = block(source,
    "CoroutineFederatedStartAdapter::handleAsync(", null);
  assert.match(nativeHandler, /params->size\(\) > 2U/);
  assert.match(nativeHandler, /entry\.first != "provider" && entry\.first != "return_to"/);
  assert.ok(nativeHandler.indexOf('entry.first != "provider"') <
    nativeHandler.indexOf("co_await m_authentication->beginAsync("),
    "An unsupported native ceremony must fail before its transaction is persisted");
});

test("native redirect proof family and ceremony purpose are checked before provider exchange", () => {
  const service = cppExecutableText(fs.readFileSync(path.join(root,
    "src/authentication/service.cpp"), "utf8"));
  const native = block(service, "AuthenticationService::completeExchangeAsync(",
    "AuthenticationService::requireActiveIdentity(");
  const consume = native.indexOf("nativeTransactions->consumeAsync(");
  const purpose = native.indexOf("isConnection != requireConnection");
  const family = native.indexOf("native->redirectProofKind()");
  const exchange = native.indexOf("native->completeAuthenticationAsync(");
  assert.ok(consume >= 0 && consume < purpose && purpose < family && family < exchange,
    "consumption must precede purpose and provider proof-family checks before exchange");
  const sync = block(service, "AuthenticationService::completeExchange(",
    "AuthenticationService::completeExchangeAsync(");
  assert.ok(sync.indexOf("isConnection != requireConnection") >= 0 &&
    sync.indexOf("isConnection != requireConnection") <
      sync.indexOf("implementation->completeAuthentication(response)"));
  const callback = fs.readFileSync(path.join(root,
    "src/authentication/http/coroutine_federated_callback_http.cpp"), "utf8");
  assert.match(callback, /code==values->end\(\) && state==values->end\(\) && user==values->end\(\)/);
  assert.match(callback, /proof.setParameter\("oauth_token"/);
  assert.match(callback, /proof.setParameter\("oauth_verifier"/);
  const x = fs.readFileSync(path.join(root, "src/providers/x/x.cppm"), "utf8");
  assert.match(x, /RedirectProofKind::OAuth1/);
});

test("native form post admits one bounded proof source with exact media type",()=>{
  const source=fs.readFileSync(path.join(root,
    "src/authentication/http/coroutine_federated_callback_http.cpp"),"utf8");
  const parser=block(source,"callbackParameters(","readCookie(");
  assert.match(parser,/request.method\(\)==gateway::HttpMethod::Post/);
  assert.match(parser,/\*type!="application\/x-www-form-urlencoded"/);
  assert.match(parser,/suffix.starts_with\("provider="\)/);
  assert.match(parser,/input.size\(\)>64U\*1024U/);
  assert.match(parser,/output.contains\(\*key\)/);
  assert.match(source,/request.method\(\)==gateway::HttpMethod::Get\s*&& bounded\(oauthToken/);
  assert.match(source,/CookieCopyGuard wipeContinuation\{continuation\}/);
  assert.match(source,/CookieCopyGuard wipePrevious\{previous\}/);
});

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

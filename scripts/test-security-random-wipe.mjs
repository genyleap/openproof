#!/usr/bin/env node
// CSPRNG secret-lifetime guard. Runtime OpenSSL/GTest checks remain mandatory.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root=path.resolve(import.meta.dirname,"..");
const source=cppExecutableText(fs.readFileSync(
  path.join(root,"src/security/random.cpp"),"utf8"));
const tests=fs.readFileSync(
  path.join(root,"tests/security/security_test.cpp"),"utf8");
const raw=source.slice(source.indexOf("randomBytes(std::size_t count)"),
  source.indexOf("randomTokenBase64Url(std::size_t byteCount)"));
const encoded=source.slice(source.indexOf(
  "randomTokenBase64Url(std::size_t byteCount)"));

test("OpenSSL RNG failure wipes partial entropy and cannot silently downgrade",()=>{
  assert.match(raw,/const int status = RAND_bytes/);
  assert.match(raw,/if \(status != 1\)/);
  assert.match(raw,/foundation::secureWipe\(buffer\.data\(\), buffer\.size\(\)\)/);
  assert.ok(raw.indexOf("foundation::secureWipe(") < raw.lastIndexOf(
    "return foundation::fail("));
  assert.doesNotMatch(raw,/\brand\s*\(|\bstd::mt19937\b/);
});

test("GCC16 C++26 implicit move avoids a redundant move rejected by -Werror",()=>{
  assert.match(raw,/return buffer;/);
  assert.doesNotMatch(raw,/return std::move\(buffer\);/);
});

test("Base64URL token generation RAII-scrubs its raw CSPRNG entropy",()=>{
  assert.match(encoded,/auto bytes = randomBytes\(byteCount\)/);
  assert.match(encoded,/if \(!bytes\.has_value\(\)\)/);
  assert.match(encoded,/foundation::Secret<std::vector<std::byte>> entropy\{/);
  assert.match(encoded,/std::move\(bytes\)\.value\(\)/);
  assert.match(encoded,/foundation::toBase64Url\(entropy\.expose\(\)\)/);
  assert.doesNotMatch(encoded,/foundation::toBase64Url\(bytes\.value\(\)\)/);
});

test("cryptographic runtime regressions verify token entropy and error boundaries",()=>{
  assert.match(tests,/TEST\(RandomTest, SuccessiveCallsDifferAndAreNotAllZero\)/);
  assert.match(tests,/TEST\(RandomTest, TokenIsUrlSafeAndDerivedFromRequestedEntropy\)/);
  assert.match(tests,/TEST\(RandomTest, RejectsAnImpossiblyLargeRequest\)/);
});

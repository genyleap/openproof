#!/usr/bin/env node
// Source-only guard for HMAC input buffers which contain browser/callback or
// provider signing secrets. Not a substitute for compiled C++ crypto tests.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const read = file => fs.readFileSync(path.join(root, file), "utf8");
const local = read("src/authentication/http/http.cpp");
const provider = read("src/providers/x/x.cpp");

test("preauthentication browser binding HMAC material is scrubbed on all exit paths", () => {
  const begin = local.indexOf("preauthBinding(");
  const end = local.indexOf("decodePreauthSubject(", begin);
  assert.ok(begin >= 0 && end > begin);
  const block = local.slice(begin, end);
  assert.match(local, /class SensitiveBindingMaterialGuard final/);
  assert.match(local, /~SensitiveBindingMaterialGuard\(\)[\s\S]*?foundation::secureWipe\(m_value.data\(\), m_value.size\(\)\)/);
  assert.match(block, /SensitiveBindingMaterialGuard wipeMaterialOnExit\{material\}/);
  assert.ok(block.indexOf("wipeMaterialOnExit{material}") <
    block.indexOf("material.append(bindingToken)"));
  assert.match(block, /return security::sha256\(material\)/);
});

test("X OAuth1 shared-secret signing key is securely wiped before returning the signature", () => {
  const begin = provider.indexOf("oauthAuthorization(");
  const end = provider.indexOf("struct HttpResponse final", begin);
  assert.ok(begin >= 0 && end > begin);
  const block = provider.slice(begin, end);
  assert.match(provider, /class SensitiveSigningKeyGuard final/);
  assert.match(provider, /~SensitiveSigningKeyGuard\(\) \{ wipe\(\); \}/);
  assert.match(provider, /foundation::secureWipe\(m_value.data\(\), m_value.size\(\)\)/);
  assert.match(block, /SensitiveSigningKeyGuard wipeSigningKeyOnExit\{signingKey\}/);
  assert.ok(block.indexOf("wipeSigningKeyOnExit{signingKey}") <
    block.indexOf("signingKey.append(percentEncode(tokenSecret))"));
  assert.ok(block.indexOf("wipeSigningKeyOnExit.wipe();") >
    block.indexOf("hmacSha1Base64(signingKey, signatureBase)"));
  assert.doesNotMatch(block, /std::ranges::fill\(signingKey/);
});

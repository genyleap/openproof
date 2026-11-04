#!/usr/bin/env node
// Credential-memory hygiene in the legacy LDAP bridge. These source tests
// deliberately do NOT claim LDAP has migrated to nonblocking coroutines.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const raw = fs.readFileSync(
  path.join(root, "src/providers/enterprise/enterprise.cpp"), "utf8");
const source = cppExecutableText(raw);
const start = source.indexOf("foundation::Status simpleBind(");
const end = source.indexOf("std::optional<std::string> ldapValue(", start);
assert.ok(start >= 0 && end > start);
const bind = source.slice(start, end);

test("LDAP simple bind erases temporary plaintext on every exit", () => {
  assert.match(bind, /std::string passwordStorage\{password\}/);
  assert.match(bind, /struct PasswordScrub final/);
  assert.match(bind, /~PasswordScrub\(\) noexcept/);
  assert.match(bind, /volatile char\* bytes = value\.data\(\)/);
  assert.match(raw.slice(raw.indexOf("foundation::Status simpleBind("),
    raw.indexOf("std::optional<std::string> ldapValue(")),
    /for\s*\(std::size_t i = 0; i < value\.size\(\); \+\+i\) bytes\[i\] = '\\0'/);
  assert.match(bind, /\}\s*scrub\{passwordStorage\};/);
  assert.ok(bind.indexOf("scrub{passwordStorage}") <
            bind.indexOf("ldap_sasl_bind_s("));
});

test("legacy LDAP synchronous search and bind remain explicit blockers", () => {
  assert.match(source, /ldap_sasl_bind_s\s*\(/);
  assert.match(source, /ldap_search_ext_s\s*\(/);
  const gate = fs.readFileSync(
    path.join(root, "scripts/verify-coroutine-coverage.mjs"), "utf8");
  assert.match(gate, /blocking LDAP bind\/search/);
  assert.match(gate, /ldap_\(\?:sasl_bind_s\|search_ext_s\|simple_bind_s\)/);
});

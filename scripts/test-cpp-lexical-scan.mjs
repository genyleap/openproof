#!/usr/bin/env node
import assert from "node:assert/strict";
import test from "node:test";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

test("does not accept co_await or blocking calls in comments and literals", () => {
  const source = [
    "// co_await PQexec(connection, sql)",
    'auto literal = "co_await PQexec(connection, sql)";',
    'auto raw = R"OP(co_await PQexec(connection, sql))OP";',
    "/* co_await",
    "  PQexec(connection, sql) */",
    "auto count = 250'000U;",
    "co_await database.async_query();"
  ].join("\n");
  const code = cppExecutableText(source);
  assert.equal(code.length, source.length);
  assert.equal(code.split("\n").length, source.split("\n").length);
  assert.equal([...code.matchAll(/\bco_await\b/g)].length, 1);
  assert.doesNotMatch(code, /\bPQexec\s*\(/);
  assert.match(code, /250'000U/);
  assert.match(code, /co_await database\.async_query\(\)/);
});

test("finds actual forbidden C++ calls and preserves line number", () => {
  const source = [
    "/* PQexec(fake, fake) */",
    'const auto sql = "PQexec(quoted, quoted)";',
    "auto* output = PQexec(connection, query);",
    'auto* fake = R"abc(PQreset(fake))abc";'
  ].join("\n");
  const code = cppExecutableText(source);
  const match = /\bPQexec\s*\(/.exec(code);
  assert.ok(match);
  assert.equal(code.slice(0, match.index).split("\n").length, 3);
  assert.doesNotMatch(code, /\bPQreset\s*\(/);
});

test("retains character literals, escapes and bounded raw-string syntax", () => {
  const source = [
    "auto c = 'x'; auto x = \"quoted\";",
    'auto text = u8R"XYZ(ldap_sasl_bind_s(handle, secret);',
    'co_await fake(); )XYZ";',
    "auto answer = 120'000U;",
    "co_await real();"
  ].join("\n");
  const code = cppExecutableText(source);
  assert.equal(code.length, source.length);
  assert.doesNotMatch(code, /ldap_sasl_bind_s|fake/);
  assert.match(code, /co_await real\(\)/);
  assert.match(code, /120'000U/);
});

test("empty and unterminated comments cannot manufacture coroutine coverage", () => {
  assert.equal(cppExecutableText(""), "");
  assert.doesNotMatch(
    cppExecutableText("int main() {} /* co_await unreachable();"),
    /\bco_await\b/
  );
});

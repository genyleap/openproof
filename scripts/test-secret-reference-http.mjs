#!/usr/bin/env node
// Explicitly guard the HTTP paths where a SecretString-backed bearer or
// challenge is inspected. A const auto initialized from expose() silently
// copies the protected std::string into an ordinary, non-wiping buffer.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const read = file => fs.readFileSync(path.join(root, file), "utf8");
const evidence = read("src/evidence/http/http.cpp");
const ldap = read("src/authentication/http/enterprise.cpp");
const local = read("src/authentication/http/http.cpp");

for (const [name, source, start, end, token] of [
  ["evidence challenge", evidence, "Api::issueChallenge(", "Api::verify(", "challenge->token"],
  ["native LDAP session", ldap, "EnterpriseAuthenticationHttpApi::completeLdapAsync(", "} // namespace openproof::authentication::http", "grant->token"],
  ["native first-party session", local, "AuthenticationHttpApi::verifyAsync(", "gateway::HttpResponse AuthenticationHttpApi::login(", "issued->token"]
]) {
  test(name + " inspection must borrow, never clone, the auto-wiping secret", () => {
    const begin = source.indexOf(start);
    const finish = source.indexOf(end, begin + start.length);
    assert.ok(begin >= 0 && finish > begin, "cannot locate handler");
    const handler = source.slice(begin, finish);
    assert.ok(handler.includes("const auto& " + (name === "evidence challenge" ? "token" : "bearer") +
      " = " + token + ".expose();"));
    assert.ok(!handler.includes("const auto " + (name === "evidence challenge" ? "token" : "bearer") +
      " = " + token + ".expose();"));
  });
}

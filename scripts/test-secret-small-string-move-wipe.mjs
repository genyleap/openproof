#!/usr/bin/env node
// Security contract: a moved-from short std::string may have size()==0
// while retaining all but the first byte in SSO storage. Structural
// checks complement native C++ object-representation regressions.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const root=path.resolve(import.meta.dirname,"..");
const read=f=>fs.readFileSync(path.join(root,f),"utf8");
const foundation=read("src/foundation/secret.cppm");
const implementation=read("src/foundation/secret.cpp");
const credentialApi=read("src/identity/provider/outcome.cppm");
const credential=read("src/identity/provider/outcome.cpp");
const foundationTests=read("tests/foundation/secret_test.cpp");
const credentialTests=read("tests/identity/provider_test.cpp");

test("foundation scrub re-exposes only moved-from inline size and securely wipes",()=>{
  assert.match(foundation,/void wipeMovedFromString\(std::string& source, std::size_t originalSize\) noexcept/);
  const start=implementation.indexOf("void wipeMovedFromString(");
  const end=implementation.indexOf("void secureWipe(",start);
  const method=implementation.slice(start,end);
  assert.ok(start>=0 && end>start);
  assert.match(method,/source\.size\(\) < originalSize && originalSize <= source\.capacity\(\)/);
  assert.match(method,/source\.resize\(originalSize\)/);
  assert.match(method,/secureWipe\(source\.data\(\), source\.size\(\)\)/);
  assert.ok(method.indexOf("source.resize(originalSize)")<method.indexOf("secureWipe("));
  assert.match(method,/source\.clear\(\)/);
  assert.doesNotMatch(method,/secureWipe\(source\.data\(\),\s*originalSize\)/);
});

test("move-only Secret scrubs caller rvalue and wrapper move sources",()=>{
  assert.match(foundation,/explicit Secret\(T&& value\)/);
  assert.match(foundation,/explicit Secret\(const T& value\)/);
  assert.match(foundation,/wipeMovedFromString\(value, m_value\.size\(\)\)/);
  assert.match(foundation,/wipeMovedFromString\(other\.m_value, m_value\.size\(\)\)/);
  assert.ok((foundation.match(/wipeMovedFromString\(other\.m_value, m_value\.size\(\)\)/g)||[]).length===2);
  for(const name of ["ShortRvalueConstructionScrubsInlineSource",
                     "ShortMoveConstructionAndAssignmentScrubInlineSources"]){
    assert.ok(foundationTests.includes("TEST(SecretTest, "+name+")"));
  }
  assert.match(foundationTests,/objectContainsText\(source, "tp-1234"\)/);
  assert.match(foundationTests,/objectContainsText\(another\.expose\(\), "ode-678"\)/);
});

test("provider credential type retains lvalue copy and scrubs rvalue SSO sources",()=>{
  assert.match(credentialApi,/explicit CredentialValue\(std::string&& value\) noexcept/);
  assert.match(credentialApi,/explicit CredentialValue\(const std::string& value\)/);
  assert.match(credential,/CredentialValue::CredentialValue\(std::string&& value\) noexcept/);
  assert.match(credential,/foundation::wipeMovedFromString\(value, m_value\.size\(\)\)/);
  assert.equal((credential.match(/foundation::wipeMovedFromString\(other\.m_value, m_value\.size\(\)\)/g)||[]).length,2);
  for(const name of ["ShortTotpRvalueConstructionScrubsCaller",
                     "ShortSecretMoveScrubsInlineSource"])
    assert.ok(credentialTests.includes("TEST(CredentialValueTest, "+name+")"));
  assert.match(credentialTests,/containsObjectBytes\(code, "19284"\)/);
  assert.match(credentialTests,/containsObjectBytes\(other\.expose\(\), "fa-4567"\)/);
});

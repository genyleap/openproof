#!/usr/bin/env node
// Source contract for the common protected-route credential extractor.
// This is not a substitute for the gateway C++ GTests. It ensures the
// production extractor never reintroduces plain credential temporaries.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root=path.resolve(import.meta.dirname,"..");
const read=file=>fs.readFileSync(path.join(root,file),"utf8");
const gateway=cppExecutableText(read("src/gateway/gateway.cpp"));
const model=read("src/gateway/gateway.cppm");
const tests=read("tests/gateway/gateway_test.cpp");
const extractor=gateway.slice(gateway.indexOf("takeSessionCredential(HttpRequest& request)"),
    gateway.indexOf("\nRoute::Route(",gateway.indexOf("takeSessionCredential(HttpRequest& request)")));

test("authorization header erased in-place on valid and malformed bearer inputs",()=>{
  assert.match(model,/void wipeAuthorizationHeader\(\) noexcept/);
  assert.match(gateway,/void HttpRequest::wipeAuthorizationHeader\(\) noexcept[\s\S]*?secureWipe\(found->second\.data\(\), found->second\.size\(\)\)/);
  assert.match(extractor,/std::optional<foundation::SecretString> bearer/);
  assert.doesNotMatch(extractor,/std::optional<std::string> bearer/);
  assert.match(extractor,/bearer\.emplace\(foundation::SecretString/);
  assert.ok((extractor.match(/request\.wipeAuthorizationHeader\(\)/g)||[]).length>=2);
  assert.doesNotMatch(extractor,/request\.eraseHeader\("authorization"\)/);
});
test("duplicate session cookies fail closed before a credential copy is allocated",()=>{
  assert.match(extractor,/std::optional<std::string_view> cookieTokenView/);
  assert.match(extractor,/if \(!valid \|\| cookieTokenView\.has_value\(\)\)/);
  assert.match(extractor,/cookieTokenView = value;/);
  assert.match(extractor,/cookieToken\.emplace\(foundation::SecretString/);
  assert.ok(extractor.indexOf("cookieTokenView = value;") <
    extractor.indexOf("cookieToken.emplace("));
  assert.match(extractor,/std::vector<std::string_view> retained/);
  assert.doesNotMatch(extractor,/std::vector<std::string> retained/);
  assert.match(extractor,/request\.wipeCookieHeader\(\)/);
  assert.doesNotMatch(extractor,/request\.eraseHeader\("cookie"\)/);
});
test("rejected bearer plus cookie never reaches downstream with leftover credentials",()=>{
  assert.match(extractor,/if \(bearer\.has_value\(\) && cookieToken\.has_value\(\)\)/);
  assert.match(extractor,/request\.wipeCookieHeader\(\);\s*return foundation::fail\(foundation::ErrorCode::AuthenticationRequired/);
  assert.match(extractor,/request\.wipeAuthorizationHeader\(\);\s*[\s\S]*?request\.wipeCookieHeader\(\);\s*return foundation::fail/);
  for(const name of [
    "SessionCredentialExtractionScrubsBearerAndRetainsOtherCookies",
    "SessionCookieExtractionScrubsOriginalAndPreservesOtherCookies",
    "DuplicateOrAmbiguousCredentialsAreRejectedAndScrubbed",
    "NoSessionCredentialPreservesUnrelatedHeaders"
  ]) assert.ok(tests.includes("TEST(HttpRequestTest, "+name+")"),name);
});

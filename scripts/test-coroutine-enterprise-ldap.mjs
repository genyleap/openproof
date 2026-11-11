#!/usr/bin/env node
// Legacy LDAP socket operations are retired. A native Asio LDAPS service
// remains, but federated HTTP integration is an explicit release blocker.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root=path.resolve(import.meta.dirname,"..");
const read=p=>fs.readFileSync(path.join(root,p),"utf8");
const enterprise=cppExecutableText(read("src/providers/enterprise/enterprise.cpp"));
const native=cppExecutableText(read("src/providers/enterprise/async_ldaps.cpp"));
const gate=read("scripts/verify-coroutine-coverage.mjs");
const federated=cppExecutableText(read("src/authentication/http/federated.cpp"));
const sync=enterprise.slice(enterprise.indexOf(
  "LdapAuthenticationProvider::completeAuthentication("),
  enterprise.indexOf("LdapAuthenticationProvider::beginAuthenticationAsync("));
const async=enterprise.slice(enterprise.indexOf(
  "LdapAuthenticationProvider::completeAuthenticationAsync("),
  enterprise.indexOf("SamlProviderConfig::SamlProviderConfig("));

test("retired synchronous LDAP completion fails closed without network I/O",()=>{
  assert.match(sync,/foundation::fail\(foundation::ErrorCode::Unavailable/);
  assert.doesNotMatch(sync,/\b(?:simpleBind|ldap_sasl_bind_s|ldap_search_ext_s|openLdap|co_spawn|context\.run)\s*\(/);
  assert.doesNotMatch(enterprise,/\bldap_(?:sasl_bind_s|search_ext_s|simple_bind_s|unbind_ext_s)\s*\(/);
});

test("native LDAP still awaits certificate-verified bounded Asio DNS TCP TLS BER",()=>{
  for(const rule of [
    /co_await\s+async_detail::AsyncLdapsClient::authenticate\s*\(/,
    /security::constantTimeEquals/,
  ]) assert.match(async,rule);
  for(const rule of [
    /resolver\.async_resolve\s*\(/,
    /async_connect\s*\(/,
    /stream\.async_handshake\s*\(/,
    /asio::async_read\s*\(/,
    /asio::async_write\s*\(/,
    /ssl::host_name_verification\s*\(/,
  ]) assert.match(native,rule);
  assert.doesNotMatch(native,/\bldap_\w+\s*\(/);
});

test("federated HTTP still blocks release until native completion is wired",()=>{
  assert.match(federated,/m_authentication->complete\s*\(/);
  assert.doesNotMatch(federated,/co_await\s+m_authentication->completeAsync\s*\(/);
  assert.match(gate,/LDAP federation HTTP still lacks native authentication completion/);
  assert.match(gate,/federatedHttp/);
});

test("LDAP parser validation remains local-only and does not disable SAML",()=>{
  assert.match(enterprise,/ldap_str2dn\s*\(/);
  assert.match(enterprise,/SamlAuthenticationProvider::completeAuthentication\s*\(/);
  assert.match(enterprise,/LdapAuthenticationProvider::beginAuthenticationAsync\s*\(/);
});

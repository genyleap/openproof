#!/usr/bin/env node
// Legacy LDAP socket operations are retired. A native Asio LDAPS service
// remains, but LDAP enterprise HTTP runtime integration is a release blocker.
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
const enterpriseHttp=cppExecutableText(read("src/authentication/http/enterprise.cpp"));
const app=read("apps/opp/main.cpp");
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

test("native LDAP runtime has a separate, explicitly gated transactional stack",()=>{
  assert.match(enterpriseHttp,/co_await\s+m_authentication->beginAsync\s*\(/);
  assert.match(enterpriseHttp,/co_await\s+m_authentication->completeAsync\s*\(/);
  assert.match(enterpriseHttp,/co_await\s+m_asyncSessions->issueReplacingAsync\s*\(/);
  assert.match(app,/environment\.get\("OPENPROOF_EXPERIMENTAL_NATIVE_LDAP"\)/);
  assert.match(app,/nativeLdapFlag\s*&&\s*\*nativeLdapFlag\s*==\s*"1"/);
  assert.match(app,/nativeLdapFlag\s*&&\s*\*nativeLdapFlag\s*!=\s*"0"/);
  assert.match(app,/if\s*\(nativeLdapEnabled\)\s*\{/);
  assert.match(app,/std::make_unique<\s*postgres::CoroutinePostgresAuthenticationTransactionStore>/);
  assert.match(app,/std::make_unique<\s*postgres::CoroutinePostgresCanonicalFinalizer>/);
  assert.match(app,/std::make_unique<\s*postgres::CoroutinePostgresSessionRepository>/);
  assert.match(app,/std::make_unique<\s*postgres::CoroutinePostgresSessionService>/);
  assert.match(app,/std::make_unique<auth::AuthenticationService>/);
  assert.match(app,/nativeAuthentication\s*\?\s*\*nativeAuthentication\s*:\s*authentication/);
  assert.match(app,/fallback, nativeSessions\.get\(\)/);
  assert.match(app,/auto nativeTrust = trust;/);
  assert.match(app,/if\s*\(nativeLdapEnabled\)\s*nativeSessionSecret\.emplace\(sessionSecret->clone\(\)\)/);
  assert.match(app,/std::move\(\*nativeSessionSecret\), sessionPolicy/);
  const server = app.slice(app.indexOf("[[nodiscard]] ExitCode runGatewayServer("));
  assert.ok(server.indexOf("OPENPROOF_EXPERIMENTAL_NATIVE_LDAP") >= 0
       && server.indexOf("OPENPROOF_EXPERIMENTAL_NATIVE_LDAP")
          < server.indexOf("postgres::Migrator migrator{*pool.value()}"),
    "invalid native flags must fail before any schema migration");
  assert.match(app,/!platform\.auth\(\)\.enabled\(\)\s*\|\|\s*!ldapUri/);
  assert.match(gate,/LDAP native HTTP login not connected to runtime transaction\/canonical\/session stack/);
  assert.match(gate,/src\/authentication\/http\/enterprise\.cpp/);
});

test("LDAP parser validation remains local-only and does not disable SAML",()=>{
  assert.match(enterprise,/ldap_str2dn\s*\(/);
  assert.match(enterprise,/SamlAuthenticationProvider::completeAuthentication\s*\(/);
  assert.match(enterprise,/LdapAuthenticationProvider::beginAuthenticationAsync\s*\(/);
});

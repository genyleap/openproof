#!/usr/bin/env node
// Structural migration guard. A passing test does NOT certify LDAP BER/TLS
// behavior; the isolated GTests and the compiled provider module are required.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const read = p => fs.readFileSync(path.join(root,p),"utf8");
const native = cppExecutableText(read("src/providers/enterprise/async_ldaps.cpp"));
const interfaceSource = read("src/providers/enterprise/enterprise.cppm");
const providerSource = cppExecutableText(read("src/providers/enterprise/enterprise.cpp"));
const testSource = read("tests/providers/async_ldaps_test.cpp");

test("enterprise LDAP exposes a true CoroutineAuthenticationProvider SPI", () => {
  assert.match(interfaceSource, /LdapAuthenticationProvider final\s*:\s*public identity::provider::AuthenticationProvider,\s*public identity::provider::CoroutineAuthenticationProvider/);
  assert.match(interfaceSource, /beginAuthenticationAsync\(identity::provider::AuthenticationRequest request\) override/);
  assert.match(interfaceSource, /completeAuthenticationAsync\(identity::provider::AuthenticationResponse response\) override/);
  const completion = providerSource.slice(providerSource.indexOf("LdapAuthenticationProvider::completeAuthenticationAsync("),
    providerSource.indexOf("SamlProviderConfig::SamlProviderConfig("));
  assert.match(completion, /security::constantTimeEquals/);
  assert.match(completion, /co_await async_detail::AsyncLdapsClient::authenticate\(/);
  assert.doesNotMatch(completion, /simpleBind\s*\(|findUniqueLdapEntry\s*\(|ldap_result\s*\(|ldap_sasl_bind_s\s*\(/);
});

test("LDAP native transport has no blocking OpenLDAP, offloaded workers or private io.run", () => {
  assert.match(native, /AsyncLdapsClient::authenticate\(LdapsRequest request\)/);
  assert.match(native, /resolver\.async_resolve\(/);
  assert.match(native, /async_connect\(/);
  assert.match(native, /stream\.async_handshake\(/);
  assert.match(native, /asio::async_write\(/);
  assert.match(native, /asio::async_read\(/);
  assert.doesNotMatch(native, /\bldap_[a-z0-9_]+\s*\(/i);
  assert.doesNotMatch(native, /(?:io|context)\.run\s*\(|\b(?:std::thread|thread_pool|async\(|post\()/);
  assert.match(native, /SSL_CTRL_SET_TLSEXT_HOSTNAME/);
  assert.match(native, /ssl::host_name_verification\(endpoint->first\)/);
});

test("wire parser bounds untrusted ASN.1 lengths, entries and attributes", () => {
  for (const expression of [
    /kMaximumLdapFrame = 65536U/, /kMaximumAttributes = 16U/,
    /kMaximumAttributeValue = 4096U/, /count > kMaximumLdapFrame/,
    /if \(found\) co_return std::nullopt/,
    /response\.tag == 0x64U/, /response\.tag == 0x65U/,
    /throw InvalidFrame\{\}/, /if \(!messageContents\.empty\(\)\)/,
    /append\(equality, 0x04U, username\)/,
    /append\(operation, 0xA3U, equality\)/
  ]) assert.match(native, expression);
});

test("all LDAP network stages have one absolute budget and secrets are wiped", () => {
  assert.match(native, /const Deadline deadline = Clock::now\(\) \+ request\.timeout/);
  assert.match(native, /request\.timeout > kTotalDeadline/);
  assert.match(native, /asio::cancel_after\(deadline - Clock::now\(\)/);
  assert.match(native, /beast::get_lowest_layer\(stream\)\.expires_at\(deadline\)/);
  assert.match(native, /SensitiveString::~SensitiveString\(\) noexcept/);
  assert.match(native, /volatile char\* data = m_value->data\(\)/);
  assert.match(native, /struct Eraser final/);
  assert.match(native, /co_await writeMessage\(stream, bindRequest\(id, dn, password\), deadline, true\)/);
});

test("offline LDAPS real TLS fixture covers credential rejection and downgrade prevention", () => {
  for (const name of [
    "VerifiedTlsBindSearchAndUserRebindAreNative",
    "InvalidUserBindCannotAuthenticate",
    "AmbiguousSearchNeverBindsUser",
    "MissingStableSubjectNeverBindsUser",
    "UntrustedCertificateIsNotAccepted",
    "InvalidMessageIdIsRejected",
    "OversizedLengthPrefixIsRejected",
    "NativeTimeoutCannotBlockOnSlowDirectory",
    "UntrustedUriAndDeadlineFailWithoutNetworking",
  ]) assert.match(testSource, new RegExp("TEST\\(AsyncLdapsTest, "+name+"\\)"));
  assert.match(testSource, /EVP_PKEY_Q_keygen/);
  assert.match(testSource, /Tcp::endpoint\{/);
  assert.match(testSource, /asio::ssl::stream<Tcp::socket>/);
});

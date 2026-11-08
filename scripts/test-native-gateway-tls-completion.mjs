#!/usr/bin/env node
// Source contract for the actual gateway TLS test; source checks alone do
// not certify the named-module C++ listener or its loopback TLS behavior.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const raw = fs.readFileSync(path.join(root, "src/gateway/http.cpp"), "utf8");
const code = cppExecutableText(raw);
const native = code.slice(
  code.indexOf("asio::awaitable<foundation::Result<HttpResponse>> sendAsync("),
  code.indexOf("BeastProxyTransport::BeastProxyTransport("));
const tls = native.slice(
  native.indexOf("beast::ssl_stream<beast::tcp_stream> stream"));
const server = fs.readFileSync(path.join(root,
  "tests/gateway/http_integration_test.cpp"), "utf8");

test("native gateway still verifies TLS identity and shares the request deadline",()=>{
  assert.match(tls, /SSL_CTRL_SET_TLSEXT_HOSTNAME/);
  assert.match(tls, /ssl::host_name_verification\{host\}/);
  assert.match(tls, /expires_at\(deadline\)/);
  assert.match(tls, /co_await stream\.async_handshake\(/);
});

test("completed bounded TLS response is returned before optional peer shutdown",()=>{
  const response = tls.slice(tls.indexOf("auto response = co_await exchangeAsync("),
    tls.indexOf("\n    }\n\nprivate:"));
  assert.match(response,/co_await exchangeAsync\(stream, endpoint, request, deadline\)/);
  assert.match(response,/beast::get_lowest_layer\(stream\)\.socket\(\)\.close\(ignored\)/);
  assert.match(response,/co_return response;/);
  assert.doesNotMatch(response,/stream\.async_shutdown\(/);
  assert.doesNotMatch(response,/io\.run\(/);
  assert.match(native,/parser\.header_limit\(/);
  assert.match(native,/parser\.body_limit\(/);
  assert.match(native,/beastHttp::async_read\(/);
  assert.match(native,/if \(error\) co_return foundation::fail\(networkError\(/);
});

test("native Gateway adapter still awaits the nonblocking upstream transport",()=>{
  const fn = code.slice(code.indexOf("CoroutineGatewayAdapter::handleAsync("));
  assert.match(fn, /co_await m_transport->sendAsync\(/);
  assert.match(fn, /remainingForwardBudget\(plan\)/);
  assert.match(fn, /m_gateway->recordForwardResult\(/);
  assert.doesNotMatch(fn, /m_gateway->handle\s*\(/);
});

test("real gateway C++ regression uses ephemeral pinned TLS and held-open peer",()=>{
  for (const item of [
    /NativeTlsProxyDoesNotWaitForPeerCloseNotify/,
    /struct DelayedCloseTlsProxyPeer final/,
    /EVP_PKEY_Q_keygen/,
    /X509V3_EXT_conf_nid/,
    /std::this_thread::sleep_for\(std::chrono::milliseconds\{750\}\)/,
    /EXPECT_LT\(elapsed, std::chrono::milliseconds\{500\}\)/,
    /EXPECT_EQ\(response->value\(\)\.body\(\), "gateway-tls-complete"\)/
  ]) assert.match(server,item);
});

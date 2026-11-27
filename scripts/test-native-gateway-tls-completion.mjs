#!/usr/bin/env node
// Source contract for the actual gateway TLS test; source checks alone do
// not certify the named-module C++ listener or its loopback TLS behavior.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const raw = fs.readFileSync(path.join(root, "src/gateway/http_proxy.cpp"), "utf8");
const code = cppExecutableText(raw);
const deadlineHeader = cppExecutableText(fs.readFileSync(
  path.join(root, "src/gateway/steady_deadline.hpp"), "utf8"));
const adapters = cppExecutableText(fs.readFileSync(
  path.join(root, "src/gateway/http_coroutine.cpp"), "utf8"));
const native = code.slice(
  code.indexOf("asio::awaitable<foundation::Result<HttpResponse>> sendAsync("),
  code.indexOf("BeastProxyTransport::BeastProxyTransport("));
const tls = native.slice(
  native.indexOf("beast::ssl_stream<beast::tcp_stream> stream"));
const server = fs.readFileSync(path.join(root,
  "tests/gateway/http_integration_test.cpp"), "utf8");

test("native gateway refuses late DNS success before initiating TCP or TLS",()=>{
  const resolved = native.indexOf("co_await resolver->async_resolve(");
  const cancelled = native.indexOf("resolverDeadline.cancel()", resolved);
  const timeout = native.indexOf("if (std::chrono::steady_clock::now() >= deadline)", cancelled);
  const error = native.indexOf("if (error)", cancelled);
  const tcp = native.indexOf("if (!endpoint.tls())", cancelled);
  assert.ok(resolved >= 0 && cancelled > resolved && timeout > cancelled);
  assert.ok(error > timeout && tcp > error,
    "check the absolute deadline even after a successful DNS resolution");
  const afterDns = native.slice(timeout, error);
  assert.match(afterDns, /foundation::ErrorCode::Timeout/);
  assert.doesNotMatch(afterDns, /co_await/);
});

test("native gateway saturates huge budgets instead of overflowing the steady clock",()=>{
  assert.match(raw, /#include "steady_deadline\.hpp"/);
  const creation = native.slice(
    native.indexOf("const auto deadline = detail::saturatingSteadyDeadline(timeout);"),
    native.indexOf("auto executor = co_await asio::this_coro::executor;"));
  assert.match(creation,/detail::saturatingSteadyDeadline\(timeout\)/);
  assert.match(deadlineHeader,/duration_cast<std::chrono::milliseconds>/);
  assert.match(deadlineHeader,/Clock::duration::max\(\)/);
  assert.match(deadlineHeader,/timeout >= longestDelay/);
  assert.match(deadlineHeader,/Clock::time_point::max\(\) - delay/);
  assert.match(deadlineHeader,/now >= latestStart/);
  assert.doesNotMatch(deadlineHeader,/now\(\) \+ timeout/);
  assert.match(server,/NativeCoroutineProxySaturatesExtremeDeadline/);
  assert.match(server,/std::chrono::milliseconds::max\(\), result/);
  assert.match(server,/EXPECT_EQ\(handler.received.load\(std::memory_order_relaxed\), 1\)/);
});

test("native gateway checks the absolute budget after writing and reading",()=>{
  const exchange = native.slice(
    native.indexOf("asio::awaitable<foundation::Result<HttpResponse>> exchangeAsync("),
    native.indexOf("ProxyConfig m_config;"));
  const built = exchange.indexOf("auto outgoing = toBeast(endpoint, request);");
  const write = exchange.indexOf("co_await beastHttp::async_write(");
  const writeError = exchange.indexOf(
    "if (error) co_return foundation::fail(networkError(", write);
  const read = exchange.indexOf("co_await beastHttp::async_read(");
  const readError = exchange.indexOf(
    "if (error) co_return foundation::fail(networkError(", read);
  const returned = exchange.indexOf("co_return fromBeast(parser.release());");
  assert.ok(built >= 0 && write > built && writeError > write
    && read > writeError && readError > read && returned > readError);
  const check = (from,to) => {
    const section = exchange.slice(from,to);
    assert.match(section,/if \(std::chrono::steady_clock::now\(\) >= deadline\)/);
    assert.match(section,/foundation::ErrorCode::Timeout/);
  };
  check(built,write);
  check(write,writeError);
  check(read,readError);
  assert.doesNotMatch(exchange.slice(readError,returned),/co_await/);
});

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
  const fn = adapters.slice(adapters.indexOf("CoroutineGatewayAdapter::handleAsync("));
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

test("literal IPv4 bypasses DNS but retains common deadline and TLS verification",()=>{
  const parse = native.indexOf("asio::ip::make_address(host, addressError)");
  const branch = native.indexOf("if (!addressError && address.is_v4())",parse);
  const literal = native.indexOf("Tcp::resolver::results_type::create(",branch);
  const fallback = native.indexOf("} else {",literal);
  const resolve = native.indexOf("co_await resolver->async_resolve(",fallback);
  const commonDeadline = native.indexOf("if (std::chrono::steady_clock::now() >= deadline)",resolve);
  const tcp = native.indexOf("if (!endpoint.tls())",commonDeadline);
  assert.ok(parse >= 0 && branch > parse && literal > branch && fallback > literal &&
    resolve > fallback && commonDeadline > resolve && tcp > commonDeadline);
  assert.doesNotMatch(native.slice(branch,fallback),/co_await|async_wait|async_resolve/);
  assert.match(native.slice(branch,fallback),/Tcp::endpoint\{address, endpoint\.port\(\)\}, host, service/);
  assert.match(tls,/ssl::host_name_verification\{host\}/);
  assert.match(server,/concurrent-hostname/);
  assert.match(server,/targetIndex\+\+ % 2U == 0U/);
});

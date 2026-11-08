#!/usr/bin/env node
// Structural guard; TLS loopback C++ regression provides behavioral evidence.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const source = fs.readFileSync(path.join(root,
  "src/providers/http/async_https.cpp"), "utf8");
const executable = cppExecutableText(source);
const tests = fs.readFileSync(path.join(root,
  "tests/providers/async_https_test.cpp"), "utf8");
const exchange = executable.slice(executable.indexOf("AsyncHttpsClient::exchange("));
const afterRead = exchange.slice(exchange.indexOf("auto received = parser.release();"));

test("the entire bounded HTTPS response must be validated before success", () => {
  assert.match(exchange, /stream\.set_verify_callback\(ssl::host_name_verification\(request\.host\)\)/);
  assert.match(exchange, /co_await wire::async_read\(/);
  assert.match(exchange, /parser\.body_limit\(m_maxBodyBytes\)/);
  assert.match(exchange, /parser\.header_limit\(/);
  assert.match(exchange, /if \(error == wire::error::body_limit \|\| error == wire::error::header_limit\)/);
  assert.match(exchange, /if \(error\) co_return connectionFailure\(error, deadline\)/);
  assert.match(exchange, /if \(Clock::now\(\) >= deadline\) co_return failure\(HttpsFailure::Timeout\)/);
  assert.ok(exchange.indexOf("auto received = parser.release();") <
            exchange.indexOf("co_return HttpsResult{HttpsFailure::None"));
});

test("TLS peer close-notify cannot consume the successful OAuth response budget", () => {
  assert.match(afterRead, /beast::get_lowest_layer\(stream\)\.socket\(\)\.close\(ignored\)/);
  assert.match(afterRead, /co_return HttpsResult\{HttpsFailure::None, std::move\(response\), true\}/);
  assert.doesNotMatch(afterRead, /\bco_await\s+stream\.async_shutdown\s*\(/);
  assert.doesNotMatch(afterRead, /\bio\.run\s*\(/);
});

test("loopback test retains complete TLS response while peer defers closing", () => {
  assert.match(tests, /TEST\(AsyncProviderHttpsTest, CompleteResponseDoesNotWaitForPeerTlsCloseNotify\)/);
  assert.match(tests, /server\.holdOpenAfterResponse = 500ms/);
  assert.match(tests, /request\.timeout = 1500ms/);
  assert.match(tests, /EXPECT_TRUE\(result\.success\)/);
  assert.match(tests, /EXPECT_EQ\(result\.response\.status, 200U\)/);
  assert.match(tests, /EXPECT_LT\(elapsed, 350ms\)/);
  assert.match(tests, /pghttp::AsyncHttpsClient client\{server\.caFile\}/);
});

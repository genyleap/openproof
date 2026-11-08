#!/usr/bin/env node
// Static SQL contract. The disposable PostgreSQL test is required separately.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const raw = fs.readFileSync(path.join(root,
  "src/storage/postgres/async_auth_transaction.cpp"), "utf8");
const native = cppExecutableText(raw);
const begin = native.slice(native.indexOf("AsyncAuthenticationTransactionSql::begin("),
  native.indexOf("AsyncAuthenticationTransactionSql::consume("));
const metadataStart = begin.indexOf("if (!row.metadata.empty())");
const metadataEnd = begin.indexOf("connection.query(", metadataStart);
const section = begin.slice(metadataStart, metadataEnd);

test("metadata transaction enforces row and field bounds before BEGIN", () => {
  assert.match(native, /kMaximumTransactionMetadataRows = 64U/);
  assert.match(begin, /row\.metadata\.size\(\) > kMaximumTransactionMetadataRows/);
  assert.match(begin, /key\.size\(\) > 200U/);
  assert.match(begin, /value\.size\(\) > 8192U/);
  assert.ok(begin.indexOf("row.metadata.size()") < begin.indexOf('connection.query('));
});

test("metadata insert uses one bounded set of generated numeric placeholders", () => {
  assert.match(section, /if \(!row\.metadata\.empty\(\)\)/);
  assert.match(section, /parameters\.reserve\(row\.metadata\.size\(\) \* 3U\)/);
  assert.match(section, /std::to_string\(index \+ 1U\)/);
  assert.match(section, /std::to_string\(index \+ 2U\)/);
  assert.match(section, /std::to_string\(index \+ 3U\)/);
  assert.match(section, /parameters\.emplace_back\(row\.id\)/);
  assert.match(section, /parameters\.emplace_back\(key\)/);
  assert.match(section, /parameters\.emplace_back\(std::move\(value\)\)/);
  assert.doesNotMatch(section, /insert\s*\+=[^;]*(?:row\.id|key|value)/);
});

test("the parameterized metadata insert awaits exactly once before COMMIT", () => {
  const body = begin.slice(metadataStart, begin.indexOf("co_return true"));
  assert.equal((body.match(/\bco_await\b/g) || []).length, 2,
    "one metadata INSERT and one COMMIT, not one await per metadata item");
  assert.match(body, /connection\.query\(\s*std::move\(insert\), std::move\(parameters\), remaining\(deadline\)\)/);
  assert.match(body, /connection\.query\(\s*[^,]+,\s*\{\},\s*remaining\(deadline\)\)/);
});

test("metadata redemption is SQL-limited to one overflow sentinel before materialization", () => {
  const consume = raw.slice(raw.indexOf("AsyncAuthenticationTransactionSql::consume("));
  assert.match(consume, /" WHERE transaction_id=\$1 ORDER BY key LIMIT "/);
  assert.match(consume, /std::to_string\(kMaximumTransactionMetadataRows \+ 1U\)/);
  assert.match(consume, /values\.rows\.size\(\) > kMaximumTransactionMetadataRows/);
  assert.match(consume, /throw std::runtime_error\{"PostgreSQL transaction metadata exceeds limit"\}/);
  assert.ok(consume.indexOf("LIMIT ") < consume.indexOf("if (values.rows.size()"));
});

test("malformed persisted metadata cannot be returned or reused after overflow", () => {
  const cpp = fs.readFileSync(path.join(root,
    "tests/storage/postgres_async_auth_transaction_test.cpp"), "utf8");
  assert.match(cpp, /OversizedPersistedMetadataFailsClosed/);
  assert.match(cpp, /generate_series\(1,63\)/);
  assert.match(cpp, /catch \(const std::runtime_error&\)/);
  assert.match(cpp, /nonReusable = !conn->reusable\(\)/);
});

test("the regression exercises 64 maximum-length metadata values on a temp table", () => {
  const cpp = fs.readFileSync(path.join(root,
    "tests/storage/postgres_async_auth_transaction_test.cpp"), "utf8");
  assert.match(cpp, /TEST\(AsyncAuthenticationTransactionSqlTest, BatchedMaximumMetadataIsAtomicOnDisposablePg\)/);
  assert.match(cpp, /for \(std::size_t index = 0U; index < 64U; \+\+index\)/);
  assert.match(cpp, /std::string\(8192U, 'x'\)/);
  assert.match(cpp, /consumed->metadata\.size\(\) == 64U/);
  assert.match(cpp, /GTEST_SKIP\(\)/);
});

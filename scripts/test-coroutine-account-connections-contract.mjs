#!/usr/bin/env node
// Contract checks complement GCC16 native compilation and disposable real-PG E2E.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const read = name => fs.readFileSync(path.join(root, name), "utf8");
const main = read("apps/opp/main.cpp");
const http = read("src/account/http/coroutine_session_http.cpp");
const native = cppExecutableText(http);
const sql = read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
const sqlNative = cppExecutableText(sql);

test("connection reads are independently enabled and method-scoped", () => {
  const header = read("src/account/http/coroutine_session_http.hpp");
  assert.match(header, /ReadConnections readConnections = \{\}/);
  assert.match(main, /OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_CONNECTIONS/);
  assert.match(main, /nativeAccountConnectionsFlag && \*nativeAccountConnectionsFlag == "1"/);
  assert.match(main, /nativeAccountConnectionsEnabled[\s\S]*?!nativeAccountEnabled/);
  assert.match(main, /nativeMethods.emplace_back\("\/account\/connections", gateway::HttpMethod::Get\)/);
  assert.match(http, /request.method\(\) == gateway::HttpMethod::Get\s*&& request.path\(\) == "\/account\/connections"/);
  assert.match(http, /if \(connectionsReadRoute\(request\)\)[\s\S]*?\!request.header\("authorization"\).has_value\(\)/);
});

test("native SQL refuses other tenants and inactive identities without mutating", () => {
  const start = sqlNative.indexOf("CoroutinePostgresCanonicalFinalizer::readConnectionsAsync(");
  const end = sqlNative.indexOf("CoroutinePostgresCanonicalFinalizer::authorizeConnectionTargetAsync(", start);
  assert.ok(start > 0 && end > start);
  const impl = sqlNative.slice(start, end);
  const original = sql.slice(start, end);
  for (const guard of ["m_impl->pool.acquire(deadline)", "remaining(deadline)",
    "owner.empty()", "result.rows.size() > 256U", "required(row[0]) != owner.value()"])
    assert.ok(impl.includes(guard), "missing bound: " + guard);
  for (const term of ["i.id=$1", "i.organization_id=$2", "i.status=0",
    "o.state=0", "LIMIT 257", "LEFT JOIN openproof.external_identities"])
    assert.ok(original.includes(term), "missing SQL constraint: " + term);
  assert.doesNotMatch(impl, /\b(?:PQexec|PQexecParams|PQconnectdb|PQreset|context\.run)\s*\(/);
  assert.doesNotMatch(original, /INSERT INTO|UPDATE openproof|DELETE FROM/);
});

test("HTTP validates session and repository owner before disclosure", () => {
  const start = native.indexOf("CoroutineAccountSessionAdapter::connectionsRead(");
  assert.ok(start > 0);
  const body = native.slice(start);
  const auth = body.indexOf("co_await m_authenticate(std::move(credential->value()))");
  const readIndex = body.indexOf("co_await m_readConnections(authenticated->identity())");
  const validate = body.indexOf("connections->first != authenticated->identity()");
  const serialize = body.indexOf("json::array connectionsJson;");
  assert.ok(auth < readIndex && readIndex < validate && validate < serialize);
  assert.match(body, /connections->second.size\(\) > 256U/);
  assert.match(body, /jsonResponse\(200/);
  assert.doesNotMatch(body, /m_legacyAccount->handle\s*\(/);
  const cxx = read("tests/account/session_coroutine_http_test.cpp");
  assert.match(cxx, /ConnectionsReadIsCookieOnlyAndPreservesLegacyBearer/);
  assert.match(cxx, /ConnectionsReadRejectsForeignAndMissingWithoutDisclosure/);
});

test("native connection list preserves Farcaster projection and no-store", () => {
  assert.match(http, /item\["profile_url"\] = "https:\/\/farcaster.xyz\/\~\/profiles\/"/);
  assert.match(http, /std::ranges::all_of\(fid/);
  const tests = read("tests/account/session_coroutine_http_test.cpp");
  assert.match(tests, /connectionsCookieRequest/);
  assert.match(tests, /"www-authenticate"\), "Bearer"/);
  assert.match(tests, /"cache-control"\), "no-store"/);
});

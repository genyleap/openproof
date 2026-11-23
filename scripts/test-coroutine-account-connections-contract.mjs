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

test("canonical PostgreSQL and repeated HTTP E2E use isolated guarded databases", () => {
  const workflow = read(".github/workflows/ci.yml");
  assert.match(workflow, /Native canonical connections isolated PostgreSQL regressions/);
  assert.match(workflow, /bash scripts\/run-disposable-postgres-canonical-tests\.sh/);
  const collect = (name, endName) => {
    const start = workflow.indexOf("      - name: " + name);
    const end = workflow.indexOf(endName, start);
    assert.ok(start >= 0 && end > start, "missing scoped E2E step: " + name);
    const section = workflow.slice(start, end);
    const db = section.match(/OPENPROOF_E2E_POSTGRES: [^\n]*\/([a-z0-9_]+)\s*$/m)?.[1];
    assert.ok(db && /(^|_)e2e($|_)/i.test(db), "unsafe E2E database in " + name);
    assert.match(section, new RegExp("createdb -O openproof_ci " + db + "\\b"));
    assert.match(section, /OPENPROOF_E2E_DATABASE_ACK: YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE/);
    assert.match(section, /OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_CONNECTIONS: "1"/);
    assert.match(section, /node scripts\/e2e-identity-platform\.mjs/);
    return db;
  };
  const profile = collect(
    "Native account profile read disposable PostgreSQL E2E",
    "      - name: Repeated native connections disposable PostgreSQL HTTP E2E");
  const connections = collect(
    "Repeated native connections disposable PostgreSQL HTTP E2E",
    "      - name: Isolated OpenProof PostgreSQL E2E and mixed-read benchmark");
  assert.notEqual(profile, connections, "repeat E2E must use a fresh empty database");
});

test("native HTTP E2E exercises concurrent reads with no extra identity creation", () => {
  const e2e = read("scripts/e2e-identity-platform.mjs");
  assert.match(e2e, /OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_CONNECTIONS === "1"/);
  assert.match(e2e, /Promise\.all\(Array\.from\(\{ length: 8 \}/);
  assert.match(e2e, /edgeRequest\("\/account\/connections", \{ jar: consumerJar \}\)/);
  assert.match(e2e, /jsonBody\(response\)\.connections\.map/);
  assert.doesNotMatch(
    e2e.slice(e2e.indexOf("const reads = await Promise.all"),
      e2e.indexOf("const connectionStart = await jsonRequest")),
    /\/account\/signup|\/account\/connections\/web3\/complete/);
});

test("disposable proxy error classification never exposes raw upstream exception data", () => {
  const e2e = read("scripts/e2e-identity-platform.mjs");
  const start = e2e.indexOf('forwarded.on("error", (error) =>');
  const end = e2e.indexOf('request.pipe(forwarded);', start);
  assert.ok(start > 0 && end > start);
  const proxy = e2e.slice(start, end);
  for (const safeCode of ["ECONNRESET", "ECONNREFUSED", "EPIPE", "ETIMEDOUT"]) {
    assert.ok(proxy.includes(safeCode));
  }
  assert.match(proxy, /permitted\.has\(error\?\.code\) \? error\.code : "OTHER"/);
  assert.match(proxy, /"x-openproof-e2e-upstream-failure": category/);
  assert.doesNotMatch(proxy, /error\?\.message|error\.stack|console\.|oppLog/);
  assert.match(e2e, /concurrent native connections upstream disconnected \(transport=/);
  assert.match(e2e, /oppProcess\?\.signalCode \?\? "none"/);
});

test("canonical integration exercises pool contention across executor threads", () => {
  const integration = read("tests/storage/postgres_async_canonical_test.cpp");
  assert.match(integration, /asio::awaitable<bool> concurrentConnectionRead\(/);
  assert.match(integration, /pendingReads\.reserve\(8U\)/);
  assert.match(integration, /workers\.reserve\(4U\)/);
  assert.match(integration, /io\.restart\(\);[\s\S]*?std::vector<std::future<bool>> pendingReads;/);
  assert.match(integration, /emptyExpected \? seed\.emptyConnectionsOwner : seed\.owner/);
  assert.match(integration, /for \(auto& worker : workers\) worker\.join\(\)/);
  assert.match(read(".github/workflows/ci.yml"), /bash scripts\/run-disposable-postgres-canonical-tests\.sh/);
});

test("disposable reverse proxy does not reuse one-request Beast TCP sockets", () => {
  const e2e = read("scripts/e2e-identity-platform.mjs");
  const start = e2e.indexOf("const forwarded = http.request({");
  const end = e2e.indexOf("}, (upstream) => {", start);
  assert.ok(start >= 0 && end > start);
  const options = e2e.slice(start, end);
  assert.match(options, /hostname: "127\.0\.0\.1"/);
  assert.match(options, /port: oppPort/);
  assert.match(options, /agent: false/);
  const gateway = read("src/gateway/http.cpp");
  assert.match(gateway, /output\.keep_alive\(false\)/);
});

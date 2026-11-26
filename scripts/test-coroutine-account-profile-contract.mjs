#!/usr/bin/env node
// Native account profile boundary checks complement, not replace, GCC16
// compilation and the disposable real-PostgreSQL integration suite.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const read = name => fs.readFileSync(path.join(root, name), "utf8");
const account = read("src/account/http/coroutine_session_http.cpp");
const accountNative = cppExecutableText(account);
const sql = read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
const sqlNative = cppExecutableText(sql);
const main = read("apps/opp/main.cpp");

test("native profile route is explicit, read-only and disabled by default", () => {
  const header = read("src/account/http/coroutine_session_http.hpp");
  assert.match(header, /ReadProfile readProfile = \{\}/);
  assert.match(header, /nativeEnabled\(\) const noexcept override \{ return false; \}/);
  assert.match(account, /request.method\(\) == gateway::HttpMethod::Get[\s\S]*?request.path\(\) == "\/account\/profile"/);
  assert.match(account, /if \(profileReadRoute\(request\)\)[\s\S]*?static_cast<bool>\(m_readProfile\)/);
  assert.match(main, /OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_PROFILE/);
  assert.match(main, /nativeAccountProfileFlag && \*nativeAccountProfileFlag == "1"/);
  assert.match(main, /nativeAccountProfileEnabled[\s\S]*?!nativeAccountEnabled/);
  assert.match(main, /if \(nativeAccountProfileEnabled\) \{\s*nativeMethods.emplace_back\("\/account\/profile", gateway::HttpMethod::Get\)/);
  const overlay = read("src/gateway/http_coroutine.cpp");
  assert.match(overlay, /m_methodScopedNativePaths/);
  assert.match(overlay, /method == request\.method\(\)/);
  const gatewayTests = read("tests/gateway/http_integration_test.cpp");
  assert.match(gatewayTests, /MethodScopedNativeGetPreservesLegacyPatchAndStrictPaths/);
  const accountTests = read("tests/account/session_coroutine_http_test.cpp");
  assert.match(accountTests, /gw::HttpMethod::Patch, "\/account\/profile"/);
  assert.match(accountTests, /gw::HttpMethod::Put, "\/account\/profile"/);
});

test("native profile reader checks active tenant and rejects duplicate or corrupt rows", () => {
  const start = sqlNative.indexOf("CoroutinePostgresCanonicalFinalizer::readProfileAsync(");
  const end = sqlNative.indexOf("CoroutinePostgresCanonicalFinalizer::authorizeConnectionTargetAsync(", start);
  assert.ok(start >= 0 && end > start);
  const body = sqlNative.slice(start, end);
  for (const guard of ["m_impl->pool.acquire(deadline)", "remaining(deadline)",
                       "owner.empty()", "result.rows.size() != 1U",
                       "result.rows.front().size() != 11U",
                       "profile::IdentityProfile::restore("])
    assert.ok(body.includes(guard), "missing native profile SQL validation: " + guard);
  const sqlText = sql.slice(start, end);
  for (const condition of ["p.identity_id=$1", "i.organization_id=$2",
                          "i.status=0", "o.state=0", "LIMIT 2",
                          "JOIN openproof.identities i",
                          "JOIN openproof.organizations o"])
    assert.ok(sqlText.includes(condition), "missing SQL tenant/lifecycle boundary: " + condition);
  assert.doesNotMatch(body, /\bPQ(?:exec|execParams|connectdb|reset)\s*\(|\bcontext\.run\s*\(/);
});

test("native HTTP authenticates session before lookup and checks returned identity", () => {
  const start = accountNative.indexOf("CoroutineAccountSessionAdapter::profileRead(");
  assert.ok(start >= 0);
  const code = accountNative.slice(start);
  const auth = code.indexOf("co_await m_authenticate(std::move(credential->value()))");
  const readIndex = code.indexOf("co_await m_readProfile(authenticated->identity())");
  const identityCheck = code.indexOf("value->identity() != authenticated->identity()");
  const serialize = code.indexOf("json::object body;");
  assert.ok(auth >= 0 && auth < readIndex && readIndex < identityCheck
    && identityCheck < serialize, "authorization and ownership must precede JSON");
  assert.doesNotMatch(code, /m_legacyAccount->handle\s*\(|\bPQexec\s*\(/);
  const cpp = read("tests/account/session_coroutine_http_test.cpp");
  assert.match(cpp, /ProfileReadRequiresExplicitNativeCapabilityAndSession/);
  assert.match(cpp, /ProfileReadFailsClosedOnForeignOrMissingProfile/);
});

test("profile route is isolated from OAuth transaction provisioning", () => {
  assert.match(main, /nativeLdapEnabled \|\| nativeWeb3Enabled \|\| nativeFederatedStartEnabled[\s\S]*?\|\| nativeAccountProfileEnabled/);
  const native = main.slice(main.indexOf("nativeSessionRepository = std::make_unique<"),
    main.indexOf("std::optional<passkey::PasskeyService>"));
  assert.ok(native.indexOf("nativeCanonical = std::make_unique<") <
    native.indexOf("nativeTransactions = std::make_unique<"));
  assert.match(native, /if \(nativeLdapEnabled \|\| nativeWeb3Enabled \|\| nativeFederatedStartEnabled \|\| nativeLocalEnabled\) \{\s*nativeTransactions/);
  assert.match(main, /reader->readProfileAsync\(std::move\(owner\)\)/);
});

test("delegated Bearer profile access preserves compatibility without blocking reactor", () => {
  assert.match(account, /!request\.header\("authorization"\)\.has_value\(\)/);
  const gateway = read("src/gateway/http_coroutine.cpp");
  const sync = gateway.slice(
    gateway.indexOf("HttpResponse CoroutineRouteOverlay::handle(HttpRequest request)"),
    gateway.indexOf("boost::asio::awaitable<HttpResponse>\nCoroutineRouteOverlay::handleAsync("));
  assert.match(sync, /overlays\(request\.path\(\)\) \|\| nativeEnabledFor\(request\)/);
  assert.match(sync, /return m_compatibility->handle\(std::move\(request\)\)/);
  const asyncMethod = gateway.slice(
    gateway.indexOf("CoroutineRouteOverlay::handleAsync("),
    gateway.indexOf("CoroutineMetricsAdapter::CoroutineMetricsAdapter("));
  assert.doesNotMatch(asyncMethod, /m_compatibility->handle\(/);
  const tests = read("tests/account/session_coroutine_http_test.cpp");
  assert.match(tests, /profileCookieRequest\(/);
  assert.match(tests, /Delegated OAuth Bearer credentials/);
  assert.match(tests, /EXPECT_FALSE\(overlay\.nativeEnabledFor\(request\(/);
});

test("native profile HTTP E2E keeps a separate guard-approved disposable database", () => {
  const ci = read(".github/workflows/ci.yml");
  const start = ci.indexOf("      - name: Native account profile read disposable PostgreSQL E2E");
  const end = ci.indexOf("      - name: Isolated OpenProof PostgreSQL E2E", start);
  assert.ok(start >= 0 && end > start, "missing isolated profile E2E step");
  const step = ci.slice(start, end);
  const configured = step.match(/OPENPROOF_E2E_POSTGRES: [^\n]*\/([a-z0-9_]+)\s*$/m);
  assert.ok(configured, "missing explicit dedicated profile test database");
  const database = configured[1];
  assert.match(database, /(^|_)e2e($|_)/i,
    "E2E runner requires a standalone e2e database-name segment");
  assert.match(step, new RegExp("createdb -O openproof_ci " + database + "\\b"),
    "created disposable database must match the E2E connection URI");
  assert.match(step, /OPENPROOF_E2E_DATABASE_ACK: YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE/);
  assert.match(step, /OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_SESSIONS: "1"/);
  assert.match(step, /OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_PROFILE: "1"/);
});

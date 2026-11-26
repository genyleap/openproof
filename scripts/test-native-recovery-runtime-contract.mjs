import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
const root = path.resolve(import.meta.dirname, "..");
const read = p => fs.readFileSync(path.join(root,p), "utf8");
const app = read("apps/opp/main.cpp");
const http = read("src/authentication/http/coroutine_recovery_code_http.cpp");
test("recovery issuance is an independent, disabled-by-default method-scoped capability", () => {
  assert.match(app, /nativeRecoveryFlag && \*nativeRecoveryFlag == "1"/);
  assert.match(app, /nativeRecoveryEnabled && \(!nativeAuthSessionEnabled \|\| !platform\.auth\(\)\.enabled\(\)\)/);
  assert.match(app, /nativeMethods\.emplace_back\("\/auth\/recovery-codes", gateway::HttpMethod::Post\)/);
  assert.match(app, /#ifndef OPENPROOF_HAS_NATIVE_RECOVERY_HTTP\s+if \(nativeRecoveryEnabled\)/);
  assert.match(app, /if \(nativeRecoveryEnabled\) nativeRecoverySecret\.emplace\(recoverySecret->clone\(\)\)/);
  assert.match(read("apps/opp/CMakeLists.txt"), /if\(TARGET openproof_authentication_async_recovery_http\)/);
});
test("runtime injects genuine native session and tenant-scoped eligibility, never synchronous stores", () => {
  const body = app.slice(app.indexOf("asyncRecovery = std::make_unique<"), app.indexOf("nativeHandler = asyncRecovery.get()"));
  assert.match(body, /return service->authenticate\(std::move\(bearer\)\)/);
  assert.match(body, /co_await canonical->readTotpStatusAsync\(owner, providerId\)/);
  assert.match(body, /status->first != owner/);
  assert.match(body, /status->second\.value_or\(false\)/);
  assert.match(http, /if \(request\.path\(\) == "\/auth\/recovery-codes"\)/);
  assert.match(http, /m_nativeFallback->nativeEnabledFor\(request\)/);
  assert.match(http, /co_await m_nativeFallback->handleAsync\(std::move\(request\)\)/);
  assert.doesNotMatch(http, /m_nativeFallback->handle\(/);
  assert.match(read("tests/authentication/coroutine_recovery_code_http_test.cpp"), /OtherNativeAuthCapabilityIsPreserved/);
});
test("CI exercises two legacy redemption workloads and the separate native local pilot", () => {
  const ci = read(".github/workflows/ci.yml");
  assert.equal((ci.match(/OPENPROOF_EXPERIMENTAL_NATIVE_RECOVERY_CODES: "1"/g) ?? []).length, 3);
  const pilot = ci.slice(ci.indexOf("- name: Native LDAP TLS and PostgreSQL HTTP E2E"),
    ci.indexOf("- name: Isolated OpenProof PostgreSQL E2E"));
  assert.match(pilot, /OPENPROOF_EXPERIMENTAL_NATIVE_LOCAL_LOGIN: "1"/);
  assert.match(pilot, /OPENPROOF_EXPERIMENTAL_NATIVE_RECOVERY_CODES: "1"/);
  assert.equal((ci.match(/OPENPROOF_EXPERIMENTAL_NATIVE_LOCAL_LOGIN: "1"/g) ?? []).length, 1);
  const e2e = read("scripts/e2e-identity-platform.mjs");
  assert.match(e2e, /await recover\(old\[0\], 401\)/);
  assert.match(e2e, /await recover\(fresh\[0\], 200\)/);
  assert.match(e2e, /await recover\(fresh\[0\], 401\)/);
  assert.match(e2e, /assert\.equal\(countCodes\(\), 9\)/);
});

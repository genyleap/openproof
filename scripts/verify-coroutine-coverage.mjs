#!/usr/bin/env node
// Strict, deliberately incomplete-by-design migration gate.
// A green source scan alone is NEVER sufficient for release approval.
// Runtime verification, security regressions and real-system benchmarks
// are independent mandatory gates documented in COROUTINE_ACCEPTANCE.md.
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const segments = [
  ["HTTP listener + proxy", "src/gateway/http.cpp"],
  ["PostgreSQL storage", "src/storage/postgres/postgres.cpp"],
  ["GitHub OAuth", "src/providers/github/github.cpp"],
  ["OIDC federation", "src/providers/oidc/oidc.cpp"],
  ["X provider", "src/providers/x/x.cpp"],
  ["Wallet + Farcaster RPC", "src/providers/web3/web3.cpp"],
  ["Enterprise LDAP", "src/providers/enterprise/enterprise.cpp"],
  ["Trusted authentication canonical completion", "src/authentication/service.cpp"],
  ["HTTP authentication API", "src/authentication/http/http.cpp"],
  ["HTTP Web3 coroutine API", "src/authentication/http/web3.cpp"],
  ["PostgreSQL coroutine session issuance", "src/storage/postgres/coroutine_session_service.cpp"],
  ["PostgreSQL coroutine canonical finalization", "src/storage/postgres/coroutine_canonical_finalizer.cpp"],
  ["PostgreSQL bounded coroutine connection pool", "src/storage/postgres/async_pool.cpp"],
  ["PostgreSQL native asynchronous hostname resolution", "src/storage/postgres/async_connection.cpp"],
  ["PostgreSQL fail-closed coroutine listener", "src/storage/postgres/coroutine_session_listener.cpp"],
  ["HTTP OAuth API", "src/oauth/http/http.cpp"],
  ["HTTP account API", "src/account/http/http.cpp"],
  ["HTTP administration API", "src/administration/administration.cpp"],
];

const forbidden = [
  ["blocking PostgreSQL", /\bPQ(?:exec|execParams|connectdb|reset)\s*\(/g],
  ["blocking HTTP transport", /\b(?:beastHttp|http)::(?:read|write)\s*\(/g],
  ["blocking DNS", /\b(?:resolver|m_resolver)\.resolve\s*\(/g],
  ["blocking stream connect", /\b(?:stream|m_stream)\.connect\s*\(/g],
  ["blocking TLS handshake", /\b(?:stream|m_stream)\.handshake\s*\(/g],
  ["blocking pool acquisition", /\b(?:m_condition|m_cv|m_cond)\.wait_for\s*\(/g],
  ["blocking LDAP bind/search", /\bldap_(?:sasl_bind_s|search_ext_s|simple_bind_s)\s*\(/g],
  ["blocking LDAP shutdown", /\bldap_unbind_ext_s\s*\(/g]
];
const checked = segments.map(([name, relative]) => {
  const source = fs.readFileSync(path.join(root,relative),"utf8");
  const executable = cppExecutableText(source);
  const issues=[];
  for (const [label,regex] of forbidden) {
    for (const match of executable.matchAll(regex)) {
      const line = executable.slice(0,match.index).split("\n").length;
      issues.push({line, kind:label, expression:match[0]});
    }
  }
  const awaitCount=[...executable.matchAll(/\bco_await\b/g)].length;
  // The named boundary must have directly auditable coroutine implementation.
  if(awaitCount===0)issues.push({line:0,kind:"no native coroutine",expression:"co_await missing"});
  if(relative==="src/gateway/http.cpp"){
    if(!/asyncHandler\s*&&\s*asyncHandler->nativeEnabled\s*\(/.test(source))
      issues.push({line:0,kind:"missing opt-in coroutine dispatch guard",expression:"asyncHandler->nativeEnabled("});
    if(!/asio::co_spawn\s*\(\s*context\s*,\s*sendResultAsync\s*\(/.test(source)
       || !/co_await\s+sendAsync\s*\(\s*std::move\(endpoint\)/.test(source))
      issues.push({line:0,kind:"synchronous proxy compatibility bypasses native transport",
        expression:"co_spawn(context, sendResultAsync(...)) -> co_await sendAsync"});
    // Private io_context.run() still occupies a legacy handler thread.
    // A coroutine-only migration cannot approve this compatibility facade.
    if(/\bcontext\.run\s*\(\s*\)/.test(executable))
      issues.push({line:0,kind:"legacy proxy facade still blocks a calling thread",
        expression:"context.run()"});
    const interfaceSource=fs.readFileSync(
      path.join(root,"src/gateway/http.cppm"),"utf8");
    if(!/CoroutineMetricsAdapter[\s\S]*?nativeEnabled\s*\(\)\s*const\s*noexcept\s*override\s*\{\s*return\s+m_fallback->nativeEnabled\s*\(\);/.test(interfaceSource))
      issues.push({line:0,kind:"missing middleware coroutine capability propagation",expression:"m_fallback->nativeEnabled()"});
    if(!/virtual\s+bool\s+nativeEnabled\s*\(\)\s*const\s*noexcept\s*\{\s*return\s+false;\s*\}/.test(interfaceSource))
      issues.push({line:0,kind:"unsafe default-enabled coroutine handler capability",
        expression:"CoroutineHttpHandler::nativeEnabled() default false"});
    if(!/class\s+CoroutineGatewayAdapter[\s\S]*?nativeEnabled\s*\(\)\s*const\s*noexcept\s*override\s*\{\s*return\s+true;\s*\}/.test(interfaceSource))
      issues.push({line:0,kind:"missing explicit native gateway opt-in",
        expression:"CoroutineGatewayAdapter::nativeEnabled() true"});
  }
  if([
    "src/providers/github/github.cpp",
    "src/providers/oidc/oidc.cpp",
    "src/providers/x/x.cpp",
    "src/providers/web3/web3.cpp"
  ].includes(relative)){
    const target = relative.endsWith("/web3.cpp") ? "rpcAsync" : "httpsRequestAsync";
    const legacyBridge = /asio::co_spawn\s*\(\s*io\s*,\s*(?:httpsRequestAsync|rpcAsync)\s*\(/;
    if(!legacyBridge.test(source))
      issues.push({line:0,kind:"legacy provider I/O bypasses coroutine HTTPS",
        expression:"co_spawn(io, "+target+"(...))"});
    // Even with native transport, this legacy facade waits synchronously
    // for the future; do not mark its caller nonblocking until retired.
    if(/\bio\.run\s*\(\s*\)/.test(executable))
      issues.push({line:0,kind:"legacy provider facade still blocks a calling thread",
        expression:"io.run()"});
  }
  if(relative==="src/authentication/service.cpp"){
    const nativeReady = source.slice(
      source.indexOf("AuthenticationService::nativeProviderAuthenticationEnabled("),
      source.indexOf("foundation::Result<AuthenticationStart> AuthenticationService::begin("));
    for (const [kind, expression] of [
      ["native provider capability", /CoroutineAuthenticationProvider/],
      ["native transaction capability", /CoroutineAuthenticationTransactionStore/],
      ["canonical finalizer capability", /m_asyncCanonical\s*==\s*nullptr/],
      ["operator trust policy", /effectiveMaximum\s*\(/]
    ]) {
      if (!expression.test(nativeReady))
        issues.push({line:0,kind:"missing "+kind,expression:expression.source});
    }
    const begin = source.slice(
      source.indexOf("AuthenticationService::beginAsync("),
      source.indexOf("AuthenticationService::beginConnectionAsync("));
    const completion = source.slice(
      source.indexOf("AuthenticationService::completeAsync("),
      source.indexOf("AuthenticationService::finishVerified("));
    if(!/if\s*\(m_asyncCanonical\s*==\s*nullptr\)/.test(begin))
      issues.push({line:0,kind:"missing pre-challenge canonical gate",
        expression:"m_asyncCanonical == nullptr"});
    if(!/if\s*\(finalizer\s*==\s*nullptr\)/.test(completion)
       || completion.indexOf("finalizer == nullptr")
          > completion.indexOf("completeExchangeAsync("))
      issues.push({line:0,kind:"missing pre-redemption canonical gate",
        expression:"finalizer == nullptr before completeExchangeAsync"});
    if(!/\bco_await\s+finalizer->finishLoginAsync\s*\(/.test(completion)
       || /\bfinishVerified\s*\(/.test(completion))
      issues.push({line:0,kind:"blocking canonical completion in coroutine",
        expression:"co_await finalizer->finishLoginAsync"});
    const connectionStart = source.slice(
      source.indexOf("AuthenticationService::beginConnectionAsync("),
      source.indexOf("AuthenticationService::beginInternal("));
    const connectionFinish = source.slice(
      source.indexOf("AuthenticationService::completeConnectionAsync("),
      source.indexOf("AuthenticationService::finishConnection("));
    if(!/co_await\s+finalizer->authorizeConnectionTargetAsync\s*\(/.test(connectionStart)
       || /\brequireActiveIdentity\s*\(/.test(connectionStart)
       || !/finalizer->nativeConnectionsEnabled\s*\(\)/.test(connectionStart))
      issues.push({line:0,kind:"blocking native connection start",
        expression:"authorizeConnectionTargetAsync"});
    if(!/co_await\s+finalizer->finishConnectionAsync\s*\(/.test(connectionFinish)
       || /\bfinishConnection\s*\(/.test(connectionFinish)
       || !/finalizer->nativeConnectionsEnabled\s*\(\)/.test(connectionFinish)
       || connectionFinish.indexOf("finalizer->nativeConnectionsEnabled()")
          > connectionFinish.indexOf("completeExchangeAsync("))
      issues.push({line:0,kind:"blocking native connection finalization",
        expression:"finishConnectionAsync before proof redemption"});

  }
  if(relative==="src/storage/postgres/coroutine_canonical_finalizer.cpp"){
    const checks=[
      ["tenant-scoped canonical read", /i\.organization_id=\$3\s+AND\s+i\.status=0/],
      ["active canonical target", /i\.organization_id=\$2\s*"\s*"AND i\.status=0/],
      ["active tenant lifecycle", /o\.state=0/],
      ["tenant-row lifecycle lock", /FOR SHARE OF o/],
      ["canonical row lifecycle lock", /FOR UPDATE OF i/],
      ["canonical profile serialization", /mutationLock\s*\?\s*" FOR UPDATE OF i FOR SHARE OF o"/],
      ["atomic owner-conflict guard", /ON CONFLICT\(provider,external_subject\) DO UPDATE/],
      ["no implicit owner reassignment", /WHERE openproof\.external_identities\.identity_id=EXCLUDED\.identity_id/],
      ["connection presentation-only claims", /ProfilePurpose::Connection/],
      ["login verified-contact claims", /ProfilePurpose::Login/],
      ["profile domain refresh", /co_await\s+saveProfile\s*\(/],
      ["no-op profile WAL suppression", /IS DISTINCT FROM ROW\(EXCLUDED\.display_name/],
      ["SQL commit", /co_await\s+connection\.query\s*\(\s*"COMMIT"/],
      ["bounded coroutine pool", /co_await\s+m_impl->pool\.acquire\s*\(deadline\)/]
    ];
    for(const [kind, regex] of checks)
      if(!regex.test(source))
        issues.push({line:0,kind:"missing "+kind,expression:regex.source});
    if(/\b(?:telegram|genycaster|genyleap)\b/i.test(source))
      issues.push({line:0,kind:"provider-specific canonical storage dependency",
        expression:"native canonical storage must be provider-neutral"});
  }
  if(relative==="src/storage/postgres/async_pool.cpp"){
    for(const [kind, regex] of [
      ["pool uses a caller deadline", /AsyncConnectionPool::acquire\(\s*std::chrono::steady_clock::time_point deadline/],
      ["deadline bounds pool wait", /bounded\(state->acquireTimeout\)/],
      ["deadline bounds connect", /bounded\(state->connectTimeout\)/],
      ["sub-millisecond deadline fails closed", /if\s*\(remaining\s*<=\s*std::chrono::milliseconds::zero\(\)\)/],
      ["post-acquisition expiry gate", /static_cast<void>\(bounded\(state->connectTimeout\)\)/]
    ])
      if(!regex.test(source))
        issues.push({line:0,kind:"missing "+kind,expression:regex.source});
  }
  if(relative==="src/storage/postgres/async_connection.cpp"){
    for(const [kind, regex] of [
      ["bounded Asio DNS", /co_await\s+resolver\.async_resolve\s*\(/],
      ["DNS consumes shared deadline", /asio::cancel_after\s*\(\s*deadline\s*-\s*Clock::now\s*\(\)/],
      ["libpq hostname preserved for TLS", /ownedKeys\.emplace_back\s*\(\s*"hostaddr"\s*\)/],
      ["libpq numeric address connection", /PQconnectStartParams\s*\(/],
      ["nonblocking libpq connection polling", /PQconnectPoll\s*\(/],
      ["scrub parsed credentials before polling", /options\.reset\s*\(\s*\)/],
      ["multi-host native enumeration", /for\s*\(std::size_t\s+i\s*=\s*0;\s*i\s*<\s*hosts\.size\s*\(\s*\)/],
      ["multi-host port association", /ports\.size\s*\(\s*\)\s*!=\s*hosts\.size\s*\(\s*\)/],
      ["failed DNS hostname cannot suppress HA fallback", /if\s*\(error\s*\|\|\s*endpoints\.empty\s*\(\s*\)\)/],
      ["empty DNS result fails closed", /if\s*\(addressCount\s*==\s*0U\)/],
      ["partial hostaddr still resolves asynchronously", /const\s+auto\s+pinnedAddresses\s*=\s*csv\s*\(hostaddr\)/],
      ["pinned hostaddr selection is explicit", /if\s*\(\s*!pinned\.empty\s*\(\s*\)\s*\)/],
      ["inherited hostname is explicit", /effective\s*\(\s*"host"\s*,\s*"PGHOST"\s*\)/],
      ["inherited pinned address is explicit", /effective\s*\(\s*"hostaddr"\s*,\s*"PGHOSTADDR"\s*\)/],
      ["inherited port list is explicit", /effective\s*\(\s*"port"\s*,\s*"PGPORT"\s*\)/],
      ["cancelled DNS must not silently retry HA hosts", /error\s*==\s*asio::error::operation_aborted\s*\|\|\s*error\s*==\s*asio::error::timed_out/],
      ["cancelled DNS throws before HA skip", /throw\s+std::runtime_error\s*\{\s*"PostgreSQL DNS resolution cancelled"\s*\}/],
      ["service-file indirection must not restart blocking DNS", /optionValue\s*\(\s*"service"\s*\)\.empty\s*\(\s*\)/],
      ["inherited PGSERVICE must be checked", /std::getenv\s*\(\s*"PGSERVICE"\s*\)/],
      ["unsupported service files fail closed", /PostgreSQL service files are unsupported by the native connector/]
    ]){
      if(!regex.test(source)) issues.push({line:0,kind:"missing "+kind,expression:regex.source});
    }
  }
  if(relative==="src/storage/postgres/coroutine_session_service.cpp"){
    if(!/CoroutinePostgresSessionService::issueAsync\s*\(/.test(source)
        || !/\bco_await\s+issue\s*\(/.test(source))
      issues.push({line:0,kind:"missing native session issuer adapter",expression:"issueAsync / co_await issue"});
    if(!/CoroutinePostgresSessionService::issueReplacingAsync\s*\(/.test(source)
       || !/co_await\s+issueReplacing\s*\(/.test(source))
      issues.push({line:0,kind:"missing atomic native session replacement",
        expression:"issueReplacingAsync / co_await issueReplacing"});
  }
  if(relative==="src/storage/postgres/coroutine_session_listener.cpp"){
    if(!/if\s*\(\s*!fallback\.nativeEnabled\s*\(\s*\)\s*\)/.test(source))
      issues.push({line:0,kind:"coroutine session listener accepts disabled native fallback",
        expression:"!fallback.nativeEnabled()"});
    if(!/throw\s+std::invalid_argument/.test(source))
      issues.push({line:0,kind:"listener composition must reject inactive fallback",
        expression:"throw std::invalid_argument"});
    if(!/co_return\s+co_await\s+fallback\.handleAsync\s*\(/.test(source))
      issues.push({line:0,kind:"listener fallback must use native awaitable dispatch",
        expression:"co_await fallback.handleAsync"});
    if(/\bfallback\.handle\s*\(/.test(source))
      issues.push({line:0,kind:"listener fallback may not call synchronous handler",
        expression:"fallback.handle("});
    const listenerInterface = fs.readFileSync(
      path.join(root,"src/storage/postgres/coroutine_session_listener.hpp"),"utf8");
    if(!/class\s+CoroutineSessionListenerAdapter[\s\S]*?nativeEnabled\s*\(\)\s*const\s*noexcept\s*override\s*\{\s*return\s+true;\s*\}/.test(listenerInterface))
      issues.push({line:0,kind:"native PostgreSQL listener lacks explicit opt-in",
        expression:"CoroutineSessionListenerAdapter::nativeEnabled() true"});
  }
  if(relative==="src/authentication/http/http.cpp"){
    const legacy = source.slice(source.indexOf("AuthenticationHttpApi::login("));
    // co_await on login/verify does not migrate logout, rotation, recovery
    // issuance, or the legacy public handler. Keep this entire HTTP boundary
    // blocking until every route and production caller has a native port.
    // Native capability is per-handler, so partial route migrations must
    // not be activated for all /auth requests.
    const nativeInterface = fs.readFileSync(
      path.join(root,"src/authentication/http/http.cppm"),"utf8");
    if(!/static\s+constexpr\s+bool\s+kAllAuthRoutesNative\s*=\s*false/.test(nativeInterface)
       || !/return\s+kAllAuthRoutesNative\s*&&\s*m_asyncSessions\s*!=\s*nullptr/.test(nativeInterface))
      issues.push({line:0,kind:"partially native authentication handler enabled before all routes migrate",
        expression:"kAllAuthRoutesNative=false"});
    if(/\bm_sessions->(?:issueReplacing|authenticate|rotate|revoke|revokeAll)\s*\(/.test(legacy)
       || /\bm_recoveryCodes->issue\s*\(/.test(legacy)
       || /\bm_authentication->(?:begin|complete)\s*\(/.test(legacy))
      issues.push({line:0,kind:"legacy HTTP authentication routes still use synchronous services",
        expression:"AuthenticationHttpApi::login/verify/rotate/logout/recoveryCodes"});
    const nativeSection = source.slice(
      source.indexOf("AuthenticationHttpApi::handleAsync("),
      source.indexOf("gateway::HttpResponse AuthenticationHttpApi::login("));
    for(const [kind,regex] of [
      ["native provider capability guard", /nativeEnabled\s*\(\)/],
      ["native challenge start", /co_await\s+m_authentication->beginAsync\s*\(/],
      ["native proof completion", /co_await\s+m_authentication->completeAsync\s*\(/],
      ["atomic native session replacement", /co_await\s+m_asyncSessions->issueReplacingAsync\s*\(/]
    ]) if(!regex.test(nativeSection))
      issues.push({line:0,kind:"missing "+kind,expression:regex.source});
    if(/\bm_sessions->/.test(nativeSection))
      issues.push({line:0,kind:"native HTTP authentication uses legacy session service",
        expression:"m_sessions->"});
  }
  if(relative==="src/authentication/http/web3.cpp"){
    // Native session grants expose a token field rather than token().
    const nativeComplete = source.slice(
      source.indexOf("Web3AuthenticationHttpApi::completeAsync("));
    if(!/sessionCookie\s*\(\s*issued->token\.expose\s*\(/.test(nativeComplete)
       || /issued->token\(\)/.test(nativeComplete))
      issues.push({line:0,kind:"invalid native session grant access",expression:"issued->token.expose()"});
    // Disabled downstream coroutine handlers must stay disabled.
    const nativeEntry = source.slice(
      source.indexOf("Web3AuthenticationHttpApi::handleAsync("),
      source.indexOf("Web3AuthenticationHttpApi::startAsync("));
    if(!/native\s*!=\s*nullptr\s*&&\s*native->nativeEnabled\s*\(\)/.test(nativeEntry))
      issues.push({line:0,kind:"missing downstream native capability guard",expression:"native->nativeEnabled()"});

    // Web3 must leave the listener's compatibility dispatch enabled by
    // default when no native asynchronous session service is configured.
    const interfaceSource=fs.readFileSync(
      path.join(root,"src/authentication/http/web3.cppm"),"utf8");
    if(!/nativeEnabled\s*\(\)\s*const\s*noexcept\s*override\s*\{\s*return\s+m_asyncSessions\s*!=\s*nullptr\s*&&\s*m_authentication->nativeCanonicalCompletionEnabled\s*\(\)/.test(interfaceSource))
      issues.push({line:0,kind:"missing Web3 compatibility gate",expression:"nativeEnabled()"});
    // Require the actual trusted coordinator awaits, not merely a synthetic
    // coroutine wrapper around the synchronous HTTP handler.
    // Connection/handoff paths are intentionally fail-closed until their
    // synchronous persistence dependencies have native coroutine ports.
    for(const method of ["beginAsync","completeAsync"]){
      const call=new RegExp("\\bco_await\\s+m_authentication->"+method+"\\s*\\(");
      if(!call.test(source))
        issues.push({line:0,kind:"missing trusted Web3 coroutine flow",expression:method+"("});
    }
    const nativeIndex=source.indexOf("Web3AuthenticationHttpApi::handleAsync(");
    if(nativeIndex<0){
      issues.push({line:0,kind:"missing native Web3 HTTP entry",expression:"handleAsync("});
    }else{
      // Only inspect native entry points: compatibility handlers above this
      // boundary may continue blocking until the complete migration passes.
      const nativeSection=source.slice(nativeIndex);
      if(/\bm_fallback->handle\s*\(/.test(nativeSection))
        issues.push({line:0,kind:"blocking native HTTP fallback",expression:"m_fallback->handle("});
      for(const expression of [
        /\bm_sessions->(?:issue|authenticate|issueReplacing)\s*\(/,
        /\bm_authentication->(?:publishBrowserAuthenticationHandoff|consumeBrowserConnectionHandoff|updateConnectionPresentation)\s*\(/
      ]){
        if(expression.test(nativeSection))
          issues.push({line:0,kind:"legacy blocking call in native Web3 handler",expression:expression.source});
      }
      if(!/\bco_await\s+m_asyncSessions->issueAsync\s*\(/.test(nativeSection))
        issues.push({line:0,kind:"missing native session persistence",expression:"m_asyncSessions->issueAsync("});
      if(!/if\s*\(connection\s*\|\|\s*m_asyncSessions\s*==\s*nullptr\s*\|\|\s*!m_authentication->nativeCanonicalCompletionEnabled\s*\(\)/.test(nativeSection))
        issues.push({line:0,kind:"missing fail-closed session/connection gate",expression:"connection || m_asyncSessions == nullptr || !nativeCanonicalCompletionEnabled()"});
    }
  }
  return {name,file:relative,coAwaitCount:awaitCount,issues};
});
// Do not silently overlook newly added storage/provider/transport files.
// The fixed boundary matrix above verifies coroutine presence; this additional
// inventory checks *every* implementation unit for concrete synchronous I/O
// primitives, even when it was not previously named in the release gate.
const namedPaths = new Set(segments.map(([, relative]) => relative));
const uncoveredBlockingSources = [];
const globalForbidden = [
  ...forbidden,
  ["blocking cURL", /\bcurl_easy_perform\s*\(/g],
  ["blocking OpenSSL transport", /\bSSL_(?:connect|accept|read|write)\s*\(/g]
];
function auditDirectory(directory) {
  for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      auditDirectory(absolute);
      continue;
    }
    if (!/\.(?:cpp|cppm|cc|cxx|h|hpp|hxx)$/.test(entry.name)) continue;
    const relative = path.relative(root, absolute).split(path.sep).join("/");
    if (namedPaths.has(relative)) continue;
    const source = fs.readFileSync(absolute,"utf8");
    const executable = cppExecutableText(source);
    const issues = [];
    for (const [kind, regex] of globalForbidden) {
      for (const match of executable.matchAll(regex)) {
        issues.push({
          line: executable.slice(0,match.index).split("\n").length,
          kind, expression: match[0],
        });
      }
    }
    if (issues.length) uncoveredBlockingSources.push({file:relative,issues});
  }
}
auditDirectory(path.join(root,"src"));
const failures=checked.reduce((count,area)=>count+area.issues.length,0)
  + uncoveredBlockingSources.reduce((count,source)=>count+source.issues.length,0);
const report={
  status:failures===0?"STATIC_GATE_PASSED_REQUIRES_DYNAMIC_VALIDATION":"NOT_APPROVED",
  reviewRequired:true,
  releaseApproved:false,
  blockingFindings:failures,
  areas:checked,
  uncoveredBlockingSources,
};
if(process.argv.includes("--json"))console.log(JSON.stringify(report,null,2));
else{
  console.log("OpenProof end-to-end coroutine migration gate: "+report.status);
  for(const area of checked){
    console.log((area.issues.length?"FAIL":"PASS")+" "+area.name+" ["+area.file+"] co_await="+area.coAwaitCount);
    for(const issue of area.issues)console.log("  "+issue.line+" "+issue.kind+": "+issue.expression);
  }
  for (const untracked of uncoveredBlockingSources) {
    console.log("FAIL untracked blocking I/O [" + untracked.file + "]");
    for (const issue of untracked.issues) {
      console.log("  " + issue.line + " " + issue.kind + ": " + issue.expression);
    }
  }
  console.log("Release always requires full build, security regression, E2E tests, comparative baseline and latency/error-budget measurements.");
}
if(failures>0)process.exitCode=1;

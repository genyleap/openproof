#!/usr/bin/env node
// Strict, deliberately incomplete-by-design migration gate.
// A green source scan alone is NEVER sufficient for release approval.
// Runtime verification, security regressions and real-system benchmarks
// are independent mandatory gates documented in COROUTINE_ACCEPTANCE.md.
import fs from "node:fs";
import path from "node:path";

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
  const lines = source.split("\n");
  const issues=[];
  for (const [label,regex] of forbidden) {
    for (const match of source.matchAll(regex)) {
      const line = source.slice(0,match.index).split("\n").length;
      issues.push({line, kind:label, expression:match[0]});
    }
  }
  const awaitCount=[...source.matchAll(/\bco_await\b/g)].length;
  // The named boundary must have directly auditable coroutine implementation.
  if(awaitCount===0)issues.push({line:0,kind:"no native coroutine",expression:"co_await missing"});
  if(relative==="src/gateway/http.cpp"){
    if(!/asyncHandler\s*&&\s*asyncHandler->nativeEnabled\s*\(/.test(source))
      issues.push({line:0,kind:"missing opt-in coroutine dispatch guard",expression:"asyncHandler->nativeEnabled("});
    const interfaceSource=fs.readFileSync(
      path.join(root,"src/gateway/http.cppm"),"utf8");
    if(!/CoroutineMetricsAdapter[\s\S]*?nativeEnabled\s*\(\)\s*const\s*noexcept\s*override\s*\{\s*return\s+m_fallback->nativeEnabled\s*\(\);/.test(interfaceSource))
      issues.push({line:0,kind:"missing middleware coroutine capability propagation",expression:"m_fallback->nativeEnabled()"});
  }
  if(relative==="src/authentication/service.cpp"){
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
  if(relative==="src/storage/postgres/coroutine_session_service.cpp"){
    if(!/CoroutinePostgresSessionService::issueAsync\s*\(/.test(source)
        || !/\bco_await\s+issue\s*\(/.test(source))
      issues.push({line:0,kind:"missing native session issuer adapter",expression:"issueAsync / co_await issue"});
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
    const issues = [];
    for (const [kind, regex] of globalForbidden) {
      for (const match of source.matchAll(regex)) {
        issues.push({
          line: source.slice(0,match.index).split("\n").length,
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

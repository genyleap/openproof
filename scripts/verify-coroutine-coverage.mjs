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
  ["HTTP authentication API", "src/authentication/http/http.cpp"],
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
  ["blocking pool acquisition", /\b(?:m_condition|m_cv|m_cond)\.wait_for\s*\(/g]
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
  return {name,file:relative,coAwaitCount:awaitCount,issues};
});
const failures=checked.reduce((count,area)=>count+area.issues.length,0);
const report={
  status:failures===0?"STATIC_GATE_PASSED_REQUIRES_DYNAMIC_VALIDATION":"NOT_APPROVED",
  reviewRequired:true,
  releaseApproved:false,
  blockingFindings:failures,
  areas:checked
};
if(process.argv.includes("--json"))console.log(JSON.stringify(report,null,2));
else{
  console.log("OpenProof end-to-end coroutine migration gate: "+report.status);
  for(const area of checked){
    console.log((area.issues.length?"FAIL":"PASS")+" "+area.name+" ["+area.file+"] co_await="+area.coAwaitCount);
    for(const issue of area.issues)console.log("  "+issue.line+" "+issue.kind+": "+issue.expression);
  }
  console.log("Release always requires full build, security regression, E2E tests, comparative baseline and latency/error-budget measurements.");
}
if(failures>0)process.exitCode=1;

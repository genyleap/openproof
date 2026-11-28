import assert from "node:assert/strict";
import {routes,summarizeRoutes} from "../../scripts/ci/summarize-route-cpu.mjs";
const baseline="ccb396182936d717960fdca319999baf2f580ff9",candidate="a".repeat(40);
const record=(route,side,pair)=>({benchmark:"openproof-isolated-e2e-route-attribution",commit:side==="baseline"?baseline:candidate,isolatedRoute:route,executionProfile:{name:side==="baseline"?"auto":"minimal"},requests:3072,normalizedResponseChecks:3072,concurrency:1,warmupRequests:66,routes:[{name:route,requests:3072}],requestsPerSecond:side==="baseline"?100:110,p50Ms:2,p95Ms:3,p99Ms:4,serverCpuTicksDelta:side==="baseline"?40:36,serverUserCpuTicksDelta:side==="baseline"?30:26,serverSystemCpuTicksDelta:10});
const summary=summarizeRoutes(record,candidate);
assert.equal(summary.results.length,routes.length);
assert.equal(summary.requests,73728);
assert.ok(Math.abs(summary.results[0].metrics.requestsPerSecond.pairedChangePct-10)<1e-9);
assert.ok(Math.abs(summary.results[0].metrics.serverCpuTicksDelta.pairedChangePct+10)<1e-9);
for(const patch of [{benchmark:"openproof-isolated-e2e-mixed-read"},{normalizedResponseChecks:3071},{warmupRequests:0},{isolatedRoute:"wrong"},{serverUserCpuTicksDelta:99},{commit:"b".repeat(40)}]){
  assert.throws(()=>summarizeRoutes((route,side,pair)=>({...record(route,side,pair),...patch}),candidate));
}
console.log("Route CPU attribution contract: PASSED");

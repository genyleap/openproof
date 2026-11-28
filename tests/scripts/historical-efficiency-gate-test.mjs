import assert from "node:assert/strict";
import {baselineCommit,loads,evaluateEfficiency} from "../../scripts/ci/evaluate-historical-efficiency.mjs";
const sha="a".repeat(40);
const metric=(median,worst,best)=>({baselineMedian:100,candidateMedian:100+median,pairedChangePct:median,pairedRangePct:[worst,best]});
const fixture=()=>loads.map(concurrency=>({baselineCommit,candidateCommit:sha,comparison:"historical-native",pairCount:4,requestsPerRun:1536,concurrency,warmupRequests:Math.max(24,Math.ceil(2*concurrency/6)*6),metrics:{requestsPerSecond:metric(15,10,18),serverCpuTicksDelta:metric(-14,-18,-10),p99Ms:metric(-4,-8,5)}}));
assert.equal(evaluateEfficiency(fixture(),sha).pass,true);
for(const [key,change] of [["requestsPerSecond",metric(15,9,20)],["serverCpuTicksDelta",metric(-14,-20,-9)],["p99Ms",metric(-4,-8,6)]]){
  const rows=fixture();rows[2].metrics[key]=change;
  const report=evaluateEfficiency(rows,sha);
  assert.equal(report.pass,false);assert.equal(report.results[2].pass,false);
}
for(const mutate of [r=>r.pop(),r=>r[1].concurrency=1,r=>r[1].candidateCommit="b".repeat(40),r=>r[1].comparison="native-native",r=>r[1].metrics.serverCpuTicksDelta.pairedRangePct=null,r=>r[1].warmupRequests=0,r=>r[1].metrics.requestsPerSecond.pairedChangePct=NaN]){
  const rows=fixture();mutate(rows);assert.throws(()=>evaluateEfficiency(rows,sha));
}
console.log("Historical efficiency gate contract: PASSED");

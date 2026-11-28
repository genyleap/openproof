// Historical acceptance is intentionally stricter than a native/native
// experiment. Require every paired result to meet both objectives; no
// additive estimates, averaging across loads or missing-data success.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {pathToFileURL} from "node:url";

export const baselineCommit="ccb396182936d717960fdca319999baf2f580ff9";
export const loads=[1,8,32,128];

export function evaluateEfficiency(records,candidateCommit) {
  assert.match(candidateCommit,/^[a-f0-9]{40}$/);
  assert.notEqual(candidateCommit,baselineCommit);
  assert.equal(records.length,loads.length);
  const results=loads.map(concurrency=>{
    const matched=records.filter(r=>r.concurrency===concurrency);
    assert.equal(matched.length,1,"missing or duplicate concurrency");
    const r=matched[0];
    assert.equal(r.baselineCommit,baselineCommit);
    assert.equal(r.candidateCommit,candidateCommit);
    assert.equal(r.comparison,"historical-native");
    assert.equal(r.pairCount,4);
    assert.equal(r.requestsPerRun,1536);
    const warmup=Math.max(24,Math.ceil(2*concurrency/6)*6);
    assert.equal(r.warmupRequests,warmup);
    const check=k=>{
      const m=r.metrics?.[k];
      assert.ok(m && Number.isFinite(m.baselineMedian) && m.baselineMedian>0 &&
        Number.isFinite(m.candidateMedian) && m.candidateMedian>0);
      assert.ok(Number.isFinite(m.pairedChangePct) &&
        Array.isArray(m.pairedRangePct) && m.pairedRangePct.length===2 &&
        m.pairedRangePct.every(Number.isFinite) &&
        m.pairedRangePct[0]<=m.pairedChangePct && m.pairedChangePct<=m.pairedRangePct[1],
        "invalid paired evidence for "+k);
      return m;
    };
    const throughput=check("requestsPerSecond"),cpu=check("serverCpuTicksDelta");
    const p99=check("p99Ms");
    const throughputPass=throughput.pairedRangePct[0]>=10;
    const cpuPass=cpu.pairedRangePct[1]<=-10;
    const tailPass=p99.pairedRangePct[1]<=5;
    return {concurrency,throughputPct:throughput.pairedChangePct,
      throughputWorstPct:throughput.pairedRangePct[0],cpuPct:cpu.pairedChangePct,
      cpuWorstPct:cpu.pairedRangePct[1],p99WorstPct:p99.pairedRangePct[1],
      throughputPass,cpuPass,tailPass,pass:throughputPass&&cpuPass&&tailPass};
  });
  return {baselineCommit,candidateCommit,pass:results.every(r=>r.pass),
    objectives:{throughputMinPct:10,cpuMaxPct:-10,p99MaxRegressionPct:5},
    scope:"Mixed-read historical benchmark only; release requires additional security, correctness and delayed-I/O checks",results};
}

if(process.argv[1] && import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href) {
  const [dir,sha]=process.argv.slice(2);
  assert.ok(dir&&sha);
  const report=evaluateEfficiency(loads.map(c=>JSON.parse(fs.readFileSync(path.join(dir,"c"+c,"summary.json"),"utf8"))),sha);
  fs.writeFileSync(path.join(dir,"efficiency-gate.json"),JSON.stringify(report,null,2)+"\n",{mode:0o600,flag:"wx"});
  console.log("| C | Throughput median / worst | CPU median / worst | P99 worst | Gate |");
  console.log("|---:|---:|---:|---:|---|");
  const fmt=n=>n.toFixed(2)+"%";
  for(const r of report.results) console.log("| "+r.concurrency+" | "+fmt(r.throughputPct)+" / "+fmt(r.throughputWorstPct)+" | "+fmt(r.cpuPct)+" / "+fmt(r.cpuWorstPct)+" | "+fmt(r.p99WorstPct)+" | "+(r.pass?"PASS":"FAIL")+" |");
  console.log(report.pass?"MIXED-READ EFFICIENCY OBJECTIVES MET":"MIXED-READ EFFICIENCY OBJECTIVES NOT MET");
  if(!report.pass) process.exitCode=1;
}

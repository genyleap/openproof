import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const [dir, baselineCommit, candidateCommit] = process.argv.slice(2);
assert.ok(dir && /^[a-f0-9]{40}$/.test(baselineCommit ?? "") &&
  /^[a-f0-9]{40}$/.test(candidateCommit ?? "") && baselineCommit !== candidateCommit,
  "Usage: summarize-mixed-read-bench.mjs directory baseline-sha candidate-sha");
const labels = ["readiness", "discovery", "jwks", "userinfo", "gateway", "introspection"];
const median = values => {
  const sorted = [...values].sort((a,b) => a-b);
  const mid = Math.floor(sorted.length/2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid-1]+sorted[mid])/2;
};
function positive(value) { assert.ok(Number.isFinite(value) && value > 0); }
function latency(record) {
  for (const k of ["p50Ms","p95Ms","p99Ms"]) positive(record[k]);
  assert.ok(record.p50Ms <= record.p95Ms && record.p95Ms <= record.p99Ms);
}
function read(concurrency, trial, side, commit, requests) {
  const data = JSON.parse(fs.readFileSync(path.join(dir, [concurrency,trial,side].join("-")+".json"),"utf8"));
  assert.equal(data.benchmark,"openproof-isolated-e2e-mixed-read");
  assert.equal(data.commit,commit);
  assert.equal(data.concurrency,concurrency);
  assert.equal(data.requests,requests);
  positive(data.requestsPerSecond);
  latency(data);
  assert.deepEqual(Object.keys(data.byOperation).sort(), [...labels].sort());
  for (const label of labels) {
    const row=data.byOperation[label];
    assert.equal(row.requests, requests/labels.length);
    latency(row);
  }
  for (const k of ["serverCpuTicksDelta","serverRssKiBEnd"]) {
    assert.ok(Number.isFinite(data[k]) && data[k] >= 0, "Missing resource metric: "+k);
  }
  positive(data.serverRssKiBEnd);
  return data;
}
const workloads=[];
for (const [concurrency,requests] of [[24,600],[96,1200]]) {
  const pairs=[];
  for (let trial=1;trial<=4;trial++) pairs.push({
    baseline:read(concurrency,trial,"baseline",baselineCommit,requests),
    candidate:read(concurrency,trial,"candidate",candidateCommit,requests)
  });
  function metric(get, higher) {
    const base=pairs.map(p=>get(p.baseline)), candidate=pairs.map(p=>get(p.candidate));
    const relative=pairs.map((_,i)=>base[i]===0 ? null : 100*(candidate[i]-base[i])/base[i]);
    return { baselineMedian:median(base),candidateMedian:median(candidate),
      medianPairedChangePercent:relative.includes(null)?null:median(relative),
      pairedChangePercent:relative,
      candidateWins:pairs.filter((_,i)=>higher?candidate[i]>base[i]:candidate[i]<base[i]).length };
  }
  const metrics={};
  for (const k of ["requestsPerSecond","p50Ms","p95Ms","p99Ms","serverCpuTicksDelta","serverRssKiBEnd"])
    metrics[k]=metric(row=>row[k],k==="requestsPerSecond");
  const byOperation=Object.fromEntries(labels.map(label=>[label,Object.fromEntries(
    ["p50Ms","p95Ms","p99Ms"].map(k=>[k,metric(row=>row.byOperation[label][k],false)]))]));
  workloads.push({concurrency,requests,pairs:pairs.length,metrics,byOperation});
}
const summary={baselineCommit,candidateCommit,workloads,
  qualification:"descriptive paired measurements only; not statistical significance or release approval"};
fs.writeFileSync(path.join(dir,"summary.json"), JSON.stringify(summary,null,2)+"\n",{mode:0o600});
console.log(JSON.stringify(summary,null,2));

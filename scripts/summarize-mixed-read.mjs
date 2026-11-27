#!/usr/bin/env node
// Repeated real-HTTP E2E measurements. Never combine different commits,
// request mixes, or unmatched trials. No simulated values are accepted.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const [dir, baselineCommit, candidateCommit] = process.argv.slice(2);
assert.ok(dir, "Usage: summarize-mixed-read.mjs <directory> <baseline-sha> <candidate-sha>");
for (const sha of [baselineCommit,candidateCommit]) assert.match(sha,/^[a-f0-9]{40}$/);
assert.notEqual(baselineCommit,candidateCommit);
const routes = ["readiness","discovery","jwks","userinfo","protected-proxy","introspection"];
const fields = ["requestsPerSecond","p50Ms","p95Ms","p99Ms","serverCpuTicksDelta","serverRssKiBEnd"];
const files = fs.readdirSync(dir);
for (const side of ["baseline","candidate"]) {
  assert.equal(files.filter(f => new RegExp("^"+side+"-[1-9][0-9]*\\.json$").test(f)).length,
    5, "Exactly five matched trials required on each side");
}
function validate(record, commit) {
  assert.equal(record.benchmark,"openproof-isolated-e2e-mixed-read");
  assert.equal(record.commit,commit,"Commit mismatch");
  assert.equal(record.requests,600);
  assert.equal(record.concurrency,24);
  for (const key of fields) {
    assert.ok(Number.isFinite(record[key]) && (key==="serverCpuTicksDelta" ? record[key]>=0 : record[key]>0),
      "Invalid measurement: "+key);
  }
  function latency(item) {
    assert.ok([item.p50Ms,item.p95Ms,item.p99Ms].every(v=>Number.isFinite(v)&&v>0));
    assert.ok(item.p50Ms<=item.p95Ms && item.p95Ms<=item.p99Ms);
  }
  latency(record);
  assert.ok(Array.isArray(record.routes));
  assert.equal(record.routes.length,routes.length);
  for (const name of routes) {
    const matching=record.routes.filter(r=>r.name===name);
    assert.equal(matching.length,1,"Missing or repeated route: "+name);
    assert.equal(matching[0].requests,100);
    latency(matching[0]);
  }
  return record;
}
const pairs=Array.from({length:5},(_,i)=>{
  const read=(side,sha)=>validate(JSON.parse(fs.readFileSync(path.join(dir,side+"-"+(i+1)+".json"),"utf8")),sha);
  return {baseline:read("baseline",baselineCommit),candidate:read("candidate",candidateCommit)};
});
function median(values) {
  const sorted=[...values].sort((a,b)=>a-b);
  return sorted[Math.floor(sorted.length/2)];
}
function summarize(key, selector=r=>r) {
  const a=pairs.map(p=>selector(p.baseline)[key]);
  const b=pairs.map(p=>selector(p.candidate)[key]);
  const changes=a.every(v=>v>0)?a.map((v,i)=>100*(b[i]/v-1)):null;
  return {baselineMedian:median(a),candidateMedian:median(b),
    pairedChangePct:changes?median(changes):null,
    pairedRangePct:changes?[Math.min(...changes),Math.max(...changes)]:null};
}
// Optional scheduling diagnostics are comparable only if both sides of
// every trial provide valid measurements. Missing is never treated as zero.
const diagnosticKeys = ["serverUserCpuTicksDelta","serverSystemCpuTicksDelta",
  "serverVoluntaryContextSwitchesDelta","serverInvoluntaryContextSwitchesDelta",
  "serverStableThreadCount"];
const diagnosticMetrics = {};
for (const key of diagnosticKeys) {
  const present = pairs.every(p => [p.baseline,p.candidate].every(
    r => Number.isSafeInteger(r[key]) && r[key] >= (key==="serverStableThreadCount"?1:0)));
  if (present) diagnosticMetrics[key] = summarize(key);
}
const report={benchmark:"openproof-isolated-e2e-mixed-read",baselineCommit,candidateCommit,
  pairCount:5,requestsPerRun:600,concurrency:24,
  metrics:Object.fromEntries(fields.map(k=>[k,summarize(k)])),
  diagnosticMetrics,
  routes:Object.fromEntries(routes.map(name=>[name,Object.fromEntries(
    ["p50Ms","p95Ms","p99Ms"].map(k=>[k,summarize(k,r=>r.routes.find(x=>x.name===name))]))])),
  caveat:"Exploratory paired medians; not full coroutine acceptance or production qualification."};
fs.writeFileSync(path.join(dir,"summary.json"),JSON.stringify(report,null,2)+"\n",{mode:0o600});
console.log("# Matched mixed-read: five alternating pairs, 600 requests / concurrency 24");
console.log("| Metric | Baseline median | Candidate median | Median paired change | Range |");
console.log("|---|---:|---:|---:|---:|");
for (const [k,v] of Object.entries({...report.metrics,...report.diagnosticMetrics})) {
  const fmt=x=>x===null?"n/a":x.toFixed(2)+"%";
  console.log("| "+k+" | "+v.baselineMedian.toFixed(2)+" | "+v.candidateMedian.toFixed(2)+" | "+
    fmt(v.pairedChangePct)+" | "+(v.pairedRangePct?v.pairedRangePct.map(fmt).join(" to "):"n/a")+" |");
}
console.log("Positive change means an increase; lower latency/CPU/RSS is favorable.");
console.log(report.caveat);

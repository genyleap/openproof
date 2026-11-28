#!/usr/bin/env node
// Repeated real-HTTP E2E measurements. Never combine different commits,
// request mixes, or unmatched trials. No simulated values are accepted.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {validateConnectionMetrics,connectionLegs} from "./ci/mixed-read-connections.mjs";
import {fields as statementFields,validateSnapshot as validateStatementMetrics} from "./ci/postgres-statement-metrics.mjs";

const [dir, baselineCommit, candidateCommit, load] = process.argv.slice(2);
assert.ok(process.argv.length === 5 || process.argv.length === 6);
const matrix = load !== undefined;
if (matrix) assert.ok(["1","8","32","128"].includes(load), "Unsupported matrix load");
const concurrency = matrix ? Number(load) : 24;
const requests = matrix ? 1536 : 600;
const pairCount = matrix ? 4 : 5;
const warmupRequests = matrix ? 6 * Math.ceil(Math.max(24,2*concurrency)/6) : 0;
assert.ok(dir, "Usage: summarize-mixed-read.mjs <directory> <baseline-sha> <candidate-sha>");
for (const sha of [baselineCommit,candidateCommit]) assert.match(sha,/^[a-f0-9]{40}$/);
assert.notEqual(baselineCommit,candidateCommit);
const routes = ["readiness","discovery","jwks","userinfo","protected-proxy","introspection"];
const fields = ["requestsPerSecond","p50Ms","p95Ms","p99Ms","serverCpuTicksDelta","serverRssKiBEnd"];
const files = fs.readdirSync(dir);
for (const side of ["baseline","candidate"]) {
  assert.equal(files.filter(f => new RegExp("^"+side+"-[1-9][0-9]*\\.json$").test(f)).length,
    pairCount, "Exact matched trial count required on each side");
}
function validate(record, commit) {
  assert.equal(record.benchmark,"openproof-isolated-e2e-mixed-read");
  assert.equal(record.commit,commit,"Commit mismatch");
  assert.equal(record.requests,requests);
  assert.equal(record.concurrency,concurrency);
  assert.equal(record.warmupRequests ?? 0,warmupRequests,"Warmup mismatch");
  if (matrix) {
    assert.equal(record.normalizedResponseChecks,requests,"Missing normalized response evidence");
    validateConnectionMetrics(record.connectionMetrics,requests);
    assert.equal(record.executionProfile?.name,commit===candidateCommit?"minimal":"auto","Execution profile mismatch");
  }
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
    assert.equal(matching[0].requests,requests/routes.length);
    latency(matching[0]);
  }
  return record;
}
const pairs=Array.from({length:pairCount},(_,i)=>{
  const read=(side,sha)=>validate(JSON.parse(fs.readFileSync(path.join(dir,side+"-"+(i+1)+".json"),"utf8")),sha);
  return {baseline:read("baseline",baselineCommit),candidate:read("candidate",candidateCommit)};
});
function median(values) {
  const sorted=[...values].sort((a,b)=>a-b);
  const mid=Math.floor(sorted.length/2);
  return sorted.length%2 ? sorted[mid] : (sorted[mid-1]+sorted[mid])/2;
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
const cpuKeys = ["serverUserCpuTicksDelta","serverSystemCpuTicksDelta"];
const schedulingKeys = ["serverVoluntaryContextSwitchesDelta",
  "serverInvoluntaryContextSwitchesDelta","serverStableThreadCount"];
const diagnosticMetrics = {};
const records = pairs.flatMap(p => [p.baseline,p.candidate]);
const validCounter = n => Number.isSafeInteger(n) && n >= 0;
if (records.every(r => cpuKeys.every(k => validCounter(r[k])) &&
    r[cpuKeys[0]] + r[cpuKeys[1]] === r.serverCpuTicksDelta)) {
  for (const key of cpuKeys) diagnosticMetrics[key] = summarize(key);
}
if (records.every(r => schedulingKeys.every(k => validCounter(r[k])) &&
    r.serverStableThreadCount > 0)) {
  for (const key of schedulingKeys) diagnosticMetrics[key] = summarize(key);
}
// Edge diagnostics have their own completeness contract. A zero duration
// is valid at clock resolution, but a zero baseline has no percentage ratio.
const edgePhases = ["edgeForwardSend", "edgeUpstreamResponseHeaders",
  "edgeResponseFinish", "edgeTotal"];
const latencyKeys = ["p50Ms","p95Ms","p99Ms"];
const validEdge = r => {
  const edge = r.edgePhaseMetrics;
  if (!edge || edge.samples !== r.requests ||
      !edge.phases || Object.keys(edge.phases).length !== edgePhases.length)
    return false;
  return edgePhases.every(name => {
    const phase = edge.phases[name];
    return phase && latencyKeys.every(k => Number.isFinite(phase[k]) && phase[k] >= 0) &&
      phase.p50Ms <= phase.p95Ms && phase.p95Ms <= phase.p99Ms &&
      latencyKeys.every(k => Number.isFinite(edge.phases.edgeTotal?.[k]) &&
        phase[k] <= edge.phases.edgeTotal[k]);
  });
};
const edgePhaseComparison = records.every(validEdge)
  ? Object.fromEntries(edgePhases.map(name => [name,Object.fromEntries(
      latencyKeys.map(k => [k,summarize(k,r=>r.edgePhaseMetrics.phases[name])]))]))
  : null;
const statementProbe=process.env.OPENPROOF_E2E_STATEMENT_PROBE==="1";
const statementRecords=records.filter(r=>r.postgresStatementMetrics!==undefined);
if(statementProbe || statementRecords.length>0) {
  assert.equal(statementRecords.length,records.length,"Missing paired PostgreSQL statement evidence");
  for(const r of records) {
    validateStatementMetrics(r.postgresStatementMetrics);
    assert.ok(r.postgresStatementMetrics.calls>0);
  }
}
const postgresStatementComparison=statementRecords.length===records.length
  ? Object.fromEntries(statementFields.map(k=>[k,summarize(k,r=>r.postgresStatementMetrics)]))
  : null;
const report={benchmark:"openproof-isolated-e2e-mixed-read",baselineCommit,candidateCommit,
  pairCount,requestsPerRun:requests,concurrency,
  ...(matrix ? {warmupRequests} : {}),
  metrics:Object.fromEntries(fields.map(k=>[k,summarize(k)])),
  diagnosticMetrics,
  ...(postgresStatementComparison ? {postgresStatementComparison} : {}),
  ...(matrix ? {connectionMetrics:Object.fromEntries(connectionLegs.map(leg=>[leg,Object.fromEntries(["assignments","distinctSockets","firstSeenSockets","reusedAssignments"].map(key=>[key,summarize(key,r=>r.connectionMetrics[leg])]))]))} : {}),
  ...(edgePhaseComparison ? {edgePhaseComparison} : {}),
  routes:Object.fromEntries(routes.map(name=>[name,Object.fromEntries(
    ["p50Ms","p95Ms","p99Ms"].map(k=>[k,summarize(k,r=>r.routes.find(x=>x.name===name))]))])),
  caveat:"Exploratory paired medians; not full coroutine acceptance or production qualification."};
fs.writeFileSync(path.join(dir,"summary.json"),JSON.stringify(report,null,2)+"\n",{mode:0o600});
console.log(`# Matched mixed-read: ${pairCount} alternating pairs, ${requests} requests / concurrency ${concurrency}; warmup ${warmupRequests}`);
console.log("| Metric | Baseline median | Candidate median | Median paired change | Range |");
console.log("|---|---:|---:|---:|---:|");
for (const [k,v] of Object.entries({...report.metrics,...report.diagnosticMetrics})) {
  const fmt=x=>x===null?"n/a":x.toFixed(2)+"%";
  console.log("| "+k+" | "+v.baselineMedian.toFixed(2)+" | "+v.candidateMedian.toFixed(2)+" | "+
    fmt(v.pairedChangePct)+" | "+(v.pairedRangePct?v.pairedRangePct.map(fmt).join(" to "):"n/a")+" |");
}
if(postgresStatementComparison) {
  console.log("| PostgreSQL metric | Baseline median | Candidate median | Median paired change |");
  console.log("|---|---:|---:|---:|");
  for(const [key,value] of Object.entries(postgresStatementComparison))
    console.log("| "+key+" | "+value.baselineMedian.toFixed(2)+" | "+value.candidateMedian.toFixed(2)+" | "+(value.pairedChangePct===null?"n/a":value.pairedChangePct.toFixed(2)+"%")+" |");
  console.log("Statement execution time is summed across server backends, not wall-clock HTTP latency; includes utility statements and excludes client scheduling.");
}
console.log("| Route | Paired p50 change | Paired p95 change | Paired p99 change |");
console.log("|---|---:|---:|---:|");
for (const [name, metrics] of Object.entries(report.routes)) {
  console.log("| " + name + " | " + ["p50Ms","p95Ms","p99Ms"].map(
    key => metrics[key].pairedChangePct.toFixed(2) + "%").join(" | ") + " |");
}
if (edgePhaseComparison) {
  console.log("| Edge phase (ms) | Percentile | Baseline median | Candidate median | Median paired change |");
  console.log("|---|---|---:|---:|---:|");
  for (const [name, metrics] of Object.entries(edgePhaseComparison)) {
    for (const [key,v] of Object.entries(metrics))
      console.log("| "+name+" | "+key+" | "+v.baselineMedian.toFixed(2)+" | "+
        v.candidateMedian.toFixed(2)+" | "+(v.pairedChangePct===null?"n/a":v.pairedChangePct.toFixed(2)+"%")+" |");
  }
  console.log("Edge timings include transport and fixture scheduling; they are not isolated OPP service time. Percentiles are not additive.");
}
console.log("Positive change means an increase; lower latency/CPU/RSS is favorable.");
console.log(report.caveat);

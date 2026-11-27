#!/usr/bin/env node
// Same executable, paired workload, distinct explicit runtime profiles.
// No release decision is inferred from two exploratory matched trials.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { profiles } from "./ci/executor-profiles.mjs";

const [directory, commit] = process.argv.slice(2);
assert.ok(directory);
assert.match(commit, /^[a-f0-9]{40}$/);
const names = Object.keys(profiles);
const routes = ["readiness","discovery","jwks","userinfo","protected-proxy","introspection"];
const latencies = ["p50Ms","p95Ms","p99Ms"];
const fields = ["requestsPerSecond", ...latencies, "serverCpuTicksDelta", "serverRssKiBEnd"];
const diagnostic = ["serverStableThreadCount", "serverVoluntaryContextSwitchesDelta",
  "serverInvoluntaryContextSwitchesDelta"];
const records = {};
const finitePositive = n => Number.isFinite(n) && n > 0;
const counter = n => Number.isSafeInteger(n) && n >= 0;
const validLatency = r => latencies.every(k => finitePositive(r[k]))
  && r.p50Ms <= r.p95Ms && r.p95Ms <= r.p99Ms;
for (const name of names) {
  records[name] = [1,2].map(trial => {
    const row = JSON.parse(fs.readFileSync(path.join(directory, name+"-"+trial+".json"),"utf8"));
    assert.equal(row.benchmark, "openproof-isolated-e2e-mixed-read");
    assert.equal(row.commit, commit, "Executor profile commit mismatch");
    assert.deepEqual(row.executionProfile, {name,requestedOverrides:profiles[name]});
    assert.equal(row.requests,600);
    assert.equal(row.concurrency,24);
    assert.ok(validLatency(row));
    assert.ok(finitePositive(row.requestsPerSecond) && finitePositive(row.serverRssKiBEnd));
    assert.ok(counter(row.serverCpuTicksDelta));
    assert.ok(Array.isArray(row.routes) && row.routes.length === routes.length);
    for (const route of routes) {
      const found = row.routes.filter(x => x.name === route);
      assert.equal(found.length,1);
      assert.equal(found[0].requests,100);
      assert.ok(validLatency(found[0]));
    }
    return row;
  });
}
const median = values => (values[0]+values[1])/2;
function paired(name,key,select=r=>r) {
  const a = records.auto.map(r=>select(r)[key]);
  const b = records[name].map(r=>select(r)[key]);
  const changes = a.every(v=>v>0) ? a.map((v,i)=>100*(b[i]/v-1)) : null;
  return {autoMedian:median(a),profileMedian:median(b),
    pairedChangePct:changes ? median(changes) : null,
    pairedRangePct:changes ? [Math.min(...changes),Math.max(...changes)] : null};
}
const all = Object.values(records).flat();
const diagnosticsAvailable = all.every(r => diagnostic.every(k=>counter(r[k]))
  && r.serverStableThreadCount > 0);
const comparisons = Object.fromEntries(names.filter(n=>n!=="auto").map(name=>[name,{
  requestedOverrides:profiles[name],
  metrics:Object.fromEntries(fields.map(k=>[k,paired(name,k)])),
  diagnostics:diagnosticsAvailable ? Object.fromEntries(diagnostic.map(k=>[k,paired(name,k)])) : {},
  routes:Object.fromEntries(routes.map(route=>[route,Object.fromEntries(latencies.map(k=>
    [k,paired(name,k,r=>r.routes.find(x=>x.name===route))]))])),
}]));
const report={benchmark:"openproof-executor-profile-qualification",commit,pairCount:2,
  requestsPerRun:600,concurrency:24,comparisons,qualified:false,
  caveat:"Requested profiles; process counters are independent evidence. Two pairs are exploratory, not release acceptance."};
fs.writeFileSync(path.join(directory,"summary.json"),JSON.stringify(report,null,2)+"\n",{mode:0o600});
for(const [name,result] of Object.entries(comparisons)){
  console.log("Executor profile:",name);
  for(const [key,value] of Object.entries({...result.metrics,...result.diagnostics}))
    console.log(key,value.pairedChangePct===null?"n/a":value.pairedChangePct.toFixed(2)+"%");
}
console.log(report.caveat);

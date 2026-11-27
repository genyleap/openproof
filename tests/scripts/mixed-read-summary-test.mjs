#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";
const script=fileURLToPath(new URL("../../scripts/summarize-mixed-read.mjs",import.meta.url));
const dir=fs.mkdtempSync(path.join(os.tmpdir(),"openproof-mixed-summary-test-"));
const a="a".repeat(40), b="b".repeat(40);
const source={benchmark:"openproof-isolated-e2e-mixed-read",commit:a,requests:600,concurrency:24,
  requestsPerSecond:100,p50Ms:20,p95Ms:30,p99Ms:40,serverCpuTicksDelta:10,serverRssKiBEnd:20000,
  routes:["readiness","discovery","jwks","userinfo","protected-proxy","introspection"].map(name=>({
    name,requests:100,p50Ms:20,p95Ms:30,p99Ms:40}))};
const candidate={...source,commit:b,requestsPerSecond:125,p99Ms:35};
const write=(side,n,x)=>fs.writeFileSync(path.join(dir,side+"-"+n+".json"),JSON.stringify(x),{mode:0o600});
const run=()=>spawnSync(process.execPath,[script,dir,a,b],{encoding:"utf8",timeout:10000});
try {
  for(let i=1;i<=5;i++){write("baseline",i,source);write("candidate",i,candidate);}
  let r=run();assert.equal(r.status,0,r.stderr);
  let report=JSON.parse(fs.readFileSync(path.join(dir,"summary.json"),"utf8"));
  assert.equal(report.pairCount,5);
  assert.equal(report.metrics.requestsPerSecond.pairedChangePct,25);
  assert.equal(report.metrics.p99Ms.pairedChangePct,-12.5);
  assert.deepEqual(report.diagnosticMetrics, {});
  assert.match(r.stdout, /\| readiness \| 0\.00% \| 0\.00% \| 0\.00% \|/);
  const diagnostic = {serverUserCpuTicksDelta:7,serverSystemCpuTicksDelta:3,
    serverVoluntaryContextSwitchesDelta:20,serverInvoluntaryContextSwitchesDelta:0,
    serverStableThreadCount:4};
  const measuredBaseline = {...source,...diagnostic};
  const measuredCandidate = {...candidate,...diagnostic,serverVoluntaryContextSwitchesDelta:10};
  for(let i=1;i<=5;i++){write("baseline",i,measuredBaseline);write("candidate",i,measuredCandidate);}
  r=run();assert.equal(r.status,0,r.stderr);
  report=JSON.parse(fs.readFileSync(path.join(dir,"summary.json"),"utf8"));
  assert.equal(report.diagnosticMetrics.serverVoluntaryContextSwitchesDelta.pairedChangePct,-50);
  assert.equal(report.diagnosticMetrics.serverInvoluntaryContextSwitchesDelta.pairedChangePct,null);
  assert.equal(report.diagnosticMetrics.serverUserCpuTicksDelta.pairedChangePct,0);
  write("candidate",3,{...measuredCandidate,serverSystemCpuTicksDelta:4,serverStableThreadCount:0});
  r=run();assert.equal(r.status,0,r.stderr);
  report=JSON.parse(fs.readFileSync(path.join(dir,"summary.json"),"utf8"));
  assert.deepEqual(report.diagnosticMetrics,{},"Inconsistent diagnostic groups must be omitted");
  const phase = (n) => ({p50Ms:n,p95Ms:n+1,p99Ms:n+2});
  const edgePhaseMetrics = {samples:600,phases:{
    edgeForwardSend:phase(0),edgeUpstreamResponseHeaders:phase(10),
    edgeResponseFinish:phase(2),edgeTotal:phase(20)}};
  const candidateEdge = {...edgePhaseMetrics,phases:{...edgePhaseMetrics.phases,
    edgeUpstreamResponseHeaders:phase(8)}};
  for(let i=1;i<=5;i++){
    write("baseline",i,{...source,edgePhaseMetrics});
    write("candidate",i,{...candidate,edgePhaseMetrics:candidateEdge});
  }
  r=run();assert.equal(r.status,0,r.stderr);
  report=JSON.parse(fs.readFileSync(path.join(dir,"summary.json"),"utf8"));
  assert.equal(report.edgePhaseComparison.edgeForwardSend.p50Ms.pairedChangePct,null);
  assert.ok(Math.abs(report.edgePhaseComparison.edgeUpstreamResponseHeaders.p50Ms.pairedChangePct+20)<1e-9);
  assert.match(r.stdout,/Percentiles are not additive/);
  for(const invalid of [
    {...candidateEdge,samples:599},
    {...candidateEdge,phases:{...candidateEdge.phases,edgeTotal:phase(1)}},
    {...candidateEdge,phases:{...candidateEdge.phases,edgeForwardSend:phase(-1)}},
    undefined
  ]) {
    write("candidate",3,{...candidate,edgePhaseMetrics:invalid});
    r=run();assert.equal(r.status,0,r.stderr);
    report=JSON.parse(fs.readFileSync(path.join(dir,"summary.json"),"utf8"));
    assert.equal(report.edgePhaseComparison,undefined);
  }
  for(let i=1;i<=5;i++){write("baseline",i,source);write("candidate",i,candidate);}
  for(const invalid of [
    {...candidate,commit:a},
    {...candidate,requests:599},
    {...candidate,concurrency:8},
    {...candidate,p95Ms:50},
    {...candidate,routes:candidate.routes.map((route,i)=>({...route,requests:i===0?99:100}))},
    {...candidate,routes:candidate.routes.map((route,i)=>({...route,name:i===0?"jwks":route.name}))},
    {...candidate,serverCpuTicksDelta:-1},
  ]) {
    write("candidate",3,invalid);
    assert.notEqual(run().status,0,"Invalid pair must be rejected");
  }
  write("candidate",3,candidate);
  fs.unlinkSync(path.join(dir,"candidate-5.json"));
  assert.notEqual(run().status,0,"Missing pair must be rejected");
  console.log("Mixed-read paired-report regression: PASSED");
} finally {fs.rmSync(dir,{recursive:true,force:true});}

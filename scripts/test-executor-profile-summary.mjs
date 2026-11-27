import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { profiles,requestedExecutionProfile } from "./ci/executor-profiles.mjs";

const commit="a".repeat(40);
const routes=["readiness","discovery","jwks","userinfo","protected-proxy","introspection"];
const script=path.resolve(import.meta.dirname,"summarize-executor-profiles.mjs");
test("requested profile verifies exact overrides and default remains absent",()=>{
  assert.equal(requestedExecutionProfile({}),undefined);
  for(const [name,overrides] of Object.entries(profiles))
    assert.deepEqual(requestedExecutionProfile({OPENPROOF_E2E_EXECUTION_PROFILE:name,...overrides}),
      {name,requestedOverrides:overrides});
  assert.throws(()=>requestedExecutionProfile({OPENPROOF_E2E_EXECUTION_PROFILE:"two"}));
  assert.throws(()=>requestedExecutionProfile({OPENPROOF_E2E_EXECUTION_PROFILE:"compact",
    ...profiles.compact, OPENPROOF_EXPERIMENTAL_REACTOR_THREADS:"1"}));
  assert.throws(()=>requestedExecutionProfile({OPENPROOF_E2E_EXECUTION_PROFILE:"minimal",
    ...profiles.minimal, OPENPROOF_EXPERIMENTAL_CPU_BUDGET:"1"}));
  assert.throws(()=>requestedExecutionProfile({OPENPROOF_E2E_EXECUTION_PROFILE:"auto",
    OPENPROOF_EXPERIMENTAL_REACTOR_THREADS:"2"}));
  assert.throws(()=>requestedExecutionProfile({OPENPROOF_E2E_EXECUTION_PROFILE:"constructor"}));
});
test("paired profile summary rejects stale/mislabeled records and preserves percent semantics",()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),"opp-executor-profile-test-"));
  try{
    const row=(name,trial)=>({
      benchmark:"openproof-isolated-e2e-mixed-read",commit,requests:600,concurrency:24,
      executionProfile:{name,requestedOverrides:profiles[name]},
      requestsPerSecond:name==="auto"?100:trial===1?110:120,
      p50Ms:10,p95Ms:20,p99Ms:30,serverCpuTicksDelta:0,serverRssKiBEnd:1000,
      serverStableThreadCount:name==="auto"?26:12,
      serverVoluntaryContextSwitchesDelta:100,serverInvoluntaryContextSwitchesDelta:5,
      routes:routes.map(name=>({name,requests:100,p50Ms:10,p95Ms:20,p99Ms:30})),
    });
    const write=(name,trial,r)=>fs.writeFileSync(path.join(dir,name+"-"+trial+".json"),JSON.stringify(r));
    for(const name of Object.keys(profiles)) for(const trial of [1,2])write(name,trial,row(name,trial));
    const run=()=>spawnSync(process.execPath,[script,dir,commit],{encoding:"utf8"});
    const good=run();
    assert.equal(good.status,0,good.stderr);
    const report=JSON.parse(fs.readFileSync(path.join(dir,"summary.json"),"utf8"));
    assert.ok(Math.abs(report.comparisons.two.metrics.requestsPerSecond.pairedChangePct-15)<1e-9);
    assert.equal(report.comparisons.two.metrics.serverCpuTicksDelta.pairedChangePct,null);
    assert.equal(report.comparisons.two.diagnostics.serverStableThreadCount.profileMedian,12);
    assert.deepEqual(report.comparisons.compact.requestedOverrides,profiles.compact);
    assert.deepEqual(report.comparisons.minimal.requestedOverrides,profiles.minimal);
    assert.equal(report.comparisons.minimal.diagnostics.serverStableThreadCount.profileMedian,12);
    assert.equal(report.qualified,false);
    const original=row("two",1);
    for(const invalid of [{...original,commit:"b".repeat(40)},
      {...original,executionProfile:{name:"auto",requestedOverrides:{}}},
      {...original,routes:original.routes.slice(1)}]){
      write("two",1,invalid);
      assert.notEqual(run().status,0);
    }
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});

test("combined inlining qualification enforces warmed matched workloads and exact runtime profiles",()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),"opp-combined-profile-test-"));
  try{
    fs.writeFileSync(path.join(dir,"provenance.txt"),"commit="+commit+"\ncontrol_sha256="+"a".repeat(64)+"\ncandidate_sha256="+"b".repeat(64)+"\n");
    for(const load of [1,8,32,128]){
      const warmupRequests=6*Math.ceil(Math.max(24,2*load)/6);
      const row=(name)=>({benchmark:"openproof-isolated-e2e-mixed-read",commit,
        requests:1536,concurrency:load,warmupRequests,
        executionProfile:{name,requestedOverrides:profiles[name]},
        requestsPerSecond:name==="auto"?100:125,p50Ms:10,p95Ms:20,p99Ms:30,
        serverCpuTicksDelta:10,serverRssKiBEnd:1000,serverStableThreadCount:name==="auto"?26:9,
        serverVoluntaryContextSwitchesDelta:100,serverInvoluntaryContextSwitchesDelta:5,
        routes:routes.map(name=>({name,requests:256,p50Ms:10,p95Ms:20,p99Ms:30}))});
      const write=(side,i,r)=>fs.writeFileSync(path.join(dir,side+"-"+i+".json"),JSON.stringify(r));
      for(let i=1;i<=4;i++){write("control",i,row("auto"));write("candidate",i,row("minimal"));}
      const run=()=>spawnSync(process.execPath,[path.resolve(import.meta.dirname,"summarize-gateway-inline-pairs.mjs"),dir,commit,String(load)],{encoding:"utf8"});
      const good=run();assert.equal(good.status,0,good.stderr);
      const report=JSON.parse(fs.readFileSync(path.join(dir,"summary.json"),"utf8"));
      assert.equal(report.metrics.requestsPerSecond.medianPairedChangePercent,25);
      assert.equal(report.threads.candidateMedian,9);assert.equal(report.qualified,false);
      write("candidate",1,row("auto"));assert.notEqual(run().status,0);
      write("candidate",1,{...row("minimal"),warmupRequests:0});assert.notEqual(run().status,0);
      write("candidate",1,row("minimal"));fs.unlinkSync(path.join(dir,"candidate-4.json"));
      assert.notEqual(run().status,0);
    }
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});

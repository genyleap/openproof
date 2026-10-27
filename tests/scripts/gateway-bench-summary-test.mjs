#!/usr/bin/env node
// Regression for the real-Gateway repeated-pair report; no network or DB.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const summarizer = path.join(root,"scripts/summarize-gateway-bench.mjs");
const directory = fs.mkdtempSync(path.join(os.tmpdir(),"openproof-gateway-summary-test-"));
const source = {
  benchmark:"openproof-gateway-actual-tcp-delayed-upstream",
  requests:600, concurrency:24, upstreamDelayMs:50, metricsEnabled:true,
  errors:0, requestsPerSecond:100, p50Ms:310, p95Ms:320, p99Ms:330,
  commit:"ccb396182936d717960fdca319999baf2f580ff9",
};
const write = (which,n,body) =>
  fs.writeFileSync(path.join(directory,which+"-"+n+".json"),
    JSON.stringify(body),{mode:0o600});
const run = () => spawnSync(process.execPath,[summarizer,directory],{
  encoding:"utf8",timeout:10000,
});
try {
  for(let n=1;n<=5;n++){
    write("baseline",n,source);
    write("candidate",n,{
      ...source,commit:"candidate",requestsPerSecond:200,
      p50Ms:155,p95Ms:160,p99Ms:165,
    });
  }
  let result=run();
  assert.equal(result.status,0,result.stderr);
  const report=JSON.parse(fs.readFileSync(path.join(directory,"summary.json"),"utf8"));
  assert.equal(report.pairCount,5);
  assert.equal(report.workload.metricsEnabled,true);
  assert.equal(report.metrics[0].name,"Throughput");
  assert.equal(report.metrics[0].medianFavorableChangePct,100);
  assert(report.metrics[0].exploratoryBootstrap95Pct.every(x=>x===100));

  write("candidate",3,{...source,concurrency:12});
  result=run();
  assert.notEqual(result.status,0,"Workload mismatches must reject the sample");
  write("candidate",3,{...source,errors:1});
  result=run();
  assert.notEqual(result.status,0,"A failed request must reject the sample");
  write("candidate",3,{...source,metricsEnabled:false});
  result=run();
  assert.notEqual(result.status,0,"Metrics configuration mismatch must reject paired comparison");
  console.log("Gateway paired-report regression: PASSED");
} finally {
  fs.rmSync(directory,{recursive:true,force:true});
}

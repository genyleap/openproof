// Isolated routes are diagnostics, not a substitute for the mixed-read gate.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {pathToFileURL} from "node:url";
export const routes=["readiness","discovery","jwks","userinfo","protected-proxy","introspection"];
const baseline="ccb396182936d717960fdca319999baf2f580ff9";
export function summarizeRoutes(read,candidate) {
  assert.match(candidate,/^[a-f0-9]{40}$/);
  assert.notEqual(candidate,baseline);
  const validate=(r,route,side)=>{
    assert.equal(r.benchmark,"openproof-isolated-e2e-route-attribution");
    assert.equal(r.commit,side==="baseline"?baseline:candidate);
    assert.equal(r.isolatedRoute,route);
    assert.equal(r.executionProfile?.name,side==="baseline"?"auto":"minimal");
    assert.equal(r.requests,3072);
    assert.equal(r.normalizedResponseChecks,3072);
    assert.equal(r.concurrency,1);
    assert.equal(r.warmupRequests,66);
    assert.equal(r.routes.length,1);
    assert.equal(r.routes[0].name,route);
    assert.equal(r.routes[0].requests,3072);
    for(const key of ["requestsPerSecond","p50Ms","p95Ms","p99Ms","serverCpuTicksDelta"]) assert.ok(Number.isFinite(r[key])&&r[key]>0,key);
    assert.ok(r.p50Ms<=r.p95Ms&&r.p95Ms<=r.p99Ms);
    assert.ok(Number.isSafeInteger(r.serverUserCpuTicksDelta)&&r.serverUserCpuTicksDelta>=0);
    assert.ok(Number.isSafeInteger(r.serverSystemCpuTicksDelta)&&r.serverSystemCpuTicksDelta>=0);
    assert.equal(r.serverUserCpuTicksDelta+r.serverSystemCpuTicksDelta,r.serverCpuTicksDelta);
    return r;
  };
  const results=routes.map(route=>{
    const pairs=[1,2].map(i=>({baseline:validate(read(route,"baseline",i),route,"baseline"),candidate:validate(read(route,"candidate",i),route,"candidate")}));
    const mean=a=>a.reduce((s,v)=>s+v,0)/a.length;
    const metric=key=>{
      const b=pairs.map(p=>p.baseline[key]),c=pairs.map(p=>p.candidate[key]);
      const changes=b.every(x=>x>0)?b.map((x,i)=>100*(c[i]/x-1)):null;
      return {baseline:mean(b),candidate:mean(c),pairedChangePct:changes?mean(changes):null,rangePct:changes?[Math.min(...changes),Math.max(...changes)]:null};
    };
    return {route,metrics:Object.fromEntries(["requestsPerSecond","p50Ms","p99Ms","serverCpuTicksDelta","serverUserCpuTicksDelta","serverSystemCpuTicksDelta"].map(k=>[k,metric(k)]))};
  });
  return {baselineCommit:baseline,candidateCommit:candidate,requests:73728,concurrency:1,pairsPerRoute:2,results,caveat:"Exploratory isolated routes; not additive to mixed-read performance and not acceptance evidence."};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href) {
  const [dir,sha]=process.argv.slice(2);
  assert.ok(dir&&sha);
  const result=summarizeRoutes((route,side,pair)=>JSON.parse(fs.readFileSync(path.join(dir,route+"-"+side+"-"+pair+".json"),"utf8")),sha);
  fs.writeFileSync(path.join(dir,"summary.json"),JSON.stringify(result,null,2)+"\n",{mode:0o600,flag:"wx"});
  const fmt=v=>v===null?"n/a":v.toFixed(2)+"%";
  console.log("| Route | Throughput change | CPU ticks baseline | CPU ticks candidate | CPU change | P99 change |");
  console.log("|---|---:|---:|---:|---:|---:|");
  for(const {route,metrics:m} of result.results) console.log("| "+route+" | "+fmt(m.requestsPerSecond.pairedChangePct)+" | "+m.serverCpuTicksDelta.baseline+" | "+m.serverCpuTicksDelta.candidate+" | "+fmt(m.serverCpuTicksDelta.pairedChangePct)+" | "+fmt(m.p99Ms.pairedChangePct)+" |");
  console.log(result.caveat);
}

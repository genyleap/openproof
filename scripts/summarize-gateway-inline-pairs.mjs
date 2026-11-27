import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
const [dir,commit] = process.argv.slice(2);
assert.ok(dir && /^[a-f0-9]{40}$/.test(commit ?? ""));
const lines = fs.readFileSync(path.join(dir,"provenance.txt"),"utf8").trim().split("\n");
assert.equal(lines.length,3);
assert.equal(lines[0],"commit="+commit);
assert.match(lines[1],/^control_sha256=[a-f0-9]{64}$/);
assert.match(lines[2],/^candidate_sha256=[a-f0-9]{64}$/);
const controlHash=lines[1].split("=")[1],candidateHash=lines[2].split("=")[1];
assert.notEqual(controlHash,candidateHash);
const keys=["requestsPerSecond","p50Ms","p95Ms","p99Ms","serverCpuTicksDelta","serverRssKiBEnd",
  "serverVoluntaryContextSwitchesDelta","serverInvoluntaryContextSwitchesDelta"];
const routes=["readiness","discovery","jwks","userinfo","protected-proxy","introspection"];
function read(side,i){
  const r=JSON.parse(fs.readFileSync(path.join(dir,side+"-"+i+".json"),"utf8"));
  assert.equal(r.commit,commit);
  assert.equal(r.benchmark,"openproof-isolated-e2e-mixed-read");
  assert.equal(r.requests,600); assert.equal(r.concurrency,24);
  for(const k of keys) assert.ok(Number.isFinite(r[k]) && r[k]>=0,k);
  assert.ok(r.requestsPerSecond>0 && r.serverRssKiBEnd>0);
  const latency=x=>assert.ok(x.p50Ms>0 && x.p50Ms<=x.p95Ms && x.p95Ms<=x.p99Ms && Number.isFinite(x.p99Ms));
  latency(r);
  assert.deepEqual(r.routes.map(x=>x.name).sort(),[...routes].sort());
  for(const route of r.routes){assert.equal(route.requests,100);latency(route);}
  return r;
}
const pairs=[1,2,3,4].map(i=>[read("control",i),read("candidate",i)]);
const median=a=>{const s=[...a].sort((x,y)=>x-y);return (s[1]+s[2])/2;};
function metric(get){
  const before=pairs.map(p=>get(p[0])),after=pairs.map(p=>get(p[1]));
  const change=before.map((v,i)=>v===0?null:100*(after[i]/v-1));
  return {controlMedian:median(before),candidateMedian:median(after),
    medianPairedChangePercent:change.includes(null)?null:median(change),pairedChanges:change};
}
const report={commit,controlHash,candidateHash,pairs:4,requests:600,concurrency:24,
  metrics:Object.fromEntries(keys.map(k=>[k,metric(r=>r[k])])),
  routes:Object.fromEntries(routes.map(name=>[name,Object.fromEntries(["p50Ms","p95Ms","p99Ms"].map(k=>
    [k,metric(r=>r.routes.find(x=>x.name===name)[k])]))])),
  qualified:false,caveat:"Same-source experimental compile flag comparison; not release acceptance."};
fs.writeFileSync(path.join(dir,"summary.json"),JSON.stringify(report,null,2)+"\n",{mode:0o600});
console.log(JSON.stringify(report,null,2));

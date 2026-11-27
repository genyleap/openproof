import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readOppUsage, oppUsageDelta } from "../../scripts/ci/process-usage.mjs";

const root = fs.mkdtempSync(path.join(os.tmpdir(),"openproof-proc-usage-"));
const proc = path.join(root,"42");
function write(p, data) {
  fs.mkdirSync(path.dirname(p), {recursive:true});
  fs.writeFileSync(p,data);
}
function stat(user,system,start) {
  const tail = Array(50).fill("0");
  tail[0]="S"; tail[11]=String(user); tail[12]=String(system); tail[19]=String(start);
  return "42 (name with ) and spaces) "+tail.join(" ")+"\n";
}
function snapshot(user,system,start,v,iv,threadStart=25) {
  write(path.join(proc,"stat"),stat(user,system,start));
  write(path.join(proc,"status"),"VmRSS:\t 2048 kB\n");
  for (const id of ["42","43"]) {
    write(path.join(proc,"task",id,"stat"),stat(0,0,threadStart));
    write(path.join(proc,"task",id,"status"),
      "voluntary_ctxt_switches:\t"+v+"\nnonvoluntary_ctxt_switches:\t"+iv+"\n");
  }
  return readOppUsage(42,root);
}
try {
  if (process.platform === "linux") {
    const first=snapshot(10,5,100,4,2);
    const last=snapshot(16,8,100,9,3);
    assert.deepEqual(oppUsageDelta(first,last),{
      serverCpuTicksDelta:9, serverUserCpuTicksDelta:6, serverSystemCpuTicksDelta:3,
      serverRssKiBEnd:2048,serverVoluntaryContextSwitchesDelta:10,
      serverInvoluntaryContextSwitchesDelta:2,serverStableThreadCount:2});
    const reused=snapshot(16,8,100,9,3,26);
    assert.equal(oppUsageDelta(first,reused).serverVoluntaryContextSwitchesDelta,undefined);
    const reset=snapshot(16,8,101,9,3);
    assert.deepEqual(oppUsageDelta(first,reset),{});
    const backwards=snapshot(9,8,100,9,3);
    assert.deepEqual(oppUsageDelta(first,backwards),{});
    snapshot(16,8,100,9,3);
    fs.rmSync(path.join(proc,"task","43"),{recursive:true});
    const missing=oppUsageDelta(first,readOppUsage(42,root));
    assert.equal(missing.serverCpuTicksDelta,9);
    assert.equal(missing.serverStableThreadCount,undefined);
    write(path.join(proc,"task","42","status"),"malformed\n");
    assert.equal(readOppUsage(42,root).threads,null);
    write(path.join(proc,"stat"),"malformed\n");
    assert.equal(readOppUsage(42,root),null);
    assert.equal(readOppUsage(-1,root),null);
  }
  assert.deepEqual(oppUsageDelta(null,null),{});
  console.log("Process usage diagnostics regression: PASSED");
} finally { fs.rmSync(root,{recursive:true,force:true}); }

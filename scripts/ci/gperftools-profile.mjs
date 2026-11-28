// Disposable hosted CI only. libprofiler is injected into the fixture
// server, not linked into the runtime, and not propagated to other commands.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {spawnSync} from "node:child_process";
import {setTimeout as delay} from "node:timers/promises";
function requireCI() {
  assert.equal(process.env.GITHUB_ACTIONS,"true");
  assert.equal(process.env.RUNNER_ENVIRONMENT,"github-hosted");
}
export function profileEnvironment(library,base) {
  requireCI();
  assert.ok(path.isAbsolute(library)&&path.isAbsolute(base));
  assert.match(path.basename(library),/^libprofiler\.so(?:\.[0-9]+)*$/);
  assert.ok(fs.statSync(library).isFile());
  assert.ok(!fs.existsSync(base+".0"));
  return {LD_PRELOAD:library,CPUPROFILE:base,
    CPUPROFILESIGNAL:String(os.constants.signals.SIGUSR2),CPUPROFILE_FREQUENCY:"1000",
    CPUPROFILE_REALTIME:"0",CPUPROFILE_PER_THREAD_TIMERS:"0"};
}
async function until(child,predicate,label) {
  const deadline=performance.now()+10000;
  while(!predicate()) {
    assert.ok(child.exitCode===null&&child.signalCode===null,"profiled fixture exited");
    assert.ok(performance.now()<deadline,label);
    await delay(25);
  }
}
export function parseProfileReport(report) {
  const match=report.match(/^Total:\s+(\d+)\s+samples\b/m);
  assert.ok(match,"missing pprof sample count");
  const count=Number(match[1]);
  assert.ok(Number.isSafeInteger(count)&&count>=500,"insufficient CPU samples ("+count+")");
  const rows=report.split("\n").filter(line=>/^\s*\d+\s+[\d.]+%\s+[\d.]+%\s+\d+\s+[\d.]+%\s+\S/.test(line));
  assert.ok(rows.length,"missing pprof symbol histogram");
  return {count,report:["Total: "+count+" samples",...rows].join("\n")+"\n"};
}
export async function sampleFixture({child,base,output,binary,pprof,readLog,work}) {
  requireCI();
  assert.ok(child?.pid>1&&[base,output,binary,pprof].every(path.isAbsolute));
  const raw=base+".0";
  assert.ok(!fs.existsSync(raw));
  // The server must have announced the installed switch before signaling.
  assert.match(readLog(),/Using signal \d+ as cpu profiling switch/);
  assert.ok(child.kill("SIGUSR2"),"unable to start fixture profiler");
  try {
    await until(child,()=>fs.existsSync(raw),"profiler did not start");
    const result=await work();
    assert.ok(child.kill("SIGUSR2"),"unable to stop fixture profiler");
    // gperftools ProfileData::Stop prints its sample summary AFTER writing
    // the end marker and maps and closing the profile fd.
    let complete;
    await until(child,()=>{complete=readLog().match(/PROFILE: interrupts\/evictions\/bytes = (\d+)\/(\d+)\/(\d+)/);return !!complete;},"profiler did not finalize");
    assert.ok(Number(complete[1])>=500,"insufficient recorded interrupts ("+complete[1]+")");
    const report=spawnSync(pprof,["--text","--functions",binary,raw],
      {encoding:"utf8",timeout:60000,maxBuffer:8*1024*1024,env:{...process.env,LD_PRELOAD:""}});
    assert.equal(report.status,0,"pprof failed");
    const parsed=parseProfileReport(report.stdout);
    fs.writeFileSync(output,parsed.report,{mode:0o600,flag:"wx"});
    return result;
  } finally {
    // The caller stops the fixture and removes its private temporary root
    // even if collection fails. Never export the raw stack/map data.
    fs.rmSync(raw,{force:true});
  }
}

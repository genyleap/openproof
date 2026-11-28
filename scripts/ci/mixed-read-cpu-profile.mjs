// CPU sampling for disposable CI only. No call stacks, register dumps,
// request bytes or raw perf.data are exported. Keep raw samples in a
// private temporary directory until a symbol-only report is written.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {spawn,spawnSync} from "node:child_process";
import {createInterface} from "node:readline";

export async function profileMixedRead({pid,perf,output,work}) {
  assert.equal(process.env.GITHUB_ACTIONS,"true");
  assert.ok(Number.isSafeInteger(pid) && pid>1);
  assert.ok(path.isAbsolute(perf) && path.isAbsolute(output));
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),"openproof-perf-"));
  const data=path.join(dir,"perf.data");
  let child,closed,reader;
  try {
    child=spawn(perf,["record","-e","cpu-clock:u","-F","997",
      "-p",String(pid),"-D","-1","--control=fd:3,4",
      "--no-buildid-cache","-o",data],
      {stdio:["ignore","ignore","ignore","pipe","pipe"]});
    // Always observe child closure, even when the spawn fails.
    closed=new Promise(resolve=>{
      child.once("error",()=>resolve({code:null,signal:"spawn-error"}));
      child.once("close",(code,signal)=>resolve({code,signal}));
    });
    // Stream errors may arrive after acknowledgement; observe them even
    // when no command is pending (the next command/closure still fails).
    child.stdio[3].on("error",()=>{});
    child.stdio[4].on("error",()=>{});
    reader=createInterface({input:child.stdio[4],crlfDelay:Infinity});
    reader.on("error",()=>{});
    const send=async command=>{
      let timer,listener,onError;
      try {
        const ack=new Promise((resolve,reject)=>{
          listener=line=>{
            // Linux perf writes sizeof("ack\\n"), including the trailing
            // NUL. readline retains that byte before the next acknowledgement.
            if(line.replace(/\0/g,"").trim()==="ack") resolve();
          };
          onError=()=>reject(new Error("perf control pipe failed"));
          reader.on("line",listener);
          child.stdio[3].once("error",onError);
          timer=setTimeout(()=>reject(new Error("perf control acknowledgement timed out")),10000);
          child.stdio[3].write(command+"\n");
        });
        await Promise.race([ack,closed.then(()=>{throw new Error("perf exited before acknowledgement");})]);
      } finally {
        clearTimeout(timer);
        if(listener) reader.off("line",listener);
        if(onError) child.stdio[3].off("error",onError);
      }
    };
    await send("enable");
    const result=await work();
    await send("disable");
    child.kill("SIGINT");
    let stopTimer;
    let exit;
    try {
      exit=await Promise.race([closed,new Promise((_,reject)=>{
        stopTimer=setTimeout(()=>reject(new Error("perf stop timed out")),10000);
      })]);
    } finally { clearTimeout(stopTimer); }
    assert.equal(exit.code,0,"perf record failed");
    assert.ok(fs.statSync(data).size>0,"perf captured no data");
    const report=spawnSync(perf,["report","--stdio","--no-children",
      "--sort","dso,symbol","--show-nr-samples","--percent-limit","0.5","-i",data],
      {encoding:"utf8",timeout:30000,maxBuffer:8*1024*1024});
    assert.equal(report.status,0,"perf symbol report failed");
    assert.match(report.stdout,/Samples:/,"perf report lacks sample count");
    const samples=report.stdout.match(/Samples:\s*([0-9.]+)([KkMm]?)\s/);
    assert.ok(samples,"perf report lacks parseable sample count");
    const multiplier={k:1000,m:1000000}[samples[2].toLowerCase()]??1;
    assert.ok(Number(samples[1])*multiplier>=500,"insufficient CPU samples");
    // Only event/sample summaries and histogram rows are retained.
    const filtered=report.stdout.split("\n").filter(line=>
      /^#\s+(Samples:|Event count|Overhead|Lost)/.test(line) ||
      /^\s*\d+(?:\.\d+)?%\s/.test(line)).join("\n");
    assert.match(filtered,/\d+\.\d+%/,"perf report lacks symbol histogram");
    fs.writeFileSync(output,filtered+"\n",{mode:0o600,flag:"wx"});
    return result;
  } finally {
    reader?.close();
    if(child && child.exitCode===null && child.signalCode===null) child.kill("SIGKILL");
    if(closed) await closed;
    fs.rmSync(dir,{recursive:true,force:true});
  }
}

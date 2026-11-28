import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {profileMixedRead} from "../../scripts/ci/mixed-read-cpu-profile.mjs";
const root=fs.mkdtempSync(path.join(os.tmpdir(),"openproof-profile-test-"));
const fake=path.join(root,"fake-perf");
const original=process.env.GITHUB_ACTIONS;
process.env.GITHUB_ACTIONS="true";
try {
  // Simulate the perf control protocol, not a performance measurement.
  fs.writeFileSync(fake,`#!/usr/bin/env node
const fs=require("node:fs");
const readline=require("node:readline");
const net=require("node:net");
if(process.argv[2]==="record") {
  if(process.env.TEST_PERF_EARLY_EXIT==="1") process.exit(1);
  const data=process.argv[process.argv.indexOf("-o")+1];
  // spawn's extra stdio pipes are stream sockets, not regular files.
  // Avoid a blocking fs.read on a libuv worker during signal shutdown.
  const socket=new net.Socket({fd:3,readable:true,writable:false});
  const control=readline.createInterface({input:socket});
  // Real perf re-raises SIGINT; successful collection must use stop.
  process.on("SIGINT",()=>{
    process.removeAllListeners("SIGINT");
    process.kill(process.pid,"SIGINT");
  });
  control.on("line",line=>{
    if(line==="ping"||line==="disable"||line==="stop") fs.writeSync(4,"ack\\n\\0");
    if(line==="stop"){
      control.close();
      socket.destroy();
      fs.writeFileSync(data,"synthetic");
      process.exit(process.env.TEST_PERF_STOP_FAILURE==="1"?2:0);
    }
  });
} else if(process.argv[2]==="report") {
  const count=process.env.TEST_PERF_LOW_COUNT==="1"?"4":"1K";
  console.log("# Samples: "+count+" of event 'task-clock:u'");
  console.log("# Event count (approx.): 1000000");
  console.log("    80.00%  800  opp  [.] example");
  console.log("discard this extra diagnostic");
} else process.exit(2);
`,{mode:0o700});
  const output=path.join(root,"report.txt");
  const result=await profileMixedRead({pid:process.pid,perf:fake,output,work:async()=>42});
  assert.equal(result,42);
  assert.match(fs.readFileSync(output,"utf8"),/80\.00%/);
  assert.doesNotMatch(fs.readFileSync(output,"utf8"),/discard this/);
  process.env.TEST_PERF_LOW_COUNT="1";
  await assert.rejects(profileMixedRead({pid:process.pid,perf:fake,output:path.join(root,"low"),work:async()=>0}),/insufficient CPU samples/);
  delete process.env.TEST_PERF_LOW_COUNT;
  process.env.TEST_PERF_STOP_FAILURE="1";
  await assert.rejects(profileMixedRead({pid:process.pid,perf:fake,output:path.join(root,"stop-failure"),work:async()=>0}),/perf record failed/);
  delete process.env.TEST_PERF_STOP_FAILURE;
  process.env.TEST_PERF_EARLY_EXIT="1";
  await assert.rejects(profileMixedRead({pid:process.pid,perf:fake,output:path.join(root,"early"),work:async()=>{throw Error("load must not start");}}),/perf exited|perf control/);
  console.log("CPU profile control and sample-validation contract: PASSED");
} finally {
  if(original===undefined) delete process.env.GITHUB_ACTIONS;
  else process.env.GITHUB_ACTIONS=original;
  delete process.env.TEST_PERF_LOW_COUNT;
  delete process.env.TEST_PERF_EARLY_EXIT;
  delete process.env.TEST_PERF_STOP_FAILURE;
  fs.rmSync(root,{recursive:true,force:true});
}

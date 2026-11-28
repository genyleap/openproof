import assert from "node:assert/strict";
import {parseProfileReport,profileEnvironment} from "../../scripts/ci/gperftools-profile.mjs";
const valid="Total: 1000 samples\n  800 80.0% 80.0%  900 90.0% symbol_a\n  200 20.0% 100.0%  200 20.0% symbol_b\nprivate metadata\n";
const result=parseProfileReport(valid);
assert.equal(result.count,1000);
assert.match(result.report,/symbol_a/);
assert.doesNotMatch(result.report,/private metadata/);
for(const text of [valid.replace("1000 samples","0 samples"),"Total: 1000 samples\n", "malformed"]) assert.throws(()=>parseProfileReport(text));
assert.throws(()=>parseProfileReport("Total: 1000 samples\n 1000 100.0% 100.0% 1000 100.0% clock_nanosleep@@GLIBC_2.17\n"),/idle/);
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
const dir=fs.mkdtempSync(path.join(os.tmpdir(),"opp-profile-env-"));
try {
  const library=path.join(dir,"libprofiler.so.0");
  fs.writeFileSync(library,"");
  process.env.GITHUB_ACTIONS="true";
  process.env.RUNNER_ENVIRONMENT="github-hosted";
  const env=profileEnvironment(library,path.join(dir,"profile"),{CPUPROFILE_REALTIME:"0",CPUPROFILE_TIMER_SIGNAL:"99",CPUPROFILE_PER_THREAD_TIMERS:"0",OTHER:"kept"});
  assert.equal(Object.hasOwn(env,"CPUPROFILE_REALTIME"),false);
  assert.equal(Object.hasOwn(env,"CPUPROFILE_TIMER_SIGNAL"),false);
  assert.equal(Object.hasOwn(env,"CPUPROFILE_PER_THREAD_TIMERS"),false);
  assert.equal(env.OTHER,"kept");
} finally {fs.rmSync(dir,{recursive:true,force:true});}
console.log("gperftools symbol-only report contract: PASSED");

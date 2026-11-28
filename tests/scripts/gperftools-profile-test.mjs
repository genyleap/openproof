import assert from "node:assert/strict";
import {parseProfileReport} from "../../scripts/ci/gperftools-profile.mjs";
const valid="Total: 1000 samples\n  800 80.0% 80.0%  900 90.0% symbol_a\n  200 20.0% 100.0%  200 20.0% symbol_b\nprivate metadata\n";
const result=parseProfileReport(valid);
assert.equal(result.count,1000);
assert.match(result.report,/symbol_a/);
assert.doesNotMatch(result.report,/private metadata/);
for(const text of [valid.replace("1000 samples","0 samples"),"Total: 1000 samples\n", "malformed"]) assert.throws(()=>parseProfileReport(text));
console.log("gperftools symbol-only report contract: PASSED");

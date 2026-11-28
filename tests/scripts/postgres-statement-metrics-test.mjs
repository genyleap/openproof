import assert from "node:assert/strict";
import {snapshotSql,statementDelta,validateSnapshot} from "../../scripts/ci/postgres-statement-metrics.mjs";
const before={dealloc:0,statsReset:"unchanged",calls:10,executionMs:2,rows:3,sharedHits:4,sharedReads:0,resetCalls:2,resetExecutionMs:0.5};
const after={...before,calls:15,executionMs:4,rows:5,sharedHits:8,resetCalls:4,resetExecutionMs:1};
const delta=statementDelta(before,after);
assert.deepEqual(delta,{calls:5,executionMs:2,rows:2,sharedHits:4,sharedReads:0,resetCalls:2,resetExecutionMs:0.5});
for(const invalid of [{...after,calls:9},{...after,dealloc:1},{...after,statsReset:"changed"},{...after,resetCalls:16},{...after,executionMs:NaN}])
  assert.throws(()=>statementDelta(before,invalid));
assert.throws(()=>validateSnapshot({...delta,query:"not allowed"}));
assert.match(snapshotSql,/WHERE d.datname=:'fixture_database'/);
assert.match(snapshotSql,/pg_stat_statements_info/);
console.log("PostgreSQL statement attribution contract: PASSED");

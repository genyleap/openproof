// Disposable CI only. Read aggregate counters from the maintenance database,
// never return SQL text, query IDs, connection strings, or parameters.
import assert from "node:assert/strict";
export const fields=["calls","executionMs","rows","sharedHits","sharedReads","resetCalls","resetExecutionMs"];
export const snapshotSql = `SELECT json_build_object(
 'calls',coalesce(sum(s.calls),0),
 'executionMs',coalesce(sum(s.total_exec_time),0),
 'rows',coalesce(sum(s.rows),0),
 'sharedHits',coalesce(sum(s.shared_blks_hit),0),
 'sharedReads',coalesce(sum(s.shared_blks_read),0),
 'resetCalls',coalesce(sum(s.calls) FILTER (WHERE upper(trim(both ' ;' from s.query))='DISCARD ALL'),0),
 'resetExecutionMs',coalesce(sum(s.total_exec_time) FILTER (WHERE upper(trim(both ' ;' from s.query))='DISCARD ALL'),0))
 FROM pg_stat_statements s JOIN pg_database d ON d.oid=s.dbid
 WHERE d.datname=:'fixture_database'`;
export function validateSnapshot(value) {
  assert.deepEqual(Object.keys(value).sort(),[...fields].sort());
  for(const key of fields) {
    assert.ok(Number.isFinite(value[key]) && value[key]>=0,"Invalid PostgreSQL counter: "+key);
    if(!key.endsWith("Ms")) assert.ok(Number.isSafeInteger(value[key]),"Invalid PostgreSQL count: "+key);
  }
  assert.ok(value.resetCalls<=value.calls && value.resetExecutionMs<=value.executionMs+1e-6);
  return value;
}
export function statementDelta(before,after) {
  validateSnapshot(before);validateSnapshot(after);
  const delta=Object.fromEntries(fields.map(k=>[k,after[k]-before[k]]));
  return validateSnapshot(delta);
}

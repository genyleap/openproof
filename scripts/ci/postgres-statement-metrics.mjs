// Disposable CI only. Read aggregate counters from the maintenance database,
// never return SQL text, query IDs, connection strings, or parameters.
import assert from "node:assert/strict";
export const fields=["calls","executionMs","rows","sharedHits","sharedReads","resetCalls","resetExecutionMs","plans","planningMs","accessReadCalls","accessReadPlans","accessReadPlanningMs","accessReadExecutionMs"];
export const snapshotSql = `SELECT json_build_object(
 'dealloc',(SELECT dealloc FROM pg_stat_statements_info),
 'statsReset',(SELECT stats_reset::text FROM pg_stat_statements_info),
 'calls',coalesce(sum(s.calls),0),
 'executionMs',coalesce(sum(s.total_exec_time),0),
 'rows',coalesce(sum(s.rows),0),
 'sharedHits',coalesce(sum(s.shared_blks_hit),0),
 'sharedReads',coalesce(sum(s.shared_blks_read),0),
 'resetCalls',coalesce(sum(s.calls) FILTER (WHERE upper(trim(both ' ;' from s.query))='DISCARD ALL'),0),
 'resetExecutionMs',coalesce(sum(s.total_exec_time) FILTER (WHERE upper(trim(both ' ;' from s.query))='DISCARD ALL'),0),
 'plans',coalesce(sum(s.plans),0),
 'planningMs',coalesce(sum(s.total_plan_time),0),
 'accessReadCalls',coalesce(sum(s.calls) FILTER (WHERE s.query ILIKE 'SELECT%oauth_access_tokens%'),0),
 'accessReadPlans',coalesce(sum(s.plans) FILTER (WHERE s.query ILIKE 'SELECT%oauth_access_tokens%'),0),
 'accessReadPlanningMs',coalesce(sum(s.total_plan_time) FILTER (WHERE s.query ILIKE 'SELECT%oauth_access_tokens%'),0),
 'accessReadExecutionMs',coalesce(sum(s.total_exec_time) FILTER (WHERE s.query ILIKE 'SELECT%oauth_access_tokens%'),0))
 FROM pg_stat_statements s JOIN pg_database d ON d.oid=s.dbid
 WHERE d.datname=:'fixture_database'`;
export function validateSnapshot(value) {
  assert.deepEqual(Object.keys(value).sort(),[...fields].sort());
  for(const key of fields) {
    assert.ok(Number.isFinite(value[key]) && value[key]>=0,"Invalid PostgreSQL counter: "+key);
    if(!key.endsWith("Ms")) assert.ok(Number.isSafeInteger(value[key]),"Invalid PostgreSQL count: "+key);
  }
  assert.ok(value.resetCalls<=value.calls && value.resetExecutionMs<=value.executionMs+1e-6);
  assert.ok(value.accessReadCalls<=value.calls && value.accessReadPlans<=value.plans);
  assert.ok(value.accessReadPlanningMs<=value.planningMs+1e-6 &&
    value.accessReadExecutionMs<=value.executionMs+1e-6);
  return value;
}
export function statementDelta(before,after) {
  for(const snapshot of [before,after]) {
    const {dealloc,statsReset,...counters}=snapshot;
    validateSnapshot(counters);
    assert.ok(Number.isSafeInteger(dealloc) && dealloc>=0);
    assert.ok(typeof statsReset==="string" && statsReset.length>0);
  }
  assert.equal(before.dealloc,after.dealloc,"PostgreSQL statistics entries were evicted");
  assert.equal(before.statsReset,after.statsReset,"PostgreSQL statistics reset during load");
  const delta=Object.fromEntries(fields.map(k=>[k,after[k]-before[k]]));
  return validateSnapshot(delta);
}

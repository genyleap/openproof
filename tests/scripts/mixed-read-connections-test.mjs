import test from "node:test";
import assert from "node:assert/strict";
import {createConnectionAccounting,validateConnectionMetrics,connectionLegs} from "../../scripts/ci/mixed-read-connections.mjs";
test("counts previously observed sockets as reused and records only aggregate counts",()=>{
  const meter=createConnectionAccounting();
  for(const leg of connectionLegs){
    const old={private:"never exported"};
    meter.observe(leg,old);
    // Keep independent socket identities for each leg.
    if(leg==="clientToEdge") var front=old; else var back=old;
  }
  meter.begin();
  for(const [leg,old] of [["clientToEdge",front],["edgeToOpp",back]]){
    const fresh={};
    meter.observe(leg,old);meter.observe(leg,fresh);meter.observe(leg,fresh);
  }
  const result=meter.finish(3);
  for(const leg of connectionLegs)assert.deepEqual(result[leg],{assignments:3,distinctSockets:2,firstSeenSockets:1,reusedAssignments:2});
  assert.ok(!JSON.stringify(result).includes("private"));
  assert.throws(()=>validateConnectionMetrics(result,4));
  meter.begin();
  meter.observe("clientToEdge",front);
  assert.throws(()=>meter.finish(1));
});

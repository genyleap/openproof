// Count socket object identity, not addresses, ports, certificates or data.
// A first assignment within the measured window is not necessarily a new
// connection: a socket already seen before measurement is reused.
import assert from "node:assert/strict";
export const connectionLegs=["clientToEdge","edgeToOpp"];
export function validateConnectionMetrics(metrics,requests) {
  assert.ok(Number.isSafeInteger(requests)&&requests>0);
  assert.deepEqual(Object.keys(metrics).sort(),[...connectionLegs].sort());
  for(const leg of connectionLegs){
    const value=metrics[leg];
    assert.deepEqual(Object.keys(value).sort(),["assignments","distinctSockets","firstSeenSockets","reusedAssignments"].sort());
    for(const n of Object.values(value)) assert.ok(Number.isSafeInteger(n)&&n>=0);
    assert.equal(value.assignments,requests);
    assert.equal(value.firstSeenSockets+value.reusedAssignments,requests);
    assert.ok(value.firstSeenSockets<=value.distinctSockets&&value.distinctSockets<=requests);
    assert.ok(value.distinctSockets>0);
  }
}
export function createConnectionAccounting(){
  const seen=new Map(connectionLegs.map(leg=>[leg,new WeakSet()]));
  let window;
  return {
    observe(leg,socket){
      const history=seen.get(leg);
      assert.ok(history&&socket&&typeof socket==="object","Invalid socket observation");
      const fresh=!history.has(socket);
      history.add(socket);
      if(!window)return;
      const entry=window.get(leg);
      entry.assignments++;
      if(!entry.sockets.has(socket)){entry.sockets.add(socket);entry.distinctSockets++;}
      if(fresh)entry.firstSeenSockets++;
      else entry.reusedAssignments++;
    },
    begin(){
      assert.equal(window,undefined,"Connection window already active");
      window=new Map(connectionLegs.map(leg=>[leg,{assignments:0,distinctSockets:0,firstSeenSockets:0,reusedAssignments:0,sockets:new WeakSet()}]));
    },
    finish(requests){
      assert.ok(window,"Connection window not active");
      const result=Object.fromEntries([...window].map(([leg,{sockets,...counts}])=>[leg,counts]));
      window=undefined;
      validateConnectionMetrics(result,requests);
      return result;
    },
  };
}

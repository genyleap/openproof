import test from "node:test";
import assert from "node:assert/strict";
import {createMixedReadValidator} from "../../scripts/ci/mixed-read-correctness.mjs";
const check=createMixedReadValidator({readiness:{status:"ready",duration_ms:1},
  discovery:{issuer:"fixture",token_endpoint:"fixture/token"},
  jwks:{keys:[{kid:"test"}]},userinfo:{sub:"owner",email:"fixture@example.invalid"},
  protectedProxy:{upstream:true,path:"/api/ping"},introspection:{active:true,sub:"owner"}});
const response=(body,status=200)=>({status,body:JSON.stringify(body)});
test("validates stable response semantics, not JSON key order or readiness timing",()=>{
  check("discovery",response({token_endpoint:"fixture/token",issuer:"fixture"}));
  check("readiness",response({status:"ready",duration_ms:2}));
  check("userinfo",response({sub:"owner",email:"fixture@example.invalid"}));
});
test("rejects 200 responses with different owner, key, scope or health",()=>{
  for(const [name,body] of [
    ["userinfo",{sub:"other"}],["jwks",{keys:[]}],["introspection",{active:false}],
    ["protected-proxy",{upstream:true,path:"/wrong"}],["readiness",{status:"down"}],
    ["discovery",{issuer:"wrong"}],
  ]) assert.throws(()=>check(name,response(body)),/contract mismatch/);
});
test("does not leak unexpected raw response content into errors",()=>{
  const secret="secret-fixture-value";
  for(const run of [
    ()=>check("userinfo",{status:200,body:secret}),
    ()=>check("userinfo",response({sub:secret})),
    ()=>check(secret,response({})),
    ()=>check("userinfo",response({sub:"owner"},401)),
  ]) assert.throws(run,e=>!e.message.includes(secret));
});

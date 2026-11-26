import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
const root=path.resolve(import.meta.dirname,"..");
const read=file=>fs.readFileSync(path.join(root,file),"utf8");
test("native replay store consumes global keys atomically with bounded cleanup",()=>{
  const sql=read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
  const start=sql.indexOf("CoroutinePostgresCanonicalFinalizer::consumeSenderReplayAsync(");
  const body=sql.slice(start,sql.indexOf("CoroutinePostgresCanonicalFinalizer::authorizeHandoffOwnerAsync(",start));
  for (const table of ["oauth_dpop_replays","oauth_mtls_forwarding_replays"]) assert.ok(body.includes(table));
  assert.equal([...body.matchAll(/ON CONFLICT/g)].length,2);
  assert.equal([...body.matchAll(/WHERE r.expires_at_ms<=\$4 RETURNING 1/g)].length,2);
  assert.equal([...body.matchAll(/LIMIT 64 FOR UPDATE SKIP LOCKED/g)].length,2);
  assert.match(body,/expiresAt<=now/);
  assert.match(body,/if \(result.rows.empty\(\)\)/);
  assert.doesNotMatch(body,/m_impl->organization|PQexec\(|std::mutex/);
});
test("native sender verification shares cryptography and never invokes legacy replay storage",()=>{
  const source=read("src/oauth/http/sender.cpp");
  const prepare=source.slice(source.indexOf("SenderProofVerifier::prepareDpop("),
    source.indexOf("SenderProofVerifier::verifyDpop("));
  for (const guard of ["verifyRs256Jwk","expectedHtu(request)","expectedAth","replayWindow",
    "constantTimeEquals","assertedAt + maximumAge <= now"]) assert.ok(prepare.includes(guard),guard);
  const native=source.slice(source.indexOf("SenderProofVerifier::verifyAsync("),
    source.indexOf("SenderProofVerifier::tokenEndpointConstraint("));
  assert.match(native,/prepareDpop\(request,&accessToken\):prepareMtlsForwarding\(request\)/);
  assert.match(native,/prepared->binding.value\(\)!=constraint.value\(\)/);
  assert.match(native,/co_return co_await consume\(/);
  assert.doesNotMatch(native,/m_dpop->consume\(|m_mtlsReplays->|verifyDpop\(/);
});

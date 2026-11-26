import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {cppExecutableText} from "./cpp-lexical-scan.mjs";
const root=path.resolve(import.meta.dirname,"..");
const read=file=>fs.readFileSync(path.join(root,file),"utf8");
const app=read("apps/opp/main.cpp");
const http=read("src/evidence/http/coroutine_evidence_http.cpp");
const source=read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
const sql=source.slice(source.indexOf("CoroutinePostgresCanonicalFinalizer::evidenceAccountAsync("));
test("native evidence dispatch owns challenge, verification, listing and trust without legacy SQL",()=>{
  for(const route of ["/evidence","/trust","/evidence/challenge","/evidence/verify"])
    assert.ok(http.includes('r.path()=="'+route+'"'),route);
  assert.match(app,/nativePaths.emplace_back\("\/evidence"\)/);
  assert.match(app,/nativePaths.emplace_back\("\/trust"\)/);
  assert.match(app,/strictNativePrefixes.emplace_back\("\/evidence\/"\)/);
  assert.match(app,/reader->evidenceAccountAsync/);
  assert.doesNotMatch(app,/\b(?:PostgresEvidenceChallengeStore|EvidenceService|ChallengeService|TrustEngine|evidenceHttp::Api)\s+\w+\s*\{/);
  assert.match(http,/co_await m_authenticate/);
  assert.match(http,/trust::assessEvidence/);
  const ordered=["busy.compare_exchange_strong","Op::Consume","co_await asio::co_spawn(m_impl->pool",
    "proofWorker(std::move(permit)","if(!verified)","Op::Persist"];
  let prev=http.indexOf("CoroutineEvidenceAdapter::handleAsync(");
  for(const term of ordered){
    const index=http.indexOf(term,prev+1);
    assert.ok(index>prev,term);prev=index;
  }
  assert.match(http,/pool\(1U\)/);
  assert.match(http,/~Permit\(\)\{if\(state\) state->busy.store\(false/);
  assert.doesNotMatch(cppExecutableText(http),/m_fallback->handle\(|PQexec/);
});
test("evidence SQL enforces active session, bounded durable challenges, one-time consumption and atomic batch insertion",()=>{
  for(const term of ["record.identity()!=actor","record.provider()!=command.provider",
    "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
    "pg_advisory_xact_lock(hashtextextended($1::text, 684271993))",
    "i.id=$1 AND o.id=$2 AND s.id=$3 AND s.state=0 AND i.status=0 AND o.state=0",
    "FOR SHARE OF i,o,s","ORDER BY verified_at_ms,id LIMIT 257","rows.rows.size()>256U",
    "LIMIT 128 FOR UPDATE SKIP LOCKED","active.rows.size()>=32U",
    "INSERT INTO openproof.evidence_verification_challenges",
    "WHERE digest=$1 AND identity_id=$2 AND provider=$3 AND consumed_at_ms IS NULL",
    "AND issued_at_ms<=$4 AND expires_at_ms>$4 RETURNING digest",
    "count.rows.size()+command.records.size()>256U","INSERT INTO openproof.evidence(",
    "ON CONFLICT DO NOTHING RETURNING id",'execute("COMMIT",{})'])
    assert.ok(sql.includes(term),term);
  assert.ok(sql.indexOf("FOR SHARE OF i,o,s")<sql.indexOf("INSERT INTO openproof.evidence_verification_challenges"));
  assert.ok(sql.indexOf("INSERT INTO openproof.evidence(")<sql.lastIndexOf('execute("COMMIT",{})'));
  assert.doesNotMatch(cppExecutableText(sql),/PQexec|PQconnectdb/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/NativeEvidenceChallengesAndBatchesAreSessionBound/);
});

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {cppExecutableText} from "./cpp-lexical-scan.mjs";
const root=path.resolve(import.meta.dirname,"..");
const read=file=>fs.readFileSync(path.join(root,file),"utf8");
const app=read("apps/opp/main.cpp");
const http=read("src/authentication/http/coroutine_passkey_http.cpp");
const source=read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
const sql=source.slice(source.indexOf("CoroutinePostgresCanonicalFinalizer::readPasskeyAccountAsync("));
test("passkey list and registration options use native first-party authentication without changing completion dispatch",()=>{
  assert.match(http,/r.path\(\)=="\/account\/passkeys" && r.method\(\)==Method::Get/);
  assert.match(http,/r.path\(\)=="\/account\/passkeys\/options" && r.method\(\)==Method::Post/);
  assert.match(app,/nativeMethods.emplace_back\("\/account\/passkeys",gateway::HttpMethod::Get\)/);
  assert.match(app,/nativePaths.emplace_back\("\/account\/passkeys\/options"\)/);
  assert.doesNotMatch(app,/nativePaths.emplace_back\("\/account\/passkeys"\)/);
  assert.match(app,/reader->readPasskeyAccountAsync/);
  assert.match(http,/starts_with\("DPoP "\)/);
  assert.match(http,/origin && \*origin!=m_config->origin\(\)/);
  const ordered=["gateway::takeSessionCredential(r)","scrub(r);","co_await m_authenticate",
    "co_await m_read","if (!credentials)","pk::registrationOptions","__Host-openproof-passkey-registration="];
  let previous=-1;
  for (const term of ordered) {
    const index=http.indexOf(term,previous+1);
    assert.ok(index>previous,term); previous=index;
  }
  assert.match(http,/Secure; HttpOnly; SameSite=Strict/);
  assert.doesNotMatch(cppExecutableText(http),/m_fallback->handle\(|PQexec/);
});
test("native passkey metadata and challenge transaction enforce tenant session, expiry and admission bounds",()=>{
  for(const term of ["ceremony->identity!=actor","ceremony->expiresAt<=now",
    "pg_advisory_xact_lock(hashtextextended($1::text, 684271993))",
    "i.id=$1 AND o.id=$2 AND s.id=$3 AND s.state=0","i.status=0 AND i.kind=0 AND o.state=0",
    "FOR SHARE OF i,o,s","SELECT credential_id,sign_count,created_at_ms,last_used_at_ms",
    "LIMIT 257","rows.rows.size()>256U","LIMIT 128 FOR UPDATE SKIP LOCKED",
    "consumed_at_ms IS NULL LIMIT 33","active.rows.size()>=32U",
    "INSERT INTO openproof.passkey_registration_ceremonies","ON CONFLICT DO NOTHING RETURNING id"])
    assert.ok(sql.includes(term),term);
  assert.ok(sql.indexOf("FOR SHARE OF i,o,s")<sql.indexOf("INSERT INTO openproof.passkey_registration_ceremonies"));
  assert.ok(sql.indexOf("INSERT INTO openproof.passkey_registration_ceremonies")<sql.lastIndexOf('execute("COMMIT",{})'));
  assert.doesNotMatch(cppExecutableText(sql),/public_key_x|public_key_y|PQexec|PQconnectdb/);
  const provider=read("src/providers/passkey/passkey.cpp");
  const renderer=provider.slice(provider.indexOf("foundation::Result<RegistrationStart> registrationOptions("),
    provider.indexOf("foundation::Status PasskeyService::completeRegistration("));
  assert.match(renderer,/challengeFor\(config, "register", id\)/);
  assert.match(renderer,/config.relyingPartyId\(\)/);
  assert.match(renderer,/"userVerification", "required"/);
  assert.match(renderer,/excludedCredentialIds/);
  assert.match(read("tests/storage/postgres_async_canonical_test.cpp"),/NativePasskeyListingAndRegistrationChallengeAreSessionBound/);
});

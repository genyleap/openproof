import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
const root=path.resolve(import.meta.dirname,"..");
const read=file=>fs.readFileSync(path.join(root,file),"utf8");
const app=read("apps/opp/main.cpp");
const http=read("src/account/http/coroutine_session_http.cpp");
const delivery=read("src/account/delivery/delivery_impl.cppm");
test("contact issuance is native in account-enabled runtime with durable reservation and compensation",()=>{
  assert.match(app,/createCoroutineWebhookVerificationDelivery\(/);
  assert.match(app,/CoroutineVerificationChallengeStore contactStore\{/);
  assert.match(app,/CoroutineContactVerificationIssuer contactIssuer\{/);
  assert.match(app,/contactStore.reserveAndReplaceAsync\(/);
  assert.match(app,/contactStore.discardAsync\(/);
  assert.match(app,/nativeContactIssuer=&contactIssuer;/);
  assert.match(app,/CoroutineContactVerificationAdapter>\(/);
  for (const route of ["/account/email/change","/account/phone"])
    assert.ok(app.slice(app.indexOf("if (!nativeContactIssuer || !nativeSignup"),app.indexOf("nativePaths.emplace_back(path);",app.indexOf("if (!nativeContactIssuer || !nativeSignup"))).includes('"'+route+'"'));
  const native=http.slice(http.indexOf("CoroutineContactVerificationAdapter::handleAsync("));
  assert.match(native,/co_await m_authenticate\(/);
  assert.match(native,/co_await m_issue\(actor->identity\(\)/);
  assert.match(native,/VerificationPurpose::ChangeEmail:VerificationPurpose::VerifyPhone/);
  assert.match(native,/jsonResponse\(202,json::object\{\{"accepted",true\}\}\)/);
  assert.doesNotMatch(native,/m_fallback->handle\(|m_accounts->|->deliver\(/);
});
test("native delivery owns the outgoing request and compensates only its own challenge",()=>{
  const issuer=delivery.slice(delivery.indexOf("CoroutineContactVerificationIssuer::issueAsync("));
  assert.match(delivery,/co_await m_transport->sendAsync\(/);
  assert.ok(issuer.indexOf("co_await persist(")<issuer.indexOf("m_delivery->deliverAsync("));
  assert.match(issuer,/co_await m_discard\(std::move\(id\), std::move\(owner\), purpose\)/);
  assert.match(issuer,/dispatch.reset\(\)/);
});

test("public email issuance uses native eligibility and rechecks owner before replacing a challenge",()=>{
  const store=read("src/storage/postgres/coroutine_verification_challenge_store.cpp");
  assert.match(store,/r.verification_id IS NULL AND i.status IN \(0,3\)/);
  assert.match(store,/i.organization_id=\$4 AND o.state=0/);
  assert.match(store,/e.external_subject=\$2 OR e.identity_id=i.id/);
  assert.match(store,/publicOwnerSql\(challenge.purpose\(\),true\)/);
  assert.match(store,/if \(!exactRow\(eligible,owner\)\)/);
  const issuer=delivery.slice(delivery.indexOf("CoroutineContactVerificationIssuer::issuePublicEmailAsync("),
    delivery.indexOf("CoroutineContactVerificationIssuer::deliverPrepared("));
  assert.match(issuer,/if \(!owner \|\| !owner->has_value\(\)\) co_return foundation::ok\(\)/);
  assert.match(issuer,/co_await deliverPrepared\(/);
  assert.match(app,/contactIssuer.configurePublicEmail\(/);
  for (const route of ["/account/email/resend","/account/password/forgot"])
    assert.ok(app.slice(app.indexOf("if (!nativeContactIssuer || !nativeSignup"),app.indexOf("nativePaths.emplace_back(path);",app.indexOf("if (!nativeContactIssuer || !nativeSignup"))).includes('"'+route+'"'));
});

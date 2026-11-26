#!/usr/bin/env node
// Runtime composition contract for the experimental native Web3 login
// slice. These checks are NOT a replacement for compiled C++/HTTP/SQL E2E.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const read = file => fs.readFileSync(path.join(root, file), "utf8");
const app = read("apps/opp/main.cpp");
const web3 = read("src/authentication/http/web3.cpp");
const web3Api = read("src/authentication/http/web3.cppm");

test("authenticated runtime requires native Web3 before database operations", () => {
  assert.match(app, /environment\.get\("OPENPROOF_EXPERIMENTAL_NATIVE_WEB3_LOGIN"\)/);
  assert.match(app, /nativeWeb3Flag && \*nativeWeb3Flag != "0"/);
  assert.match(app, /nativeWeb3Flag && \*nativeWeb3Flag == "1"/);
  assert.match(app, /nativeWeb3Enabled && !platform\.auth\(\)\.enabled\(\)/);
  assert.match(app,/platform\.auth\(\)\.enabled\(\) && nativeWeb3Flag && \*nativeWeb3Flag == "0"/);
  assert.match(app,/const bool nativeWeb3Enabled = platform\.auth\(\)\.enabled\(\)/);
  const start = app.indexOf("OPENPROOF_EXPERIMENTAL_NATIVE_WEB3_LOGIN");
  const migrator = app.indexOf("postgres::Migrator migrator{*pool.value()}", start);
  assert.ok(start >= 0 && migrator > start);
});

test("Web3 login gets async transaction, canonical and session services without LDAP opt-in", () => {
  assert.match(app, /if \(nativeLdapEnabled \|\| nativeAccountEnabled \|\| nativeWeb3Enabled\s*\|\|\s*nativeAuthSessionEnabled\s*\|\|\s*nativeFederatedStartEnabled\s*\|\|\s*nativeProtectedGatewayEnabled\s*\|\|\s*nativeLocalEnabled\)\s*nativeSessionSecret\.emplace\(sessionSecret->clone\(\)\)/);
  assert.match(app, /if \(nativeLdapEnabled \|\| nativeAccountEnabled \|\| nativeWeb3Enabled\s*\|\|\s*nativeAuthSessionEnabled\s*\|\|\s*nativeFederatedStartEnabled\s*\|\|\s*nativeProtectedGatewayEnabled\s*\|\|\s*nativeLocalEnabled\) \{/);
  assert.match(app, /if \(nativeLdapEnabled \|\| nativeWeb3Enabled \|\| nativeFederatedStartEnabled \|\| nativeLocalEnabled\) \{/);
  const runtime = app.slice(app.indexOf("nativeIo = std::make_unique<boost::asio::thread_pool>"),
    app.indexOf("std::optional<passkey::PasskeyService>"));
  assert.match(runtime, /CoroutinePostgresSessionRepository/);
  assert.match(runtime, /CoroutinePostgresSessionService/);
  assert.match(runtime, /CoroutinePostgresAuthenticationTransactionStore/);
  assert.match(runtime, /CoroutinePostgresCanonicalFinalizer/);
  assert.match(runtime, /nativeCanonical\.get\(\)/);
  assert.match(app, /authHttp::Web3AuthenticationHttpApi nativeWeb3Api\{\s*\*nativeAuthentication, providers, sessions, limiter\.value\(\),\s*enterpriseApi, nullptr, nativeSessions\.get\(\),\s*authenticateNativeWeb3\}/);
  assert.match(app, /runWithEvidence\(enterpriseApi, nativeWeb3Api\)/);
  assert.match(app, /runWithEvidence\(enterpriseApi, enterpriseApi\)/);
});

test("native route overlay has exact opt-in path gates, never implicit LDAP or Account activation", () => {
  const start = app.indexOf("std::vector<std::string> nativePaths;");
  const end = app.indexOf("gatewayHttp::CoroutineRouteOverlay nativeRoutes{", start);
  assert.ok(start >= 0 && end > start);
  const routing = app.slice(start,end);
  const ldapStart = routing.indexOf("if (nativeLdapEnabled)");
  const web3Start = routing.indexOf("if (nativeWeb3Enabled)");
  const accountStart = routing.indexOf("if (platform.account().enabled() && nativeAccountEnabled && nativeSessions)");
  assert.ok(ldapStart >= 0 && web3Start > ldapStart && accountStart > web3Start);
  const ldap = routing.slice(ldapStart,web3Start);
  const web3Routes = routing.slice(web3Start,accountStart);
  const account = routing.slice(accountStart);
  assert.match(ldap, /nativePaths\.emplace_back\("\/auth\/ldap\/start"\)/);
  assert.match(ldap, /nativePaths\.emplace_back\("\/auth\/ldap\/complete"\)/);
  assert.match(web3Routes, /nativePaths\.emplace_back\("\/auth\/web3\/start"\)/);
  assert.match(web3Routes, /nativePaths\.emplace_back\("\/auth\/web3\/complete"\)/);
  assert.match(web3Routes,/nativePaths\.emplace_back\("\/auth\/web3\/handoff"\)/);
  assert.match(web3Routes,/nativePaths\.emplace_back\("\/auth\/web3\/handoff\/redeem"\)/);
  assert.doesNotMatch(web3Routes,/\/account\/connections/);
  assert.match(account, /nativePaths\.emplace_back\("\/account\/sessions"\)/);
  assert.match(account, /nativePaths\.emplace_back\("\/account\/sessions\/revoke"\)/);
});

test("native Web3 login and mobile handoff await native verification and session issuance", () => {
  assert.match(web3Api,/session::CoroutineSessionIssuer\* asyncSessions = nullptr/);
  const start = web3.slice(web3.indexOf("Web3AuthenticationHttpApi::nativeEnabledFor("));
  const cap = start.slice(0,start.indexOf("Web3AuthenticationHttpApi::handleAsync("));
  assert.match(cap,/path == "\/auth\/web3\/start" \|\| path == "\/auth\/web3\/complete"/);
  assert.match(cap,/m_asyncSessions != nullptr/);
  assert.match(cap,/m_authentication->nativeCanonicalCompletionEnabled\(\)/);
  assert.match(cap,/path\.starts_with\("\/auth\/web3\/"\)/);
  const begin = start.slice(start.indexOf("Web3AuthenticationHttpApi::startAsync("),
    start.indexOf("Web3AuthenticationHttpApi::completeAsync("));
  const complete = start.slice(start.indexOf("Web3AuthenticationHttpApi::completeAsync("));
  assert.match(begin,/co_await m_authentication->beginAsync\(/);
  assert.match(begin,/if \(handoffTicket\) publisherTicket.emplace/);
  assert.match(complete,/co_await m_authentication->completeAsync\(/);
  assert.match(complete,/co_await m_asyncSessions->issueAsync\(/);
  assert.match(complete,/if \(authenticationHandoff\)/);
  assert.match(complete,/co_await m_authentication->publishBrowserAuthenticationHandoffAsync\(/);
  const native=web3.slice(web3.indexOf("Web3AuthenticationHttpApi::handleAsync("));
  assert.match(native,/co_await m_authentication->issueBrowserAuthenticationHandoffAsync\(/);
  assert.match(native,/co_await m_authentication->redeemBrowserAuthenticationHandoffAsync\(/);
  assert.doesNotMatch(native,/m_authentication->(?:issue|publish|redeem)BrowserAuthenticationHandoff\(/);
  assert.doesNotMatch(complete,/m_sessions->issue\(/);
});

test("native wallet handoff owns the two one-time tickets and revalidates ownership without mutation",()=>{
  const service=read("src/authentication/service.cpp");
  const begin=service.indexOf("AuthenticationService::issueBrowserAuthenticationHandoffAsync(");
  assert.ok(begin>=0);
  const native=service.slice(begin);
  assert.match(native,/publisherSecretValue/);
  assert.match(native,/redeemSecretValue/);
  assert.equal([...native.matchAll(/co_await nativeTransactions->beginAsync\(/g)].length,2);
  assert.equal([...native.matchAll(/co_await nativeTransactions->consumeAsync\(/g)].length,2);
  assert.equal([...native.matchAll(/co_await m_asyncCanonical->authorizeHandoffOwnerAsync\(/g)].length,2);
  assert.doesNotMatch(native,/m_transactions\.(?:begin|consume)\(|m_identities\.ownerOf\(|requireActiveIdentity\(/);
  const sql=read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
  const owner=sql.slice(sql.indexOf("CoroutinePostgresCanonicalFinalizer::authorizeHandoffOwnerAsync("),
    sql.indexOf("CoroutinePostgresCanonicalFinalizer::updatePresentationAsync("));
  assert.match(owner,/i.id=\$1 AND e.provider=\$2 AND e.external_subject=\$3/);
  assert.match(owner,/i.organization_id=\$4 AND i.status=0 AND o.state=0/);
  assert.doesNotMatch(owner,/\b(?:UPDATE|INSERT|DELETE)\b/);
});

test("native Web3 presentation is owner-bound and cannot alter proof or contact claims",()=>{
  const complete=web3.slice(web3.indexOf("Web3AuthenticationHttpApi::completeAsync("));
  const proof=complete.indexOf("co_await m_authentication->completeAsync(");
  const update=complete.indexOf("co_await m_authentication->updateConnectionPresentationAsync(");
  assert.ok(proof>=0 && update>proof);
  assert.match(complete,/updateConnectionPresentationAsync\(\s*verified->identity\(\)/);
  const sql=read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
  const body=sql.slice(sql.indexOf("CoroutinePostgresCanonicalFinalizer::updatePresentationAsync("),
    sql.indexOf("CoroutinePostgresCanonicalFinalizer::finishConnectionAsync("));
  assert.match(body,/activeTarget\(/);
  assert.match(body,/WHERE identity_id=\$1 AND provider=\$2 AND external_subject=\$3 RETURNING identity_id/);
  assert.match(body,/ProfilePurpose::Connection/);
  assert.doesNotMatch(body,/ClaimName::(?:Email|PhoneNumber)|INSERT INTO openproof.external_identities/);
});

test("native wallet connection uses native ownership and never issues a login grant",()=>{
  const begin=web3.slice(web3.indexOf("Web3AuthenticationHttpApi::startAsync("),
    web3.indexOf("Web3AuthenticationHttpApi::completeAsync("));
  const complete=web3.slice(web3.indexOf("Web3AuthenticationHttpApi::completeAsync("));
  assert.match(begin,/co_await m_authentication->consumeBrowserConnectionHandoffAsync\(/);
  assert.match(begin,/co_await m_authentication->beginConnectionAsync\(/);
  assert.match(begin,/co_await m_authenticate\(std::move\(\*actorToken\)\)/);
  const link=complete.slice(complete.indexOf("if (connection) {"),
    complete.indexOf("co_await m_authentication->completeAsync("));
  assert.match(link,/co_await m_authentication->completeConnectionAsync\(/);
  assert.match(link,/co_return response;/);
  assert.doesNotMatch(link,/issueAsync\(/);
  assert.match(app,/nativePaths.emplace_back\("\/account\/connections\/web3\/start"\)/);
  assert.match(app,/nativePaths.emplace_back\("\/account\/connections\/web3\/handoff"\)/);
  assert.match(app,/nativePaths.emplace_back\("\/account\/connections\/web3\/complete"\)/);
  const service=read("src/authentication/service.cpp");
  const owner=service.slice(service.indexOf("AuthenticationService::completeConnectionAsync("),
    service.indexOf("AuthenticationService::finishConnection("));
  assert.match(owner,/finalizer->updatePresentationAsync\(\s*\*exchange->connectionTarget,/);
});

test("delegated account authorization uses one native SQL snapshot and preserves scope constraints",()=>{
  const sql=read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
  const body=sql.slice(sql.indexOf("CoroutinePostgresCanonicalFinalizer::authorizeDelegatedAccountAsync("),
    sql.indexOf("CoroutinePostgresCanonicalFinalizer::consumeSenderReplayAsync("));
  for (const required of ["t.state=0","t.expires_at_ms>$2","f.revoked_at_ms IS NULL",
    "f.sender_constraint_kind,f.sender_constraint_value",
    "c.status=0","a.status=0","i.status=0","o.state=0","i.organization_id=$3",
    "a.organization_id=$3",'access->permits("account")',"access->senderConstraint()",
    "AuthenticatedSession::fromDelegatedAccess"])
    assert.ok(body.includes(required),required);
  assert.doesNotMatch(body,/\b(?:INSERT|UPDATE|DELETE)\b/);
  assert.match(app,/security::hmacSha256\(\*nativeWeb3DelegatedKey,credential.expose\(\)\)/);
  assert.match(app,/nativeCanonical->authorizeDelegatedAccountAsync\(/);
  assert.match(app,/openproof\/oauth-token-key\/v1/);
});

test("native delegated context is snapshot-consistent, bounded and preserves sender proof requirement",()=>{
  const source=read("src/storage/postgres/coroutine_canonical_finalizer.cpp");
  const start=source.indexOf("CoroutinePostgresCanonicalFinalizer::readDelegatedAccessAsync(");
  const body=source.slice(start,source.indexOf("CoroutinePostgresCanonicalFinalizer::consumeSenderReplayAsync(",start));
  assert.equal([...body.matchAll(/co_await lease.connection\(\).query\(/g)].length,1);
  assert.match(body,/LEFT JOIN LATERAL/);
  assert.match(body,/UNION ALL/);
  assert.match(body,/oauth_token_family_audiences/);
  assert.match(body,/LIMIT 257/);
  assert.match(body,/maximumGrants=256U/);
  assert.match(body,/result.rows.size\(\)>maximumGrants/);
  assert.match(body,/std::move\(scopes\),std::move\(audiences\),std::move\(sender\)/);
  const account=source.slice(source.indexOf("CoroutinePostgresCanonicalFinalizer::authorizeDelegatedAccountAsync("),start);
  assert.match(account,/if \(access->senderConstraint\(\)\)/);
  assert.match(account,/if \(!access->permits\("account"\)\)/);
});

test("native account adapter preserves explicitly downstream Web3 ceremony capabilities",()=>{
  const source=read("src/account/http/coroutine_session_http.cpp");
  const body=source.slice(source.indexOf("CoroutineAccountSessionAdapter::nativeEnabledFor("),
    source.indexOf("CoroutineAccountSessionAdapter::handle("));
  for (const route of ["/account/connections/web3/start","/account/connections/web3/complete",
    "/account/connections/web3/handoff","/account/connections/start","/account/connections/handoff"])
    assert.ok(body.includes('request.path()=="'+route+'"'));
  assert.match(body,/return m_asyncFallback->nativeEnabledFor\(request\)/);
});

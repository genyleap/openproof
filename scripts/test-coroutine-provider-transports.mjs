#!/usr/bin/env node
// Source-level regression for deprecated synchronous OAuth/RPC compatibility.
// Runtime C++ builds, live TLS tests and the complete migration gate remain
// separate acceptance requirements. This test must never approve a release.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const cases = [
  {name:"GitHub OAuth",file:"src/providers/github/github.cpp",retired:true,legacy:"httpsRequest",native:"httpsRequestAsync",client:"AsyncHttpsClient",limit:"kMaximumResponseBytes"},
  {name:"OIDC federation",file:"src/providers/oidc/oidc.cpp",retired:true,legacy:"httpsRequest",native:"httpsRequestAsync",client:"AsyncHttpsClient",limit:"kMaximumResponseBytes"},
  {name:"X OAuth 1.0a",file:"src/providers/x/x.cpp",retired:true,legacy:"httpsRequest",native:"httpsRequestAsync",client:"AsyncHttpsClient",limit:"kMaximumResponseBytes"},
  {name:"Web3 RPC",file:"src/providers/web3/web3.cpp",retired:true,legacy:"rpc",native:"rpcAsync",client:"NativeRpcClient",limit:"kMaximumRpcResponse"}
];
const forbidden = [
  /\b(?:http|beastHttp)::(?:read|write)\s*\(/,
  /\bresolver\.resolve\s*\(/,
  /\bstream\.(?:connect|handshake)\s*\(/
];
for (const item of cases) {
  test(item.name+(item.retired?" has only native remote exchanges":" legacy I/O is delegated to native coroutine HTTPS"),()=>{
    const source = fs.readFileSync(path.join(root,item.file),"utf8");
    if (item.name==="Web3 RPC") {
      assert.doesNotMatch(source,/\b(?:io\.run|rpc|rpcString|completion\.get)\s*\(/);
      assert.equal([...source.matchAll(/co_await rpcStringAsync\(/g)].length,6);
      assert.match(source,/co_await client.exchange\(/);
      assert.match(source,/co_await universalSignatureValidAsync\(/);
      assert.match(source,/co_await native->verifySignatureAsync\(/);
      assert.match(source,/co_await native->authorizeSignerAsync\(/);
      for (const pattern of forbidden) assert.doesNotMatch(source,pattern);
      return;
    }
    if (item.retired) {
      const type=item.name==="GitHub OAuth"?"GitHubAuthenticationProvider":
        item.name==="OIDC federation"?"OidcAuthenticationProvider":"XAuthenticationProvider";
      const github=type.startsWith("GitHub");
      const sync=source.slice(source.indexOf(type+(github?"::completeAuthentication(":"::beginAuthentication(")),
        source.indexOf(type+"::beginAuthenticationAsync("));
      assert.equal([...sync.matchAll(/return foundation::fail\(foundation::ErrorCode::Unavailable,/g)].length,
        github?1:2);
      assert.doesNotMatch(source,/\b(?:io\.run|httpsRequest|completion\.get)\s*\(/);
      assert.equal([...source.matchAll(/co_await httpsRequestAsync\(/g)].length,
        github?3:type.startsWith("Oidc")?4:2);
      assert.match(source,/co_await\s+client\.exchange\s*\(/);
      for (const pattern of forbidden) assert.doesNotMatch(source,pattern);
      return;
    }
    const beginning = source.indexOf("foundation::Result<",source.indexOf("struct ",source.indexOf("namespace {")));
    assert.ok(beginning>=0);
    const legacyStart = source.indexOf(" "+item.legacy+"(",source.indexOf("namespace {"));
    const nativeStart = source.indexOf(
      "[[nodiscard]] asio::awaitable<foundation::Result",legacyStart+1);
    assert.ok(legacyStart>=0 && nativeStart>legacyStart,
      "legacy API must precede native I/O implementation");
    const legacy = source.slice(legacyStart,nativeStart);
    assert.match(legacy,/asio::io_context\s+io/);
    assert.match(legacy,/asio::co_spawn\s*\(/);
    assert.ok(legacy.includes(item.native+"("));
    assert.ok(legacy.includes(item.client));
    assert.ok(legacy.includes(item.limit));
    assert.match(legacy,/io\.run\s*\(\)/);
    assert.match(legacy,/completion\.get\s*\(\)/);
    assert.match(legacy,/std::chrono::seconds\{10\}/);
    for (const pattern of forbidden) {
      assert.doesNotMatch(source,pattern);
    }
    const native = source.slice(nativeStart);
    assert.match(native,/co_await\s+client\.exchange\s*\(/,
      "native transport must use the bounded shared HTTPS implementation");
  });
}

test("runtime delegated federation initiation issues a native handoff instead of blocking provider I/O",()=>{
  const source=fs.readFileSync(path.join(root,"src/authentication/http/federated.cpp"),"utf8");
  const entry=source.slice(source.indexOf("FederatedAuthenticationHttpApi::handle("),source.indexOf("FederatedAuthenticationHttpApi::connectionComplete("));
  assert.match(entry,/m_nativeRedirectsRequired/);
  assert.match(entry,/request.path\(\)=="\/account\/connections\/handoff"/);
  assert.match(entry,/request.path\(\)=="\/account\/connections\/start"/);
  assert.match(entry,/ErrorCode::Unavailable/);
  const native=fs.readFileSync(path.join(root,"src/authentication/http/coroutine_federated_start_http.cpp"),"utf8");
  assert.match(native,/co_await m_authentication->issueBrowserConnectionHandoffAsync\(/);
  assert.match(native,/\/account\/connections\/handoff\?ticket=/);
  assert.doesNotMatch(native,/m_authentication->(?:beginConnection|beginAuthentication|issueBrowserConnectionHandoff)\(/);
  const app=fs.readFileSync(path.join(root,"apps/opp/main.cpp"),"utf8");
  assert.match(app,/authApi, nullptr, true\}/);
  assert.match(app,/authApi, &tokenService, true\}/);
});

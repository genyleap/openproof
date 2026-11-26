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
  {name:"OIDC federation",file:"src/providers/oidc/oidc.cpp",legacy:"httpsRequest",native:"httpsRequestAsync",client:"AsyncHttpsClient",limit:"kMaximumResponseBytes"},
  {name:"X OAuth 1.0a",file:"src/providers/x/x.cpp",legacy:"httpsRequest",native:"httpsRequestAsync",client:"AsyncHttpsClient",limit:"kMaximumResponseBytes"},
  {name:"Web3 RPC",file:"src/providers/web3/web3.cpp",legacy:"rpc",native:"rpcAsync",client:"NativeRpcClient",limit:"kMaximumRpcResponse"}
];
const forbidden = [
  /\b(?:http|beastHttp)::(?:read|write)\s*\(/,
  /\bresolver\.resolve\s*\(/,
  /\bstream\.(?:connect|handshake)\s*\(/
];
for (const item of cases) {
  test(item.name+(item.retired?" has only native remote exchanges":" legacy I/O is delegated to native coroutine HTTPS"),()=>{
    const source = fs.readFileSync(path.join(root,item.file),"utf8");
    if (item.retired) {
      const sync=source.slice(source.indexOf("GitHubAuthenticationProvider::completeAuthentication("),
        source.indexOf("GitHubAuthenticationProvider::beginAuthenticationAsync("));
      assert.match(sync,/return foundation::fail\(foundation::ErrorCode::Unavailable,/);
      assert.doesNotMatch(source,/\b(?:io\.run|httpsRequest|completion\.get)\s*\(/);
      const native=source.slice(source.indexOf("GitHubAuthenticationProvider::completeAuthenticationAsync("));
      assert.equal([...native.matchAll(/co_await httpsRequestAsync\(/g)].length,3);
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

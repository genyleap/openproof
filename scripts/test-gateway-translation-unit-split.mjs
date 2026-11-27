#!/usr/bin/env node
// Safe decomposition of one GCC16 C++26 named-module implementation into
// listener, TLS proxy and coroutine middleware. Source-level validation only:
// the compilation target and loopback E2E still require real C++ tests.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";

const root=path.resolve(import.meta.dirname,"..");
const read=p=>fs.readFileSync(path.join(root,p),"utf8");
const server=read("src/gateway/http.cpp");
const proxy=read("src/gateway/http_proxy.cpp");
const middleware=read("src/gateway/http_coroutine.cpp");
const cmake=read("src/gateway/CMakeLists.txt");
const scanner=read("scripts/verify-coroutine-coverage.mjs");

test("each implementation is a named module with distinct definitions",()=>{
  for(const source of [server,proxy,middleware]){
    assert.match(source,/^module;/);
    assert.match(source,/\nmodule openproof\.gateway\.http;/);
    assert.match(source,/namespace openproof::gateway::http \{/);
  }
  assert.match(server,/BeastHttpServer::Implementation/);
  assert.match(server,/ServerConfig::create\(/);
  assert.doesNotMatch(server,/BeastProxyTransport::Implementation/);
  assert.match(proxy,/BeastProxyTransport::Implementation/);
  assert.match(proxy,/ProxyConfig::create\(/);
  assert.doesNotMatch(proxy,/BeastHttpServer::Implementation/);
  assert.match(middleware,/CoroutineRouteOverlay::handleAsync\(/);
  assert.match(middleware,/CoroutineMetricsAdapter::handleAsync\(/);
  assert.match(middleware,/CoroutineGatewayAdapter::handleAsync\(/);
});

test("TLS includes are isolated from listener and nonnetwork middleware",()=>{
  for(const source of [server,middleware]){
    assert.doesNotMatch(source,/#include <boost\/asio\/ssl\.hpp>/);
    assert.doesNotMatch(source,/#include <boost\/beast\/ssl\.hpp>/);
    assert.doesNotMatch(source,/#include <openssl\/ssl\.h>/);
  }
  assert.match(proxy,/#include <boost\/asio\/ssl\.hpp>/);
  assert.match(proxy,/#include <boost\/beast\/ssl\.hpp>/);
  assert.match(proxy,/#include <openssl\/ssl\.h>/);
  for(const source of [server,proxy,middleware]){
    assert.match(source,/#include "asio_thread_context_extern\.hpp"/);
  }
});

test("GCC16 Asio coroutine allocation workaround is isolated without suppressing -Werror",()=>{
  assert.match(cmake,/if\(CMAKE_CXX_COMPILER_ID STREQUAL "GNU"\s*AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "16"\s*AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "17"\)/);
  assert.match(cmake,/set_source_files_properties\(\s*http_coroutine\.cpp http_proxy\.cpp http\.cpp\s*PROPERTIES COMPILE_OPTIONS "-fno-inline"\)/);
  assert.doesNotMatch(cmake,/-Wno-error|-Wno-mismatched-new-delete/);
});

test("the same gateway library links all three C++26 implementation files",()=>{
  for(const name of ["http.cpp","http_proxy.cpp","http_coroutine.cpp","asio_thread_context.cpp"])
    assert.ok(cmake.includes("        "+name+"\n"));
  assert.match(cmake,/openproof_add_module\(openproof_gateway_http/);
});

test("scanner covers all implementation units and requires retirement of blocking proxy",()=>{
  for(const file of ["src/gateway/http.cpp","src/gateway/http_proxy.cpp",
                     "src/gateway/http_coroutine.cpp"])
    assert.ok(scanner.includes('"'+file+'"'));
  assert.match(scanner,/legacy proxy facade still blocks a calling thread/);
  assert.doesNotMatch(proxy,/context\.run\(\)|asio::use_future|sendResultAsync/);
  const sync=proxy.slice(proxy.indexOf("BeastProxyTransport::send("),proxy.indexOf("BeastProxyTransport::sendAsync("));
  assert.match(sync,/return foundation::fail\(foundation::ErrorCode::Unavailable/);
  assert.doesNotMatch(sync,/co_spawn|m_implementation->/);
  assert.match(proxy,/co_await m_implementation->sendAsync\(/);
  assert.match(scanner,/proxy synchronous ABI or production native wiring is not retired/);
  assert.match(middleware,/co_await m_transport->sendAsync\(/);
});

test("network layer retains bounded request and response framing",()=>{
  assert.match(server,/beastHttp::async_read\(/);
  assert.match(server,/beastHttp::async_write\(/);
  assert.match(server,/m_parser->header_limit\(/);
  assert.match(server,/m_parser->body_limit\(/);
  assert.match(proxy,/beastHttp::async_read\(/);
  assert.match(proxy,/beastHttp::async_write\(/);
  assert.match(proxy,/parser\.header_limit\(/);
  assert.match(proxy,/parser\.body_limit\(/);
  assert.match(proxy,/SSL_CTRL_SET_TLSEXT_HOSTNAME/);
  assert.match(proxy,/host_name_verification\{host\}/);
});

test("normal HTTP completion awaits the bounded pool and writes on the connection strand",()=>{
  const read=server.slice(server.indexOf("asio::awaitable<void> readRequest()"),
    server.indexOf("asio::awaitable<beastHttp::response<beastHttp::string_body>> dispatchHandler("));
  const dispatch=server.slice(server.indexOf("asio::awaitable<beastHttp::response<beastHttp::string_body>> dispatchHandler("),
    server.indexOf("void write(beastHttp::response"));
  assert.ok(read.length>0 && dispatch.length>0);
  assert.match(read,/m_pendingHandlers\.fetch_add\(/);
  assert.match(read,/struct PendingHandlerGuard final[\s\S]*?pending\.fetch_sub\(1U, std::memory_order_acq_rel\)/);
  assert.match(read,/co_await asio::co_spawn\(m_owner->m_handlerPool,\s*dispatchHandler\(std::move\(\*operation\), version, headRequest\),\s*asio::use_awaitable\)/);
  const completion=read.indexOf("m_response.emplace(std::move(wire))");
  assert.ok(completion>read.indexOf("co_await asio::co_spawn("));
  assert.ok(read.indexOf("co_await writeResponse(headRequest);")>completion);
  assert.match(read,/if \(!m_owner->m_running.load\(std::memory_order_acquire\)\) co_return;/);
  assert.match(dispatch,/asyncHandler->nativeEnabledFor\(operation\)/);
  assert.match(dispatch,/co_return wire;/);
  assert.doesNotMatch(dispatch,/m_stream|asio::post\(|writeResponse\(/);
  assert.match(server,/asio::make_strand\(m_context\)/);
  assert.match(server,/beastHttp::async_write_header\(/);
});

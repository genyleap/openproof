#!/usr/bin/env node
// Source-only fd ownership invariant; C++/libpq integration is still required.
import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const text = fs.readFileSync(
  path.join(root, "src/storage/postgres/async_connection.cpp"), "utf8");
const source = cppExecutableText(text);
const start = source.indexOf("asio::awaitable<void> waitForSocket(");
const end = text.indexOf("} // namespace", start);
assert.ok(start >= 0 && end > start);
const body = source.slice(start, end);

test("libpq socket is only duplicated after Asio descriptor construction", () => {
  const wrapper = body.indexOf("slot.emplace(executor);");
  const duplicate = body.indexOf("const int fd = ::dup(originalFd);");
  assert.ok(wrapper >= 0 && duplicate > wrapper);
  assert.match(body, /const int originalFd = PQsocket\(connection\)/);
  assert.doesNotMatch(body, /stream_descriptor descriptor\{executor,\s*fd\}/);
});

test("failed Asio descriptor adoption closes only the duplicated fd", () => {
  assert.match(body, /descriptor\.assign\(fd,\s*assignmentError\)/);
  assert.match(body, /if\s*\(assignmentError\)\s*\{\s*\(void\)::close\(fd\);\s*throw\s+std::runtime_error/);
  assert.doesNotMatch(body, /::close\(originalFd\)/);
  assert.match(body, /co_await descriptor\.async_wait\(/);
});

test("real loopback regression exercises stalled PostgreSQL handshake and fd cleanup", () => {
  const tests = fs.readFileSync(
    path.join(root, "tests/storage/postgres_async_dns_test.cpp"), "utf8");
  assert.match(tests, /TEST\(PostgresAsyncDnsTest, FailedNativeConnectionsDoNotLeakSocketDescriptors\)/);
  assert.match(tests, /TEST\(PostgresAsyncDnsTest, StalledLoopbackDatabaseHonorsConnectDeadline\)/);
  assert.match(tests, /TEST\(PostgresAsyncDnsTest, StalledTlsNegotiationHonorsConnectDeadline\)/);
  assert.match(tests, /expectStalledLoopbackDeadline\("require"\)/);
  assert.match(tests, /asio::ip::tcp::acceptor/);
  assert.match(tests, /std::jthread server/);
  assert.match(tests, /acceptor\.async_accept\(/);
  assert.match(tests, /AsyncConnection::connect\(dsn, 250ms\)/);
  assert.match(tests, /EXPECT_TRUE\(timedOut\)/);
});

test("benchmark compares serial vs concurrent native libpq stalls on one reactor", () => {
  const fixture = fs.readFileSync(
    path.join(root, "tests/storage/postgres_native_benchmark_test.cpp"), "utf8");
  const start = fixture.indexOf(
    "TEST(PostgresAsyncDnsTest, ParallelStalledConnectionsDoNotSerializeReactor)");
  const end = fixture.indexOf("} // namespace", start);
  assert.ok(start >= 0 && end > start);
  const benchmark = fixture.slice(start, end);
  assert.match(benchmark, /constexpr int attempts = 6/);
  assert.match(benchmark, /asio::co_spawn\(serverIo, acceptAll\(\), asio::detached\)/);
  assert.match(benchmark, /const auto serialStart/);
  assert.match(benchmark, /const auto concurrentStart/);
  assert.match(benchmark, /concurrentClient\.run\(\)/);
  assert.match(benchmark, /EXPECT_EQ\(expired\.load/);
  assert.match(benchmark, /NativePgLoopbackBench attempts=/);
});

test("socket readiness remains cancellation- and deadline-bound", () => {
  assert.match(body, /if\s*\(Clock::now\(\)\s*>=\s*deadline\)/);
  assert.match(body, /asio::cancel_after\(remaining/);
  assert.match(body, /asio::redirect_error\(asio::use_awaitable,\s*error\)/);
});

test("timed PostgreSQL operations are serialized on their current executor", () => {
  const connect = source.indexOf("AsyncConnection::connect(");
  const connectImpl = source.indexOf("AsyncConnection::connectSerialized(", connect);
  const query = source.indexOf("AsyncConnection::query(");
  const queryImpl = source.indexOf("AsyncConnection::querySerialized(", query);
  assert.ok(connect > 0 && connectImpl > connect && query > connectImpl && queryImpl > query);
  for (const wrapper of [source.slice(connect, connectImpl), source.slice(query, queryImpl)]) {
    assert.match(wrapper, /const Deadline deadline = makeDeadline\(timeout\)/);
    assert.match(wrapper, /co_await asio::this_coro::executor/);
    assert.match(wrapper, /asio::co_spawn\(asio::make_strand\(executor\)/);
    assert.match(wrapper, /asio::use_awaitable/);
  }
  assert.doesNotMatch(source, /m_impl->executor/);
  const implementation = source.slice(queryImpl);
  assert.match(implementation, /auto executor = co_await asio::this_coro::executor/);
  assert.match(implementation, /waitForSocket\(executor, connection,/);
  const testSource = fs.readFileSync(path.join(root,
    "tests/storage/postgres_async_canonical_test.cpp"), "utf8");
  assert.match(testSource, /TEST\(PostgresCanonicalCoroutineTest, RealDatabaseConnectionUsesCurrentExecutor\)/);
  assert.match(testSource, /ASSERT_TRUE\(opening.stopped\(\)\)/);
  assert.match(testSource, /queryOnNextExecutor\(std::move\(connection\)\)/);
});

test("connected query reuses readiness ownership only within its own executor and lifetime", () => {
  assert.match(source, /struct QuerySocketReadiness final\s*\{\s*std::optional<asio::posix::stream_descriptor> descriptor;/);
  assert.match(body, /QuerySocketReadiness\* querySocket = nullptr/);
  assert.match(body, /auto& slot = querySocket \? querySocket->descriptor : transient/);
  assert.match(body, /if \(slot.has_value\(\)\)[\s\S]*?if \(querySocket->originalFd != originalFd\)\s*\{\s*throw std::runtime_error/);
  const connect = source.slice(source.indexOf("AsyncConnection::connectSerialized("),
    source.indexOf("AsyncConnection::query("));
  assert.match(connect, /co_await waitForSocket\(/);
  assert.doesNotMatch(connect, /QuerySocketReadiness|&querySocket/);
  const query = source.slice(source.indexOf("AsyncConnection::querySerialized("));
  assert.match(query, /try\s*\{\s*QuerySocketReadiness querySocket;/);
  for (const direction of ["wait_read", "wait_write"]) {
    assert.ok(query.includes("asio::posix::stream_descriptor::"+direction+", deadline, &querySocket)"));
  }
  assert.match(query, /catch\s*\(\.\.\.\)\s*\{\s*m_impl->connection.reset\(\);/);
});

test("simple query optimization is restricted to the exact parameter-free reset", () => {
  assert.match(text,/const bool sessionReset=!migrationScript && params\.empty\(\) && sql=="DISCARD ALL";/);
  assert.match(text,/const int submitted=\(migrationScript \|\| sessionReset\)\s*\? PQsendQuery\(connection,sql\.c_str\(\)\)\s*:\s*submitParameterized\(connection,sql,params\)/);
  assert.match(text,/if \(!migrationScript && PQsetSingleRowMode\(connection\) != 1\)/);
  const pool=fs.readFileSync(path.join(root,"src/storage/postgres/async_pool.cpp"),"utf8");
  assert.match(pool,/reset\.commandTag!="DISCARD ALL" \|\| !reset\.rows\.empty\(\)/);
});

test("single-row results drain buffered input without an unconditional socket read per row", () => {
  const query = source.slice(source.indexOf("QueryRows output;"));
  const guard = query.indexOf("if (needInput || PQisBusy(connection) != 0)");
  const consume = query.indexOf("PQconsumeInput(connection)");
  const wait = query.indexOf("co_await waitForSocket(");
  const result = query.indexOf("PQgetResult(connection)");
  assert.match(query, /bool needInput = true;/);
  assert.ok(guard >= 0 && consume > guard && wait > consume && result > wait);
  assert.match(query, /co_await waitForSocket\([\s\S]*?needInput = true;\s*continue;/);
  assert.match(query, /needInput = false;\s*\}/);
  assert.match(query, /if \(!result\)\s*\{\s*if \(!finished\)/);
  assert.match(query, /catch\s*\(\.\.\.\)\s*\{\s*m_impl->connection.reset\(\);/);
});

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
  const wrapper = body.indexOf("asio::posix::stream_descriptor descriptor{executor};");
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

test("socket readiness remains cancellation- and deadline-bound", () => {
  assert.match(body, /if\s*\(Clock::now\(\)\s*>=\s*deadline\)/);
  assert.match(body, /asio::cancel_after\(remaining/);
  assert.match(body, /asio::redirect_error\(asio::use_awaitable,\s*error\)/);
});

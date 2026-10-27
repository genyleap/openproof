#!/usr/bin/env node
// Regression for the read-only deployment preflight, using mock loopback HTTP.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import http from "node:http";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const exec = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const script = path.join(root, "scripts/verify-running-service.mjs");
let ready = true;
const server = http.createServer((request, response) => {
  response.setHeader("content-type", "application/json");
  if (request.headers["x-forwarded-for"] !== "127.0.0.1") {
    response.writeHead(400);
    response.end('{"error":"invalid ingress"}');
    return;
  }
  if (request.url === "/health/ready" && !ready) {
    response.writeHead(503);
    response.end('{"status":"not-ready"}');
    return;
  }
  if (!["/health/live", "/health/ready"].includes(request.url)) {
    response.writeHead(404);
    response.end('{}');
    return;
  }
  response.writeHead(200);
  response.end('{"status":"ok"}');
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = "http://127.0.0.1:" + server.address().port + "/";
const run = (...args) => exec(process.execPath, [script, ...args], {
  timeout: 10000, encoding: "utf8",
});
try {
  const success = await run(base, "127.0.0.1");
  assert.match(success.stdout, /\/health\/live: 200 OK/);
  assert.match(success.stdout, /\/health\/ready: 200 OK/);
  await assert.rejects(run(base), /Command failed/);
  await assert.rejects(run(base, "invalid-client-ip"), /Command failed/);
  await assert.rejects(run("http://example.com/"), /Command failed/);
  ready = false;
  await assert.rejects(run(base, "127.0.0.1"), /Command failed/);
  console.log("Read-only live readiness preflight regression: PASSED");
} finally {
  await new Promise((resolve) => server.close(resolve));
}

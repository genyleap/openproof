#!/usr/bin/env node
// Read-only live-service preflight. It never prints configuration or secrets.
// Run before and after a controlled OpenProof deployment. Fail closed.
import assert from "node:assert/strict";
import { isIP } from "node:net";

const [, , address, forwardedIp] = process.argv;
if (!address || process.argv.length > 4) {
  console.error("Usage: node scripts/verify-running-service.mjs <base-url> [trusted-proxy-client-ip]");
  process.exit(2);
}

try {
  const base = new URL(address);
  const hostname = base.hostname.toLowerCase();
  const loopback = hostname === "localhost" || hostname === "127.0.0.1"
    || hostname === "[::1]";
  assert(base.protocol === "https:" || (base.protocol === "http:" && loopback),
    "Plaintext readiness probes must stay on loopback");
  assert(!base.username && !base.password && !base.search && !base.hash
    && base.pathname === "/", "Expected a base URL without credentials or a path");
  assert(forwardedIp === undefined || (loopback && isIP(forwardedIp) !== 0),
    "A forwarded client IP may only be supplied to a loopback listener");

  for (const endpoint of ["/health/live", "/health/ready"]) {
    const headers = forwardedIp ? { "x-forwarded-for": forwardedIp } : {};
    const response = await fetch(new URL(endpoint, base), {
      method: "GET",
      cache: "no-store",
      redirect: "error",
      headers,
      signal: AbortSignal.timeout(5000),
    });
    assert.equal(response.status, 200, endpoint + " must return HTTP 200");
    assert(response.headers.get("content-type")?.includes("application/json"),
      endpoint + " must use JSON");
    const body = await response.json();
    assert.equal(body?.status, "ok", endpoint + " must report ok");
    console.log(endpoint + ": 200 OK");
  }
  console.log("Read-only OpenProof live and PostgreSQL readiness preflight passed");
} catch (error) {
  // Do not print HTTP bodies, bearer tokens, connection strings or input URLs.
  console.error("OpenProof live readiness preflight failed:", error.message);
  process.exitCode = 1;
}

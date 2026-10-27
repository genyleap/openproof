#!/usr/bin/env node
// Measured OpenProof opp + real HTTP/TCP, with a deliberately slow loopback
// upstream. This is a controlled-I/O micro-workload, NOT identity-platform E2E.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { performance } from "node:perf_hooks";

const binary = process.argv[2] ? path.resolve(process.argv[2]) : "";
const outputFile = process.argv[3] ? path.resolve(process.argv[3]) : "";
if (!binary || !outputFile || !fs.existsSync(binary)) {
  console.error("Usage: node scripts/benchmark-gateway-upstream.mjs <opp> <output.json>");
  process.exit(2);
}
const requests = Number(process.env.OPENPROOF_GATEWAY_BENCH_REQUESTS ?? 600);
const concurrency = Number(process.env.OPENPROOF_GATEWAY_BENCH_CONCURRENCY ?? 24);
const delayMs = Number(process.env.OPENPROOF_GATEWAY_BENCH_DELAY_MS ?? 50);
assert(Number.isInteger(requests) && requests >= concurrency && concurrency > 0);
assert(Number.isInteger(delayMs) && delayMs >= 1 && delayMs <= 500);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}
async function reservePort() {
  const listener = net.createServer();
  const port = await listen(listener);
  await new Promise((resolve) => listener.close(resolve));
  return port;
}
function request(port) {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const pending = http.get({
      host: "127.0.0.1", port, path: "/api/bench", agent: false,
      timeout: 5000,
    }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (piece) => { body += piece; });
      response.on("end", () => {
        if (response.statusCode !== 200 || body !== "ok") {
          reject(new Error("Gateway response mismatch"));
          return;
        }
        resolve(performance.now() - started);
      });
      response.on("error", reject);
    });
    pending.on("timeout", () => pending.destroy(new Error("Gateway request timeout")));
    pending.on("error", reject);
  });
}
function usage(pid) {
  try {
    const raw = fs.readFileSync("/proc/" + pid + "/stat", "utf8");
    const fields = raw.slice(raw.lastIndexOf(")") + 2).trim().split(/\s+/);
    const status = fs.readFileSync("/proc/" + pid + "/status", "utf8");
    const rss = status.match(/^VmRSS:\s*(\d+)\s+kB$/m);
    const cpu = Number(fields[11]) + Number(fields[12]);
    if (!rss || !Number.isFinite(cpu)) return {};
    return { cpuTicks: cpu, rssKiB: Number(rss[1]) };
  } catch { return {}; }
}
const percentile = (sorted, q) => {
  const index = (sorted.length - 1) * q;
  const a = Math.floor(index), b = Math.ceil(index);
  return sorted[a] + (sorted[b] - sorted[a]) * (index - a);
};
async function runLoad(port, count, workers) {
  const latencies = [];
  let next = 0;
  const started = performance.now();
  await Promise.all(Array.from({ length: workers }, async () => {
    for (;;) {
      if (next >= count) return;
      next++;
      latencies.push(await request(port));
    }
  }));
  const elapsedSeconds = (performance.now() - started) / 1000;
  latencies.sort((a,b)=>a-b);
  return {
    requests: count, concurrency: workers,
    requestsPerSecond: count / elapsedSeconds,
    p50Ms: percentile(latencies, .50),
    p95Ms: percentile(latencies, .95),
    p99Ms: percentile(latencies, .99),
    errors: 0,
  };
}

const temp = fs.mkdtempSync(path.join(os.tmpdir(), "openproof-gateway-bench-"));
const upstream = http.createServer((req, res) => {
  setTimeout(() => {
    res.writeHead(200, { "content-type":"text/plain", "cache-control":"no-store" });
    res.end("ok");
  }, delayMs);
});
let child;
try {
  const upstreamPort = await listen(upstream);
  const oppPort = await reservePort();
  const configFile = path.join(temp, "config.toml");
  fs.writeFileSync(configFile, [
    "[server]",
    'bind_address = "127.0.0.1"',
    "port = " + oppPort,
    "[logging]",
    'level = "error"',
    "console = false",
    "[operations]",
    "metrics_enabled = false",
    "[security]",
    'token_signing_key = "env:OPENPROOF_TOKEN_SIGNING_KEY"',
    "[gateway]",
    "enabled = true",
    'route_prefix = "/"',
    'upstream_host = "127.0.0.1"',
    "upstream_port = " + upstreamPort,
    "upstream_tls = false",
    "rate_limit_capacity = 100000",
    "rate_limit_refill_per_second = 100000",
    "rate_limit_maximum_keys = 100000",
    "[auth]",
    "enabled = false",
    "",
  ].join("\n"), { mode: 0o600 });
  const env = {
    ...process.env,
    OPENPROOF_TOKEN_SIGNING_KEY: crypto.randomBytes(48).toString("base64url"),
  };
  const check = spawnSync(binary, ["check-config", "--config", configFile], {
    env, encoding: "utf8", timeout: 15000,
  });
  if (check.status !== 0) throw new Error("Gateway benchmark config validation failed");
  child = spawn(binary, ["server", "--config", configFile], {
    env, stdio: "ignore",
  });
  let ready = false;
  for (let attempt = 0; attempt < 100; ++attempt) {
    if (child.exitCode !== null) break;
    try { await request(oppPort); ready = true; break; } catch { await sleep(75); }
  }
  if (!ready) throw new Error("Gateway benchmark server did not become ready");
  await runLoad(oppPort, 48, Math.min(concurrency, 12)); // warmup
  const before = usage(child.pid);
  const metrics = await runLoad(oppPort, requests, concurrency);
  const after = usage(child.pid);
  const output = {
    benchmark: "openproof-gateway-actual-tcp-delayed-upstream",
    commit: process.env.OPENPROOF_GATEWAY_BENCH_COMMIT
      ?? process.env.GITHUB_SHA ?? "local",
    timestamp: new Date().toISOString(),
    upstreamDelayMs: delayMs,
    ...metrics,
    ...(Number.isFinite(before.cpuTicks) && Number.isFinite(after.cpuTicks)
      ? { serverCpuTicksDelta: Math.max(0, after.cpuTicks - before.cpuTicks) } : {}),
    ...(Number.isFinite(after.rssKiB) ? { serverRssKiBEnd: after.rssKiB } : {}),
  };
  fs.writeFileSync(outputFile, JSON.stringify(output, null, 2) + "\n", { mode: 0o600 });
  console.log(JSON.stringify(output));
} finally {
  if (child && child.exitCode === null) {
    child.kill("SIGTERM");
    await Promise.race([
      new Promise((resolve) => child.once("exit", resolve)),
      sleep(4000),
    ]);
    if (child.exitCode === null) child.kill("SIGKILL");
  }
  await new Promise((resolve) => upstream.close(resolve));
  fs.rmSync(temp, { recursive: true, force: true });
}

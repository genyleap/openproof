#!/usr/bin/env node

const origin = process.env.OPENPROOF_LOAD_ORIGIN;
const total = Number.parseInt(process.env.OPENPROOF_LOAD_REQUESTS ?? "1000", 10);
const concurrency = Number.parseInt(process.env.OPENPROOF_LOAD_CONCURRENCY ?? "25", 10);
const path = process.env.OPENPROOF_LOAD_PATH ?? "/health/ready";

if (!origin || !origin.startsWith("https://") || !Number.isSafeInteger(total)
    || !Number.isSafeInteger(concurrency) || total < 1 || total > 1_000_000
    || concurrency < 1 || concurrency > 1000 || !path.startsWith("/")
    || path.startsWith("//")) {
  console.error("Set a HTTPS OPENPROOF_LOAD_ORIGIN and valid request/concurrency limits.");
  process.exit(2);
}

const target = new URL(path, origin);
if (target.origin !== new URL(origin).origin) {
  console.error("OPENPROOF_LOAD_PATH must remain on the configured origin.");
  process.exit(2);
}

const latencies = [];
let next = 0;
let failures = 0;

async function worker() {
  while (true) {
    const index = next++;
    if (index >= total) return;
    const started = performance.now();
    try {
      const response = await fetch(target, {
        method: "GET",
        redirect: "manual",
        signal: AbortSignal.timeout(10_000),
        headers: { "user-agent": "openproof-load-smoke/1.1" }
      });
      if (response.status < 200 || response.status >= 300) failures++;
      await response.arrayBuffer();
    } catch {
      failures++;
    } finally {
      latencies.push(performance.now() - started);
    }
  }
}

const wallStarted = performance.now();
await Promise.all(Array.from({ length: Math.min(concurrency, total) }, worker));
const wallSeconds = (performance.now() - wallStarted) / 1000;
latencies.sort((left, right) => left - right);
const percentile = value => latencies[Math.min(
  latencies.length - 1, Math.ceil(latencies.length * value) - 1)];

console.log(JSON.stringify({
  target: target.toString(), requests: total, concurrency, failures,
  requests_per_second: Number((total / wallSeconds).toFixed(2)),
  latency_ms: {
    p50: Number(percentile(0.50).toFixed(2)),
    p95: Number(percentile(0.95).toFixed(2)),
    p99: Number(percentile(0.99).toFixed(2)),
    max: Number(latencies.at(-1).toFixed(2))
  }
}, null, 2));

if (failures > 0) process.exit(1);

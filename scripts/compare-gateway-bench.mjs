#!/usr/bin/env node
// This is a real OpenProof binary/TCP gateway comparison under a *controlled*
// delayed upstream. It is not a general identity/OAuth workload or significance test.
import assert from "node:assert/strict";
import fs from "node:fs";
const [baselineFile, candidateFile] = process.argv.slice(2);
if (!baselineFile || !candidateFile) {
  console.error("Usage: node scripts/compare-gateway-bench.mjs <baseline.json> <candidate.json>");
  process.exit(2);
}
function load(file) {
  const item = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(item.benchmark, "openproof-gateway-actual-tcp-delayed-upstream");
  for (const key of ["requests", "concurrency", "upstreamDelayMs",
    "requestsPerSecond", "p50Ms", "p95Ms", "p99Ms", "errors"]) {
    assert(Number.isFinite(item[key]), "Bad measurement: " + key);
  }
  assert.equal(item.errors, 0, "A benchmark with request failures is invalid");
  assert(item.requests > 0 && item.requests >= item.concurrency);
  assert(item.requestsPerSecond > 0);
  return item;
}
const baseline = load(baselineFile);
const candidate = load(candidateFile);
for (const key of ["requests","concurrency","upstreamDelayMs"]) {
  assert.equal(candidate[key], baseline[key], "Workload mismatch: " + key);
}
console.log("# OpenProof actual Gateway TCP controlled-I/O comparison");
console.log("Baseline: " + baseline.commit);
console.log("Candidate: " + candidate.commit);
console.log("Requests: " + baseline.requests +
  ", concurrency: " + baseline.concurrency +
  ", upstream latency: " + baseline.upstreamDelayMs + "ms");
console.log("");
console.log("| Metric | Baseline | Candidate | Favorable change |");
console.log("|---|---:|---:|---:|");
for (const [label, key, up] of [
  ["Throughput (req/s)", "requestsPerSecond", true],
  ["p50 (ms)", "p50Ms", false],
  ["p95 (ms)", "p95Ms", false],
  ["p99 (ms)", "p99Ms", false],
  ["Server CPU ticks", "serverCpuTicksDelta", false],
  ["Server RSS (KiB)", "serverRssKiBEnd", false],
]) {
  const x = baseline[key], y = candidate[key];
  if (!Number.isFinite(x) || !Number.isFinite(y) || x <= 0 || y <= 0) continue;
  const improvement = ((up ? y / x : x / y) - 1) * 100;
  console.log("| " + label + " | " + x.toFixed(2) +
    " | " + y.toFixed(2) +
    " | " + (improvement >= 0 ? "+" : "") + improvement.toFixed(2) + "% |");
}
console.log("");
console.log("NOT APPROVED: single paired sample, artificial upstream delay. " +
  "Must validate protected identity/OAuth, multiple paired repetitions, " +
  "latency tails, failure rate and all Coroutine release gates.");

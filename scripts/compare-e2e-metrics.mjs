#!/usr/bin/env node
// Compare *measured* OpenProof E2E results, never simulator values.
// A numeric improvement is not a release approval or a significance test.
import assert from "node:assert/strict";
import fs from "node:fs";

const [baselinePath, candidatePath] = process.argv.slice(2);
if (!baselinePath || !candidatePath) {
  console.error("Usage: node scripts/compare-e2e-metrics.mjs <baseline.json> <candidate.json>");
  process.exit(2);
}

function readMetrics(file) {
  const metrics = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(metrics.benchmark, "openproof-isolated-e2e-mixed-read",
    "Unrecognized benchmark type");
  for (const field of ["requests", "concurrency", "requestsPerSecond",
                       "p50Ms", "p95Ms", "p99Ms"]) {
    assert.equal(typeof metrics[field], "number", "Invalid " + field);
    assert.ok(Number.isFinite(metrics[field]) && metrics[field] > 0,
      "Non-positive/nonfinite " + field);
  }
  assert.ok(metrics.requests >= metrics.concurrency);
  return metrics;
}

const baseline = readMetrics(baselinePath);
const candidate = readMetrics(candidatePath);
assert.equal(candidate.requests, baseline.requests,
  "Workload request counts must match");
assert.equal(candidate.concurrency, baseline.concurrency,
  "Workload concurrency must match");
if (baseline.commit === candidate.commit) {
  console.error("Warning: the two input artifacts record the same commit.");
}

const metrics = [
  ["Throughput (req/s)", "requestsPerSecond", true],
  ["p50 (ms)", "p50Ms", false],
  ["p95 (ms)", "p95Ms", false],
  ["p99 (ms)", "p99Ms", false],
];
console.log("# OpenProof matched-workload E2E comparison");
console.log("Baseline commit: " + baseline.commit);
console.log("Candidate commit: " + candidate.commit);
console.log("Workload: " + baseline.requests +
  " requests / concurrency " + baseline.concurrency);
console.log("");
console.log("| Metric | Baseline | Candidate | Relative change |");
console.log("|---|---:|---:|---:|");
for (const [label, key, higherIsBetter] of metrics) {
  const oldValue = baseline[key], newValue = candidate[key];
  const ratio = higherIsBetter ? newValue / oldValue : oldValue / newValue;
  const percent = (ratio - 1) * 100;
  console.log("| " + label + " | " + oldValue.toFixed(2) +
    " | " + newValue.toFixed(2) +
    " | " + (percent >= 0 ? "+" : "") + percent.toFixed(1) +
    "% favorable |");
}
for (const [label, key] of [
  ["Server CPU ticks (same runner)", "serverCpuTicksDelta"],
  ["Server RSS at workload end (KiB)", "serverRssKiBEnd"],
]) {
  const before = baseline[key], after = candidate[key];
  if (Number.isFinite(before) && before > 0
      && Number.isFinite(after) && after > 0) {
    const favorable = (before / after - 1) * 100;
    console.log("| " + label + " | " + before.toFixed(2) +
      " | " + after.toFixed(2) + " | " +
      (favorable >= 0 ? "+" : "") + favorable.toFixed(1) +
      "% favorable |");
  }
}
if (baseline.routes || candidate.routes) {
  const validated = (record) => {
    assert.ok(Array.isArray(record.routes), "Route metrics must be present on both sides");
    const routes = new Map();
    let count = 0;
    for (const route of record.routes) {
      assert.match(route.name, /^[a-z-]+$/);
      assert.ok(!routes.has(route.name), "Duplicate benchmark route");
      assert.ok(Number.isInteger(route.requests) && route.requests > 0);
      assert.ok([route.p50Ms, route.p95Ms, route.p99Ms].every(v => Number.isFinite(v) && v > 0));
      assert.ok(route.p50Ms <= route.p95Ms && route.p95Ms <= route.p99Ms);
      routes.set(route.name, route);
      count += route.requests;
    }
    assert.equal(count, record.requests, "Route sample count mismatch");
    return routes;
  };
  const before = validated(baseline), after = validated(candidate);
  assert.equal(before.size, after.size, "Route workloads must match");
  console.log("\n| Route | Requests | Baseline p50 / p95 / p99 (ms) | Candidate p50 / p95 / p99 (ms) |");
  console.log("|---|---:|---:|---:|");
  const format = r => [r.p50Ms, r.p95Ms, r.p99Ms].map(v => v.toFixed(2)).join(" / ");
  for (const [name, old] of before) {
    const current = after.get(name);
    assert.ok(current, "Missing matching route");
    assert.equal(old.requests, current.requests, "Route request counts must match");
    console.log(`| ${name} | ${old.requests} | ${format(old)} | ${format(current)} |`);
  }
}
console.log("");
console.log("NOT APPROVED: this tool compares point estimates, not statistically " +
  "significant results. The same hardware, build flags, warmed-up state, " +
  "multiple paired repetitions, security tests and full Coroutine release gate " +
  "are mandatory before any production claim.");

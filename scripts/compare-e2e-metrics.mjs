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
if (baseline.byOperation || candidate.byOperation) {
  assert.ok(baseline.byOperation && candidate.byOperation,
    "Both artifacts must have route metrics for a matched breakdown");
  const labels = ["readiness", "discovery", "jwks", "userinfo", "gateway", "introspection"];
  for (const artifact of [baseline, candidate]) {
    assert.deepEqual(Object.keys(artifact.byOperation).sort(), [...labels].sort());
    let total = 0;
    for (const [i, label] of labels.entries()) {
      const route = artifact.byOperation[label];
      const expected = Math.floor(artifact.requests / labels.length)
        + (i < artifact.requests % labels.length ? 1 : 0);
      assert.equal(route.requests, expected, "Unexpected request distribution: " + label);
      for (const key of ["p50Ms", "p95Ms", "p99Ms"]) {
        assert.ok(Number.isFinite(route[key]) && route[key] > 0, "Invalid " + label + " " + key);
      }
      assert.ok(route.p50Ms <= route.p95Ms && route.p95Ms <= route.p99Ms);
      total += route.requests;
    }
    assert.equal(total, artifact.requests);
  }
  console.log("");
  console.log("Mixed-workload per-operation latencies (ms; not isolated capacity):");
  console.log("| Operation | Samples per run | Baseline p50 / p95 / p99 | Candidate p50 / p95 / p99 | p95 favorable change |");
  console.log("|---|---:|---:|---:|---:|");
  for (const label of labels) {
    const b = baseline.byOperation[label], c = candidate.byOperation[label];
    const fmt = r => [r.p50Ms, r.p95Ms, r.p99Ms].map(v => v.toFixed(2)).join(" / ");
    const favorable = (b.p95Ms / c.p95Ms - 1) * 100;
    console.log("| " + label + " | " + b.requests + " | " + fmt(b) +
      " | " + fmt(c) + " | " + (favorable >= 0 ? "+" : "") + favorable.toFixed(1) + "% |");
  }
}
console.log("");
console.log("NOT APPROVED: this tool compares point estimates, not statistically " +
  "significant results. The same hardware, build flags, warmed-up state, " +
  "multiple paired repetitions, security tests and full Coroutine release gate " +
  "are mandatory before any production claim.");

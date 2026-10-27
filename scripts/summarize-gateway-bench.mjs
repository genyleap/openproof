#!/usr/bin/env node
// Paired real-opp Gateway measurements with explicitly limited inference.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const directory = process.argv[2];
if (!directory) {
  console.error("Usage: node scripts/summarize-gateway-bench.mjs <results-directory>");
  process.exit(2);
}
const files = fs.readdirSync(directory);
const baselineFiles = files.filter((file) => /^baseline-[1-9][0-9]*\.json$/.test(file))
  .sort((a,b) => Number(a.match(/\d+/)[0]) - Number(b.match(/\d+/)[0]));
const candidateFiles = files.filter((file) => /^candidate-[1-9][0-9]*\.json$/.test(file))
  .sort((a,b) => Number(a.match(/\d+/)[0]) - Number(b.match(/\d+/)[0]));
assert(baselineFiles.length >= 5, "At least five paired runs are required");
assert.equal(baselineFiles.length, candidateFiles.length);
const pairs = baselineFiles.map((file,i) => {
  const index = Number(file.match(/\d+/)[0]);
  assert.equal(Number(candidateFiles[i].match(/\d+/)[0]), index);
  const a = JSON.parse(fs.readFileSync(path.join(directory, file), "utf8"));
  const b = JSON.parse(fs.readFileSync(path.join(directory, candidateFiles[i]), "utf8"));
  for (const item of [a,b]) {
    assert.equal(item.benchmark, "openproof-gateway-actual-tcp-delayed-upstream");
    assert.equal(item.errors, 0);
    for (const key of ["requestsPerSecond","p50Ms","p95Ms","p99Ms"]) {
      assert(Number.isFinite(item[key]) && item[key] > 0);
    }
  }
  for (const key of ["requests","concurrency","upstreamDelayMs","metricsEnabled"]) {
    assert.equal(a[key], b[key], "Different workload: " + key);
  }
  return { baseline:a, candidate:b };
});
const median = (values) => {
  const ordered = [...values].sort((a,b) => a - b);
  const mid = Math.floor(ordered.length / 2);
  return ordered.length % 2 ? ordered[mid] : (ordered[mid-1] + ordered[mid]) / 2;
};
function range(values) {
  const ordered = values.sort((a,b) => a - b);
  return [ordered[Math.floor(.025 * (ordered.length-1))],
    ordered[Math.ceil(.975 * (ordered.length-1))]];
}
let randomState = 0x263a78d9;
function randomIndex(count) {
  randomState ^= randomState << 13;
  randomState ^= randomState >>> 17;
  randomState ^= randomState << 5;
  return (randomState >>> 0) % count;
}
function bootstrap(values) {
  const samples = [];
  for (let trial=0; trial<10000; trial++) {
    const selected = [];
    for (let j=0; j<values.length; j++) selected.push(values[randomIndex(values.length)]);
    samples.push(median(selected));
  }
  return range(samples);
}
const results = {
  benchmark:"openproof-gateway-actual-tcp-delayed-upstream",
  pairCount:pairs.length,
  workload:{
    requests:pairs[0].baseline.requests,
    concurrency:pairs[0].baseline.concurrency,
    upstreamDelayMs:pairs[0].baseline.upstreamDelayMs,
    metricsEnabled:pairs[0].baseline.metricsEnabled,
  },
  baselineCommit:pairs[0].baseline.commit,
  candidateCommit:pairs[0].candidate.commit,
  caveat:"Exploratory paired-run bootstrap; not production performance or full Coroutine acceptance",
  metrics:[],
};
console.log("# OpenProof Gateway: repeated paired actual-TCP tests");
console.log("Pairs: " + pairs.length +
  "; " + results.workload.requests + " requests per run" +
  "; concurrency " + results.workload.concurrency +
  "; upstream delay " + results.workload.upstreamDelayMs + "ms");
console.log("| Metric | Median favorable change | Exploratory paired-bootstrap 95% interval |");
console.log("|---|---:|---:|");
for (const [label,key,greaterIsBetter] of [
  ["Throughput","requestsPerSecond",true],
  ["p50","p50Ms",false],
  ["p95","p95Ms",false],
  ["p99","p99Ms",false],
]) {
  const changes = pairs.map(({baseline:a,candidate:b}) =>
    (greaterIsBetter ? b[key] / a[key] : a[key] / b[key]) - 1);
  const middle = median(changes);
  const [low,high] = bootstrap(changes);
  const percentage = (v) => ((v>=0 ? "+" : "") + (v*100).toFixed(2) + "%");
  console.log("| " + label + " | " + percentage(middle) +
    " | " + percentage(low) + " to " + percentage(high) + " |");
  results.metrics.push({
    name:label,medianFavorableChangePct:middle*100,
    exploratoryBootstrap95Pct:[low*100,high*100],
  });
}
fs.writeFileSync(path.join(directory,"summary.json"),
  JSON.stringify(results,null,2) + "\n", {mode:0o600});
console.log("NOT APPROVED: small samples, controlled local upstream, shared-runner " +
  "noise and workload-specific effects; protected APIs and full Coroutine gate remain mandatory.");

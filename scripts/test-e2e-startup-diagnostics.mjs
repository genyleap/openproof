import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { classifyStartupFailure, replaceFixturePort } from "./ci/e2e-startup-diagnostics.mjs";

test("startup diagnosis exposes only fixed categories", () => {
  assert.equal(classifyStartupFailure("opp: bind listener failed: Address already in use\n"),
    "listener-address-in-use");
  assert.equal(classifyStartupFailure("opp: bind listener failed: private-secret\n"),
    "listener-bind-failed");
  assert.equal(classifyStartupFailure("opp: fatal: postgresql://user:password@host/db"),
    "uncaught-exception");
  assert.equal(classifyStartupFailure("opp: arbitrary private detail [UNAVAILABLE]"),
    "startup-unavailable");
  assert.equal(classifyStartupFailure("opp: arbitrary private detail [SECRET]"),
    "unclassified");
  assert.equal(classifyStartupFailure("unrelated: bind listener failed: Address already in use"),
    "unclassified");
  assert.equal(classifyStartupFailure("opp: bind listener failed: Address already in use plus extra"),
    "listener-bind-failed");
});

test("collision recovery rewrites only the fixture listener port", () => {
  const config = '[server]\nbind_address = "127.0.0.1"\nport = 1234\n\n[gateway]\nupstream_port = 1234\n';
  assert.equal(replaceFixturePort(config, 1234, 4321),
    '[server]\nbind_address = "127.0.0.1"\nport = 4321\n\n[gateway]\nupstream_port = 1234\n');
  assert.throws(() => replaceFixturePort(config, 2345, 4321));
  assert.throws(() => replaceFixturePort(config, 1234, 0));
  assert.throws(() => replaceFixturePort(config, 1234, 65536));
});

const routeLabels = ["readiness", "discovery", "jwks", "userinfo", "gateway", "introspection"];

function fixtureMetrics(commit, requests = 7) {
  return {
    benchmark: "openproof-isolated-e2e-mixed-read",
    commit, requests, concurrency: 2, requestsPerSecond: 100,
    p50Ms: 1, p95Ms: 2, p99Ms: 3,
    byOperation: Object.fromEntries(routeLabels.map((label, i) => [
      label, { requests: Math.floor(requests / 6) + (i < requests % 6 ? 1 : 0),
        p50Ms: 1, p95Ms: 2, p99Ms: 3 },
    ])),
  };
}

function compareFixtures(t, baseline, candidate) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "openproof-mixed-read-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const files = ["baseline.json", "candidate.json"].map(name => path.join(directory, name));
  for (const [i, metrics] of [baseline, candidate].entries())
    fs.writeFileSync(files[i], JSON.stringify(metrics), { mode: 0o600 });
  return spawnSync(process.execPath,
    [fileURLToPath(new URL("./compare-e2e-metrics.mjs", import.meta.url)), ...files],
    { encoding: "utf8", timeout: 5000 });
}

test("mixed-read comparator accepts a matched uneven route distribution", t => {
  const result = compareFixtures(t, fixtureMetrics("baseline"), fixtureMetrics("candidate"));
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Mixed-workload per-operation latencies/);
  for (const label of routeLabels) assert.ok(result.stdout.includes("| " + label + " |"));
  assert.match(result.stdout, /NOT APPROVED/);
});

test("mixed-read comparator rejects missing, partial, or miscounted route data", t => {
  for (const corrupt of [
    m => delete m.byOperation,
    m => delete m.byOperation.jwks,
    m => { m.byOperation.readiness.requests--; m.byOperation.discovery.requests++; },
    m => { m.byOperation.userinfo.p95Ms = 0; },
    m => { m.byOperation.gateway.p99Ms = 1; },
  ]) {
    const candidate = fixtureMetrics("candidate");
    corrupt(candidate);
    const result = compareFixtures(t, fixtureMetrics("baseline"), candidate);
    assert.ifError(result.error);
    assert.equal(result.status, 1);
  }
});

test("mixed-read comparator still accepts two historical aggregate-only artifacts", t => {
  const baseline = fixtureMetrics("baseline"), candidate = fixtureMetrics("candidate");
  delete baseline.byOperation;
  delete candidate.byOperation;
  const result = compareFixtures(t, baseline, candidate);
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stdout, /Mixed-workload per-operation latencies/);
});

test("repeated mixed-read summary validates all pairs and provenance", t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openproof-paired-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const base = "a".repeat(40), candidate = "b".repeat(40);
  const script = fileURLToPath(new URL("./summarize-mixed-read-bench.mjs", import.meta.url));
  const run = () => spawnSync(process.execPath, [script, dir, base, candidate],
    { encoding: "utf8", timeout: 5000 });
  const file = (c, trial, side) => path.join(dir, [c, trial, side].join("-") + ".json");
  for (const [c, requests] of [[24,600],[96,1200]]) {
    for (let trial=1; trial<=4; trial++) {
      for (const [side, commit] of [["baseline",base],["candidate",candidate]]) {
        const m = fixtureMetrics(commit, requests);
        m.concurrency = c;
        m.serverCpuTicksDelta = 20;
        m.serverRssKiBEnd = 5000;
        if (side === "candidate") { m.requestsPerSecond = 110; m.p95Ms = 1.5; }
        fs.writeFileSync(file(c,trial,side),JSON.stringify(m));
      }
    }
  }
  const good = run();
  assert.ifError(good.error);
  assert.equal(good.status,0,good.stderr);
  const summary = JSON.parse(fs.readFileSync(path.join(dir,"summary.json"),"utf8"));
  assert.deepEqual(summary.workloads.map(w=>w.concurrency),[24,96]);
  for (const w of summary.workloads) {
    assert.equal(w.pairs,4);
    assert.equal(w.metrics.requestsPerSecond.medianPairedChangePercent,10);
    assert.equal(w.metrics.requestsPerSecond.candidateWins,4);
    assert.equal(w.metrics.p95Ms.medianPairedChangePercent,-25);
  }
  const invalid = file(96,4,"candidate");
  const record = JSON.parse(fs.readFileSync(invalid,"utf8"));
  record.commit = base;
  fs.writeFileSync(invalid,JSON.stringify(record));
  const bad = run();
  assert.ifError(bad.error);
  assert.equal(bad.status,1);
  fs.unlinkSync(invalid);
  const missing = run();
  assert.ifError(missing.error);
  assert.equal(missing.status,1);
});

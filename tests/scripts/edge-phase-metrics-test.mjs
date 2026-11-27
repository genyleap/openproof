import assert from "node:assert/strict";
import test from "node:test";
import { createEdgePhaseMetrics } from "../../scripts/ci/edge-phase-metrics.mjs";

function sample(collector, received, sent, headers, finished) {
  const phase = collector.start(received);
  phase.sent(sent);
  phase.headers(headers);
  phase.finish(finished);
}

test("reports only aggregate phase durations for a complete workload", () => {
  const collector = createEdgePhaseMetrics(2);
  sample(collector, 100, 101, 104, 105);
  sample(collector, 200, 202, 210, 213);
  assert.deepEqual(collector.report(), {
    samples: 2,
    phases: {
      edgeForwardSend: {p50Ms:1,p95Ms:2,p99Ms:2},
      edgeUpstreamResponseHeaders: {p50Ms:3,p95Ms:8,p99Ms:8},
      edgeResponseFinish: {p50Ms:1,p95Ms:3,p99Ms:3},
      edgeTotal: {p50Ms:5,p95Ms:13,p99Ms:13},
    },
  });
});

test("incomplete, invalid and extra samples cannot become zero-duration measurements", () => {
  const missing = createEdgePhaseMetrics(2);
  sample(missing,0,1,2,3);
  assert.equal(missing.report(),null);
  const inverted = createEdgePhaseMetrics(1);
  sample(inverted,0,3,2,4);
  assert.equal(inverted.report(),null);
  const extra = createEdgePhaseMetrics(1);
  sample(extra,0,1,2,3);
  sample(extra,4,5,6,7);
  assert.equal(extra.report(),null);
  const incomplete = createEdgePhaseMetrics(1);
  incomplete.start(0).finish(1);
  assert.equal(incomplete.report(),null);
  assert.throws(()=>createEdgePhaseMetrics(0),RangeError);
});

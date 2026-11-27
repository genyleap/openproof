// Diagnostic timings for the disposable E2E TLS edge. No request data,
// routes, credentials or individual samples leave this collector.
export function createEdgePhaseMetrics(expected) {
  if (!Number.isSafeInteger(expected) || expected < 1 || expected > 1_000_000)
    throw new RangeError("Invalid edge sample count");
  const samples = [];
  let started = 0;
  let invalid = false;
  return {
    start(receivedAt) {
      started++;
      let sentAt, headersAt, finished = false;
      return {
        sent(at) { sentAt = at; },
        headers(at) { headersAt = at; },
        finish(at) {
          if (finished) { invalid = true; return; }
          finished = true;
          const times = [receivedAt, sentAt, headersAt, at];
          if (!times.every(Number.isFinite) ||
              times.some((value, i) => i > 0 && value < times[i-1]) ||
              samples.length >= expected) {
            invalid = true;
            return;
          }
          samples.push([sentAt-receivedAt, headersAt-sentAt, at-headersAt, at-receivedAt]);
        },
      };
    },
    report() {
      if (invalid || started !== expected || samples.length !== expected) return null;
      const names = ["edgeForwardSend", "edgeUpstreamResponseHeaders", "edgeResponseFinish", "edgeTotal"];
      return {
        samples: expected,
        phases: Object.fromEntries(names.map((name, i) => {
          const values = samples.map(row => row[i]).sort((a,b)=>a-b);
          const percentile = fraction => values[Math.ceil(values.length*fraction)-1];
          return [name, {p50Ms:percentile(0.5),p95Ms:percentile(0.95),p99Ms:percentile(0.99)}];
        })),
      };
    },
  };
}

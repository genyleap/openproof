// Validate the complete JSON response against an independently checked
// reference within the same fixture. Do not persist bodies, identities,
// tokens or reference values. No raw values in validation errors.
import {isDeepStrictEqual} from "node:util";
export function createMixedReadValidator(reference) {
  const expected = new Map([
    ["readiness", reference.readiness], ["discovery", reference.discovery],
    ["jwks", reference.jwks], ["userinfo", reference.userinfo],
    ["protected-proxy", reference.protectedProxy], ["introspection", reference.introspection],
  ]);
  // Readiness can legitimately report changing per-check timing. Validate
  // its stable semantic contract (status and check identities/statuses)
  // rather than dynamic diagnostic values. Other documents must match
  // the pre-load fixture exactly, irrespective of JSON key order.
  const readiness = value => {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      return value;
    // Ignore only named timing fields, never health states.
    const visit = v => Array.isArray(v) ? v.map(visit) :
      v !== null && typeof v === "object"
        ? Object.fromEntries(Object.entries(v).filter(([k]) =>
            !["duration_ms","latency_ms","elapsed_ms","timestamp"].includes(k))
            .map(([k,x]) => [k,visit(x)])) : v;
    return visit(value);
  };
  return (route, response) => {
    let body;
    try { body=JSON.parse(response.body); }
    catch { throw new Error("Mixed-read response is not JSON: "+(expected.has(route)?route:"unknown route")); }
    const normalize=route==="readiness"?readiness:v=>v;
    if (!expected.has(route) || response.status!==200 ||
        !isDeepStrictEqual(normalize(body),normalize(expected.get(route))))
      throw new Error("Mixed-read response contract mismatch: "+(expected.has(route)?route:"unknown route"));
  };
}

// Linux process diagnostics for the isolated E2E runner. Do not persist
// raw procfs contents, process names, TIDs or per-thread metadata.
import fs from "node:fs";

function integer(value) {
  if (typeof value !== "string" || !/^\d+$/.test(value)) return null;
  const n = Number(value);
  return Number.isSafeInteger(n) ? n : null;
}

function statFields(raw) {
  const end = raw.lastIndexOf(")");
  if (end < 0) return null;
  const fields = raw.slice(end + 1).trim().split(/\s+/);
  // /proc/<pid>/stat fields 14, 15 and 22; comm may contain spaces or ')'.
  const userTicks = integer(fields[11]);
  const systemTicks = integer(fields[12]);
  const start = integer(fields[19]);
  if ([userTicks, systemTicks, start].some(v => v === null)) return null;
  return { userTicks, systemTicks, start };
}

function statusValue(status, key, suffix = "") {
  return integer(status.match(new RegExp("^" + key + ":\\s*(\\d+)" + suffix + "$", "m"))?.[1]);
}

export function readOppUsage(pid, procRoot = "/proc") {
  if (!Number.isSafeInteger(pid) || pid <= 0 || process.platform !== "linux") return null;
  const base = procRoot + "/" + pid;
  try {
    const stat = statFields(fs.readFileSync(base + "/stat", "utf8"));
    const status = fs.readFileSync(base + "/status", "utf8");
    const rssKiB = statusValue(status, "VmRSS", "\\s+kB");
    if (!stat || rssKiB === null || rssKiB <= 0) return null;
    let threads = null;
    // /proc/pid/status exposes only the leader's context-switch counts.
    // Sum thread deltas only when the same complete thread set survives
    // both snapshots. A disappearing or reused TID is not zero switches.
    try {
      const ids = fs.readdirSync(base + "/task").sort();
      if (ids.length === 0 || ids.some(id => integer(id) === null))
        throw new Error("invalid thread set");
      const entries = new Map();
      for (const id of ids) {
        const prefix = base + "/task/" + id;
        const before = statFields(fs.readFileSync(prefix + "/stat", "utf8"));
        const threadStatus = fs.readFileSync(prefix + "/status", "utf8");
        const after = statFields(fs.readFileSync(prefix + "/stat", "utf8"));
        const voluntary = statusValue(threadStatus, "voluntary_ctxt_switches");
        const involuntary = statusValue(threadStatus, "nonvoluntary_ctxt_switches");
        if (!before || !after || before.start !== after.start ||
            voluntary === null || involuntary === null)
          throw new Error("incomplete thread snapshot");
        entries.set(id, { start: before.start, voluntary, involuntary });
      }
      const afterIds = fs.readdirSync(base + "/task").sort();
      if (ids.length === afterIds.length && ids.every((id, i) => id === afterIds[i]))
        threads = entries;
    } catch {
      // Thread metrics are optional; preserve the process CPU/RSS snapshot.
    }
    const end = statFields(fs.readFileSync(base + "/stat", "utf8"));
    if (!end || end.start !== stat.start) return null;
    return { ...stat, rssKiB, threads };
  } catch {
    return null;
  }
}

export function oppUsageDelta(before, after) {
  if (!before || !after || before.start !== after.start) return {};
  const user = after.userTicks - before.userTicks;
  const system = after.systemTicks - before.systemTicks;
  if (![user, system, user + system].every(v => Number.isSafeInteger(v) && v >= 0)) return {};
  const metrics = {
    serverCpuTicksDelta: user + system,
    serverUserCpuTicksDelta: user,
    serverSystemCpuTicksDelta: system,
    serverRssKiBEnd: after.rssKiB,
  };
  const a = before.threads, b = after.threads;
  if (!(a instanceof Map) || !(b instanceof Map) || a.size !== b.size || a.size === 0)
    return metrics;
  let voluntary = 0, involuntary = 0;
  for (const [id, first] of a) {
    const last = b.get(id);
    if (!last || first.start !== last.start) return metrics;
    const v = last.voluntary - first.voluntary;
    const iv = last.involuntary - first.involuntary;
    if (![v, iv].every(n => Number.isSafeInteger(n) && n >= 0)) return metrics;
    voluntary += v;
    involuntary += iv;
  }
  if (![voluntary, involuntary].every(Number.isSafeInteger)) return metrics;
  return { ...metrics, serverVoluntaryContextSwitchesDelta: voluntary,
    serverInvoluntaryContextSwitchesDelta: involuntary, serverStableThreadCount: a.size };
}

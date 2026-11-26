// Only fixed diagnostic categories escape child stderr. Never return any
// captured message, URL, config value, credential or arbitrary exception.
export function classifyStartupFailure(stderr) {
  const lines = String(stderr).split(/\r?\n/);
  if (lines.includes("opp: bind listener failed: Address already in use"))
    return "listener-address-in-use";
  for (const [prefix, category] of [
    ["opp: bind listener failed:", "listener-bind-failed"],
    ["opp: open listener failed:", "listener-open-failed"],
    ["opp: configure listener failed:", "listener-configure-failed"],
    ["opp: listen failed:", "listener-listen-failed"],
    ["opp: read bound port failed:", "listener-bound-port-failed"],
    ["opp: fatal:", "uncaught-exception"],
  ]) {
    if (lines.some(line => line.startsWith(prefix))) return category;
  }
  // Extract no free-form strings, even when a child emits unexpected codes.
  for (const code of ["INVALID_ARGUMENT", "FAILED_PRECONDITION", "UNAVAILABLE",
    "INTERNAL", "TIMEOUT", "PERMISSION_DENIED", "NOT_FOUND", "CONFLICT"]) {
    if (lines.some(line => line.startsWith("opp: ") && line.endsWith(` [${code}]`)))
      return `startup-${code.toLowerCase().replaceAll("_", "-")}`;
  }
  return "unclassified";
}

export function replaceFixturePort(configuration, oldPort, newPort) {
  for (const value of [oldPort, newPort]) {
    if (!Number.isInteger(value) || value < 1 || value > 65535)
      throw new Error("invalid fixture listener port");
  }
  // Only replace the top-level server port; upstream and delivery ports and
  // all key references remain unchanged. Refuse unexpected config shapes.
  const prefix = `[server]\nbind_address = "127.0.0.1"\nport = ${oldPort}\n`;
  if (!configuration.startsWith(prefix))
    throw new Error("unexpected fixture server configuration");
  return `[server]\nbind_address = "127.0.0.1"\nport = ${newPort}\n` +
    configuration.slice(prefix.length);
}

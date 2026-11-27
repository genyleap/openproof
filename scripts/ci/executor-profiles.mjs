// Only an explicit disposable diagnostic opts in. These are requested
// settings, not proof of active runtime scheduling; process counters and
// the TCP dispatch regressions provide independent evidence.
export const profiles = Object.freeze({
  auto: Object.freeze({}),
  two: Object.freeze({ OPENPROOF_EXPERIMENTAL_HANDLER_THREADS: "2" }),
  reactor: Object.freeze({ OPENPROOF_EXPERIMENTAL_REACTOR_PUBLIC_READS: "1" }),
  budget: Object.freeze({ OPENPROOF_EXPERIMENTAL_CPU_BUDGET: "1" }),
});
const keys = [
  "OPENPROOF_EXPERIMENTAL_HANDLER_THREADS",
  "OPENPROOF_EXPERIMENTAL_REACTOR_PUBLIC_READS",
  "OPENPROOF_EXPERIMENTAL_CPU_BUDGET",
  "OPENPROOF_EXPERIMENTAL_REACTOR_THREADS",
];
export function requestedExecutionProfile(environment) {
  const name = environment.OPENPROOF_E2E_EXECUTION_PROFILE;
  if (name === undefined) return undefined;
  if (!Object.hasOwn(profiles, name))
    throw new Error("Invalid executor qualification profile");
  for (const key of keys) {
    if (environment[key] !== profiles[name][key])
      throw new Error("Executor qualification profile does not match overrides");
  }
  return { name, requestedOverrides: { ...profiles[name] } };
}

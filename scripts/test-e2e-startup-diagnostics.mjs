import assert from "node:assert/strict";
import test from "node:test";
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

#!/usr/bin/env node
// Source-only policy guard for disposable SQL acceptance runners. CTest can
// return success when DB-dependent tests have been skipped or none registered.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const read = file => fs.readFileSync(path.join(root, file), "utf8");
const auth = read("scripts/run-disposable-postgres-auth-tests.sh");
const canonical = read("scripts/run-disposable-postgres-canonical-tests.sh");

test("native auth SQL runner requires actual non-skipped testcases", () => {
  assert.ok(auth.includes('--output-junit "$work/test-results.xml"'));
  assert.ok(auth.includes('[[ ! -s "$work/test-results.xml" ]]'));
  assert.ok(auth.includes('! grep -q \'<testcase\' "$work/test-results.xml"'));
  assert.ok(auth.includes('grep -q \'<skipped\' "$work/test-results.xml"'));
  assert.ok(auth.includes('exit 1'));
});
test("disposable auth database is never started as root or redirected to production", () => {
  assert.ok(auth.includes('! runuser -u postgres -- /usr/bin/true'));
  assert.ok(auth.indexOf('! runuser -u postgres -- /usr/bin/true') <
            auth.indexOf('work="$(mktemp -d'));
  assert.ok(auth.includes('listen_addresses='));
  assert.ok(auth.includes('unix_socket_directories=$work'));
  assert.ok(auth.includes('if [[ "$started" == 1 ]]'));
  assert.ok(!auth.includes('pg_ctlcluster'));
});
test("canonical SQL runner denies both skipped tests and empty discovery", () => {
  assert.ok(canonical.includes('--output-junit "$work/test-results.xml"'));
  assert.ok(canonical.includes('! grep -q \'<testcase\' "$work/test-results.xml"'));
  assert.ok(canonical.includes('grep -q \'<skipped\' "$work/test-results.xml"'));
  assert.ok(canonical.includes('! runuser -u postgres -- /usr/bin/true'));
  assert.ok(canonical.indexOf('! runuser -u postgres -- /usr/bin/true') <
            canonical.indexOf('work="$(mktemp -d'));
});

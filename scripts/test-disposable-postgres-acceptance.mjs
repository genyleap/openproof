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
const integration = read("scripts/run-disposable-postgres-integration-tests.sh");

test("destructive integration tests require a dedicated acknowledged Unix socket",()=>{
  const fixture=read("tests/storage/postgres_integration_test.cpp");
  const setup=fixture.slice(fixture.indexOf("void SetUp()"),fixture.indexOf("struct ConnectionDeleter"));
  assert.doesNotMatch(setup,/getenv\("OPENPROOF_TEST_POSTGRES"\)/);
  for(const marker of ['getenv("OPENPROOF_TEST_POSTGRES_INTEGRATION")',
    'getenv("OPENPROOF_TEST_POSTGRES_INTEGRATION_ACK")','ASSERT_STREQ(ack,"YES_EXCLUSIVE_DISPOSABLE_DATABASE")',
    'value.starts_with(prefix)','value.ends_with(suffix)','prefix.size()+8U+suffix.size()',
    'getenv("PGHOSTADDR")','getenv("PGSERVICE")','getenv("PGOPTIONS")'])
    assert.ok(setup.indexOf(marker)>=0 && setup.indexOf(marker)<setup.indexOf("migrateSchemaBeforeListener"),marker);
  for(const marker of ['mktemp -d /tmp/openproof-integration-pg.XXXXXXXX','listen_addresses=',
    'unix_socket_directories=$work','unset "$variable"','--output-junit "$work/test-results.xml"',
    "grep -q '<skipped'",'OPENPROOF_TEST_POSTGRES_INTEGRATION_ACK=YES_EXCLUSIVE_DISPOSABLE_DATABASE'])
    assert.ok(integration.includes(marker),marker);
  assert.ok(integration.indexOf('! runuser -u postgres -- /usr/bin/true')<integration.indexOf('work="$(mktemp -d'));
  for(const file of [".github/workflows/ci.yml",".github/workflows/release.yml","scripts/qualify-production.sh"])
    assert.ok(read(file).includes("run-disposable-postgres-integration-tests.sh"),file);
});

test("native auth SQL runner requires actual non-skipped testcases", () => {
  assert.ok(auth.includes('--output-junit "$work/test-results.xml"'));
  // A fresh native SQL test must accept an explicit isolated CMake build
  // directory and must not silently fall back to an older cached test binary.
  assert.ok(auth.includes('build_dir="${1:-$repo/cmake-build-gcc-release}"'));
  assert.ok(auth.includes('[[ ! -f "$build_dir/CMakeCache.txt"'));
  assert.ok(auth.includes('ctest --test-dir "$build_dir"'));
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

test("canonical SQL fixture includes sender constraint schema and supports exact cached build",()=>{
  assert.match(canonical,/0010_oauth_sender_constraints\.sql/);
  assert.ok(canonical.indexOf("0007_oauth_device_flow.sql")<canonical.indexOf("0008_oauth_par.sql"));
  assert.ok(canonical.indexOf("0008_oauth_par.sql")<canonical.indexOf("0009_oauth_jar.sql"));
  assert.ok(canonical.indexOf("0009_oauth_jar.sql")<canonical.indexOf("0010_oauth_sender_constraints.sql"));
  assert.ok(canonical.indexOf("0003_identity_provider.sql")<canonical.indexOf("0010_oauth_sender_constraints.sql"));
  assert.ok(canonical.indexOf("0010_oauth_sender_constraints.sql")<canonical.indexOf("0021_verification_reservation_generation.sql"));
  assert.ok(canonical.includes('build_dir="${1:-$repo/cmake-build-gcc-release}"'));
  assert.ok(canonical.includes('ctest --test-dir "$build_dir"'));
  assert.ok(canonical.indexOf('[[ ! -f "$build_dir/CMakeCache.txt"')<canonical.indexOf('work="$(mktemp -d'));
});

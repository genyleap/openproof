#!/usr/bin/env node
// Guard the disposable PostgreSQL test fixture against future accidental
// connection to production and password-like sample code in Git history.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const text = fs.readFileSync(
  path.join(import.meta.dirname, "run-disposable-postgres-recovery-tests.py"),
  "utf8");
const compatibility = fs.readFileSync(
  path.join(import.meta.dirname, "run-disposable-postgres-recovery-tests.sh"),
  "utf8");

test("OS account lookup never uses password database fields or plaintext credentials", () => {
  assert.doesNotMatch(text, /\bimport\s+pwd\b|\bpwd\.getpwnam\(|\bpw_passwd\b/);
  assert.match(text, /must_drop_privileges = os\.geteuid\(\) == 0/);
  assert.match(text, /shutil\.chown\(work, user="postgres", group="postgres"\)/);
  assert.match(text, /command = \["\/usr\/sbin\/runuser", "-u", "postgres", "--", \*command\]/);
});

test("disposable PostgreSQL cannot bind TCP or use trust/password authentication", () => {
  assert.match(text, /tempfile\.TemporaryDirectory\(prefix="openproof-recovery-pg-", dir="\/tmp"\)/);
  assert.match(text, /"--auth-local=peer", "--auth-host=reject"/);
  assert.match(text, /-c listen_addresses= -c unix_socket_directories=\{work\}/);
  assert.doesNotMatch(text, /["']trust["']|--auth-(?:local|host)=(?:trust|password)/);
  assert.doesNotMatch(text, /\b(?:127\.0\.0\.1|localhost|0\.0\.0\.0)\b/);
});

test("test runner discards inherited PostgreSQL secrets and uses only private socket", () => {
  assert.match(text, /not key\.startswith\("PG"\) and key != "OPENPROOF_TEST_POSTGRES"/);
  assert.match(text, /f"host=\{work\} port=\{PORT\} dbname=postgres"/);
  assert.match(text, /if must_drop_privileges:\s+uri \+= " user=postgres"/);
  assert.match(text, /env\["OPENPROOF_TEST_POSTGRES"\] = uri/);
  assert.match(text, /shutil\.copyfile\(/);
  assert.match(text, /executable\.chmod\(0o700\)/);
  assert.match(text, /shutil\.chown\(executable, user="postgres", group="postgres"\)/);
  assert.match(text, /command = \[str\(executable\)\]/);
  assert.doesNotMatch(text, /(?:host|dbname|password)=(?:\/opt\/genyleap|127\.0\.0\.1|localhost)/i);
});

test("errors and cleanup cannot fall back to a production database", () => {
  assert.match(text, /finally:\s+if started:/);
  assert.match(text, /pg\(\[str\(PGBIN \/ "pg_ctl"\), "-D", str\(datadir\)/);
  assert.match(text, /subprocess\.run\(command, env=env, text=True, check=False\)/);
  assert.match(text, /raise RuntimeError/);
});


test("legacy shell entrypoint cannot bypass peer-authenticated private runner", () => {
  assert.match(compatibility, /set -euo pipefail/);
  assert.match(compatibility,
    /exec python3 "\$\(dirname "\$0"\)\/run-disposable-postgres-recovery-tests\.py" "\$@"/);
  assert.doesNotMatch(compatibility, /\b(?:initdb|pg_ctl|ctest)\b|\btrust\b/);
  assert.doesNotMatch(compatibility, /\bOPENPROOF_TEST_POSTGRES\b/);
});

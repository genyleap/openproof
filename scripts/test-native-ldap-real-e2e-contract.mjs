import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { parseFixtureSubjects } from "./ci/native-ldap-fixture.mjs";
const root = path.resolve(import.meta.dirname, "..");
const read = p => fs.readFileSync(path.join(root,p), "utf8");
test("real LDAP fixture is guarded, loopback-only and owns its process", () => {
  const fixture = read("scripts/ci/native-ldap-fixture.mjs");
  assert.match(fixture, /OPENPROOF_E2E_DATABASE_ACK !== "YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE"/);
  assert.match(fixture, /ldaps:\/\/127\.0\.0\.1:/);
  assert.match(fixture, /"--publish", "127\.0\.0\.1:" \+ port \+ ":1636"/);
  assert.match(fixture, /"--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"/);
  assert.match(fixture, /owner !== token/);
  assert.doesNotMatch(fixture, /--privileged|apparmor=unconfined|--network=host/);
  assert.match(fixture, /LDAPTLS_REQCERT: "demand"/);
  assert.match(fixture, /LDAPTLS_CACERT: ca/);
  assert.match(fixture, /child\.kill\("SIGTERM"\)/);
  assert.doesNotMatch(fixture, /service slapd|systemctl|killall|pkill|LDAPTLS_REQCERT: "never"/);
  assert.match(fixture, /"entryUUID"/);
});
test("HTTP LDAP E2E checks negative proofs against persistent row counts", () => {
  const e2e = read("scripts/e2e-identity-platform.mjs");
  assert.match(e2e, /url\.hostname !== "127\.0\.0\.1"/);
  assert.match(e2e, /url\.pathname !== "\/openproof_native_ldap_e2e_ci"/);
  assert.match(e2e, /await startNativeLdapFixture\(tempRoot, reservePort\)/);
  assert.match(e2e, /"intentionally-invalid-fixture-password", wrongJar\), 401/);
  assert.match(e2e, /completeLdap\(unlinked, ldapFixture\.unlinkedPassword, unlinkedJar\), 401/);
  assert.match(e2e, /assert\.equal\(counts\(\), initialCounts/);
  assert.match(e2e, /assert\.equal\(counts\(\), afterLogin/);
  assert.match(e2e, /identity_id, "e2e-ldap-linked"/);
  const ci = read(".github/workflows/ci.yml");
  assert.match(ci, /createdb -O openproof_ci openproof_native_ldap_e2e_ci/);
  assert.match(ci, /OPENPROOF_E2E_NATIVE_LDAP_FIXTURE: "1"/);
});

test("LDIF identity mapping requires two independently unique subjects", () => {
  const linked = "11111111-1111-4111-8111-111111111111";
  const unlinked = "22222222-2222-4222-8222-222222222222";
  const first = "dn: uid=linked,ou=people,dc=e2e,dc=invalid\nuid: linked\nentryUUID: " + linked;
  const second = "dn: uid=unlinked,ou=people,dc=e2e,dc=invalid\nentryUUID: " + unlinked + "\nuid: unlinked";
  assert.deepEqual(parseFixtureSubjects(second + "\n\n" + first + "\n\n"), { linked, unlinked });
  assert.equal(parseFixtureSubjects(first), null);
  assert.equal(parseFixtureSubjects(first + "\n\n" + first), null);
  assert.equal(parseFixtureSubjects(first + "\n\n" + second.replace(unlinked, linked)), null);
  assert.equal(parseFixtureSubjects(first + "\n\n" + second + "\n\n" + first), null);
  assert.equal(parseFixtureSubjects(first + "\n\n" + second.replace("uid: unlinked", "uid: other")), null);
  assert.equal(parseFixtureSubjects(first + "\n\n" + second.replace(unlinked, "malformed")), null);
  assert.equal(parseFixtureSubjects(first + "\nentryUUID: " + unlinked + "\n\n" + second), null);
});

test("fixture verifies a real certificate chain and tests bind before full build", () => {
  const fixture = read("scripts/ci/native-ldap-fixture.mjs");
  assert.match(fixture, /basicConstraints=critical,CA:FALSE/);
  assert.match(fixture, /extendedKeyUsage=serverAuth/);
  assert.match(fixture, /rejectUnauthorized: true/);
  assert.match(fixture, /TLSCertificateFile \/fixture\/ldap\.crt/);
  assert.match(fixture, /TLS_REQCERT demand/);
  assert.match(fixture, /const uri = "ldaps:\/\/127\.0\.0\.1:"/);
  const smoke = read("scripts/ci/test-native-ldap-fixture.mjs");
  assert.match(smoke, /spawnSync\("ldapwhoami"/);
  assert.match(smoke, /assert\.equal\(bind\(\)\.status, 0/);
  assert.match(smoke, /assert\.notEqual\(denied\.status, 0/);
  assert.match(read(".github/workflows/ci.yml"), /name: Real LDAPS fixture preflight/);
});

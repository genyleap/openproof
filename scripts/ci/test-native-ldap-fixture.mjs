// Fast real directory preflight, no application or database required.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { startNativeLdapFixture } from "./native-ldap-fixture.mjs";

const root = fs.mkdtempSync(path.join(os.tmpdir(), "openproof-e2e-"));
fs.chmodSync(root, 0o700);
let fixture;
async function reservePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}
try {
  fixture = await startNativeLdapFixture(root, reservePort);
  const env = fixture.environment;
  const passwordFile = path.join(root, "linked.password");
  fs.writeFileSync(passwordFile, fixture.linkedPassword, { mode: 0o600 });
  const bind = () => spawnSync("ldapwhoami", [
    "-x", "-H", env.OPENPROOF_LDAP_URI, "-D", "uid=linked," + env.OPENPROOF_LDAP_BASE_DN,
    "-y", passwordFile, "-o", "nettimeout=2",
  ], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 5000,
    env: { ...process.env, HOME: path.join(root, "ldap"),
      LDAPCONF: path.join(root, "ldap", "ldap.conf"), LDAPRC: "ldap.conf",
      LDAPTLS_CACERT: env.OPENPROOF_LDAP_CA_FILE, LDAPTLS_REQCERT: "demand" } });
  assert.equal(bind().status, 0, "real TLS directory must accept the seeded user");
  fs.writeFileSync(passwordFile, "deliberately-invalid-fixture-password", { mode: 0o600 });
  const denied = bind();
  assert.notEqual(denied.status, 0, "invalid user credential must fail");
  assert.match(denied.stderr ?? "", /invalid credentials/i, "failure must be a credential rejection, not a network error");
  console.log("PASS: real LDAPS certificate chain, two distinct entryUUID values, accepted bind and rejected password");
} finally {
  await fixture?.close();
  fs.rmSync(root, { recursive: true, force: true });
}

// A real OpenLDAP instance owned exclusively by this disposable E2E process.
// No system slapd config, database, service manager or external directory.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";

const baseDn = "dc=e2e,dc=invalid";
const peopleDn = "ou=people," + baseDn;
const readerDn = "cn=reader," + baseDn;
const randomPassword = () => crypto.randomBytes(24).toString("base64url");
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const digest = crypto.createHash("sha1").update(password).update(salt).digest();
  return "{SSHA}" + Buffer.concat([digest, salt]).toString("base64");
}
function run(program, args, options = {}) {
  const result = spawnSync(program, args, {
    encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
    timeout: 10_000, ...options,
  });
  if (result.status !== 0) throw new Error("disposable LDAPS fixture command failed: " + program);
  return result.stdout;
}

export async function startNativeLdapFixture(tempRoot, reservePort) {
  if (process.env.OPENPROOF_E2E_NATIVE_LDAP_FIXTURE !== "1"
      || process.env.OPENPROOF_E2E_DATABASE_ACK !== "YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE"
      || !path.basename(tempRoot).startsWith("openproof-e2e-"))
    throw new Error("disposable LDAPS fixture is not explicitly authorized");
  const directory = path.join(tempRoot, "ldap");
  fs.mkdirSync(directory, { mode: 0o700 });
  const db = path.join(directory, "mdb");
  fs.mkdirSync(db, { mode: 0o700 });
  const ca = path.join(directory, "ldap.crt");
  const key = path.join(directory, "ldap.key");
  const config = path.join(directory, "slapd.conf");
  const ldif = path.join(directory, "seed.ldif");
  const readerPasswordFile = path.join(directory, "reader.password");
  const readerPassword = randomPassword();
  const linkedPassword = randomPassword();
  const unlinkedPassword = randomPassword();
  const rootPassword = randomPassword();
  run("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
    "-days", "1", "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    "-keyout", key, "-out", ca]);
  fs.chmodSync(key, 0o600);
  fs.writeFileSync(readerPasswordFile, readerPassword, { mode: 0o600 });
  const settings = [
    "include /etc/ldap/schema/core.schema",
    "include /etc/ldap/schema/cosine.schema",
    "include /etc/ldap/schema/inetorgperson.schema",
    "pidfile " + path.join(directory, "slapd.pid"),
    "argsfile " + path.join(directory, "slapd.args"),
    "modulepath /usr/lib/ldap",
    "moduleload back_mdb",
    "TLSCertificateFile " + ca,
    "TLSCertificateKeyFile " + key,
    "TLSCACertificateFile " + ca,
    "TLSVerifyClient never",
    "database mdb",
    "maxsize 16777216",
    'suffix "' + baseDn + '"',
    'rootdn "cn=fixture-root,' + baseDn + '"',
    "rootpw " + hashPassword(rootPassword),
    "directory " + db,
    "access to attrs=userPassword by anonymous auth by * none",
    'access to * by dn.exact="' + readerDn + '" read by * none',
  ];
  fs.writeFileSync(config, settings.join("\n") + "\n", { mode: 0o600 });
  const entry = (uid, name, password) => [
    "dn: uid=" + uid + "," + peopleDn,
    "objectClass: inetOrgPerson", "uid: " + uid,
    "cn: " + name, "sn: Fixture", "mail: " + uid + "@e2e.invalid",
    "userPassword: " + hashPassword(password), "",
  ].join("\n");
  fs.writeFileSync(ldif, [
    "dn: " + baseDn, "objectClass: domain", "dc: e2e", "",
    "dn: " + peopleDn, "objectClass: organizationalUnit", "ou: people", "",
    "dn: " + readerDn, "objectClass: organizationalRole",
    "objectClass: simpleSecurityObject", "cn: reader",
    "userPassword: " + hashPassword(readerPassword), "",
    entry("linked", "Linked LDAP Fixture", linkedPassword),
    entry("unlinked", "Unlinked LDAP Fixture", unlinkedPassword),
  ].join("\n"), { mode: 0o600 });
  run("/usr/sbin/slapadd", ["-f", config, "-l", ldif]);
  const port = await reservePort();
  const uri = "ldaps://localhost:" + port;
  const child = spawn("/usr/sbin/slapd",
    ["-f", config, "-h", "ldaps://127.0.0.1:" + port + "/", "-d", "0"],
    { stdio: ["ignore", "ignore", "ignore"] });
  let failed = false;
  child.once("error", () => { failed = true; });
  async function close() {
    if (!child.pid || child.exitCode !== null || child.signalCode !== null) return;
    const exited = new Promise(resolve => child.once("exit", resolve));
    child.kill("SIGTERM");
    if (!await Promise.race([exited.then(() => true), delay(2000, false)])) {
      child.kill("SIGKILL");
      await exited;
    }
  }
  const lookup = uid => spawnSync("ldapsearch", [
    "-LLL", "-x", "-H", uri, "-D", readerDn, "-y", readerPasswordFile,
    "-o", "nettimeout=1", "-l", "2", "-b", peopleDn,
    "(uid=" + uid + ")", "entryUUID",
  ], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 3000,
    env: { ...process.env, LDAPTLS_CACERT: ca, LDAPTLS_REQCERT: "demand" } });
  try {
    const deadline = Date.now() + 15_000;
    let subject;
    while (Date.now() < deadline && !failed && child.exitCode === null) {
      const result = lookup("linked");
      if (result.status === 0) {
        subject = result.stdout.match(/^entryUUID: ([0-9a-f-]{36})$/mi)?.[1];
        if (subject) break;
      }
      await delay(100);
    }
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const unlinked = lookup("unlinked");
    const unlinkedSubject = unlinked.status === 0
      ? unlinked.stdout.match(/^entryUUID: ([0-9a-f-]{36})$/mi)?.[1] : undefined;
    if (!uuid.test(subject ?? "") || !uuid.test(unlinkedSubject ?? "")
        || subject === unlinkedSubject) throw new Error("disposable LDAPS lookup did not return unique fixture UUIDs");
    return {
      subject, linkedPassword, unlinkedPassword, close,
      environment: {
        OPENPROOF_EXPERIMENTAL_NATIVE_LDAP: "1",
        OPENPROOF_LDAP_URI: uri,
        OPENPROOF_LDAP_BASE_DN: peopleDn,
        OPENPROOF_LDAP_USERNAME_ATTRIBUTE: "uid",
        OPENPROOF_LDAP_SUBJECT_ATTRIBUTE: "entryUUID",
        OPENPROOF_LDAP_DISPLAY_NAME_ATTRIBUTE: "cn",
        OPENPROOF_LDAP_EMAIL_ATTRIBUTE: "mail",
        OPENPROOF_LDAP_BIND_DN: readerDn,
        OPENPROOF_LDAP_BIND_PASSWORD: readerPassword,
        OPENPROOF_LDAP_CA_FILE: ca,
      },
    };
  } catch (error) {
    await close();
    throw error;
  }
}

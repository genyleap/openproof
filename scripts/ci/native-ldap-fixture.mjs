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

// Parse LDIF records rather than taking an unscoped regex match from the
// complete output. LDAP attribute names are case-insensitive.
export function parseFixtureSubjects(output) {
  const entries = new Map();
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const records = output.trim().split(/\r?\n\r?\n/).filter(Boolean);
  if (records.length !== 2) return null;
  for (const record of records) {
    const lines = record.split(/\r?\n/);
    const uid = lines.filter(line => /^uid: /i.test(line));
    const id = lines.filter(line => /^entryUUID: /i.test(line));
    if (uid.length !== 1 || id.length !== 1) return null;
    const name = uid[0].slice(5);
    const subject = id[0].slice(11).toLowerCase();
    if (!["linked", "unlinked"].includes(name) || !uuid.test(subject)
        || entries.has(name)) return null;
    entries.set(name, subject);
  }
  if (entries.get("linked") === entries.get("unlinked")) return null;
  return { linked: entries.get("linked"), unlinked: entries.get("unlinked") };
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
    "userPassword: " + hashPassword(password),
  ].join("\n");
  // LDIF records must be separated by a complete empty line, including
  // the boundary between the two generated user records and the final EOF.
  const records = [
    ["dn: " + baseDn, "objectClass: domain", "dc: e2e"].join("\n"),
    ["dn: " + peopleDn, "objectClass: organizationalUnit", "ou: people"].join("\n"),
    ["dn: " + readerDn, "objectClass: organizationalRole",
      "objectClass: simpleSecurityObject", "cn: reader",
      "userPassword: " + hashPassword(readerPassword)].join("\n"),
    entry("linked", "Linked LDAP Fixture", linkedPassword),
    entry("unlinked", "Unlinked LDAP Fixture", unlinkedPassword),
  ];
  fs.writeFileSync(ldif, records.join("\n\n") + "\n\n", { mode: 0o600 });
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
  const lookup = () => spawnSync("ldapsearch", [
    "-LLL", "-x", "-H", uri, "-D", readerDn, "-y", readerPasswordFile,
    "-o", "nettimeout=1", "-o", "ldif-wrap=no", "-l", "2", "-b", peopleDn,
    "(|(uid=linked)(uid=unlinked))", "uid", "entryUUID",
  ], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 3000,
    env: { ...process.env, LDAPTLS_CACERT: ca, LDAPTLS_REQCERT: "demand" } });
  try {
    const deadline = Date.now() + 15_000;
    let subject;
    let lastOutcome = "not-ready";
    while (Date.now() < deadline && !failed && child.exitCode === null
           && child.signalCode === null) {
      const result = lookup();
      if (result.status === 0) {
        // One directory snapshot must contain exactly the two requested
        // entries, with unique stable identifiers. Never infer identity
        // from record order or accidentally match the first UUID twice.
        const entries = parseFixtureSubjects(result.stdout);
        if (entries) {
          subject = entries.linked;
          break;
        }
        lastOutcome = "invalid-entry-set";
      } else {
        lastOutcome = result.error?.code === "ETIMEDOUT"
          ? "search-timeout"
          : "search-exit-" + (Number.isInteger(result.status) ? result.status : "unknown");
      }
      await delay(100);
    }
    if (!subject) {
      // The outcome contains only a fixed category or numeric exit status.
      // Do not print LDAP stdout/stderr, DNs, UUIDs or fixture credentials.
      throw new Error("disposable LDAPS lookup did not return unique fixture UUIDs (" + lastOutcome + ")");
    }
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

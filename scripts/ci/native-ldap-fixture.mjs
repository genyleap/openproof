// A real OpenLDAP instance in a dedicated unprivileged disposable container.
// No host slapd config, service manager, confinement changes or external directory.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import tls from "node:tls";
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
  const ca = path.join(directory, "ca.crt");
  const caKey = path.join(directory, "ca.key");
  const cert = path.join(directory, "ldap.crt");
  const key = path.join(directory, "ldap.key");
  const csr = path.join(directory, "ldap.csr");
  const extensions = path.join(directory, "ldap.ext");
  const ldapConf = path.join(directory, "ldap.conf");
  const config = path.join(directory, "slapd.conf");
  const ldif = path.join(directory, "seed.ldif");
  const readerPasswordFile = path.join(directory, "reader.password");
  const readerPassword = randomPassword();
  const linkedPassword = randomPassword();
  const unlinkedPassword = randomPassword();
  const rootPassword = randomPassword();
  // Use a distinct CA and server leaf so OpenSSL and GnuTLS independently
  // verify a normal certificate chain rather than a self-signed CA-as-leaf.
  run("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
    "-days", "1", "-subj", "/CN=OpenProof disposable LDAP CA",
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    "-keyout", caKey, "-out", ca]);
  run("openssl", ["req", "-new", "-newkey", "rsa:2048", "-nodes",
    "-subj", "/CN=localhost", "-keyout", key, "-out", csr]);
  fs.writeFileSync(extensions, [
    "basicConstraints=critical,CA:FALSE",
    "keyUsage=critical,digitalSignature,keyEncipherment",
    "extendedKeyUsage=serverAuth",
    "subjectAltName=DNS:localhost,IP:127.0.0.1",
  ].join("\n") + "\n", { mode: 0o600 });
  run("openssl", ["x509", "-req", "-in", csr, "-CA", ca, "-CAkey", caKey,
    "-CAcreateserial", "-days", "1", "-sha256", "-extfile", extensions, "-out", cert]);
  fs.chmodSync(caKey, 0o600);
  fs.chmodSync(key, 0o600);
  run("openssl", ["verify", "-CAfile", ca, "-verify_ip", "127.0.0.1", cert]);
  fs.writeFileSync(ldapConf, "TLS_CACERT " + ca + "\nTLS_REQCERT demand\n", { mode: 0o600 });
  fs.writeFileSync(readerPasswordFile, readerPassword, { mode: 0o600 });
  const settings = [
    "include /etc/ldap/schema/core.schema",
    "include /etc/ldap/schema/cosine.schema",
    "include /etc/ldap/schema/inetorgperson.schema",
    "pidfile /fixture/slapd.pid",
    "argsfile /fixture/slapd.args",
    "modulepath /usr/lib/ldap",
    "moduleload back_mdb",
    "TLSCertificateFile /fixture/ldap.crt",
    "TLSCertificateKeyFile /fixture/ldap.key",
    "TLSCACertificateFile /fixture/ca.crt",
    "TLSVerifyClient never",
    "database mdb",
    "maxsize 16777216",
    'suffix "' + baseDn + '"',
    'rootdn "cn=fixture-root,' + baseDn + '"',
    "rootpw " + hashPassword(rootPassword),
    "directory /fixture/mdb",
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
  if (typeof process.getuid !== "function" || process.getuid() === 0) {
    throw new Error("real LDAPS fixture requires an unprivileged Linux runner");
  }
  const port = await reservePort();
  const uri = "ldaps://127.0.0.1:" + port;
  const token = crypto.randomBytes(16).toString("hex");
  const containerName = "openproof-ldap-e2e-" + token;
  const child = spawn("docker", [
    "run", "--rm", "--name", containerName,
    "--label", "org.openproof.fixture=" + token,
    "--user", process.getuid() + ":" + process.getgid(),
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
    "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
    "--publish", "127.0.0.1:" + port + ":1636",
    "--mount", "type=bind,source=" + directory + ",target=/fixture",
    "openproof-ldap-fixture:ci",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let failed = false;
  let daemonOutcome = "no-startup-error-observed";
  child.once("error", () => { failed = true; });
  // Classify, never forward raw diagnostics. Even a fixture log may include
  // bind DNs or credential material. Drain continuously to avoid pipe stalls.
  child.stderr.on("data", chunk => {
    const message = chunk.toString("utf8");
    if (/permission denied|operation not permitted/i.test(message)) daemonOutcome = "permission";
    else if (/address already in use|bind\(\) failed/i.test(message)) daemonOutcome = "listen";
    else if (/TLS.*(?:error|failed)|certificate.*(?:error|failed)/i.test(message)) daemonOutcome = "tls";
    else if (/mdb.*(?:error|failed)/i.test(message)) daemonOutcome = "mdb";
  });
  async function close() {
    // Inspect the exact randomly named container and match its ownership
    // label before stopping it. Never stop a host daemon or other container.
    const inspect = () => spawnSync("docker", [
      "inspect", "--format", '{{.Id}} {{index .Config.Labels "org.openproof.fixture"}}',
      containerName,
    ], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 5000 });
    const stopOwned = () => {
      const info = inspect();
      if (info.status !== 0) return;
      const [id, owner] = info.stdout.trim().split(" ");
      if (!/^[0-9a-f]{64}$/.test(id) || owner !== token)
        throw new Error("disposable LDAPS container ownership mismatch");
      const stopped = spawnSync("docker", ["stop", "--time", "2", id],
        { stdio: "ignore", timeout: 5000 });
      if (stopped.status !== 0 && inspect().status === 0)
        throw new Error("disposable LDAPS container failed to stop");
    };
    stopOwned();
    if (child.pid && child.exitCode === null && child.signalCode === null) {
      const exited = new Promise(resolve => child.once("exit", resolve));
      if (!await Promise.race([exited.then(() => true), delay(2000, false)])) {
        child.kill("SIGTERM"); // Only our attached docker CLI, not a host service.
        if (!await Promise.race([exited.then(() => true), delay(2000, false)])) {
          child.kill("SIGKILL");
          await exited;
        }
      }
    }
    stopOwned(); // Cover a startup/cleanup race after the attached CLI exited.
  }
  const lookup = () => spawnSync("ldapsearch", [
    "-LLL", "-x", "-H", uri, "-D", readerDn, "-y", readerPasswordFile,
    "-o", "nettimeout=1", "-l", "2", "-b", peopleDn,
    "(|(uid=linked)(uid=unlinked))", "uid", "entryUUID",
  ], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 3000,
    env: { ...process.env, HOME: directory, LDAPCONF: ldapConf,
      LDAPRC: "ldap.conf", LDAPTLS_CACERT: ca, LDAPTLS_REQCERT: "demand" } });
  // Independently prove the endpoint serves the pinned certificate and
  // hostname. No anonymous/simple bind is attempted by this probe.
  function verifyTls() {
    return new Promise(resolve => {
      const socket = tls.connect({ host: "127.0.0.1", port,
        servername: "localhost", ca: fs.readFileSync(ca), rejectUnauthorized: true });
      const done = outcome => { socket.destroy(); resolve(outcome); };
      socket.once("secureConnect", () => done(socket.authorized ? "verified" : "unverified"));
      socket.once("error", error => done(
        ["ECONNREFUSED", "ECONNRESET", "ETIMEDOUT"].includes(error.code)
          ? error.code : "certificate-or-tls"));
      socket.setTimeout(1000, () => done("timeout"));
    });
  }
  try {
    const deadline = Date.now() + 15_000;
    let subject;
    let lastOutcome = "not-ready";
    let tlsOutcome = "not-ready";
    while (Date.now() < deadline && !failed && child.exitCode === null
           && child.signalCode === null) {
      if (tlsOutcome !== "verified") tlsOutcome = await verifyTls();
      if (tlsOutcome !== "verified") { await delay(100); continue; }
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
        const diagnostic = result.stderr ?? "";
        lastOutcome = result.error?.code === "ETIMEDOUT" ? "search-timeout"
          : /invalid credentials/i.test(diagnostic) ? "bind-rejected"
          : /certificate|TLS/i.test(diagnostic) ? "ldap-tls"
          : /can't contact LDAP server|cannot contact LDAP server/i.test(diagnostic) ? "ldap-transport"
          : /unrecognized option|invalid option|usage:/i.test(diagnostic) ? "ldap-client-option"
          : "search-exit-" + (Number.isInteger(result.status) ? result.status : "unknown");
      }
      await delay(100);
    }
    if (!subject) {
      // The outcome contains only a fixed category or numeric exit status.
      // Do not print LDAP stdout/stderr, DNs, UUIDs or fixture credentials.
      const processState = failed ? "spawn-failed" : child.signalCode ? "signaled"
        : child.exitCode === null ? "running" : "exit-" + child.exitCode;
      throw new Error("disposable LDAPS fixture failed: tls=" + tlsOutcome
        + "; search=" + lastOutcome + "; daemon=" + processState + "/" + daemonOutcome);
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

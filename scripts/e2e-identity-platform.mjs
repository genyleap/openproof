#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";

import { startLocalDemoPortal } from "./local-demo-portal.mjs";
import { startNativeLdapFixture } from "./ci/native-ldap-fixture.mjs";
import { classifyStartupFailure, replaceFixturePort } from "./ci/e2e-startup-diagnostics.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const databaseUrl = process.env.OPENPROOF_E2E_POSTGRES ?? "";
const databaseAck = process.env.OPENPROOF_E2E_DATABASE_ACK ?? "";
const nativeLdapFixtureEnabled = process.env.OPENPROOF_E2E_NATIVE_LDAP_FIXTURE === "1";
const metricsFile = process.env.OPENPROOF_E2E_METRICS_FILE ?? "";
const mixedLoadRequests = Number.parseInt(
  process.env.OPENPROOF_E2E_LOAD_REQUESTS ?? "600", 10,
);
const mixedLoadConcurrency = Number.parseInt(
  process.env.OPENPROOF_E2E_LOAD_CONCURRENCY ?? "24", 10,
);
const holdOpen = process.env.OPENPROOF_E2E_HOLD_OPEN === "1";
const connectionFile = process.env.OPENPROOF_E2E_CONNECTION_FILE ?? "";
const realAuthMode = holdOpen && process.env.OPENPROOF_E2E_REAL_AUTH === "1";
const requestedFrontPort = Number.parseInt(
  process.env.OPENPROOF_E2E_FRONT_PORT ?? "0", 10,
);
const realFarcasterRpcEndpoint =
  process.env.OPENPROOF_E2E_FARCASTER_RPC_ENDPOINT ?? "https://mainnet.optimism.io/";
const binary = path.resolve(
  process.env.OPENPROOF_E2E_OPP ?? path.join(root, "cmake-build-gcc-release/apps/opp/opp"),
);

function fail(message) {
  throw new Error(`identity E2E: ${message}`);
}

function command(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
  if (result.status !== 0) {
    // Child stderr/stdout may contain database URLs or credentials.
    // Surface the failed executable and exit status, not raw output.
    fail(`${program} failed with exit status ${result.status ?? "unknown"}`);
  }
  return result.stdout;
}

function tomlString(value) {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function listen(server, port = 0) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", reject);
      resolve(server.address().port);
    });
  });
}

async function reservePort() {
  const server = http.createServer();
  const port = await listen(server);
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

function closeServer(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

class CookieJar {
  #values = new Map();

  apply(setCookies) {
    for (const header of setCookies ?? []) {
      const [pair, ...attributes] = header.split(";");
      const separator = pair.indexOf("=");
      if (separator <= 0) continue;
      const name = pair.slice(0, separator).trim();
      const value = pair.slice(separator + 1).trim();
      const expired = attributes.some((item) => item.trim().toLowerCase() === "max-age=0");
      if (expired || value === "") this.#values.delete(name);
      else this.#values.set(name, value);
    }
  }

  header() {
    return [...this.#values].map(([name, value]) => `${name}=${value}`).join("; ");
  }
}

function base32Decode(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const symbol of text.toUpperCase().replaceAll("=", "")) {
    const value = alphabet.indexOf(symbol);
    if (value < 0) fail("bootstrap returned a malformed Base32 TOTP secret");
    bits += value.toString(2).padStart(5, "0");
  }
  const output = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    output.push(Number.parseInt(bits.slice(offset, offset + 8), 2));
  }
  return Buffer.from(output);
}

function totp(secret) {
  const counter = BigInt(Math.floor(Date.now() / 30_000));
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(counter);
  const digest = crypto.createHmac("sha1", base32Decode(secret)).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const value = (digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return value.toString().padStart(6, "0");
}

async function nextTotp(secret, previous) {
  const deadline = Date.now() + 35_000;
  while (Date.now() < deadline) {
    const candidate = totp(secret);
    if (candidate !== previous) return candidate;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  fail("TOTP step did not advance within the bounded rotation wait");
}

function base64Url(buffer) {
  return Buffer.from(buffer).toString("base64url");
}

function jsonBody(response) {
  try {
    return JSON.parse(response.body);
  } catch {
    // Never print response paths (OAuth codes and state can be in query
    // strings) or raw bodies (which may contain credentials) to CI logs.
    fail("expected JSON response, received invalid JSON");
  }
}

function expectStatus(response, ...allowed) {
  if (!allowed.includes(response.status)) {
    // CI logs must never contain OAuth codes, state, cookies, tokens,
    // or secrets from query parameters and unexpected response bodies.
    fail(`${response.method} request returned HTTP ${response.status}; expected ${allowed.join(", ")}`);
  }
}

function verifyIdToken(compact, jwks, expected) {
  const pieces = compact.split(".");
  assert.equal(pieces.length, 3, "ID Token must be a compact JWS");
  const header = JSON.parse(Buffer.from(pieces[0], "base64url").toString("utf8"));
  const claims = JSON.parse(Buffer.from(pieces[1], "base64url").toString("utf8"));
  assert.equal(header.alg, "RS256");
  const jwk = jwks.keys.find((candidate) => candidate.kid === header.kid);
  assert.ok(jwk, `JWKS does not contain kid ${header.kid}`);
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  assert.ok(crypto.verify(
    "RSA-SHA256",
    Buffer.from(`${pieces[0]}.${pieces[1]}`),
    key,
    Buffer.from(pieces[2], "base64url"),
  ), "ID Token signature is invalid");
  assert.equal(claims.iss, expected.issuer);
  assert.ok(Array.isArray(claims.aud)
    ? claims.aud.includes(expected.clientId)
    : claims.aud === expected.clientId);
  assert.equal(claims.nonce, expected.nonce);
  assert.ok(Number.isInteger(claims.exp) && claims.exp > Math.floor(Date.now() / 1000));
  return { header, claims };
}

async function concurrentSmoke(operations, requestCount = 600, concurrency = 24) {
  assert.ok(operations.length > 0);
  const latencies = [];
  let cursor = 0;
  const startedAt = performance.now();
  const workers = Array.from({ length: concurrency }, async () => {
    while (true) {
      const index = cursor++;
      if (index >= requestCount) return;
      const requestStarted = performance.now();
      const response = await operations[index % operations.length]();
      expectStatus(response, 200);
      latencies.push(performance.now() - requestStarted);
    }
  });
  await Promise.all(workers);
  const elapsedMs = performance.now() - startedAt;
  latencies.sort((left, right) => left - right);
  const percentile = (fraction) => latencies[Math.min(
    latencies.length - 1,
    Math.ceil(latencies.length * fraction) - 1,
  )];
  return {
    requests: requestCount,
    concurrency,
    requestsPerSecond: requestCount / (elapsedMs / 1000),
    p50Ms: percentile(0.50),
    p95Ms: percentile(0.95),
    p99Ms: percentile(0.99),
  };
}

// Optional Linux-only process metrics: these measure the *opp server*,
// not the Node.js load generator. The same runner provides the same tick
// frequency for a paired baseline. No credentials or request data are saved.
function readOppUsage(pid) {
  if (!Number.isInteger(pid) || pid <= 0 || process.platform !== "linux") return null;
  try {
    const raw = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    const tail = raw.slice(raw.lastIndexOf(")") + 2).trim().split(/\s+/);
    const userTicks = Number(tail[11]); // procfs fields 14 / 15
    const systemTicks = Number(tail[12]);
    const status = fs.readFileSync(`/proc/${pid}/status`, "utf8");
    const rssKiB = Number(status.match(/^VmRSS:\s*(\d+)\s+kB$/m)?.[1]);
    if (![userTicks, systemTicks, rssKiB].every(Number.isFinite)) return null;
    return { cpuTicks: userTicks + systemTicks, rssKiB };
  } catch {
    return null;
  }
}

async function main() {
  if (!databaseUrl) fail("OPENPROOF_E2E_POSTGRES must name a disposable empty PostgreSQL database");
  if (databaseAck !== "YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE") {
    fail("set OPENPROOF_E2E_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE");
  }
  if (!Number.isSafeInteger(mixedLoadRequests) || mixedLoadRequests < 6
      || mixedLoadRequests > 1_000_000
      || !Number.isSafeInteger(mixedLoadConcurrency) || mixedLoadConcurrency < 1
      || mixedLoadConcurrency > 1_000) {
    fail("E2E load requests/concurrency are outside the safe supported bounds");
  }
  if (!fs.existsSync(binary)) fail(`opp binary is missing at ${binary}`);

  if (nativeLdapFixtureEnabled) {
    let url;
    try { url = new URL(databaseUrl); } catch { fail("invalid LDAPS fixture database URL"); }
    if (url.protocol !== "postgresql:" || url.hostname !== "127.0.0.1"
        || url.pathname !== "/openproof_native_ldap_e2e_ci" || url.search || holdOpen)
      fail("native LDAP E2E requires the dedicated noninteractive loopback database");
  }
  const databaseName = command("psql", [databaseUrl, "-AtX", "-v", "ON_ERROR_STOP=1", "-c", "select current_database()"])
    .trim();
  if (!/(^|_)e2e($|_)/i.test(databaseName)
      || ["postgres", "template0", "template1"].includes(databaseName)) {
    fail("the PostgreSQL database name must contain a standalone 'e2e' segment");
  }
  const tableCount = Number(command("psql", [
    databaseUrl, "-AtX", "-v", "ON_ERROR_STOP=1", "-c",
    "select count(*) from information_schema.tables where table_schema not in ('pg_catalog','information_schema')",
  ]).trim());
  if (tableCount !== 0) fail("the E2E database must contain zero user tables before the run");

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "openproof-e2e-"));
  fs.chmodSync(tempRoot, 0o700);
  const tlsKey = path.join(tempRoot, "edge.key");
  const tlsCertificate = path.join(tempRoot, "edge.crt");
  const oldOidcKey = path.join(tempRoot, "oidc-old.key");
  const newOidcKey = path.join(tempRoot, "oidc-new.key");
  const replacementCredentialKey = path.join(tempRoot, "credential-encryption-v2.key");
  const replacementMasterKeyFile = path.join(tempRoot, "master-v2.key");
  const persistentKeyDirectory = path.join(tempRoot, "persistent-keys");
  const materializedCredentialKey = path.join(persistentKeyDirectory, "credential-encryption.key");
  const passwordPepperFile = path.join(persistentKeyDirectory, "password-pepper.key");
  const recoveryCodePepperFile = path.join(persistentKeyDirectory, "recovery-code-pepper.key");
  const auditChainKeyFile = path.join(persistentKeyDirectory, "audit-chain.key");
  const oauthClientSecretKeyFile = path.join(persistentKeyDirectory, "oauth-client-secret.key");
  const previousKeys = path.join(tempRoot, "previous-keys");
  const configurationPath = path.join(tempRoot, "openproof.e2e.toml");
  fs.mkdirSync(previousKeys, { mode: 0o700 });
  fs.mkdirSync(persistentKeyDirectory, { mode: 0o700 });

  command("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1",
    "-keyout", tlsKey, "-out", tlsCertificate, "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,digitalSignature",
  ]);
  command("openssl", ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", oldOidcKey]);
  command("openssl", ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", newOidcKey]);
  fs.writeFileSync(
    replacementCredentialKey, base64Url(crypto.randomBytes(24)), { mode: 0o600 });
  const replacementMasterKey = base64Url(crypto.randomBytes(48));
  fs.writeFileSync(replacementMasterKeyFile, replacementMasterKey, { mode: 0o600 });
  for (const privateFile of [tlsKey, oldOidcKey, newOidcKey]) fs.chmodSync(privateFile, 0o600);

  const certificate = fs.readFileSync(tlsCertificate);
  const privateTlsKey = fs.readFileSync(tlsKey);
  const notifications = [];
  const deliveryToken = base64Url(crypto.randomBytes(32));
  const metricsToken = base64Url(crypto.randomBytes(32));
  const farcasterFid = 6841;
  const farcasterAddress = "0x1111111111111111111111111111111111111111";
  const farcasterAuthAddress = "0x2222222222222222222222222222222222222222";
  const farcasterIdRegistry = "0x00000000fc6c5f01fc30151999387bb99a9f489b";
  const farcasterKeyRegistry = "0x00000000fc1237824fb747abde0ff18990e59b7e";

  const notificationServer = https.createServer(
    { key: privateTlsKey, cert: certificate },
    (request, response) => {
      const chunks = [];
      request.on("data", (chunk) => chunks.push(chunk));
      request.on("end", () => {
        if (request.method !== "POST" || request.url !== "/v1/openproof/verification"
            || request.headers.authorization !== `Bearer ${deliveryToken}`) {
          response.writeHead(403).end();
          return;
        }
        try {
          notifications.push({
            ...JSON.parse(Buffer.concat(chunks).toString("utf8")),
            received_at: Date.now(),
          });
          response.writeHead(204).end();
        } catch {
          response.writeHead(400).end();
        }
      });
    },
  );
  const notificationPort = await listen(notificationServer);

  const farcasterRpcServer = https.createServer(
    { key: privateTlsKey, cert: certificate },
    (request, response) => {
      const chunks = [];
      request.on("data", (chunk) => chunks.push(chunk));
      request.on("end", () => {
        let payload;
        try {
          payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        } catch {
          response.writeHead(400).end();
          return;
        }
        let result;
        if (request.method !== "POST" || request.url !== "/") {
          response.writeHead(404).end();
          return;
        }
        if (payload.method === "eth_chainId") {
          result = "0xa";
        } else if (payload.method === "eth_getCode") {
          result = [farcasterAddress, farcasterAuthAddress].includes(
            String(payload.params?.[0] ?? "").toLowerCase())
            ? "0x6001600055" : "0x";
        } else if (payload.method === "eth_call") {
          const target = String(payload.params?.[0]?.to ?? "").toLowerCase();
          const data = String(payload.params?.[0]?.data ?? "").toLowerCase();
          if (target === farcasterIdRegistry) {
            result = data.endsWith(farcasterAddress.slice(2))
              ? `0x${farcasterFid.toString(16).padStart(64, "0")}`
              : `0x${"0".repeat(64)}`;
          } else if (target === farcasterKeyRegistry) {
            result = data.endsWith(farcasterAuthAddress.slice(2))
              ? `0x${"1".padStart(64, "0")}${"2".padStart(64, "0")}`
              : `0x${"0".repeat(64)}${"0".repeat(64)}`;
          } else if ([farcasterAddress, farcasterAuthAddress].includes(target)) {
            result = `0x1626ba7e${"0".repeat(56)}`;
          }
        }
        const body = result === undefined
          ? { jsonrpc: "2.0", id: payload.id ?? 1,
              error: { code: -32601, message: "unsupported deterministic demo RPC call" } }
          : { jsonrpc: "2.0", id: payload.id ?? 1, result };
        response.writeHead(200, {
          "content-type": "application/json",
          "cache-control": "no-store",
        });
        response.end(JSON.stringify(body));
      });
    },
  );
  const farcasterRpcPort = await listen(farcasterRpcServer);

  const upstreamServer = http.createServer((request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ upstream: true, path: request.url }));
  });
  const upstreamPort = await listen(upstreamServer);
  let oppPort = await reservePort();

  let oppProcess;
  let oppLog = "";
  let oppClosed;
  let startupFailureCategory;
  let loadResult;
  let loadResourceMetrics = {};
  let nativeClientId = "";
  const masterKey = base64Url(crypto.randomBytes(48));
  const ownerPassword = `E2E-owner-${base64Url(crypto.randomBytes(24))}`;
  const consumerPassword = `E2E-consumer-${base64Url(crypto.randomBytes(24))}`;
  const replacementPassword = `E2E-replaced-${base64Url(crypto.randomBytes(24))}`;
  const resourceAudience = "https://api.e2e.openproof.invalid";
  // The candidate enables native account capabilities by default. Only the
  // explicitly pinned historical binary retains the legacy expectations.
  const nativeAccountRuntime = process.env.OPENPROOF_E2E_EXPECT_LEGACY_AUTH !== "1";

  let frontPort;
  const edgeServer = https.createServer(
    { key: privateTlsKey, cert: certificate },
    (request, response) => {
      const headers = {
        ...request.headers,
        // Preserve the public TLS authority for the same-origin POST
        // contract; other fixture routes retain their historical Host.
        host: request.method === "POST" && request.url === "/account/password/upgrade"
          ? request.headers.host : `127.0.0.1:${oppPort}`,
        "x-forwarded-for": request.socket.remoteAddress,
      };
      const forwarded = http.request({
        hostname: "127.0.0.1",
        port: oppPort,
        method: request.method,
        path: request.url,
        headers,
        // In the experimental concurrent-read E2E, Beast explicitly sends
        // Connection: close. Use a fresh upstream socket to exclude stale
        // pooled-socket races, without changing the existing Agent behavior
        // in the default E2E or pinned comparative benchmark workload.
        ...(process.env.OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_CONNECTIONS === "1"
          ? { agent: false } : {}),
      }, (upstream) => {
        const responseHeaders = { ...upstream.headers };
        responseHeaders["strict-transport-security"] = "max-age=31536000";
        response.writeHead(upstream.statusCode, responseHeaders);
        upstream.pipe(response);
      });
      // Record protocol phase without recording any request/response bytes.
      // A reset during TCP connection differs from one after the request
      // has been completely flushed to the Beast listener.
      let upstreamConnected = false;
      let upstreamRequestSent = false;
      forwarded.once("socket", (socket) => {
        if (!socket.connecting) upstreamConnected = true;
        else socket.once("connect", () => { upstreamConnected = true; });
      });
      forwarded.once("finish", () => { upstreamRequestSent = true; });
      forwarded.on("error", (error) => {
        // Expose ONLY a fixed allow-list of transport error categories in
        // this disposable local test proxy. Never include raw socket error
        // messages, request URLs, headers, OAuth codes or cookie material.
        const permitted = new Set([
          "ECONNRESET", "ECONNREFUSED", "EPIPE", "ETIMEDOUT",
          "EHOSTUNREACH", "ENETUNREACH", "ERR_STREAM_PREMATURE_CLOSE",
        ]);
        const category = permitted.has(error?.code) ? error.code : "OTHER";
        const stage = !upstreamConnected ? "connect"
          : !upstreamRequestSent ? "send" : "response";
        if (!response.headersSent) response.writeHead(502, {
          "content-type": "text/plain",
          "x-openproof-e2e-upstream-failure": category,
          "x-openproof-e2e-upstream-stage": stage,
        });
        response.end("identity upstream unavailable");
      });
      request.pipe(forwarded);
    },
  );
  if (!Number.isInteger(requestedFrontPort)
      || requestedFrontPort < 0 || requestedFrontPort > 65535) {
    fail("OPENPROOF_E2E_FRONT_PORT must be a valid TCP port");
  }
  frontPort = await listen(edgeServer, requestedFrontPort);
  const issuer = `https://127.0.0.1:${frontPort}`;

  function writeConfiguration(
    signingKey, keyId, includePrevious,
    credentialKey = undefined, credentialKeyVersion = 1, masterKeyVersion = 1,
    includePersistentKeys = false,
  ) {
    const previousLine = includePrevious
      ? `previous_signing_keys_directory = ${tomlString(previousKeys)}\n`
      : "";
    const text = `[server]\n`+
      `bind_address = "127.0.0.1"\nport = ${oppPort}\n`+
      `trust_proxy_client_ip = true\n\n`+
      `[logging]\nlevel = "info"\nconsole = true\n\n`+
      `[operations]\nmetrics_enabled = true\n`+
      `metrics_bearer_token = "env:OPENPROOF_METRICS_BEARER_TOKEN"\n`+
      `metrics_maximum_series = 512\n\n`+
      `[security]\ntoken_signing_key = "env:OPENPROOF_TOKEN_SIGNING_KEY"\n`+
      `master_key_version = ${masterKeyVersion}\n`+
      (credentialKey
        ? `credential_encryption_key = ${tomlString(
          `${credentialKey === materializedCredentialKey ? "hexfile" : "file"}:${credentialKey}`,
        )}\n`
        : "")+
      `credential_encryption_key_version = ${credentialKeyVersion}\n`+
      (includePersistentKeys
        ? `password_pepper = ${tomlString(`hexfile:${passwordPepperFile}`)}\n`+
          `recovery_code_pepper = ${tomlString(`hexfile:${recoveryCodePepperFile}`)}\n`+
          `audit_chain_key = ${tomlString(`hexfile:${auditChainKeyFile}`)}\n`+
          `oauth_client_secret_key = ${tomlString(`hexfile:${oauthClientSecretKeyFile}`)}\n`
        : "")+
      `\n`+
      `[gateway]\nenabled = true\nroute_prefix = "/"\n`+
      `upstream_host = "127.0.0.1"\nupstream_port = ${upstreamPort}\nupstream_tls = false\n\n`+
      (mixedLoadRequests > 600
        ? `rate_limit_capacity = ${Math.min(1_000_000, mixedLoadRequests + 10_000)}\n`+
          `rate_limit_refill_per_second = 1000000\nrate_limit_maximum_keys = 100000\n\n`
        : "")+
      `[database]\nconnection_string = "env:OPENPROOF_DATABASE_URL"\n`+
      `pool_size = 4\nmigration_directory = ${tomlString(path.join(root, "migrations"))}\n\n`+
      `[auth]\nenabled = true\nprovider_id = "local"\norganization_id = "e2e-org"\n`+
      `protected_route_prefix = "/api"\n\n`+
      `[[auth.route_policies]]\npath_prefix = "/api"\n`+
      `methods = ["GET", "HEAD", "POST"]\nrequired_roles = ["owner"]\n`+
      `role_match = "any"\nminimum_assurance = "ial1"\nrequired_scope = "api"\n`+
      `required_audience = ${tomlString(resourceAudience)}\n\n`+
      `[account]\nenabled = true\nphone_provider_id = "phone"\n`+
      `delivery_host = "127.0.0.1"\ndelivery_port = ${notificationPort}\ndelivery_tls = true\n`+
      `delivery_path = "/v1/openproof/verification"\n`+
      `delivery_ca_file = ${tomlString(tlsCertificate)}\n`+
      `delivery_authorization = "env:OPENPROOF_VERIFICATION_WEBHOOK_TOKEN"\n\n`+
      `[oidc]\nenabled = true\nissuer = ${tomlString(issuer)}\nkey_id = ${tomlString(keyId)}\n`+
      `signing_key = ${tomlString(`file:${signingKey}`)}\n${previousLine}`;
    fs.writeFileSync(configurationPath, text, { mode: 0o600 });
  }

  const childEnvironment = {
    ...process.env,
    OPENPROOF_DATABASE_URL: databaseUrl,
    OPENPROOF_TOKEN_SIGNING_KEY: masterKey,
    OPENPROOF_VERIFICATION_WEBHOOK_TOKEN: deliveryToken,
    OPENPROOF_METRICS_BEARER_TOKEN: metricsToken,
    OPENPROOF_WEB3_DOMAIN: `127.0.0.1:${frontPort}`,
    OPENPROOF_WEB3_URI: `${issuer}/auth/farcaster`,
    OPENPROOF_WEB3_CA_FILE: tlsCertificate,
    OPENPROOF_FARCASTER_RPC_ENDPOINT: `https://127.0.0.1:${farcasterRpcPort}/`,
    // The shared HTTPS transport blocks private/loopback RPCs by default.
    // Explicitly authorize only this disposable, locally generated TLS RPC
    // fixture; FarcasterProviderConfig rejects nonliteral/private DNS hosts
    // and missing pinned CA certificates when this option is enabled.
    OPENPROOF_FARCASTER_TRUSTED_LOOPBACK_RPC: "1",
    OPENPROOF_FARCASTER_CHAIN_ID: "10",
    OPENPROOF_FARCASTER_ID_REGISTRY: farcasterIdRegistry,
    OPENPROOF_FARCASTER_KEY_REGISTRY: farcasterKeyRegistry,
  };

  async function startOpp() {
    // A released ephemeral port is not reserved until the subprocess binds.
    // Retry only a positively identified listener collision, never a failed
    // migration, crypto operation, readiness check or unknown startup error.
    for (let attempt = 0; attempt < 3; ++attempt) {
      startupFailureCategory = undefined;
      try {
        await launchOpp();
        return;
      } catch (error) {
        if (startupFailureCategory !== "listener-address-in-use" || attempt === 2)
          throw error;
        const nextPort = await reservePort();
        fs.writeFileSync(configurationPath,
          replaceFixturePort(fs.readFileSync(configurationPath, "utf8"), oppPort, nextPort),
          { mode: 0o600 });
        oppPort = nextPort;
        console.warn("identity E2E: fixture listener collision; retrying with a fresh port");
      }
    }
  }

  async function launchOpp() {
    oppLog = "";
    const checked = command(binary, ["check-config", "--config", configurationPath], {
      env: childEnvironment,
    });
    assert.match(checked, /configuration is valid/i);
    oppProcess = spawn(binary, ["server", "--config", configurationPath], {
      cwd: root,
      env: childEnvironment,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const append = (chunk) => {
      oppLog += chunk.toString("utf8");
      if (oppLog.length > 32_000) oppLog = oppLog.slice(-32_000);
    };
    oppClosed = new Promise(resolve => oppProcess.once("close", resolve));
    // Drain stdout without retaining potentially sensitive structured logs.
    oppProcess.stdout.resume();
    oppProcess.stderr.on("data", append);
    await waitUntilReady();
  }

  async function stopOpp() {
    if (!oppProcess || oppProcess.exitCode !== null) return;
    const exited = new Promise((resolve) => oppProcess.once("exit", resolve));
    oppProcess.kill("SIGTERM");
    const graceful = await Promise.race([
      exited.then(() => true),
      new Promise((resolve) => setTimeout(() => resolve(false), 10_000)),
    ]);
    if (!graceful) {
      oppProcess.kill("SIGKILL");
      await exited;
      fail("opp did not stop within the 10-second E2E grace period");
    }
  }

  function edgeRequest(requestPath, options = {}) {
    const method = options.method ?? "GET";
    const body = options.body ?? "";
    const headers = { ...(options.headers ?? {}) };
    if (options.jar?.header()) headers.cookie = options.jar.header();
    if (body) headers["content-length"] = Buffer.byteLength(body);
    return new Promise((resolve, reject) => {
      const request = https.request({
        hostname: "127.0.0.1",
        port: frontPort,
        path: requestPath,
        method,
        headers,
        ca: certificate,
        rejectUnauthorized: true,
      }, (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          options.jar?.apply(response.headers["set-cookie"]);
          resolve({
            status: response.statusCode,
            headers: response.headers,
            body: Buffer.concat(chunks).toString("utf8"),
            method,
            path: requestPath,
          });
        });
      });
      request.on("error", reject);
      if (body) request.write(body);
      request.end();
    });
  }

  // Only after a failed experimental HTTPS fanout, query the same native
  // read over loopback HTTP to isolate a proxy reset from a listener or
  // account-session failure. Return a fixed status category, not any body,
  // exception message, URL, session cookie or response header.
  async function directNativeConnectionsProbe(jar) {
    return new Promise((resolve) => {
      const headers = {
        host: `127.0.0.1:${oppPort}`,
        "x-forwarded-for": "127.0.0.1",
      };
      if (jar?.header()) headers.cookie = jar.header();
      const request = http.request({
        hostname: "127.0.0.1", port: oppPort,
        path: "/account/connections", method: "GET", headers,
        agent: false, timeout: 1500,
      }, (response) => {
        response.resume();
        response.once("end", () => {
          const status = response.statusCode;
          resolve(Number.isInteger(status) && status >= 100 && status <= 599
            ? `http-${status}` : "invalid-status");
        });
        response.once("error", () => resolve("response-error"));
      });
      request.once("timeout", () => {
        request.destroy();
        resolve("timeout");
      });
      request.once("error", (error) => {
        resolve(["ECONNRESET", "ECONNREFUSED", "ETIMEDOUT"].includes(error?.code)
          ? error.code : "network-error");
      });
      request.end();
    });
  }

  async function waitUntilReady() {
    let lastError;
    for (let attempt = 0; attempt < 100; ++attempt) {
      if (oppProcess.exitCode !== null || oppProcess.signalCode !== null) {
        await oppClosed; // stderr has drained before classifying the exit.
        startupFailureCategory = classifyStartupFailure(oppLog);
        oppLog = "";
        fail(`opp exited during startup (status ${oppProcess.exitCode ?? "signal"}, category ${startupFailureCategory}); raw service logs withheld`);
      }
      try {
        const response = await edgeRequest("/health/ready");
        if (response.status === 200) return;
        lastError = new Error(`readiness returned ${response.status}`);
      } catch (error) {
        lastError = error;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    fail(`readiness timed out: ${lastError?.message ?? "unknown error"}; raw service logs withheld`);
  }

  async function jsonRequest(requestPath, method, value, jar, extraHeaders = {}) {
    return edgeRequest(requestPath, {
      method,
      jar,
      body: value === undefined ? "" : JSON.stringify(value),
      headers: value === undefined
        ? extraHeaders
        : { "content-type": "application/json", ...extraHeaders },
    });
  }

  async function login(subject, password, jar, currentTotp) {
    const started = await jsonRequest("/auth/login", "POST", { subject }, jar);
    expectStatus(started, 202);
    const challenge = jsonBody(started);
    const payload = {
      transaction_id: challenge.transaction_id,
      challenge_id: challenge.challenge_id,
      password,
    };
    if (currentTotp) payload.totp = currentTotp;
    const completed = await jsonRequest("/auth/mfa/verify", "POST", payload, jar);
    expectStatus(completed, 200);
    return jsonBody(completed);
  }

  async function authorizeAndExchange(clientId, clientSecret, ownerJar, keySet, options = {}) {
    const verifier = base64Url(crypto.randomBytes(48));
    const challenge = base64Url(crypto.createHash("sha256").update(verifier).digest());
    const state = base64Url(crypto.randomBytes(18));
    const nonce = base64Url(crypto.randomBytes(18));
    const redirectUri = options.redirectUri ?? `${issuer}/callback`;
    const query = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: options.scope ?? "openid profile offline_access api",
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      nonce,
    });
    if (options.resource !== false) query.set("resource", resourceAudience);
    const authorizePath = `/oauth/authorize?${query}`;
    let response = await edgeRequest(authorizePath, { jar: ownerJar });
    if (response.status === 200) {
      const csrf = response.body.match(/name="csrf" value="([^"]+)"/)?.[1];
      if (!csrf) fail("consent page did not contain its CSRF value");
      const form = new URLSearchParams({ return_to: authorizePath, csrf, decision: "approve" });
      if (nativeAccountRuntime) {
        // A valid cookie and form CSRF must not authorize a modified target.
        const substituted = new URLSearchParams(query);
        substituted.set("state", base64Url(crypto.randomBytes(18)));
        const rejected = await edgeRequest("/oauth/consent", {
          method: "POST",
          jar: ownerJar,
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            return_to: `/oauth/authorize?${substituted}`, csrf, decision: "approve",
          }).toString(),
        });
        expectStatus(rejected, 401);
      }
      response = await edgeRequest("/oauth/consent", {
        method: "POST",
        jar: ownerJar,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form.toString(),
      });
      expectStatus(response, 303);
      // Consent may redirect directly to the registered OAuth client. That
      // Location is an output of the authorization protocol, NOT a path to
      // replay against the identity server. Only follow an internal second
      // authorization step, never an arbitrary external callback URL.
      const continuation = new URL(response.headers.location, issuer);
      const registeredCallback = new URL(redirectUri);
      if (continuation.origin === registeredCallback.origin
          && continuation.pathname === registeredCallback.pathname) {
        // OAuth authorization completed; validate the final redirect below.
      } else if (continuation.origin === new URL(issuer).origin
          && continuation.pathname === "/oauth/authorize") {
        response = await edgeRequest(continuation.pathname + continuation.search, {
          jar: ownerJar,
        });
      } else {
        fail("consent redirected to an unexpected location");
      }
    }
    expectStatus(response, 302, 303);
    const callback = new URL(response.headers.location);
    const expectedCallback = new URL(redirectUri);
    assert.equal(callback.origin, expectedCallback.origin);
    assert.equal(callback.pathname, expectedCallback.pathname);
    assert.equal(callback.searchParams.get("state"), state);
    assert.equal(callback.searchParams.get("iss"), issuer);
    const code = callback.searchParams.get("code");
    assert.ok(code);

    const form = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    });
    if (clientSecret) form.set("client_secret", clientSecret);
    if (nativeAccountRuntime) {
      const invalid = new URLSearchParams(form);
      invalid.set("code_verifier", "a".repeat(43));
      const denied = await edgeRequest("/oauth/token", {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: invalid.toString(),
      });
      expectStatus(denied, 400);
      assert.equal(jsonBody(denied).error, "invalid_grant");
    }
    const tokenResponse = await edgeRequest("/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    expectStatus(tokenResponse, 200);
    const tokens = jsonBody(tokenResponse);
    assert.ok(tokens.access_token && tokens.refresh_token && tokens.id_token);
    const verified = verifyIdToken(tokens.id_token, keySet, { issuer, clientId, nonce });
    if (nativeAccountRuntime) {
      const replay = await edgeRequest("/oauth/token", {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form.toString(),
      });
      expectStatus(replay, 400);
      assert.equal(jsonBody(replay).error, "invalid_grant");
    }
    return { ...tokens, nonce, idHeader: verified.header };
  }

  let demoPortal;
  let ldapFixture;
  try {
    if (nativeLdapFixtureEnabled) {
      ldapFixture = await startNativeLdapFixture(tempRoot, reservePort);
      Object.assign(childEnvironment, ldapFixture.environment);
      // Exercise the configured native default, never an inherited opt-in.
      delete childEnvironment.OPENPROOF_EXPERIMENTAL_NATIVE_LDAP;
    }
    if (holdOpen) {
      demoPortal = await startLocalDemoPortal({
        notifications,
        requestOpenProof: edgeRequest,
        targetBaseUrl: issuer,
        openApiPath: path.join(root, "docs", "openapi.yaml"),
        demoAccount: {
          email: "consumer@e2e.invalid",
          password: replacementPassword,
          farcaster_fid: farcasterFid,
          farcaster_address: farcasterAddress,
          farcaster_signature: "0x0102",
        },
      });
    }
    writeConfiguration(oldOidcKey, "e2e-old", false);
    const bootstrap = command(binary, [
      "bootstrap-admin", "--config", configurationPath,
      "--organization-name", "OpenProof E2E",
      "--identity-id", "e2e-owner",
      "--subject", "owner@e2e.invalid",
    ], { env: { ...childEnvironment, OPENPROOF_BOOTSTRAP_PASSWORD: ownerPassword } });
    const ownerTotp = bootstrap.match(/TOTP secret \(Base32; shown once\): ([A-Z2-7]+)/)?.[1];
    if (!ownerTotp) fail("bootstrap did not return the one-time TOTP enrollment secret");
    if (ldapFixture) {
      // Only the guarded, empty, loopback test database is seeded, with
      // an explicitly linked directory UUID validated by the fixture.
      command("psql", [databaseUrl, "-v", "ON_ERROR_STOP=1", "-c",
        "INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) " +
        "SELECT 'e2e-ldap-linked',organization_id,0,0,1770000000000 FROM openproof.identities WHERE id='e2e-owner'; " +
        "INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) VALUES " +
        "('ldap','" + ldapFixture.subject + "','e2e-ldap-linked',1770000000000)"]);
    }

    await startOpp();
    const live = await edgeRequest("/health/live");
    const ready = await edgeRequest("/health/ready");
    expectStatus(live, 200);
    expectStatus(ready, 200);
    assert.equal(live.headers["strict-transport-security"], "max-age=31536000");
    if (ldapFixture) {
      const counts = () => command("psql", [databaseUrl, "-AtX", "-v", "ON_ERROR_STOP=1", "-c",
        "SELECT (SELECT count(*) FROM openproof.identities), " +
        "(SELECT count(*) FROM openproof.external_identities), " +
        "(SELECT count(*) FROM openproof.sessions)"]).trim();
      async function startLdap(username, jar) {
        const response = await jsonRequest("/auth/ldap/start", "POST", { username }, jar);
        expectStatus(response, 202);
        const challenge = jsonBody(response);
        return { transaction_id: challenge.transaction_id, challenge_id: challenge.challenge_id,
          username, username_binding: challenge.username_binding };
      }
      async function completeLdap(challenge, password, jar, headers = {}) {
        return jsonRequest("/auth/ldap/complete", "POST", { ...challenge, password }, jar, headers);
      }
      const initialCounts = counts();
      const wrongJar = new CookieJar();
      const wrong = await startLdap("linked", wrongJar);
      expectStatus(await completeLdap(wrong, "intentionally-invalid-fixture-password", wrongJar), 401);
      const foreignJar = new CookieJar();
      const bound = await startLdap("linked", foreignJar);
      expectStatus(await completeLdap(bound, ldapFixture.linkedPassword, new CookieJar()), 401);
      const substitutedJar = new CookieJar();
      const substituted = await startLdap("linked", substitutedJar);
      expectStatus(await completeLdap({ ...substituted, username: "unlinked" },
        ldapFixture.unlinkedPassword, substitutedJar), 401);
      const unlinkedJar = new CookieJar();
      const unlinked = await startLdap("unlinked", unlinkedJar);
      expectStatus(await completeLdap(unlinked, ldapFixture.unlinkedPassword, unlinkedJar), 401);
      // A verified but unlinked directory account must NOT create a canonical
      // identity, external link or session. Test the actual SQL counts.
      assert.equal(counts(), initialCounts, "denied LDAP proof changed identity/link/session counts");
      // A valid directory account linked to a different organization must
      // not enter the configured tenant, create a duplicate, or issue a session.
      const sql = statement => command("psql", [databaseUrl, "-AtX", "-v", "ON_ERROR_STOP=1", "-c", statement]).trim();
      assert.ok(/^[0-9a-f-]{36}$/.test(ldapFixture.unlinkedSubject));
      sql("INSERT INTO openproof.organizations(id,name,state,created_at_ms) VALUES " +
        "('e2e-ldap-foreign-org','Foreign LDAP fixture',0,1770000000000); " +
        "INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) VALUES " +
        "('e2e-ldap-foreign','e2e-ldap-foreign-org',0,0,1770000000000); " +
        "INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) VALUES " +
        "('ldap','" + ldapFixture.unlinkedSubject + "','e2e-ldap-foreign',1770000000000)");
      const foreignCounts = counts();
      const foreignOwnerJar = new CookieJar();
      const foreignOwner = await startLdap("unlinked", foreignOwnerJar);
      expectStatus(await completeLdap(foreignOwner, ldapFixture.unlinkedPassword, foreignOwnerJar), 401);
      assert.equal(counts(), foreignCounts, "foreign LDAP proof changed persistent state");
      sql("DELETE FROM openproof.external_identities WHERE identity_id='e2e-ldap-foreign'; " +
        "DELETE FROM openproof.identities WHERE id='e2e-ldap-foreign'; " +
        "DELETE FROM openproof.organizations WHERE id='e2e-ldap-foreign-org'");
      assert.equal(counts(), initialCounts);
      sql("UPDATE openproof.identities SET status=2 WHERE id='e2e-ldap-linked'");
      const lockedJar = new CookieJar();
      const locked = await startLdap("linked", lockedJar);
      expectStatus(await completeLdap(locked, ldapFixture.linkedPassword, lockedJar), 401);
      assert.equal(counts(), initialCounts, "locked LDAP proof changed persistent state");
      sql("UPDATE openproof.identities SET status=0 WHERE id='e2e-ldap-linked'");
      const activeCount = () => Number(sql("SELECT count(*) FROM openproof.sessions WHERE identity_id='e2e-ldap-linked' AND state=0"));
      const linkedJar = new CookieJar();
      const linked = await startLdap("linked", linkedJar);
      const replayCookie = linkedJar.header();
      const completed = await completeLdap(linked, ldapFixture.linkedPassword, linkedJar);
      expectStatus(completed, 200);
      assert.equal(jsonBody(completed).assurance, "ial1");
      const profile = await edgeRequest("/account/profile", { jar: linkedJar });
      expectStatus(profile, 200);
      assert.equal(jsonBody(profile).identity_id, "e2e-ldap-linked");
      const afterLogin = counts();
      expectStatus(await completeLdap(linked, ldapFixture.linkedPassword, undefined,
        { cookie: replayCookie }), 401);
      assert.equal(counts(), afterLogin, "replayed LDAP proof changed persistent state");
      assert.equal(activeCount(), 1);
      const previousSessionCookie = linkedJar.header();
      const failedRelogin = await startLdap("linked", linkedJar);
      expectStatus(await completeLdap(failedRelogin, "intentionally-invalid-fixture-password", linkedJar), 401);
      expectStatus(await edgeRequest("/account/profile", { jar: linkedJar }), 200);
      assert.equal(counts(), afterLogin, "failed re-login changed persistent state");
      const replacementChallenge = await startLdap("linked", linkedJar);
      const replaced = await completeLdap(replacementChallenge, ldapFixture.linkedPassword, linkedJar);
      expectStatus(replaced, 200);
      assert.notEqual(jsonBody(replaced).session_id, jsonBody(completed).session_id);
      expectStatus(await edgeRequest("/account/profile", { headers: { cookie: previousSessionCookie } }), 401);
      expectStatus(await edgeRequest("/account/profile", { jar: linkedJar }), 200);
      assert.equal(activeCount(), 1, "same-browser re-login must replace the old grant");
      // Four separate browsers share only the prepared trust store, never
      // sockets, TLS streams, transactions or credential/session cookies.
      const browsers = Array.from({ length: 4 }, () => new CookieJar());
      const concurrentChallenges = await Promise.all(browsers.map(jar => startLdap("linked", jar)));
      const beforeConcurrent = counts().split("|").map(Number);
      const results = await Promise.all(browsers.map((jar, index) =>
        completeLdap(concurrentChallenges[index], ldapFixture.linkedPassword, jar)));
      for (const response of results) expectStatus(response, 200);
      assert.equal(new Set(results.map(response => jsonBody(response).session_id)).size, browsers.length);
      const afterConcurrent = counts().split("|").map(Number);
      assert.deepEqual(afterConcurrent, [beforeConcurrent[0], beforeConcurrent[1], beforeConcurrent[2] + browsers.length]);
      assert.equal(activeCount(), 1 + browsers.length);
      for (const jar of browsers) {
        const response = await edgeRequest("/account/profile", { jar });
        expectStatus(response, 200);
        assert.equal(jsonBody(response).identity_id, "e2e-ldap-linked");
        expectStatus(await jsonRequest("/auth/logout", "POST", undefined, jar), 204);
      }
      expectStatus(await jsonRequest("/auth/logout", "POST", undefined, linkedJar), 204);
      assert.equal(activeCount(), 0);
      console.log("- native LDAPS real directory + PostgreSQL: explicit link, invalid password, binding, replay, no implicit provisioning, foreign/locked rejection, atomic replacement and four concurrent proofs");
    }

    const deniedMetrics = await edgeRequest("/metrics");
    expectStatus(deniedMetrics, 401);
    assert.ok(!deniedMetrics.body.includes(metricsToken));
    const metrics = await edgeRequest("/metrics", {
      headers: { authorization: `Bearer ${metricsToken}` },
    });
    expectStatus(metrics, 200);
    assert.match(metrics.headers["content-type"], /^text\/plain; version=0\.0\.4/);
    // The production protocol version and a release-candidate suffix both
    // represent a valid 1.1.0 build. Keep the Prometheus metric and counter
    // assertion strict without hard-coding release-only version labels.
    assert.match(metrics.body,
      /^openproof_process_starts_total\{version="1\.1\.0(?:-rc[1-9][0-9]*)?"\} 1$/m);
    assert.match(metrics.body, /openproof_http_requests_total\{method="GET",status_class="2xx"\}/);
    assert.ok(!metrics.body.includes("/health/ready"));
    assert.ok(!metrics.body.includes("e2e-owner"));
    assert.ok(!metrics.body.includes(metricsToken));

    const catalogResponse = await edgeRequest("/auth/providers");
    expectStatus(catalogResponse, 200);
    assert.equal(catalogResponse.headers["cache-control"], "no-store");
    const catalog = jsonBody(catalogResponse);
    assert.ok(Array.isArray(catalog.providers));
    assert.ok(Array.isArray(catalog.challenge_providers));
    assert.ok(catalog.challenge_providers.includes("farcaster"));
    for (const route of ["/.well-known/openid-configuration", "/.well-known/jwks.json"]) {
      const preflight = await edgeRequest(route, { method: "OPTIONS" });
      expectStatus(preflight, 204);
      assert.equal(preflight.headers["access-control-allow-origin"], "*");
      assert.equal(preflight.headers["cache-control"], "no-store");
    }
    const discoveryResponse = await edgeRequest("/.well-known/openid-configuration");
    expectStatus(discoveryResponse, 200);
    const discovery = jsonBody(discoveryResponse);
    assert.equal(discovery.issuer, issuer);
    assert.equal(discovery.authorization_endpoint, `${issuer}/oauth/authorize`);
    assert.equal(discovery.token_endpoint, `${issuer}/oauth/token`);
    assert.equal(discovery.jwks_uri, `${issuer}/.well-known/jwks.json`);

    const initialJwksResponse = await edgeRequest("/.well-known/jwks.json");
    expectStatus(initialJwksResponse, 200);
    const initialJwks = jsonBody(initialJwksResponse);
    assert.deepEqual(initialJwks.keys.map((key) => key.kid), ["e2e-old"]);

    const signup = await jsonRequest("/account/signup", "POST", {
      email: "consumer@e2e.invalid",
      password: consumerPassword,
      display_name: "E2E Consumer",
    });
    expectStatus(signup, 201);
    assert.equal(jsonBody(signup).verification_required, true);
    assert.equal(notifications.length, 1);
    assert.equal(notifications[0].purpose, "signup_email");
    assert.equal(notifications[0].destination, "consumer@e2e.invalid");
    const verifiedEmail = await jsonRequest("/account/email/verify", "POST", {
      verification_id: notifications[0].verification_id,
      secret: notifications[0].secret,
    });
    expectStatus(verifiedEmail, 200);
    if (nativeAccountRuntime) {
      assert.equal(jsonBody(verifiedEmail).verified, true);
      assert.ok(jsonBody(verifiedEmail).session_id);
      const replay = await jsonRequest("/account/email/verify", "POST", {
        verification_id: notifications[0].verification_id,
        secret: notifications[0].secret,
      });
      expectStatus(replay, 401);
      assert.equal(replay.headers["set-cookie"], undefined);
      assert.equal(command("psql", [
        databaseUrl, "-AtX", "-v", "ON_ERROR_STOP=1", "-c",
        "select count(*) from openproof.pending_external_identity_reservations where provider='local' and external_subject='consumer@e2e.invalid'",
      ]).trim(), "0");
    }
    notifications[0].demo_verified = true;
    const consumerIdentityId = command("psql", [
      databaseUrl, "-AtX", "-v", "ON_ERROR_STOP=1", "-c",
      "select identity_id from openproof.external_identities where provider='local' and external_subject='consumer@e2e.invalid'",
    ]).trim();
    assert.ok(consumerIdentityId);
    command("psql", [
      databaseUrl, "-v", "ON_ERROR_STOP=1", "-c",
      `insert into openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) values ('farcaster','${farcasterFid}','${consumerIdentityId}',(extract(epoch from clock_timestamp())*1000)::bigint)`,
    ]);

    const relayJar = new CookieJar();
    const relayStart = await jsonRequest("/auth/web3/start", "POST", {
      provider: "farcaster",
    }, relayJar);
    expectStatus(relayStart, 200);
    const relayChallenge = jsonBody(relayStart);
    assert.equal(relayChallenge.statement, "Farcaster Auth");
    assert.equal(relayChallenge.chain_id, "10");
    // Canonical output is singular /fid/; the provider separately accepts
    // historic /fids/ input for backward compatibility.
    assert.equal(relayChallenge.resource_prefix, "farcaster://fid/");
    assert.ok(relayChallenge.nonce && !relayChallenge.message);

    const farcasterJar = new CookieJar();
    const farcasterStart = await jsonRequest("/auth/web3/start", "POST", {
      provider: "farcaster",
      address: farcasterAddress,
      fid: String(farcasterFid),
    }, farcasterJar);
    expectStatus(farcasterStart, 200);
    const farcasterChallenge = jsonBody(farcasterStart);
    assert.equal(farcasterChallenge.signer_kind, "custody");
    assert.match(farcasterChallenge.message, /\n\nFarcaster Auth\n\n/);
    assert.match(farcasterChallenge.message, /\nChain ID: 10\n/);
    assert.match(farcasterChallenge.message, /\nResources:\n- farcaster:\/\/fid\/6841$/);
    const farcasterComplete = await jsonRequest("/auth/web3/complete", "POST", {
      message: farcasterChallenge.message,
      signature: "0x0102",
    }, farcasterJar);
    expectStatus(farcasterComplete, 200);
    assert.equal(jsonBody(farcasterComplete).identity_id, consumerIdentityId);
    const farcasterProfile = await edgeRequest("/account/profile", { jar: farcasterJar });
    expectStatus(farcasterProfile, 200);
    assert.equal(jsonBody(farcasterProfile).email, "consumer@e2e.invalid");
    const farcasterLogout = await jsonRequest("/auth/logout", "POST", undefined, farcasterJar);
    expectStatus(farcasterLogout, 204);

    const authAddressJar = new CookieJar();
    const authAddressStart = await jsonRequest("/auth/web3/start", "POST", {
      provider: "farcaster",
      address: farcasterAuthAddress,
      fid: String(farcasterFid),
    }, authAddressJar);
    expectStatus(authAddressStart, 200);
    const authAddressChallenge = jsonBody(authAddressStart);
    assert.equal(authAddressChallenge.signer_kind, "auth_address");
    const authAddressComplete = await jsonRequest("/auth/web3/complete", "POST", {
      message: authAddressChallenge.message,
      signature: "0x0102",
    }, authAddressJar);
    expectStatus(authAddressComplete, 200);
    assert.equal(jsonBody(authAddressComplete).identity_id, consumerIdentityId);
    expectStatus(await jsonRequest("/auth/logout", "POST", undefined, authAddressJar), 204);

    const consumerJar = new CookieJar();
    const consumerGrant = await login("consumer@e2e.invalid", consumerPassword, consumerJar);
    if (process.env.OPENPROOF_E2E_EXPECT_LEGACY_AUTH !== "1") {
      assert.equal(consumerGrant.assurance, "ial1");
      const sql = statement => command("psql", [
        databaseUrl, "-AtX", "-v", "ON_ERROR_STOP=1", "-c", statement,
      ]).trim();
      const counts = () => sql("SELECT (SELECT count(*) FROM openproof.identities), " +
        "(SELECT count(*) FROM openproof.external_identities), " +
        "(SELECT count(*) FROM openproof.sessions)");
      const active = () => Number(sql("SELECT count(*) FROM openproof.sessions s " +
        "JOIN openproof.external_identities e ON e.identity_id=s.identity_id " +
        "WHERE e.provider='local' AND e.external_subject='consumer@e2e.invalid' AND s.state=0"));
      async function startLocal(subject, jar) {
        const result = await jsonRequest("/auth/login", "POST", { subject }, jar);
        expectStatus(result, 202);
        assert.equal(result.headers["cache-control"], "no-store");
        return jsonBody(result);
      }
      function completeLocal(challenge, password, jar, extraHeaders = {}) {
        return jsonRequest("/auth/mfa/verify", "POST", {
          transaction_id: challenge.transaction_id, challenge_id: challenge.challenge_id, password,
        }, jar, extraHeaders);
      }
      const before = counts();
      const beforeActive = active();
      const unknownJar = new CookieJar();
      const unknown = await startLocal("native-local-unlinked@e2e.invalid", unknownJar);
      expectStatus(await completeLocal(unknown, consumerPassword, unknownJar), 401);

      const failed = await startLocal("consumer@e2e.invalid", consumerJar);
      const failedCookie = consumerJar.header();
      expectStatus(await completeLocal(failed, "intentionally-invalid-fixture-password", consumerJar), 401);
      expectStatus(await completeLocal(failed, consumerPassword, undefined, { cookie: failedCookie }), 401);
      expectStatus(await edgeRequest("/account/profile", { jar: consumerJar }), 200);

      const browserA = new CookieJar();
      const browserB = new CookieJar();
      const boundA = await startLocal("consumer@e2e.invalid", browserA);
      await startLocal("consumer@e2e.invalid", browserB);
      expectStatus(await completeLocal(boundA, consumerPassword, browserB), 401);

      const lockedJar = new CookieJar();
      const locked = await startLocal("consumer@e2e.invalid", lockedJar);
      sql("UPDATE openproof.identities SET status=2 WHERE id=(SELECT identity_id " +
        "FROM openproof.external_identities WHERE provider='local' AND external_subject='consumer@e2e.invalid')");
      try {
        expectStatus(await completeLocal(locked, consumerPassword, lockedJar), 401);
      } finally {
        sql("UPDATE openproof.identities SET status=0 WHERE id=(SELECT identity_id " +
          "FROM openproof.external_identities WHERE provider='local' AND external_subject='consumer@e2e.invalid')");
      }
      assert.equal(counts(), before, "rejected local proof created identity/link/session rows");
      assert.equal(active(), beforeActive);

      const oldCookie = consumerJar.header();
      const replacement = await startLocal("consumer@e2e.invalid", consumerJar);
      const replayCookie = consumerJar.header();
      const completed = await completeLocal(replacement, consumerPassword, consumerJar);
      expectStatus(completed, 200);
      assert.equal(jsonBody(completed).assurance, "ial1");
      assert.notEqual(jsonBody(completed).session_id, consumerGrant.session_id);
      const replacedCounts = counts();
      expectStatus(await completeLocal(replacement, consumerPassword, undefined, { cookie: replayCookie }), 401);
      assert.equal(counts(), replacedCounts);
      expectStatus(await edgeRequest("/account/profile", { headers: { cookie: oldCookie } }), 401);
      expectStatus(await edgeRequest("/account/profile", { jar: consumerJar }), 200);
      assert.equal(active(), beforeActive, "same-browser local login must atomically replace the session");
      console.log("- native local HTTP: unknown/locked subject, invalid password, binding, replay, no provisioning and session replacement passed");
      if (nativeAccountRuntime) {
        expectStatus(await edgeRequest("/account/password/upgrade"), 401);
        const projection = await edgeRequest("/account/password/upgrade", { jar: consumerJar });
        expectStatus(projection, 200);
        assert.equal(projection.headers["cache-control"], "no-store");
        assert.deepEqual(jsonBody(projection), {
          available: true, needs_upgrade: false, target_algorithm: "argon2id",
        });
        const beforeStatus = counts();
        sql("UPDATE openproof.identities SET status=2 WHERE id=(SELECT identity_id " +
          "FROM openproof.external_identities WHERE provider='local' AND external_subject='consumer@e2e.invalid')");
        try {
          const lockedStatus = await edgeRequest("/account/password/upgrade", { jar: consumerJar });
          assert.ok([401, 403, 404].includes(lockedStatus.status),
            "inactive identity must not receive password status");
        } finally {
          sql("UPDATE openproof.identities SET status=0 WHERE id=(SELECT identity_id " +
            "FROM openproof.external_identities WHERE provider='local' AND external_subject='consumer@e2e.invalid')");
        }
        assert.equal(counts(), beforeStatus);
        const postOrigin = { origin: issuer, "sec-fetch-site": "same-origin" };
        expectStatus(await jsonRequest("/account/password/upgrade", "POST",
          { password: consumerPassword }, consumerJar, { origin: "https://foreign.invalid" }), 403);
        expectStatus(await jsonRequest("/account/password/upgrade", "POST",
          { password: consumerPassword, owner: "foreign" }, consumerJar, postOrigin), 400);
        // Default test policy is scrypt: explicit Argon2id upgrade must
        // refuse instead of silently changing the policy or credential.
        expectStatus(await jsonRequest("/account/password/upgrade", "POST",
          { password: consumerPassword }, consumerJar, postOrigin), 412);
        assert.equal(counts(), beforeStatus);
        console.log("- native password upgrade HTTP: owner-bound metadata, no-store, inactive identity denial, origin and policy enforcement passed");
      }
    }
    if (nativeAccountRuntime) {
      expectStatus(await edgeRequest("/account/totp"), 401);
      const status = await edgeRequest("/account/totp", { jar: consumerJar });
      expectStatus(status, 200);
      assert.deepEqual(jsonBody(status), { available: true, enabled: false,
        assurance: consumerGrant.assurance });
      assert.equal(status.headers["cache-control"], "no-store");
    }
    if (nativeAccountRuntime) {
      // Preserve the legacy projection: retired/unregistered provider links
      // can exist in storage, but cannot appear as available login methods.
      command("psql", [databaseUrl, "-v", "ON_ERROR_STOP=1", "-c",
        "INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) " +
        "SELECT 'fixture-retired-provider','fixture-retired-subject',identity_id,1770000000000 " +
        "FROM openproof.external_identities WHERE provider='local' AND external_subject='consumer@e2e.invalid'"]);
    }
    const connectionsBefore = await edgeRequest("/account/connections", { jar: consumerJar });
    if (connectionsBefore.status === 502) {
      // Never print upstream stdout/stderr or response bodies: those may hold
      // session cookies, OAuth codes and other secrets. A process exit/signal
      // is sufficient to distinguish a fatal native crash from a transport
      // or fixture timeout on this exact experimental boundary.
      await new Promise((resolve) => setTimeout(resolve, 100));
      fail(`native account connections upstream disconnected (transport=${connectionsBefore.headers["x-openproof-e2e-upstream-failure"] ?? "unknown"}, opp exit=${oppProcess?.exitCode ?? "running"}, signal=${oppProcess?.signalCode ?? "none"})`);
    }
    expectStatus(connectionsBefore, 200);
    assert.deepEqual(
      jsonBody(connectionsBefore).connections.map(({ provider, subject }) => `${provider}:${subject}`).sort(),
      [`farcaster:${farcasterFid}`, "local:consumer@e2e.invalid"],
    );
    if (nativeAccountRuntime) {
      // Exercise the native read concurrently: connection-pool contention
      // must suspend without dropping sockets or leaking another identity.
      // The later timed mixed-read workload is unchanged.
      const reads = await Promise.all(Array.from({ length: 8 },
        () => edgeRequest("/account/connections", { jar: consumerJar })));
      for (const response of reads) {
        if (response.status === 502) {
          // Preserve process status without exposing the upstream's HTTP
          // response bodies, logs, session tokens, OAuth codes or secrets.
          await new Promise((resolve) => setTimeout(resolve, 100));
          const direct = await directNativeConnectionsProbe(consumerJar);
          fail(`concurrent native connections upstream disconnected (transport=${response.headers["x-openproof-e2e-upstream-failure"] ?? "unknown"}, stage=${response.headers["x-openproof-e2e-upstream-stage"] ?? "unknown"}, direct=${direct}, opp exit=${oppProcess?.exitCode ?? "running"}, signal=${oppProcess?.signalCode ?? "none"})`);
        }
        expectStatus(response, 200);
        assert.deepEqual(
          jsonBody(response).connections.map(({ provider, subject }) => `${provider}:${subject}`).sort(),
          [`farcaster:${farcasterFid}`, "local:consumer@e2e.invalid"],
        );
      }
    }
    if (nativeAccountRuntime) {
      // Remove only the dedicated fixture before testing last-method policy.
      command("psql", [databaseUrl, "-v", "ON_ERROR_STOP=1", "-c",
        "DELETE FROM openproof.external_identities WHERE provider='fixture-retired-provider' " +
        "AND external_subject='fixture-retired-subject'"]);
    }
    const connectionStart = await jsonRequest("/account/connections/web3/start", "POST", {
      provider: "farcaster",
      address: farcasterAddress,
      fid: String(farcasterFid),
    }, consumerJar);
    expectStatus(connectionStart, 200);
    const connectionChallenge = jsonBody(connectionStart);
    const connectionComplete = await jsonRequest("/account/connections/web3/complete", "POST", {
      message: connectionChallenge.message,
      signature: "0x0102",
    }, consumerJar);
    expectStatus(connectionComplete, 200);
    assert.equal(jsonBody(connectionComplete).connected, true);
    assert.equal(jsonBody(connectionComplete).subject, String(farcasterFid));
    const disconnected = await jsonRequest("/account/connections/disconnect", "POST", {
      provider: "farcaster",
      subject: String(farcasterFid),
    }, consumerJar);
    expectStatus(disconnected, 200);
    if (nativeAccountRuntime) {
      const afterDisconnect=await edgeRequest("/account/connections",{jar:consumerJar});
      expectStatus(afterDisconnect,200);
      assert.ok(!jsonBody(afterDisconnect).connections.some(c=>c.provider==="farcaster" && c.subject===String(farcasterFid)));
      expectStatus(await jsonRequest("/account/connections/disconnect","POST",{
        provider:"farcaster",subject:String(farcasterFid)
      },consumerJar),404);
      expectStatus(await jsonRequest("/account/connections/disconnect","POST",{
        provider:"local",subject:"consumer@e2e.invalid",identity_id:"e2e-owner"
      },consumerJar),400);
    }
    const refusedLastMethod = await jsonRequest("/account/connections/disconnect", "POST", {
      provider: "local",
      subject: "consumer@e2e.invalid",
    }, consumerJar);
    expectStatus(refusedLastMethod, 412);
    const profile = await edgeRequest("/account/profile", { jar: consumerJar });
    expectStatus(profile, 200);
    assert.equal(jsonBody(profile).email, "consumer@e2e.invalid");
    assert.equal(jsonBody(profile).email_verified, true);
    const updatedProfile = await jsonRequest("/account/profile", "PATCH", {
      display_name: "E2E Consumer Updated",
      locale: "fa-IR",
    }, consumerJar);
    expectStatus(updatedProfile, 200);
    assert.equal(jsonBody(updatedProfile).locale, "fa-IR");
    if (nativeAccountRuntime) {
      const refused = await jsonRequest("/account/profile", "PATCH", {
        display_name: "Uncommitted profile", avatar_source: "missing-avatar-provider",
      }, consumerJar);
      expectStatus(refused, 400);
      expectStatus(await jsonRequest("/account/profile", "PUT", {
        email: "forbidden@e2e.invalid", email_verified: true,
      }, consumerJar), 400);
      const preserved = await edgeRequest("/account/profile", { jar: consumerJar });
      expectStatus(preserved, 200);
      assert.deepEqual(jsonBody(preserved), jsonBody(updatedProfile));
      assert.equal(jsonBody(preserved).email, "consumer@e2e.invalid");
      assert.equal(jsonBody(preserved).email_verified, true);
      console.log("- native profile mutation: rollback, protected contacts and tenant ownership passed");
    }

    if (nativeAccountRuntime) {
      const recovery = await edgeRequest("/account/recover");
      expectStatus(recovery,200);
      assert.match(recovery.headers["content-security-policy"],/script-src 'nonce-/);
      assert.match(recovery.body,/Reset your OpenProof password/);
      const security = await edgeRequest("/account/security",{jar:consumerJar});
      expectStatus(security,200);
      assert.equal(security.headers["cache-control"],"no-store");
      assert.match(security.headers["content-security-policy"],/frame-ancestors 'none'/);
      assert.match(security.body,/Account Security/);
      const unauthenticated = await edgeRequest("/account/security");
      expectStatus(unauthenticated,303);
      assert.equal(unauthenticated.headers.location,"/login?return_to=%2Faccount%2Fsecurity");
    }

    const forgot = await jsonRequest("/account/password/forgot", "POST", {
      email: "consumer@e2e.invalid",
    });
    expectStatus(forgot, 202);
    assert.equal(notifications.length, 2);
    assert.equal(notifications[1].purpose, "password_reset");
    const reset = await jsonRequest("/account/password/reset", "POST", {
      verification_id: notifications[1].verification_id,
      secret: notifications[1].secret,
      new_password: replacementPassword,
    });
    expectStatus(reset, 200);
    if (nativeAccountRuntime) {
      assert.equal(jsonBody(reset).password_reset, true);
      assert.equal(reset.headers["set-cookie"], undefined);
      const resetReplay = await jsonRequest("/account/password/reset", "POST", {
        verification_id: notifications[1].verification_id,
        secret: notifications[1].secret,
        new_password: replacementPassword,
      });
      expectStatus(resetReplay, 401);
      assert.equal(resetReplay.headers["set-cookie"], undefined);
      expectStatus(await edgeRequest("/account/profile", { jar: consumerJar }), 401);
    }
    const consumerJarAfterReset = new CookieJar();
    await login("consumer@e2e.invalid", replacementPassword, consumerJarAfterReset);
    if (nativeAccountRuntime) {
      const enrollment = await jsonRequest("/account/totp/start", "POST",
        { password: replacementPassword }, consumerJarAfterReset);
      expectStatus(enrollment, 201);
      const setup = jsonBody(enrollment);
      assert.equal(setup.replacing, false);
      assert.equal(enrollment.headers["cache-control"], "no-store");
      const code = totp(setup.secret_base32);
      const proof = { enrollment_id: setup.enrollment_id, code };
      expectStatus(await jsonRequest("/account/totp/complete", "POST", proof, consumerJarAfterReset), 200);
      expectStatus(await jsonRequest("/account/totp/complete", "POST", proof, consumerJarAfterReset), 401);
      expectStatus(await jsonRequest("/account/totp/disable", "POST",
        { password: replacementPassword }, consumerJarAfterReset), 403);
      const mfaJar = new CookieJar();
      const mfaGrant = await login("consumer@e2e.invalid", replacementPassword, mfaJar,
        await nextTotp(setup.secret_base32, code));
      assert.equal(mfaGrant.assurance, "ial2");
      const removed = await jsonRequest("/account/totp/disable", "POST",
        { password: replacementPassword }, mfaJar);
      expectStatus(removed, 200);
      assert.deepEqual(jsonBody(removed), { enabled: false, recovery_codes_revoked: true });
      expectStatus(await jsonRequest("/auth/logout", "POST", undefined, mfaJar), 204);
      console.log("- native TOTP lifecycle: enrollment, replay denial, IAL2 login and disable");
    }

    const ownerJar = new CookieJar();
    const initialOwnerTotp = totp(ownerTotp);
    const ownerGrant = await login(
      "owner@e2e.invalid", ownerPassword, ownerJar, initialOwnerTotp);
    assert.equal(ownerGrant.assurance, "ial2");
    if (process.env.OPENPROOF_E2E_EXPECT_LEGACY_AUTH !== "1") {
      const countOwnerSessions = () => command("psql", [
        databaseUrl, "-AtX", "-v", "ON_ERROR_STOP=1", "-c",
        "SELECT count(*) FROM openproof.sessions WHERE identity_id='e2e-owner'",
      ]).trim();
      const before = countOwnerSessions();
      for (const factor of [{}, { totp: initialOwnerTotp }]) {
        const jar = new CookieJar();
        const started = await jsonRequest("/auth/login", "POST", { subject: "owner@e2e.invalid" }, jar);
        expectStatus(started, 202);
        const challenge = jsonBody(started);
        const denied = await jsonRequest("/auth/mfa/verify", "POST", {
          transaction_id: challenge.transaction_id, challenge_id: challenge.challenge_id,
          password: ownerPassword, ...factor,
        }, jar);
        expectStatus(denied, 401);
        expectStatus(await edgeRequest("/account/profile", { jar }), 401);
      }
      assert.equal(countOwnerSessions(), before);
      console.log("- native local MFA: missing second factor and previously consumed TOTP denied");
    }
    if (nativeAccountRuntime) {
      const status = await edgeRequest("/account/totp", { jar: ownerJar });
      expectStatus(status, 200);
      assert.deepEqual(jsonBody(status), { available: true, enabled: true, assurance: "ial2" });
      assert.equal(status.headers["cache-control"], "no-store");
    }
    if (process.env.OPENPROOF_E2E_EXPECT_LEGACY_AUTH !== "1") {
      const countCodes = () => Number(command("psql", [
        databaseUrl, "-AtX", "-v", "ON_ERROR_STOP=1", "-c",
        "select count(*) from openproof.recovery_codes where identity_id='e2e-owner'",
      ]).trim());
      expectStatus(await jsonRequest("/auth/recovery-codes", "POST", undefined), 401);
      expectStatus(await jsonRequest("/auth/recovery-codes", "POST", undefined,
        consumerJarAfterReset), 403);
      assert.equal(countCodes(), 0);
      async function issueCodes() {
        const result = await jsonRequest("/auth/recovery-codes", "POST", undefined, ownerJar);
        expectStatus(result, 201);
        assert.equal(result.headers["cache-control"], "no-store");
        const codes = jsonBody(result).codes;
        assert.ok(Array.isArray(codes) && codes.length === 10 && new Set(codes).size === 10,
          "issuance must return exactly ten distinct codes");
        assert.ok(codes.every(code => typeof code === "string" && /^[A-Za-z0-9_-]{27}$/.test(code)));
        assert.equal(countCodes(), 10);
        return codes;
      }
      const old = await issueCodes();
      const fresh = await issueCodes();
      assert.ok(old.every(code => !fresh.includes(code)), "rotation must replace the prior batch");
      async function recover(code, expected) {
        const jar = new CookieJar();
        const started = await jsonRequest("/auth/login", "POST", { subject: "owner@e2e.invalid" }, jar);
        expectStatus(started, 202);
        const challenge = jsonBody(started);
        const completed = await jsonRequest("/auth/mfa/verify", "POST", {
          transaction_id: challenge.transaction_id, challenge_id: challenge.challenge_id,
          password: ownerPassword, recovery_code: code,
        }, jar);
        expectStatus(completed, expected);
        if (expected === 200) {
          assert.equal(jsonBody(completed).assurance, "ial2");
          expectStatus(await jsonRequest("/auth/logout", "POST", undefined, jar), 204);
        }
      }
      await recover(old[0], 401);
      assert.equal(countCodes(), 10);
      await recover(fresh[0], 200);
      assert.equal(countCodes(), 9);
      await recover(fresh[0], 401);
      assert.equal(countCodes(), 9);
      console.log("- native recovery issuance and " +
        (process.env.OPENPROOF_E2E_EXPECT_LEGACY_AUTH !== "1" ? "native" : "legacy") +
        " one-time redemption: IAL2, rotation, persistence and replay passed");
    }
    const adminConsole = await edgeRequest("/admin/console", { jar: ownerJar });
    expectStatus(adminConsole, 200);
    assert.match(adminConsole.body, /name="identity_id"/);
    assert.match(adminConsole.body, /identity_id:v\.identity_id/);
    assert.equal(adminConsole.headers["cache-control"], "no-store");
    assert.match(adminConsole.headers["content-security-policy"], /frame-ancestors 'none'/);
    const consoleNonce = adminConsole.body.match(/<script nonce="([^"]+)">/);
    assert.ok(consoleNonce);
    assert.ok(adminConsole.headers["content-security-policy"].includes("'nonce-" + consoleNonce[1] + "'"));
    if (nativeAccountRuntime) {
      const guestConsole = await edgeRequest("/admin/console");
      expectStatus(guestConsole, 303);
      assert.equal(guestConsole.headers.location, "/login?return_to=%2Fadmin%2Fconsole");
      assert.doesNotMatch(guestConsole.body, /OpenProof Admin Console/);
      const nonOwnerConsole = await edgeRequest("/admin/console", { jar: consumerJarAfterReset });
      expectStatus(nonOwnerConsole, 403);
      assert.doesNotMatch(nonOwnerConsole.body, /OpenProof Admin Console/);
    }
    const localMemberResponse = await jsonRequest("/admin/local-members", "POST", {
      identity_id: "e2e-dispatcher",
      subject: "dispatcher@e2e.invalid",
      roles: ["dispatcher"],
    }, ownerJar);
    expectStatus(localMemberResponse, 201);
    const localMember = jsonBody(localMemberResponse);
    assert.equal(localMember.identity_id, "e2e-dispatcher");
    assert.ok(localMember.initial_password.length >= 32);
    assert.match(localMember.totp_secret_base32, /^[A-Z2-7]+$/);
    if (nativeAccountRuntime) {
      expectStatus(await edgeRequest("/admin/local-members"), 401);
      expectStatus(await edgeRequest("/admin/local-members", { jar: consumerJarAfterReset }), 403);
      const listing = await edgeRequest("/admin/local-members", { jar: ownerJar });
      expectStatus(listing, 200);
      assert.equal(listing.headers["cache-control"], "no-store");
      const members = jsonBody(listing).members;
      assert.ok(members.some(m => m.identity_id === "e2e-owner" && m.roles.includes("owner")
        && m.identity_status === "active" && m.membership_state === "active"));
      assert.ok(members.some(m => m.identity_id === "e2e-dispatcher" && m.roles.includes("dispatcher")));
      assert.ok(members.every(m => Object.keys(m).sort().join(",")
        === "identity_id,identity_status,membership_state,roles"));
      const adminTarget = { identity_id: "e2e-dispatcher" };
      // Protect the last active owner and deny unauthorized mutation before
      // modifying any member or returning replacement credentials.
      expectStatus(await jsonRequest("/admin/local-members/roles", "PUT",
        { identity_id: "e2e-owner", roles: ["dispatcher"] }, ownerJar), 412);
      expectStatus(await jsonRequest("/admin/local-members/suspend", "POST",
        { identity_id: "e2e-owner" }, ownerJar), 412);
      expectStatus(await jsonRequest("/admin/local-members/credentials/reset", "POST",
        adminTarget, consumerJarAfterReset), 403);
      expectStatus(await jsonRequest("/admin/local-members/roles", "PUT",
        { ...adminTarget, roles: ["dispatcher", "viewer"] }, ownerJar), 204);
      expectStatus(await jsonRequest("/admin/local-members/suspend", "POST",
        adminTarget, ownerJar), 204);
      expectStatus(await jsonRequest("/admin/local-members/suspend", "POST",
        adminTarget, ownerJar), 412);
      expectStatus(await jsonRequest("/admin/local-members/credentials/reset", "POST",
        adminTarget, ownerJar), 412);
      expectStatus(await jsonRequest("/admin/local-members/reinstate", "POST",
        adminTarget, ownerJar), 204);
      expectStatus(await jsonRequest("/admin/local-members/roles", "PUT",
        { ...adminTarget, roles: ["dispatcher"] }, ownerJar), 204);
      const resetMember = await jsonRequest("/admin/local-members/credentials/reset", "POST",
        adminTarget, ownerJar);
      expectStatus(resetMember, 200);
      const replacement = jsonBody(resetMember);
      assert.equal(replacement.identity_id, localMember.identity_id);
      assert.notEqual(replacement.initial_password, localMember.initial_password);
      assert.notEqual(replacement.totp_secret_base32, localMember.totp_secret_base32);
      assert.equal(resetMember.headers["cache-control"], "no-store");
      Object.assign(localMember, replacement);
      const auditCount = command("psql", [databaseUrl, "-AtX", "-v", "ON_ERROR_STOP=1", "-c",
        "SELECT count(*) FROM openproof.audit_events a JOIN openproof.security_event_outbox o USING(event_id) WHERE a.category='administration' AND a.identity_id='e2e-dispatcher' AND a.action IN ('local-member.create','local-member.roles.replace','local-member.suspend','local-member.reinstate','local-member.credentials.reset') AND a.event_hash<>decode(repeat('00',32),'hex')"]).trim();
      assert.equal(auditCount, "6");
      console.log("- native administration: role/lifecycle/reset, final owner, denied credentials and atomic audit/outbox passed");
    }

    const applicationResponse = await jsonRequest("/admin/applications", "POST", {
      identifier: "e2e-product",
      name: "E2E Product",
      environment: "development",
    }, ownerJar);
    expectStatus(applicationResponse, 201);
    const applicationId = jsonBody(applicationResponse).id;
    assert.ok(applicationId);

    const resourceResponse = await jsonRequest("/admin/resources", "POST", {
      audience: resourceAudience,
      name: "E2E API",
      scopes: ["api"],
    }, ownerJar);
    expectStatus(resourceResponse, 201);

    const clientResponse = await jsonRequest("/admin/clients", "POST", {
      application_id: applicationId,
      name: "E2E confidential client",
      kind: "web",
      redirect_uris: [`${issuer}/callback`],
      scopes: ["openid", "profile", "offline_access", "api"],
    }, ownerJar);
    expectStatus(clientResponse, 201);
    const clientRegistration = jsonBody(clientResponse);
    const clientId = clientRegistration.id;
    const clientSecret = clientRegistration.client_secret;
    assert.ok(clientId && clientSecret && clientRegistration.client_secret_returned_once);

    const nativeClientResponse = await jsonRequest("/admin/clients", "POST", {
      application_id: applicationId,
      name: "OpenProof QML native client",
      kind: "native",
      redirect_uris: ["http://127.0.0.1:49152/oauth/callback"],
      scopes: ["openid", "profile", "offline_access", "account"],
    }, ownerJar);
    expectStatus(nativeClientResponse, 201);
    const nativeRegistration = jsonBody(nativeClientResponse);
    nativeClientId = nativeRegistration.id;
    assert.ok(nativeClientId && !nativeRegistration.client_secret);

    const nativeTokens = await authorizeAndExchange(
      nativeClientId, "", ownerJar, initialJwks, {
        redirectUri: "http://127.0.0.1:54321/oauth/callback",
        scope: "openid profile offline_access account",
        resource: false,
      },
    );
    const nativeUserInfo = await edgeRequest("/oauth/userinfo", {
      headers: { authorization: `Bearer ${nativeTokens.access_token}` },
    });
    expectStatus(nativeUserInfo, 200);
    assert.equal(jsonBody(nativeUserInfo).sub, "e2e-owner");
    const nativeAccountProfile = await edgeRequest("/account/profile", {
      headers: { authorization: `Bearer ${nativeTokens.access_token}` },
    });
    expectStatus(nativeAccountProfile, 200);
    assert.equal(jsonBody(nativeAccountProfile).identity_id, "e2e-owner");
    const nativeConnections = await edgeRequest("/account/connections", {
      headers: { authorization: `Bearer ${nativeTokens.access_token}` },
    });
    expectStatus(nativeConnections, 200);
    assert.ok(Array.isArray(jsonBody(nativeConnections).connections));

    const profileOnlyTokens = await authorizeAndExchange(
      nativeClientId, "", ownerJar, initialJwks, {
        redirectUri: "http://127.0.0.1:54322/oauth/callback",
        scope: "openid profile",
        resource: false,
      },
    );
    const accountWithoutScope = await edgeRequest("/account/profile", {
      headers: { authorization: `Bearer ${profileOnlyTokens.access_token}` },
    });
    expectStatus(accountWithoutScope, 403);
    const connectionsWithoutScope = await edgeRequest("/account/connections", {
      headers: { authorization: `Bearer ${profileOnlyTokens.access_token}` },
    });
    expectStatus(connectionsWithoutScope, 403);
    if (nativeAccountRuntime) {
      for (const route of ["/account/profile", "/account/connections", "/account/totp", "/account/password/upgrade"]) {
        const allowed = await edgeRequest(route,{headers:{authorization:`Bearer ${nativeTokens.access_token}`}});
        expectStatus(allowed,200);
        const unscoped = await edgeRequest(route,{headers:{authorization:`Bearer ${profileOnlyTokens.access_token}`}});
        expectStatus(unscoped,403);
        const proofWithoutVerifier = await edgeRequest(route, {
          headers: { authorization: `DPoP ${nativeTokens.access_token}` },
        });
        expectStatus(proofWithoutVerifier, 401);
        const ambiguous = await edgeRequest(route, {
          jar: ownerJar,
          headers: { authorization: `Bearer ${nativeTokens.access_token}` },
        });
        expectStatus(ambiguous, 401);
      }
    }

    const firstTokens = await authorizeAndExchange(clientId, clientSecret, ownerJar, initialJwks);
    assert.equal(firstTokens.idHeader.kid, "e2e-old");

    const userInfo = await edgeRequest("/oauth/userinfo", {
      headers: { authorization: `Bearer ${firstTokens.access_token}` },
    });
    expectStatus(userInfo, 200);
    assert.equal(jsonBody(userInfo).sub, "e2e-owner");

    const protectedResponse = await edgeRequest("/api/ping", {
      headers: { authorization: `Bearer ${firstTokens.access_token}` },
    });
    expectStatus(protectedResponse, 200);
    assert.equal(jsonBody(protectedResponse).upstream, true);

    const introspectionForm = new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      token: firstTokens.access_token,
    });
    const introspection = await edgeRequest("/oauth/introspect", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: introspectionForm.toString(),
    });
    expectStatus(introspection, 200);
    assert.equal(jsonBody(introspection).active, true);
    if (nativeAccountRuntime) {
      const claims = jsonBody(introspection);
      assert.equal(claims.client_id,clientId);
      assert.equal(claims.sub,"e2e-owner");
      assert.ok(Number.isInteger(claims.iat) && Number.isInteger(claims.exp) && claims.exp>claims.iat);
      const inspect = async (form) => edgeRequest("/oauth/introspect",{
        method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body:form.toString(),
      });
      const invalid = new URLSearchParams(introspectionForm);
      invalid.set("token","unknown-fixture-token");
      const inactive=await inspect(invalid);
      expectStatus(inactive,200);
      assert.deepEqual(jsonBody(inactive),{active:false});
      invalid.set("client_secret","invalid-fixture-proof");
      expectStatus(await inspect(invalid),401);
      const publicCaller=new URLSearchParams(introspectionForm);
      publicCaller.set("client_id",nativeClientId);
      expectStatus(await inspect(publicCaller),401);
      const malformed=new URLSearchParams(introspectionForm);
      malformed.append("token","duplicate");
      expectStatus(await inspect(malformed),400);
      const anonymous=await edgeRequest("/oauth/userinfo");
      expectStatus(anonymous,401);
      assert.match(anonymous.headers["www-authenticate"],/invalid_token/);
      const preflight=await edgeRequest("/oauth/userinfo",{method:"OPTIONS"});
      expectStatus(preflight,204);
    }

    const beforeLoadUsage = readOppUsage(oppProcess?.pid);
    loadResult = await concurrentSmoke([
      () => edgeRequest("/health/ready"),
      () => edgeRequest("/.well-known/openid-configuration"),
      () => edgeRequest("/.well-known/jwks.json"),
      () => edgeRequest("/oauth/userinfo", {
        headers: { authorization: `Bearer ${firstTokens.access_token}` },
      }),
      () => edgeRequest("/api/ping", {
        headers: { authorization: `Bearer ${firstTokens.access_token}` },
      }),
      () => edgeRequest("/oauth/introspect", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: introspectionForm.toString(),
      }),
    ], mixedLoadRequests, mixedLoadConcurrency);
    const afterLoadUsage = readOppUsage(oppProcess?.pid);
    if (beforeLoadUsage && afterLoadUsage) {
      loadResourceMetrics = {
        serverCpuTicksDelta: Math.max(0,
          afterLoadUsage.cpuTicks - beforeLoadUsage.cpuTicks),
        serverRssKiBEnd: afterLoadUsage.rssKiB,
      };
    }

    const refreshForm = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: firstTokens.refresh_token,
    });
    const refreshedResponse = await edgeRequest("/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: refreshForm.toString(),
    });
    expectStatus(refreshedResponse, 200);
    const refreshed = jsonBody(refreshedResponse);
    assert.notEqual(refreshed.refresh_token, firstTokens.refresh_token);
    const replayResponse = await edgeRequest("/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: refreshForm.toString(),
    });
    expectStatus(replayResponse, 400);
    assert.equal(jsonBody(replayResponse).error, "invalid_grant");
    const familyResponse = await edgeRequest("/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: clientId,
        client_secret: clientSecret,
        refresh_token: refreshed.refresh_token,
      }).toString(),
    });
    expectStatus(familyResponse, 400);
    if (nativeAccountRuntime) {
      const revoke = (form) => edgeRequest("/oauth/revoke", {
        method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},
        body:new URLSearchParams(form).toString(),
      });
      const userInfo = (token) => edgeRequest("/oauth/userinfo",{
        headers:{authorization:`Bearer ${token}`},
      });
      expectStatus(await revoke({client_id:clientId,client_secret:clientSecret,
        token:nativeTokens.refresh_token}),200); // another client's token: no-op
      expectStatus(await userInfo(nativeTokens.access_token),200);
      expectStatus(await revoke({client_id:nativeClientId,token:nativeTokens.access_token}),200);
      expectStatus(await userInfo(nativeTokens.access_token),401);
      expectStatus(await revoke({client_id:nativeClientId,token:nativeTokens.refresh_token}),200);
      expectStatus(await revoke({client_id:nativeClientId,token:nativeTokens.refresh_token}),200);
      const revokedRefresh=await edgeRequest("/oauth/token",{
        method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},
        body:new URLSearchParams({grant_type:"refresh_token",client_id:nativeClientId,
          refresh_token:nativeTokens.refresh_token}).toString(),
      });
      expectStatus(revokedRefresh,400);
      expectStatus(await userInfo(profileOnlyTokens.access_token),200);
    }

    await stopOpp();
    await startOpp();
    const persistedProfile = await edgeRequest("/account/profile", { jar: consumerJarAfterReset });
    expectStatus(persistedProfile, 200);
    const persistedAdmin = await edgeRequest("/admin/applications", { jar: ownerJar });
    expectStatus(persistedAdmin, 200);
    assert.ok(jsonBody(persistedAdmin).applications.some((item) => item.id === applicationId));

    await stopOpp();
    const materialized = command(binary, [
      "materialize-persistent-keys", "--config", configurationPath,
      "--output-directory", persistentKeyDirectory,
      "--acknowledge-secret-export",
    ], { env: childEnvironment });
    assert.match(materialized, /materialized 5 legacy-compatible persistent subkeys/i);
    for (const keyFile of [
      materializedCredentialKey, passwordPepperFile, recoveryCodePepperFile,
      auditChainKeyFile, oauthClientSecretKeyFile,
    ]) {
      assert.equal(fs.statSync(keyFile).mode & 0o077, 0);
      assert.match(fs.readFileSync(keyFile, "utf8"), /^[0-9a-f]{64}$/);
    }
    writeConfiguration(
      oldOidcKey, "e2e-old", false, materializedCredentialKey, 1, 1, true,
    );
    const rekeyDryRun = command(binary, [
      "rekey-totp", "--config", configurationPath,
      "--new-key-ref", `file:${replacementCredentialKey}`,
      "--new-key-version", "2", "--dry-run",
    ], { env: childEnvironment });
    assert.match(rekeyDryRun, /dry run passed: 2 row\(s\) re-encrypted/i);
    const rekeyCommitted = command(binary, [
      "rekey-totp", "--config", configurationPath,
      "--new-key-ref", `file:${replacementCredentialKey}`,
      "--new-key-version", "2", "--acknowledge-offline",
    ], { env: childEnvironment });
    assert.match(rekeyCommitted, /rekey committed: 2 row\(s\) re-encrypted/i);
    writeConfiguration(
      oldOidcKey, "e2e-old", false, replacementCredentialKey, 2, 1, true,
    );
    await startOpp();
    const dispatcherJar = new CookieJar();
    const initialDispatcherTotp = totp(localMember.totp_secret_base32);
    const dispatcherGrant = await login(
      "dispatcher@e2e.invalid", localMember.initial_password, dispatcherJar,
      initialDispatcherTotp,
    );
    assert.equal(dispatcherGrant.assurance, "ial2");
    if (nativeAccountRuntime) {
      expectStatus(await edgeRequest("/admin/local-members", { jar: dispatcherJar }), 403);
      expectStatus(await jsonRequest("/admin/local-members/roles", "PUT",
        { identity_id: "e2e-dispatcher", roles: ["owner"] }, dispatcherJar), 403);
      console.log("- native owner-only administration listing and mutation: IAL2 non-owner denied");
    }

    await stopOpp();
    const masterRotationDryRun = command(binary, [
      "rotate-master-key", "--config", configurationPath,
      "--new-key-ref", `file:${replacementMasterKeyFile}`,
      "--new-key-version", "2", "--dry-run",
    ], { env: childEnvironment });
    assert.match(masterRotationDryRun, /master key rotation dry run passed:/i);
    const masterRotationCommitted = command(binary, [
      "rotate-master-key", "--config", configurationPath,
      "--new-key-ref", `file:${replacementMasterKeyFile}`,
      "--new-key-version", "2", "--acknowledge-offline",
    ], { env: childEnvironment });
    assert.match(masterRotationCommitted, /master key rotation committed:/i);
    const retiredMasterStart = spawnSync(
      binary, ["server", "--config", configurationPath], {
        cwd: root, env: childEnvironment, encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"], timeout: 5_000,
      },
    );
    assert.notEqual(retiredMasterStart.error?.code, "ETIMEDOUT",
      "server accepted the retired master and remained running");
    assert.notEqual(retiredMasterStart.status, 0);
    assert.match(
      `${retiredMasterStart.stderr ?? ""}${retiredMasterStart.stdout ?? ""}`,
      /does not match the committed rotation journal/i,
    );
    childEnvironment.OPENPROOF_TOKEN_SIGNING_KEY = replacementMasterKey;
    writeConfiguration(
      oldOidcKey, "e2e-old", false, replacementCredentialKey, 2, 2, true,
    );
    await startOpp();
    const retiredDispatcherSession = await edgeRequest(
      "/account/profile", { jar: dispatcherJar });
    expectStatus(retiredDispatcherSession, 401);
    const ownerJarAfterMasterRotation = new CookieJar();
    const ownerAfterMasterRotation = await login(
      "owner@e2e.invalid", ownerPassword, ownerJarAfterMasterRotation,
      await nextTotp(ownerTotp, initialOwnerTotp),
    );
    assert.equal(ownerAfterMasterRotation.assurance, "ial2");
    const dispatcherJarAfterMasterRotation = new CookieJar();
    const dispatcherAfterMasterRotation = await login(
      "dispatcher@e2e.invalid", localMember.initial_password,
      dispatcherJarAfterMasterRotation,
      await nextTotp(localMember.totp_secret_base32, initialDispatcherTotp),
    );
    assert.equal(dispatcherAfterMasterRotation.assurance, "ial2");

    await stopOpp();
    command("openssl", ["pkey", "-in", oldOidcKey, "-pubout", "-out", path.join(previousKeys, "e2e-old.pem")]);
    writeConfiguration(
      newOidcKey, "e2e-new", true, replacementCredentialKey, 2, 2, true,
    );
    await startOpp();
    const rotatedJwksResponse = await edgeRequest("/.well-known/jwks.json");
    expectStatus(rotatedJwksResponse, 200);
    const rotatedJwks = jsonBody(rotatedJwksResponse);
    assert.deepEqual(new Set(rotatedJwks.keys.map((key) => key.kid)), new Set(["e2e-new", "e2e-old"]));
    verifyIdToken(firstTokens.id_token, rotatedJwks, {
      issuer,
      clientId,
      nonce: firstTokens.nonce,
    });
    const rotatedTokens = await authorizeAndExchange(
      clientId, clientSecret, ownerJarAfterMasterRotation, rotatedJwks);
    assert.equal(rotatedTokens.idHeader.kid, "e2e-new");

    if (nativeAccountRuntime && !holdOpen) {
      expectStatus(await jsonRequest("/admin/local-members/remove", "POST",
        { identity_id: "e2e-dispatcher" }, ownerJarAfterMasterRotation), 204);
      expectStatus(await edgeRequest("/account/profile", { jar: dispatcherJarAfterMasterRotation }), 401);
      expectStatus(await jsonRequest("/admin/local-members/reinstate", "POST",
        { identity_id: "e2e-dispatcher" }, ownerJarAfterMasterRotation), 412);
      const removed = await edgeRequest("/admin/local-members", { jar: ownerJarAfterMasterRotation });
      expectStatus(removed, 200);
      assert.ok(jsonBody(removed).members.some(m => m.identity_id === "e2e-dispatcher"
        && m.membership_state === "removed" && m.roles.length === 0));
    }

    // Native consent mutation is tested only after the final token exchange,
    // never against the historical benchmark binary or interactive demo.
    if (process.env.OPENPROOF_E2E_EXPECT_LEGACY_AUTH !== "1" && !holdOpen) {
      expectStatus(await edgeRequest("/oauth/consents"), 401);
      expectStatus(await edgeRequest("/oauth/consents", {
        headers: { authorization: `Bearer ${rotatedTokens.access_token}` },
      }), 401);
      const listed = await edgeRequest("/oauth/consents", { jar: ownerJarAfterMasterRotation });
      expectStatus(listed, 200);
      assert.equal(listed.headers["cache-control"], "no-store");
      const document = jsonBody(listed);
      const grant = document.consents.find(item => item.client_id === clientId && item.active);
      assert.ok(grant, "active grant must be present before revocation");
      assert.ok(document.csrf);
      const revoke = (csrf) => edgeRequest("/oauth/consents/revoke", {
        method: "POST",
        jar: ownerJarAfterMasterRotation,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ consent_id: grant.id, csrf }).toString(),
      });
      expectStatus(await revoke("invalid"), 401);
      expectStatus(await revoke(document.csrf), 204);
      const afterRevoke = await edgeRequest("/oauth/consents", { jar: ownerJarAfterMasterRotation });
      expectStatus(afterRevoke, 200);
      assert.equal(jsonBody(afterRevoke).consents.find(item => item.id === grant.id)?.active, false);
    }

    const logout = await jsonRequest("/auth/logout", "POST", undefined, consumerJarAfterReset);
    expectStatus(logout, 204);
    const afterLogout = await edgeRequest("/account/profile", { jar: consumerJarAfterReset });
    expectStatus(afterLogout, 401);

    console.log("OpenProof identity E2E passed:");
    console.log("- verified TLS edge, liveness/readiness, authenticated Prometheus metrics, Discovery and JWKS");
    console.log("- signup, authenticated delivery, email verification, login and password reset");
    console.log("- FIP-11 Farcaster relay/direct starts, ERC-1271 custody/auth-address checks and linked-FID sessions");
    console.log("- authenticated connection listing, idempotent Farcaster attach, safe disconnect and last-method protection");
    console.log("- persistent sessions, admin console/local-member provisioning and OAuth Authorization Code + PKCE");
    console.log("- ID Token validation, UserInfo, scoped native account access, audience/scope gateway enforcement and introspection");
    console.log("- legacy subkey materialization, atomic TOTP rekey, full master-key retirement and OIDC key overlap");
    console.log(`- mixed read load smoke: ${loadResult.requests} requests at concurrency ${loadResult.concurrency}, `+
      `${loadResult.requestsPerSecond.toFixed(1)} req/s, p50 ${loadResult.p50Ms.toFixed(1)} ms, `+
      `p95 ${loadResult.p95Ms.toFixed(1)} ms, p99 ${loadResult.p99Ms.toFixed(1)} ms`);
    console.log(`Disposable database retained for inspection: ${databaseName}`);
    if (metricsFile) {
      // Only non-sensitive aggregate metrics; no tokens, passwords or addresses.
      fs.writeFileSync(metricsFile, JSON.stringify({
        benchmark: "openproof-isolated-e2e-mixed-read",
        commit: process.env.OPENPROOF_E2E_COMMIT ?? process.env.GITHUB_SHA ?? "local",
        timestamp: new Date().toISOString(),
        ...loadResult,
        ...loadResourceMetrics,
      }, null, 2) + "\n", { mode: 0o600 });
    }
    if (holdOpen) {
      if (!connectionFile) fail("OPENPROOF_E2E_CONNECTION_FILE is required while holding the demo open");
      if (realAuthMode) {
        await stopOpp();
        command("psql", [
          databaseUrl, "-v", "ON_ERROR_STOP=1", "-c",
          `delete from openproof.external_identities where provider='farcaster' and external_subject='${farcasterFid}'`,
        ]);
        childEnvironment.OPENPROOF_FARCASTER_RPC_ENDPOINT = realFarcasterRpcEndpoint;
        delete childEnvironment.OPENPROOF_WEB3_CA_FILE;
        await startOpp();
        expectStatus(await edgeRequest("/health/ready"), 200);
        console.log(`Real-account mode enabled; Farcaster verification uses ${realFarcasterRpcEndpoint}`);
      }
      fs.writeFileSync(connectionFile, JSON.stringify({
        base_url: issuer,
        ca_certificate: tlsCertificate,
        subject: "consumer@e2e.invalid",
        password: replacementPassword,
        portal_url: demoPortal.url,
        oauth_client_id: nativeClientId,
        oauth_redirect_uri: "http://127.0.0.1:49152/oauth/callback",
        farcaster_relay_url: "https://relay.farcaster.xyz/v1",
        real_auth_mode: realAuthMode,
      }), { mode: 0o600 });
      console.log(`Interactive demo is ready at ${issuer}`);
      console.log(`Local delivery inbox and API Explorer: ${demoPortal.url}`);
      console.log("Disposable credentials were written to the protected connection file.");
      console.log("Close the QML client or press Ctrl+C to stop the local stack.");
      await new Promise((resolve) => {
        process.once("SIGINT", resolve);
        process.once("SIGTERM", resolve);
      });
    }
  } finally {
    await stopOpp().catch(() => {});
    await ldapFixture?.close();
    await Promise.all([
      closeServer(edgeServer),
      closeServer(notificationServer),
      closeServer(farcasterRpcServer),
      closeServer(upstreamServer),
      demoPortal?.close(),
    ]).catch(() => {});
    const safePrefix = `${os.tmpdir()}${path.sep}openproof-e2e-`;
    if (tempRoot.startsWith(safePrefix) && path.dirname(tempRoot) === os.tmpdir()) {
      fs.rmSync(tempRoot, { recursive: true, force: false });
    }
  }
}

main().catch((error) => {
  console.error(error.stack ?? error.message);
  process.exitCode = 1;
});

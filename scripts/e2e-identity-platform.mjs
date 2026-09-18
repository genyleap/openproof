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

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const databaseUrl = process.env.OPENPROOF_E2E_POSTGRES ?? "";
const databaseAck = process.env.OPENPROOF_E2E_DATABASE_ACK ?? "";
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
    const detail = (result.stderr || result.stdout || "no command output").trim();
    fail(`${program} failed: ${detail}`);
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
    fail(`expected JSON from ${response.path}, received ${response.body.slice(0, 200)}`);
  }
}

function expectStatus(response, ...allowed) {
  if (!allowed.includes(response.status)) {
    fail(`${response.method} ${response.path} returned ${response.status}: ${response.body.slice(0, 400)}`);
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
  const oppPort = await reservePort();

  let oppProcess;
  let oppLog = "";
  let loadResult;
  let nativeClientId = "";
  const masterKey = base64Url(crypto.randomBytes(48));
  const ownerPassword = `E2E-owner-${base64Url(crypto.randomBytes(24))}`;
  const consumerPassword = `E2E-consumer-${base64Url(crypto.randomBytes(24))}`;
  const replacementPassword = `E2E-replaced-${base64Url(crypto.randomBytes(24))}`;
  const resourceAudience = "https://api.e2e.openproof.invalid";

  let frontPort;
  const edgeServer = https.createServer(
    { key: privateTlsKey, cert: certificate },
    (request, response) => {
      const headers = {
        ...request.headers,
        host: `127.0.0.1:${oppPort}`,
        "x-forwarded-for": request.socket.remoteAddress,
      };
      const forwarded = http.request({
        hostname: "127.0.0.1",
        port: oppPort,
        method: request.method,
        path: request.url,
        headers,
      }, (upstream) => {
        const responseHeaders = { ...upstream.headers };
        responseHeaders["strict-transport-security"] = "max-age=31536000";
        response.writeHead(upstream.statusCode, responseHeaders);
        upstream.pipe(response);
      });
      forwarded.on("error", () => {
        if (!response.headersSent) response.writeHead(502, { "content-type": "text/plain" });
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
    OPENPROOF_FARCASTER_CHAIN_ID: "10",
    OPENPROOF_FARCASTER_ID_REGISTRY: farcasterIdRegistry,
    OPENPROOF_FARCASTER_KEY_REGISTRY: farcasterKeyRegistry,
  };

  async function startOpp() {
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
    oppProcess.stdout.on("data", append);
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

  async function waitUntilReady() {
    let lastError;
    for (let attempt = 0; attempt < 100; ++attempt) {
      if (oppProcess.exitCode !== null) fail(`opp exited during startup:\n${oppLog.slice(-2000)}`);
      try {
        const response = await edgeRequest("/health/ready");
        if (response.status === 200) return;
        lastError = new Error(`readiness returned ${response.status}`);
      } catch (error) {
        lastError = error;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    fail(`readiness timed out: ${lastError?.message ?? "unknown error"}\n${oppLog.slice(-2000)}`);
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
      response = await edgeRequest("/oauth/consent", {
        method: "POST",
        jar: ownerJar,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form.toString(),
      });
      expectStatus(response, 303);
      response = await edgeRequest(response.headers.location, { jar: ownerJar });
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
    const tokenResponse = await edgeRequest("/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    expectStatus(tokenResponse, 200);
    const tokens = jsonBody(tokenResponse);
    assert.ok(tokens.access_token && tokens.refresh_token && tokens.id_token);
    const verified = verifyIdToken(tokens.id_token, keySet, { issuer, clientId, nonce });
    return { ...tokens, nonce, idHeader: verified.header };
  }

  let demoPortal;
  try {
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

    await startOpp();
    const live = await edgeRequest("/health/live");
    const ready = await edgeRequest("/health/ready");
    expectStatus(live, 200);
    expectStatus(ready, 200);
    assert.equal(live.headers["strict-transport-security"], "max-age=31536000");

    const deniedMetrics = await edgeRequest("/metrics");
    expectStatus(deniedMetrics, 401);
    assert.ok(!deniedMetrics.body.includes(metricsToken));
    const metrics = await edgeRequest("/metrics", {
      headers: { authorization: `Bearer ${metricsToken}` },
    });
    expectStatus(metrics, 200);
    assert.match(metrics.headers["content-type"], /^text\/plain; version=0\.0\.4/);
    assert.match(metrics.body, /openproof_process_starts_total\{version="1\.1\.0"\} 1/);
    assert.match(metrics.body, /openproof_http_requests_total\{method="GET",status_class="2xx"\}/);
    assert.ok(!metrics.body.includes("/health/ready"));
    assert.ok(!metrics.body.includes("e2e-owner"));
    assert.ok(!metrics.body.includes(metricsToken));

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
    assert.equal(relayChallenge.resource_prefix, "farcaster://fids/");
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
    assert.match(farcasterChallenge.message, /\nResources:\n- farcaster:\/\/fids\/6841$/);
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
    await login("consumer@e2e.invalid", consumerPassword, consumerJar);
    const connectionsBefore = await edgeRequest("/account/connections", { jar: consumerJar });
    expectStatus(connectionsBefore, 200);
    assert.deepEqual(
      jsonBody(connectionsBefore).connections.map(({ provider, subject }) => `${provider}:${subject}`).sort(),
      [`farcaster:${farcasterFid}`, "local:consumer@e2e.invalid"],
    );
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
    const consumerJarAfterReset = new CookieJar();
    await login("consumer@e2e.invalid", replacementPassword, consumerJarAfterReset);

    const ownerJar = new CookieJar();
    const initialOwnerTotp = totp(ownerTotp);
    const ownerGrant = await login(
      "owner@e2e.invalid", ownerPassword, ownerJar, initialOwnerTotp);
    assert.equal(ownerGrant.assurance, "ial2");
    const adminConsole = await edgeRequest("/admin/console", { jar: ownerJar });
    expectStatus(adminConsole, 200);
    assert.match(adminConsole.body, /name="identity_id"/);
    assert.match(adminConsole.body, /identity_id:v\.identity_id/);
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

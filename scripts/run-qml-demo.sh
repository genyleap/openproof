#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QML_SOURCE="${ROOT_DIR}/examples/qml-identity-client"
QML_BUILD="${OPENPROOF_QML_BUILD_DIR:-${QML_SOURCE}/build}"
if [[ "$(uname -s)" == Darwin ]]; then
    QML_BINARY="${QML_BUILD}/openproof_qml_client.app/Contents/MacOS/openproof_qml_client"
else
    QML_BINARY="${QML_BUILD}/openproof_qml_client"
fi
OPP_BINARY="${OPENPROOF_DEMO_OPP:-${ROOT_DIR}/cmake-build-gcc-release/apps/opp/opp}"
POSTGRES_BIN="${OPENPROOF_DEMO_POSTGRES_BIN:-}"

if [[ -z "${POSTGRES_BIN}" ]]; then
    PATH_INITDB="$(command -v initdb 2>/dev/null || true)"
    PATH_POSTGRES_BIN="${PATH_INITDB%/initdb}"
    if [[ -n "${PATH_INITDB}" && -x "${PATH_POSTGRES_BIN}/postgres" ]]; then
        POSTGRES_BIN="${PATH_POSTGRES_BIN}"
    elif [[ -x /opt/homebrew/opt/postgresql@18/bin/initdb
            && -x /opt/homebrew/opt/postgresql@18/bin/postgres ]]; then
        POSTGRES_BIN=/opt/homebrew/opt/postgresql@18/bin
    else
        printf 'qml demo: a complete PostgreSQL installation was not found\n' >&2
        exit 1
    fi
fi

for tool in initdb postgres pg_ctl createdb; do
    [[ -x "${POSTGRES_BIN}/${tool}" ]] || {
        printf 'qml demo: required tool is missing: %s/%s\n' "${POSTGRES_BIN}" "${tool}" >&2
        exit 1
    }
done
[[ -x "${OPP_BINARY}" ]] || {
    printf 'qml demo: build OpenProof first with cmake --build --preset gcc-release\n' >&2
    exit 1
}
command -v node >/dev/null 2>&1 || { printf 'qml demo: Node.js is required\n' >&2; exit 1; }
command -v cmake >/dev/null 2>&1 || { printf 'qml demo: CMake is required\n' >&2; exit 1; }

printf 'OpenProof QML demo: building the Qt client...\n'
cmake -S "${QML_SOURCE}" -B "${QML_BUILD}" -G Ninja
cmake --build "${QML_BUILD}" --parallel

DEMO_ROOT="$(mktemp -d /tmp/openproof-qml-demo.XXXXXX)"
[[ -n "${DEMO_ROOT}" && -d "${DEMO_ROOT}" && "${DEMO_ROOT}" == /tmp/openproof-qml-demo.* ]] || {
    printf 'qml demo: failed to create a constrained temporary directory\n' >&2
    exit 1
}
DEMO_DATA="${DEMO_ROOT}/data"
DEMO_SOCKET="${DEMO_ROOT}/socket"
DEMO_PORT=55434
DATABASE_NAME=openproof_e2e_qml_demo
CONNECTION_FILE="${DEMO_ROOT}/connection.json"
E2E_LOG="${DEMO_ROOT}/stack.log"
POSTGRES_STARTED=false
E2E_PID=""
REAL_AUTH_MODE="${OPENPROOF_DEMO_REAL_AUTH:-0}"
declare -a CONFIGURED_REDIRECT_PROVIDER_IDS=()
FRONT_PORT=0
if [[ "${REAL_AUTH_MODE}" == 1 ]]; then
    FRONT_PORT="${OPENPROOF_DEMO_FRONT_PORT:-18443}"
fi
for provider_spec in \
    'GOOGLE:google:Google' \
    'LINKEDIN:linkedin:LinkedIn' \
    'TELEGRAM:telegram:Telegram' \
    'GITHUB:github:GitHub' \
    'APPLE:apple:Apple' \
    'MICROSOFT:microsoft:Microsoft'; do
    IFS=: read -r provider_prefix provider_id provider_label <<<"${provider_spec}"
    client_id_variable="OPENPROOF_${provider_prefix}_CLIENT_ID"
    client_secret_variable="OPENPROOF_${provider_prefix}_CLIENT_SECRET"
    client_id_value="${!client_id_variable:-}"
    client_secret_value="${!client_secret_variable:-}"
    if [[ -n "${client_id_value}" && -z "${client_secret_value}"
          && "${REAL_AUTH_MODE}" == 1 && -t 0 ]]; then
        printf 'OpenProof demo: enter the %s client secret (input is hidden): ' \
            "${provider_label}" >&2
        IFS= read -r -s client_secret_value || true
        printf '\n' >&2
        if [[ -n "${client_secret_value}" ]]; then
            printf -v "${client_secret_variable}" '%s' "${client_secret_value}"
            export "${client_secret_variable}"
        fi
    fi
    if [[ -n "${client_id_value}" || -n "${client_secret_value}" ]]; then
        [[ "${REAL_AUTH_MODE}" == 1 ]] || {
            printf 'qml demo: %s credentials require OPENPROOF_DEMO_REAL_AUTH=1\n' "${provider_label}" >&2
            exit 1
        }
        [[ -n "${client_id_value}" && -n "${client_secret_value}" ]] || {
            printf 'qml demo: %s requires both %s and %s\n' \
                "${provider_label}" "${client_id_variable}" "${client_secret_variable}" >&2
            exit 1
        }
        CONFIGURED_REDIRECT_PROVIDER_IDS+=("${provider_id}")
    fi
done
if (( ${#CONFIGURED_REDIRECT_PROVIDER_IDS[@]} > 0 )); then
    : "${OPENPROOF_FEDERATION_CALLBACK_URI:=https://127.0.0.1:${FRONT_PORT}/auth/federated/callback}"
    export OPENPROOF_FEDERATION_CALLBACK_URI
fi
CONFIGURED_REDIRECT_PROVIDERS_CSV="$(IFS=,; printf '%s' "${CONFIGURED_REDIRECT_PROVIDER_IDS[*]:-}")"

if [[ "${CONFIGURED_REDIRECT_PROVIDER_IDS[*]:-}" == *google* ]]; then
    printf 'OpenProof QML demo: validating the Google client credentials...\n'
    if ! node --input-type=module <<'NODE'
const parameters = new URLSearchParams({
  grant_type: "authorization_code",
  code: "openproof-credential-preflight-invalid-code",
  client_id: process.env.OPENPROOF_GOOGLE_CLIENT_ID,
  client_secret: process.env.OPENPROOF_GOOGLE_CLIENT_SECRET,
  redirect_uri: process.env.OPENPROOF_FEDERATION_CALLBACK_URI,
  code_verifier: "A".repeat(43),
});
try {
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: parameters,
    signal: AbortSignal.timeout(10_000),
  });
  const value = await response.json().catch(() => ({}));
  if (value.error === "invalid_grant") {
    console.log("OpenProof QML demo: Google client ID and secret match.");
    process.exit(0);
  }
  if (value.error === "invalid_client" || value.error === "deleted_client") {
    console.error("qml demo: Google rejected this client ID/secret pair; copy the current secret from the same OAuth client without quotes");
    process.exit(2);
  }
  console.error(`qml demo: Google credential validation returned ${response.status}/${value.error ?? "unknown_error"}`);
  process.exit(3);
} catch (error) {
  console.error(`qml demo: Google credential validation could not reach the token endpoint: ${error.message}`);
  process.exit(4);
}
NODE
    then
        exit 1
    fi
fi

cleanup() {
    if [[ "${E2E_PID}" =~ ^[0-9]+$ ]] && kill -0 "${E2E_PID}" 2>/dev/null; then
        kill -INT "${E2E_PID}" 2>/dev/null || true
        wait "${E2E_PID}" 2>/dev/null || true
    fi
    if [[ "${POSTGRES_STARTED}" == true && -d "${DEMO_DATA}" ]]; then
        "${POSTGRES_BIN}/pg_ctl" -D "${DEMO_DATA}" -w stop >/dev/null 2>&1 || true
    fi
    printf 'OpenProof QML demo stopped. Artifacts retained at: %s\n' "${DEMO_ROOT}"
}
trap cleanup EXIT

printf 'OpenProof QML demo: creating an isolated PostgreSQL/TLS stack...\n'
mkdir -p "${DEMO_SOCKET}"
"${POSTGRES_BIN}/initdb" -D "${DEMO_DATA}" -A trust -U "$(id -un)" --no-locale >/dev/null
"${POSTGRES_BIN}/pg_ctl" -D "${DEMO_DATA}" -l "${DEMO_ROOT}/postgres.log" \
    -o "-k ${DEMO_SOCKET} -p ${DEMO_PORT} -c listen_addresses=''" -w start >/dev/null
POSTGRES_STARTED=true
"${POSTGRES_BIN}/createdb" -h "${DEMO_SOCKET}" -p "${DEMO_PORT}" \
    -U "$(id -un)" "${DATABASE_NAME}"

E2E_ENV=(
    "OPENPROOF_E2E_OPP=${OPP_BINARY}"
    "OPENPROOF_E2E_POSTGRES=postgresql://$(id -un)@/${DATABASE_NAME}?host=${DEMO_SOCKET}&port=${DEMO_PORT}"
    "OPENPROOF_E2E_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE"
    "OPENPROOF_E2E_LOAD_REQUESTS=12"
    "OPENPROOF_E2E_LOAD_CONCURRENCY=3"
    "OPENPROOF_E2E_HOLD_OPEN=1"
    "OPENPROOF_E2E_CONNECTION_FILE=${CONNECTION_FILE}"
    "OPENPROOF_E2E_REAL_AUTH=${REAL_AUTH_MODE}"
    "OPENPROOF_E2E_FRONT_PORT=${FRONT_PORT}"
    "OPENPROOF_E2E_FARCASTER_RPC_ENDPOINT=${OPENPROOF_FARCASTER_RPC_ENDPOINT:-https://mainnet.optimism.io/}"
)
env "${E2E_ENV[@]}" node "${ROOT_DIR}/scripts/e2e-identity-platform.mjs" >"${E2E_LOG}" 2>&1 &
E2E_PID=$!

for _ in {1..480}; do
    if [[ -s "${CONNECTION_FILE}" ]]; then break; fi
    if ! kill -0 "${E2E_PID}" 2>/dev/null; then
        cat "${E2E_LOG}" >&2
        exit 1
    fi
    sleep 0.25
done
if [[ ! -s "${CONNECTION_FILE}" ]]; then
    printf 'qml demo: local stack did not become ready\n' >&2
    tail -100 "${E2E_LOG}" >&2
    exit 1
fi

tail -12 "${E2E_LOG}"
if [[ "${REAL_AUTH_MODE}" == 1 ]]; then
    printf 'Real Farcaster login: enabled (public relay + live Optimism registry).\n'
    if (( ${#CONFIGURED_REDIRECT_PROVIDER_IDS[@]} > 0 )); then
        printf 'Real redirect-provider login: enabled for %s; registered callback must be %s\n' \
            "${CONFIGURED_REDIRECT_PROVIDERS_CSV}" "${OPENPROOF_FEDERATION_CALLBACK_URI}"
    else
        printf 'Real redirect-provider login: disabled (no OAuth credentials were supplied).\n'
    fi
fi
printf 'OpenProof QML demo: launching the interactive client...\n'
if [[ "${OPENPROOF_DEMO_SERVER_ONLY:-0}" == 1 ]]; then
    node -e '
      const fs = require("node:fs");
      const value = JSON.parse(fs.readFileSync(process.argv.at(-1), "utf8"));
      console.log(`OpenProof server-only QA mode: ${value.portal_url}`);
    ' "${CONNECTION_FILE}"
    wait "${E2E_PID}"
elif [[ "${OPENPROOF_QML_SMOKE:-0}" == 1 ]]; then
    PORTAL_URL="$(node -e '
      const fs = require("node:fs");
      const value = JSON.parse(fs.readFileSync(process.argv.at(-1), "utf8")).portal_url;
      if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(value)) process.exit(2);
      process.stdout.write(value);
    ' "${CONNECTION_FILE}")"
    node --input-type=module - "${PORTAL_URL}" "${REAL_AUTH_MODE}" "${CONFIGURED_REDIRECT_PROVIDERS_CSV}" <<'NODE'
import assert from "node:assert/strict";
import vm from "node:vm";

const portal = process.argv[2];
const realAuthMode = process.argv[3] === "1";
const configuredProviders = process.argv[4] ? process.argv[4].split(",").filter(Boolean) : [];
async function portalRequest(path, options) {
  const response = await fetch(`${portal}${path}`, options);
  const value = await response.json();
  assert.equal(response.status, 200, JSON.stringify(value));
  return value;
}
async function openProof(method, path, body, credentialMode = "portal") {
  return portalRequest("/api/request", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ method, path, body, credential_mode: credentialMode }),
  });
}

const portalHtml = await fetch(portal).then((response) => response.text());
assert.match(portalHtml, /id="openproof-demo"/);
assert.match(portalHtml, /\/assets\/portal\.js/);
const enhancedScript = await fetch(`${portal}/assets/portal.js`).then(async response => {
  assert.equal(response.status, 200);
  return response.text();
});
new vm.Script(enhancedScript, { filename: "openproof-developer-portal-v3.js" });
assert.match(enhancedScript, /Complete API reference/);
assert.match(enhancedScript, /code-lines/);
assert.match(enhancedScript, /Identity & request credential/);
assert.match(enhancedScript, /Farcaster lab/);
assert.match(enhancedScript, /FIP-11/);
assert.match(enhancedScript, /Connected accounts/);
assert.match(enhancedScript, /account\/connections\/handoff/);
assert.match(enhancedScript, /resolvedPath/);
const enhancedStyles = await fetch(`${portal}/assets/portal.css`).then(async response => {
  assert.equal(response.status, 200);
  return response.text();
});
assert.match(enhancedStyles, /Material Symbols Rounded/);
assert.match(enhancedStyles, /journey-layout/);
assert.match(enhancedStyles, /credential-panel/);
assert.match(enhancedStyles, /farcaster-lab/);
assert.match(enhancedStyles, /connections-page/);
const iconFont = await fetch(`${portal}/assets/material-symbols-rounded-subset.ttf`);
assert.equal(iconFont.status, 200);
assert.ok((await iconFont.arrayBuffer()).byteLength > 10_000);
const catalog = await portalRequest("/api/catalog");
assert.ok(catalog.operations.length >= 90, "OpenAPI catalog is unexpectedly incomplete");
assert.ok(catalog.operations.find((operation) => operation.operation_id === "authorize").parameters.length >= 8);
assert.equal(catalog.operations.find((operation) => operation.operation_id === "getProfile").parameters.length, 0);
assert.ok(catalog.operations.find((operation) => operation.operation_id === "showAccountConnectionComplete"));
const anonymousSession = await portalRequest("/api/session/status");
assert.equal(anonymousSession.authenticated, false);

const ready = await openProof("GET", "/health/ready");
assert.equal(ready.status, 200);
const providers = await openProof("GET", "/auth/providers");
assert.equal(providers.status, 200);
const enabledProviders = JSON.parse(providers.body).providers;
for (const provider of configuredProviders) assert.ok(enabledProviders.includes(provider));
const connectionCompletePage = await openProof("GET", "/account/connections/complete", "", "none");
assert.equal(connectionCompletePage.status, 200);
assert.match(connectionCompletePage.body, /Account connected/);
const farcasterRelay = await openProof("POST", "/auth/web3/start", { provider: "farcaster" });
assert.equal(farcasterRelay.status, 200);
const relayChallenge = JSON.parse(farcasterRelay.body);
assert.equal(relayChallenge.statement, "Farcaster Auth");
assert.equal(relayChallenge.resource_prefix, "farcaster://fids/");
if (!realAuthMode) {
  const farcasterStart = await openProof("POST", "/auth/web3/start", {
    provider: "farcaster",
    fid: "6841",
    address: "0x1111111111111111111111111111111111111111",
  });
  assert.equal(farcasterStart.status, 200);
  const farcasterChallenge = JSON.parse(farcasterStart.body);
  assert.equal(farcasterChallenge.signer_kind, "custody");
  assert.match(farcasterChallenge.message, /Farcaster Auth/);
  const farcasterComplete = await openProof("POST", "/auth/web3/complete", {
    message: farcasterChallenge.message,
    signature: "0x0102",
  });
  assert.equal(farcasterComplete.status, 200);
  assert.equal((await portalRequest("/api/session/status")).authenticated, true);
  assert.equal((await openProof("POST", "/auth/logout", {})).status, 204);
}
const email = `portal-${Date.now()}@example.test`;
const password = ["openproof", "demo", "only", "replace-me"].join("-");
const signup = await openProof("POST", "/account/signup", {
  email, password, display_name: "Portal Smoke User",
});
assert.equal(signup.status, 201);
const inbox = await portalRequest("/api/messages");
const delivery = inbox.messages.find((message) => message.destination === email);
assert.ok(delivery, "signup delivery did not reach the local inbox");
const verification = await portalRequest(`/api/messages/${delivery.index}/verify`, {
  method: "POST",
});
assert.equal(verification.status, 200);
const started = await openProof("POST", "/auth/login", { subject: email });
assert.equal(started.status, 202);
const challenge = JSON.parse(started.body);
const completed = await openProof("POST", "/auth/mfa/verify", {
  transaction_id: challenge.transaction_id,
  challenge_id: challenge.challenge_id,
  password,
});
assert.equal(completed.status, 200);
const profile = await openProof("GET", "/account/profile");
assert.equal(profile.status, 200);
assert.equal(JSON.parse(profile.body).email_verified, true);
const authenticatedSession = await portalRequest("/api/session/status");
assert.equal(authenticatedSession.authenticated, true);
assert.equal(authenticatedSession.profile.email, email);
const profileWithoutCredential = await openProof("GET", "/account/profile", "", "none");
assert.equal(profileWithoutCredential.status, 401);
NODE
    printf 'OpenProof web lab smoke passed: Farcaster challenge, signup, inbox delivery, verification, login and profile.\n'
    QT_QPA_PLATFORM=offscreen "${QML_BINARY}" --connection-file "${CONNECTION_FILE}" --api-smoke
    if [[ "${REAL_AUTH_MODE}" == 1 ]]; then
        printf 'OpenProof QML client API smoke passed: health, login, profile, connections and logout (live Farcaster awaits user approval).\n'
    else
        printf 'OpenProof QML client API smoke passed: health, deterministic Farcaster SIWF, login, profile, connections and logout.\n'
    fi
else
    node -e '
      const fs = require("node:fs");
      const value = JSON.parse(fs.readFileSync(process.argv.at(-1), "utf8"));
      console.log(`OpenProof web lab: ${value.portal_url}`);
    ' "${CONNECTION_FILE}"
    "${QML_BINARY}" --connection-file "${CONNECTION_FILE}"
fi

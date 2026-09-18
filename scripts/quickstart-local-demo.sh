#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
        printf 'quickstart: PostgreSQL initdb was not found\n' >&2
        exit 1
    fi
fi

for tool in initdb postgres pg_ctl createdb; do
    [[ -x "${POSTGRES_BIN}/${tool}" ]] || {
        printf 'quickstart: required tool is missing: %s/%s\n' "${POSTGRES_BIN}" "${tool}" >&2
        exit 1
    }
done
[[ -x "${OPP_BINARY}" ]] || {
    printf 'quickstart: Release binary is missing; run cmake --build --preset gcc-release\n' >&2
    exit 1
}
command -v node >/dev/null 2>&1 || {
    printf 'quickstart: Node.js is required\n' >&2
    exit 1
}

DEMO_ROOT="$(mktemp -d /tmp/openproof-quickstart.XXXXXX)"
[[ -n "${DEMO_ROOT}" && -d "${DEMO_ROOT}" && "${DEMO_ROOT}" == /tmp/openproof-quickstart.* ]] || {
    printf 'quickstart: failed to create a constrained temporary directory\n' >&2
    exit 1
}
DEMO_DATA="${DEMO_ROOT}/data"
DEMO_SOCKET="${DEMO_ROOT}/socket"
DEMO_PORT=55433
DATABASE_NAME=openproof_e2e_quickstart
POSTGRES_STARTED=false

stop_postgres() {
    if [[ "${POSTGRES_STARTED}" == true && -d "${DEMO_DATA}" ]]; then
        "${POSTGRES_BIN}/pg_ctl" -D "${DEMO_DATA}" -w stop >/dev/null 2>&1 || true
    fi
}
trap stop_postgres EXIT

printf 'OpenProof quickstart: creating an isolated local PostgreSQL cluster...\n'
mkdir -p "${DEMO_SOCKET}"
"${POSTGRES_BIN}/initdb" -D "${DEMO_DATA}" -A trust -U "$(id -un)" --no-locale >/dev/null
"${POSTGRES_BIN}/pg_ctl" -D "${DEMO_DATA}" -l "${DEMO_ROOT}/postgres.log" \
    -o "-k ${DEMO_SOCKET} -p ${DEMO_PORT} -c listen_addresses=''" -w start >/dev/null
POSTGRES_STARTED=true
"${POSTGRES_BIN}/createdb" -h "${DEMO_SOCKET}" -p "${DEMO_PORT}" \
    -U "$(id -un)" "${DATABASE_NAME}"

printf 'OpenProof quickstart: running signup, verification, MFA and OAuth/OIDC...\n'
OPENPROOF_E2E_OPP="${OPP_BINARY}" \
OPENPROOF_E2E_POSTGRES="postgresql://$(id -un)@/${DATABASE_NAME}?host=${DEMO_SOCKET}&port=${DEMO_PORT}" \
OPENPROOF_E2E_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE \
OPENPROOF_E2E_LOAD_REQUESTS="${OPENPROOF_DEMO_LOAD_REQUESTS:-60}" \
OPENPROOF_E2E_LOAD_CONCURRENCY="${OPENPROOF_DEMO_LOAD_CONCURRENCY:-6}" \
    node "${ROOT_DIR}/scripts/e2e-identity-platform.mjs"

printf 'OpenProof quickstart passed. Temporary database retained at: %s\n' "${DEMO_ROOT}"

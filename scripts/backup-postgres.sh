#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'OpenProof backup: %s\n' "$1" >&2
    exit 1
}

[[ -n "${OPENPROOF_DATABASE_URL:-}" ]] \
    || fail "OPENPROOF_DATABASE_URL must reference the database to back up"
[[ $# -eq 1 ]] || fail "usage: $0 /absolute/path/openproof.dump"

OUTPUT="$1"
[[ "${OUTPUT}" = /* ]] || fail "the output path must be absolute"
[[ ! -e "${OUTPUT}" && ! -e "${OUTPUT}.sha256" ]] \
    || fail "the output or checksum file already exists"
command -v pg_dump >/dev/null 2>&1 || fail "pg_dump is required"

umask 077
pg_dump --dbname="${OPENPROOF_DATABASE_URL}" --format=custom --compress=9 \
    --no-owner --no-privileges --file="${OUTPUT}"
[[ -s "${OUTPUT}" ]] || fail "pg_dump produced an empty backup"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$(dirname "${OUTPUT}")" && sha256sum "$(basename "${OUTPUT}")") \
        > "${OUTPUT}.sha256"
else
    (cd "$(dirname "${OUTPUT}")" && shasum -a 256 "$(basename "${OUTPUT}")") \
        > "${OUTPUT}.sha256"
fi

printf 'OpenProof backup created: %s\n' "${OUTPUT}"
printf 'Checksum created: %s.sha256\n' "${OUTPUT}"

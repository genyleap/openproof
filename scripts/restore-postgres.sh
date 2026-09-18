#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'OpenProof restore: %s\n' "$1" >&2
    exit 1
}

[[ -n "${OPENPROOF_RESTORE_DATABASE_URL:-}" ]] \
    || fail "OPENPROOF_RESTORE_DATABASE_URL must reference a new, empty restore database"
[[ "${OPENPROOF_RESTORE_ACK:-}" == "YES_RESTORE_TO_EMPTY_DATABASE" ]] \
    || fail "set OPENPROOF_RESTORE_ACK=YES_RESTORE_TO_EMPTY_DATABASE"
[[ $# -eq 1 ]] || fail "usage: $0 /absolute/path/openproof.dump"

BACKUP="$1"
[[ "${BACKUP}" = /* && -f "${BACKUP}" && -f "${BACKUP}.sha256" ]] \
    || fail "the absolute backup path and its .sha256 file are required"
command -v psql >/dev/null 2>&1 || fail "psql is required"
command -v pg_restore >/dev/null 2>&1 || fail "pg_restore is required"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$(dirname "${BACKUP}")" && sha256sum --check "$(basename "${BACKUP}.sha256")")
else
    (cd "$(dirname "${BACKUP}")" && shasum -a 256 --check "$(basename "${BACKUP}.sha256")")
fi

TABLE_COUNT="$(psql "${OPENPROOF_RESTORE_DATABASE_URL}" --no-psqlrc --tuples-only \
    --no-align --set=ON_ERROR_STOP=1 --command="SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog', 'information_schema');")"
[[ "${TABLE_COUNT}" == "0" ]] \
    || fail "the restore target is not empty; no data was changed"

pg_restore --dbname="${OPENPROOF_RESTORE_DATABASE_URL}" --exit-on-error \
    --single-transaction --no-owner --no-privileges "${BACKUP}"
psql "${OPENPROOF_RESTORE_DATABASE_URL}" --no-psqlrc --set=ON_ERROR_STOP=1 \
    --command='SELECT count(*) AS applied_migrations FROM openproof.schema_migrations;'

printf 'OpenProof restore completed into the empty target database.\n'

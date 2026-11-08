#!/usr/bin/env bash
# Dedicated private socket-only PostgreSQL 16 cluster for native recovery-code
# coroutine SQL regressions. No production schema/connection is used.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
pgbin="/usr/lib/postgresql/16/bin"
work="$(mktemp -d /tmp/openproof-recovery-pg.XXXXXXXX)"
port=55418
started=0

run_as_pg() {
    if [[ "$(id -u)" == 0 ]]; then
        runuser -u postgres -- "$@"
    else
        "$@"
    fi
}

if [[ "$(id -u)" == 0 ]]; then
    chown postgres:postgres "$work"
    pg_user=postgres
else
    pg_user="$(id -un)"
fi

cleanup() {
    if [[ "$started" == 1 ]]; then
        run_as_pg "$pgbin/pg_ctl" -D "$work/data" \
            -m immediate -w stop >/dev/null || true
    fi
    if [[ "$work" == /tmp/openproof-recovery-pg.* && -d "$work" ]]; then
        rm -rf -- "$work"
    fi
}
trap cleanup EXIT INT TERM

run_as_pg "$pgbin/initdb" -D "$work/data" --no-sync \
    -A trust --no-instructions >/dev/null
run_as_pg "$pgbin/pg_ctl" -D "$work/data" -l "$work/server.log" \
    -o "-c listen_addresses= -c unix_socket_directories=$work -p $port" \
    -w start >/dev/null
started=1

# The backend only accepts Unix connections in this newly created workdir.
# The GTests create pg_temp.recovery_codes; no canonical table is touched.
export OPENPROOF_TEST_POSTGRES="host=$work port=$port user=$pg_user dbname=postgres"
ctest --test-dir "$repo/cmake-build-gcc-release" \
    -R '^NativePgRecovery\.' --output-on-failure -V -j 1

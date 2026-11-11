#!/usr/bin/env bash
# Self-contained, ephemeral PostgreSQL test fixture for the native coroutine
# auth transaction store. Never connects to or modifies a running cluster.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pgbin="${OPENPROOF_TEST_PGBIN:-/usr/lib/postgresql/16/bin}"
# PostgreSQL must never start as root. Some remote shells report uid=0
# but cannot change identity. Check before even creating a fixture directory,
# so a failed setuid leaves no orphaned private test directory.
if [[ "$(id -u)" == 0 ]] &&
   ! runuser -u postgres -- /usr/bin/true; then
    echo "Disposable PostgreSQL requires a runner permitted to drop to postgres; no database started." >&2
    exit 1
fi
work="$(mktemp -d /tmp/openproof-auth-pg.XXXXXXXX)"
port=55417
started=0

if [[ "$(id -u)" == 0 ]]; then
    chown postgres:postgres "$work"
    as_pg=(runuser -u postgres --)
else
    as_pg=()
fi

cleanup() {
    if [[ "$started" == 1 ]]; then
        "${as_pg[@]}" "$pgbin/pg_ctl" -D "$work/data" -m immediate -w stop >/dev/null || true
    fi
    if [[ "$work" == /tmp/openproof-auth-pg.* ]]; then
        rm -rf -- "$work"
    fi
}
trap cleanup EXIT INT TERM

"${as_pg[@]}" "$pgbin/initdb" -D "$work/data" --no-sync -A trust --no-instructions >/dev/null
"${as_pg[@]}" "$pgbin/pg_ctl" -D "$work/data" -l "$work/server.log" \
    -o "-c listen_addresses= -c unix_socket_directories=$work -p $port" -w start >/dev/null
started=1

# Only a private Unix-domain socket inside a temporary cluster is reachable.
# SQL tests create TEMP tables in the fixture; no production schema is touched.
export OPENPROOF_TEST_POSTGRES="host=$work port=$port user=$(if [[ $(id -u) == 0 ]]; then echo postgres; else id -un; fi) dbname=postgres"
ctest --test-dir "$repo/cmake-build-gcc-release" \
    -R '^NativePgAuthTransaction' --output-on-failure -V -j 1 \
    --output-junit "$work/test-results.xml"
# CTest may exit zero with all SQL tests SKIPPED. That is a failure of
# native database acceptance, never a passing PostgreSQL integration run.
if [[ ! -s "$work/test-results.xml" ]] \
    || ! grep -q '<testcase' "$work/test-results.xml" \
    || grep -q '<skipped' "$work/test-results.xml"; then
    echo "Disposable authentication PostgreSQL tests missing or skipped; SQL acceptance denied." >&2
    exit 1
fi

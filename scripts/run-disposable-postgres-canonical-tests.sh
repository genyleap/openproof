#!/usr/bin/env bash
# Native canonical PostgreSQL tests against a short-lived isolated cluster.
# Never connects to Production: no TCP listening; only this private Unix socket.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pgbin="${OPENPROOF_TEST_PGBIN:-/usr/lib/postgresql/16/bin}"
work="$(mktemp -d /tmp/openproof-canonical-pg.XXXXXXXX)"
port=55418
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
    if [[ "$work" == /tmp/openproof-canonical-pg.???????? ]]; then
        rm -rf -- "$work"
    fi
}
trap cleanup EXIT INT TERM

"${as_pg[@]}" "$pgbin/initdb" -D "$work/data" --no-sync -U postgres -A trust --no-instructions >/dev/null
"${as_pg[@]}" "$pgbin/pg_ctl" -D "$work/data" -l "$work/server.log" \
    -o "-c listen_addresses= -c unix_socket_directories=$work -p $port" -w start >/dev/null
started=1

"${as_pg[@]}" "$pgbin/createdb" -h "$work" -p "$port" -U postgres openproof_coroutine_ci
# Minimal, real checked-in migrations sufficient for canonical domain tests.
# Never mutate a preexisting cluster or use credentials from the environment.
for migration in \
    0001_identity_auth_gateway.sql \
    0003_identity_provider.sql \
    0005_account_lifecycle.sql \
    0018_profile_avatar_sources.sql; do
    "${as_pg[@]}" "$pgbin/psql" -X -q -v ON_ERROR_STOP=1 \
        -h "$work" -p "$port" -U postgres -d openproof_coroutine_ci \
        -f "$repo/migrations/$migration"
done

export OPENPROOF_TEST_POSTGRES_DOMAIN="host=$work port=$port user=postgres dbname=openproof_coroutine_ci"
export OPENPROOF_TEST_POSTGRES_DOMAIN_ACK=YES_EXCLUSIVE_DISPOSABLE_DATABASE
ctest --test-dir "$repo/cmake-build-gcc-release" \
    -R '^NativePgCanonical\.' --output-on-failure -V -j 1 \
    --output-junit "$work/test-results.xml"
# A skipped SQL test must never be mistaken for acceptance of the real DB
# contract, even if other offline cases passed.
if [[ ! -s "$work/test-results.xml" ]] \
    || grep -q '<skipped' "$work/test-results.xml"; then
    echo "Disposable canonical PostgreSQL suite did not exercise every test" >&2
    exit 1
fi

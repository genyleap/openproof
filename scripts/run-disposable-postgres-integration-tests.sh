#!/usr/bin/env bash
# Run destructive integration regressions only in a new private cluster.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${1:-$repo/cmake-build-gcc-release}"
pgbin="${OPENPROOF_TEST_PGBIN:-/usr/lib/postgresql/16/bin}"
binary="$build_dir/tests/openproof_tests"
if [[ ! -f "$build_dir/CMakeCache.txt" || ! -x "$binary" ]]; then
    echo "Configured current C++ integration test binary required." >&2
    exit 1
fi
if [[ "$(id -u)" == 0 ]] && ! runuser -u postgres -- /usr/bin/true; then
    echo "Disposable integration PostgreSQL requires a postgres-capable runner." >&2
    exit 1
fi
work="$(mktemp -d /tmp/openproof-integration-pg.XXXXXXXX)"
port=55419
started=0
as_pg=()
cleanup() {
    if [[ "$started" == 1 ]]; then
        "${as_pg[@]}" "$pgbin/pg_ctl" -D "$work/data" -m immediate -w stop >/dev/null || true
    fi
    if [[ "$work" == /tmp/openproof-integration-pg.???????? ]]; then
        rm -rf -- "$work"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ "$(id -u)" == 0 ]]; then
    chown postgres:postgres "$work"
    as_pg=(runuser -u postgres --)
fi
# Strip all libpq environment defaults, including hostaddr/service/options.
# The fixture is the only database selected below.
for variable in ${!PG@}; do
    unset "$variable"
done
"${as_pg[@]}" "$pgbin/initdb" -D "$work/data" --no-sync -U postgres -A trust --no-instructions >/dev/null
"${as_pg[@]}" "$pgbin/pg_ctl" -D "$work/data" -l "$work/server.log" \
    -o "-c listen_addresses= -c unix_socket_directories=$work -p $port" -w start >/dev/null
started=1
"${as_pg[@]}" "$pgbin/createdb" -h "$work" -p "$port" -U postgres openproof_integration_ci
export OPENPROOF_TEST_POSTGRES_INTEGRATION="host=$work port=$port user=postgres dbname=openproof_integration_ci"
export OPENPROOF_TEST_POSTGRES_INTEGRATION_ACK=YES_EXCLUSIVE_DISPOSABLE_DATABASE
# Baseline-specific test is mandatory in its own dedicated CI step.
filter='^PostgresIntegrationTest\.'
exclude=()
if [[ -z "${OPENPROOF_TEST_BASELINE_DIRECTORY:-}" ]]; then
    exclude=(-E '^PostgresIntegrationTest\.ExistingSchemaNeverRestoresSnapshot$')
fi
ctest --test-dir "$build_dir" -R "$filter" "${exclude[@]}" --output-on-failure -V -j 1 \
    --output-junit "$work/test-results.xml"
if [[ ! -s "$work/test-results.xml" ]] || ! grep -q '<testcase' "$work/test-results.xml" \
    || grep -q '<skipped' "$work/test-results.xml"; then
    echo "Disposable integration suite missing or skipped tests; acceptance denied." >&2
    exit 1
fi

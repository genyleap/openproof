#!/usr/bin/env bash
# Same binary, same fixture and alternating order. Diagnostic only.
# Never execute on a shared or production database.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ &&
   "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ && "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ ]] || exit 2
ROOT="$(git rev-parse --show-toplevel)"
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$GITHUB_SHA" ]] || exit 2
binary="$ROOT/cmake-build-gcc-release/apps/opp/opp"
[[ -x "$binary" ]] || exit 2
output="$ROOT/handler-pool-probe"
mkdir "$output"
run_trial() {
    local profile="$1" trial="$2" db
    local -a override=()
    case "$profile" in
        auto) ;;
        two) override=(OPENPROOF_EXPERIMENTAL_HANDLER_THREADS=2) ;;
        *) return 2 ;;
    esac
    db="openproof_e2e_pool_${GITHUB_RUN_ID}_${GITHUB_RUN_ATTEMPT}_${trial}_${profile}"
    [[ ${#db} -le 63 ]] || exit 2
    sudo -u postgres createdb -O openproof_ci "$db"
    env -u OPENPROOF_EXPERIMENTAL_HANDLER_THREADS "${override[@]}" \
        OPENPROOF_E2E_POSTGRES="postgresql://openproof_ci:ci_disposable_only@127.0.0.1:5432/$db" \
        OPENPROOF_E2E_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE \
        OPENPROOF_E2E_OPP="$binary" OPENPROOF_E2E_COMMIT="$GITHUB_SHA" \
        OPENPROOF_E2E_EXPECT_LEGACY_AUTH=0 \
        OPENPROOF_E2E_LOAD_REQUESTS=600 OPENPROOF_E2E_LOAD_CONCURRENCY=24 \
        OPENPROOF_E2E_METRICS_FILE="$output/$profile-$trial.json" \
        node "$ROOT/scripts/e2e-identity-platform.mjs"
    [[ -s "$output/$profile-$trial.json" ]]
}
run_trial auto 1
run_trial two 1
run_trial two 2
run_trial auto 2
for trial in 1 2; do
    echo "Exploratory same-binary handler pool comparison: pair $trial (auto vs two)"
    node "$ROOT/scripts/compare-e2e-metrics.mjs" \
        "$output/auto-$trial.json" "$output/two-$trial.json"
done

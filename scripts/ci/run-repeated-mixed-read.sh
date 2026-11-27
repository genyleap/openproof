#!/usr/bin/env bash
# Dedicated disposable CI runner only; never reuse a database.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ &&
   "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ && "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ ]] ||
    { echo "Disposable GitHub Actions runner required." >&2; exit 2; }
ROOT="$(git rev-parse --show-toplevel)"
BASE_DIR="${RUNNER_TEMP:?}/openproof-perf-baseline"
BASE_SHA="${OPENPROOF_PERF_BASELINE_SHA:-ccb396182936d717960fdca319999baf2f580ff9}"
[[ "$BASE_SHA" =~ ^[a-f0-9]{40}$ && "$BASE_SHA" != "$GITHUB_SHA" ]] || exit 2
[[ "$(git -C "$BASE_DIR" rev-parse HEAD)" == "$BASE_SHA" &&
   "$(git -C "$ROOT" rev-parse HEAD)" == "$GITHUB_SHA" ]] || exit 2
base_binary="$BASE_DIR/cmake-build-gcc-release/apps/opp/opp"
candidate_binary="$ROOT/cmake-build-gcc-release/apps/opp/opp"
[[ -x "$base_binary" && -x "$candidate_binary" ]] || exit 2
output="$ROOT/mixed-read-bench"
concurrency=24; requests=600; warmup=0; pairs=5
if (( $# > 0 )); then
    [[ $# == 1 ]] || exit 2
    case "$1" in 1|8|32|128) concurrency="$1" ;; *) exit 2 ;; esac
    output="$ROOT/mixed-read-matrix/c${concurrency}"
    requests=1536; pairs=4
    warmup=$(( (2*concurrency+5)/6*6 ))
    if (( warmup < 24 )); then warmup=24; fi
fi
mkdir -p "$(dirname "$output")"
mkdir "$output"
run_trial() (
    local side="$1" trial="$2" binary sha legacy db
    case "$side" in
        baseline) binary="$base_binary"; sha="$BASE_SHA"; legacy=1 ;;
        candidate) binary="$candidate_binary"; sha="$GITHUB_SHA"; legacy=0 ;;
        *) return 2 ;;
    esac
    db="opp_e2e_r_${GITHUB_RUN_ID}_${GITHUB_RUN_ATTEMPT}_${concurrency}_${trial}_${side}"
    [[ ${#db} -le 63 ]] || return 2
    sudo -u postgres createdb -O openproof_ci "$db"
    if (( warmup > 0 )); then trap 'sudo -u postgres dropdb --if-exists "$db"' EXIT; fi
    OPENPROOF_E2E_POSTGRES="postgresql://openproof_ci:ci_disposable_only@127.0.0.1:5432/$db" \
    OPENPROOF_E2E_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE \
    OPENPROOF_E2E_OPP="$binary" OPENPROOF_E2E_COMMIT="$sha" \
    OPENPROOF_E2E_EXPECT_LEGACY_AUTH="$legacy" \
    OPENPROOF_E2E_LOAD_REQUESTS="$requests" OPENPROOF_E2E_LOAD_CONCURRENCY="$concurrency" \
    OPENPROOF_E2E_LOAD_WARMUP="$warmup" \
    OPENPROOF_E2E_METRICS_FILE="$output/$side-$trial.json" \
        node "$ROOT/scripts/e2e-identity-platform.mjs"
    [[ -s "$output/$side-$trial.json" ]]
)
for ((trial=1; trial<=pairs; ++trial)); do
    if (( trial % 2 == 0 )); then
        run_trial baseline "$trial"
        run_trial candidate "$trial"
    else
        run_trial candidate "$trial"
        run_trial baseline "$trial"
    fi
done
node "$ROOT/scripts/summarize-mixed-read.mjs" "$output" "$BASE_SHA" "$GITHUB_SHA" "$@"

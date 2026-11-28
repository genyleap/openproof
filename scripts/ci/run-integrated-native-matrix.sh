#!/usr/bin/env bash
# Isolated historical baseline vs complete integrated native candidate.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ &&
   "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ && "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ ]] || exit 2
ROOT="$(git rev-parse --show-toplevel)"
mode="${1:-historical-native}"
case "$mode" in
  historical-native)
    BASE_SHA=ccb396182936d717960fdca319999baf2f580ff9
    BASE_DIR="${RUNNER_TEMP:?}/openproof-perf-baseline"
    loads=(1 8 32 128)
    ;;
  native-native)
    BASE_SHA=c18450e405aabe88abb41f9edf367b6dc8f669f1
    BASE_DIR="${RUNNER_TEMP:?}/openproof-postgres-inline-native-control"
    loads=(1 8 32 128)
    git -C "$ROOT" fetch --no-tags --depth=1 origin "$BASE_SHA"
    git -C "$ROOT" worktree add --detach "$BASE_DIR" "$BASE_SHA"
    (
      cd "$BASE_DIR"
      cmake --preset gcc-release \
        -DCMAKE_PREFIX_PATH="$HOME/.cache/openproof/boost-1.88.0/install" \
        -DOPENPROOF_EXPERIMENTAL_GATEWAY_LIMITED_INLINING=ON \
        -DOPENPROOF_EXPERIMENTAL_POSTGRES_IO_LIMITED_INLINING=ON
      cmake --build --preset gcc-release --target opp --parallel 2
    )
    grep -qx 'OPENPROOF_EXPERIMENTAL_GATEWAY_LIMITED_INLINING:BOOL=ON' "$BASE_DIR/cmake-build-gcc-release/CMakeCache.txt"
    grep -qx 'OPENPROOF_EXPERIMENTAL_POSTGRES_IO_LIMITED_INLINING:BOOL=ON' "$BASE_DIR/cmake-build-gcc-release/CMakeCache.txt"
    ;;
  *) exit 2 ;;
esac
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$GITHUB_SHA" && "$(git -C "$BASE_DIR" rev-parse HEAD)" == "$BASE_SHA" ]] || exit 2
BASE="$BASE_DIR/cmake-build-gcc-release/apps/opp/opp"
CAND="$ROOT/cmake-build-gcc-release/apps/opp/opp"
[[ -x "$BASE" && -x "$CAND" ]] || exit 2
grep -qx 'OPENPROOF_EXPERIMENTAL_GATEWAY_LIMITED_INLINING:BOOL=ON' "$ROOT/cmake-build-gcc-release/CMakeCache.txt"
if [[ "$mode" == native-native ]]; then
    grep -qx 'OPENPROOF_EXPERIMENTAL_POSTGRES_IO_LIMITED_INLINING:BOOL=ON' "$ROOT/cmake-build-gcc-release/CMakeCache.txt"
fi
OUT="$ROOT/integrated-native-matrix"
if [[ "$mode" == native-native ]]; then OUT="$ROOT/scoped-pg-readiness-matrix"; fi
mkdir "$OUT"
printf 'baseline_commit=%s\ncandidate_commit=%s\n' "$BASE_SHA" "$GITHUB_SHA" > "$OUT/provenance.txt"
sha256sum "$BASE" "$CAND" >> "$OUT/provenance.txt"
run_trial() (
    local side="$1" trial="$2" concurrency="$3" warmup="$4" output="$5" binary sha legacy db
    local -a overrides
    case "$side" in
      baseline)
        binary="$BASE"; sha="$BASE_SHA"
        if [[ "$mode" == native-native ]]; then
          legacy=0
          overrides=(OPENPROOF_E2E_EXECUTION_PROFILE=minimal OPENPROOF_EXPERIMENTAL_REACTOR_THREADS=1 OPENPROOF_EXPERIMENTAL_HANDLER_THREADS=2 OPENPROOF_EXPERIMENTAL_REACTOR_PUBLIC_READS=1)
        else
          legacy=1
          overrides=(OPENPROOF_E2E_EXECUTION_PROFILE=auto)
        fi
        ;;
      candidate) binary="$CAND"; sha="$GITHUB_SHA"; legacy=0; overrides=(OPENPROOF_E2E_EXECUTION_PROFILE=minimal OPENPROOF_EXPERIMENTAL_REACTOR_THREADS=1 OPENPROOF_EXPERIMENTAL_HANDLER_THREADS=2 OPENPROOF_EXPERIMENTAL_REACTOR_PUBLIC_READS=1) ;;
      *) exit 2 ;;
    esac
    db="opp_e2e_int_${GITHUB_RUN_ID}_${GITHUB_RUN_ATTEMPT}_${concurrency}_${trial}_${side}"
    [[ ${#db} -le 63 ]] || exit 2
    sudo -u postgres createdb -O openproof_ci "$db"
    trap 'sudo -u postgres dropdb --if-exists "$db"' EXIT
    env -u OPENPROOF_EXPERIMENTAL_HANDLER_THREADS -u OPENPROOF_EXPERIMENTAL_REACTOR_PUBLIC_READS \
      -u OPENPROOF_EXPERIMENTAL_CPU_BUDGET -u OPENPROOF_EXPERIMENTAL_REACTOR_THREADS \
      -u OPENPROOF_E2E_EXECUTION_PROFILE "${overrides[@]}" \
      OPENPROOF_E2E_POSTGRES="postgresql://openproof_ci:ci_disposable_only@127.0.0.1:5432/$db" \
      OPENPROOF_E2E_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE \
      OPENPROOF_E2E_OPP="$binary" OPENPROOF_E2E_COMMIT="$sha" OPENPROOF_E2E_EXPECT_LEGACY_AUTH="$legacy" \
      OPENPROOF_E2E_LOAD_REQUESTS=1536 OPENPROOF_E2E_LOAD_WARMUP="$warmup" OPENPROOF_E2E_LOAD_CONCURRENCY="$concurrency" \
      OPENPROOF_E2E_METRICS_FILE="$output/$side-$trial.json" node "$ROOT/scripts/e2e-identity-platform.mjs"
    [[ -s "$output/$side-$trial.json" ]]
)
for concurrency in "${loads[@]}"; do
    warmup=$(( (2*concurrency+5)/6*6 ))
    if (( warmup < 24 )); then warmup=24; fi
    output="$OUT/c$concurrency"
    mkdir "$output"
    for trial in 1 2 3 4; do
        if (( trial % 2 == 1 )); then
            run_trial baseline "$trial" "$concurrency" "$warmup" "$output"
            run_trial candidate "$trial" "$concurrency" "$warmup" "$output"
        else
            run_trial candidate "$trial" "$concurrency" "$warmup" "$output"
            run_trial baseline "$trial" "$concurrency" "$warmup" "$output"
        fi
        node "$ROOT/scripts/compare-e2e-metrics.mjs" "$output/baseline-$trial.json" "$output/candidate-$trial.json"
    done
    if [[ "$mode" == native-native ]]; then
        node "$ROOT/scripts/summarize-mixed-read.mjs" "$output" "$BASE_SHA" "$GITHUB_SHA" "$concurrency" native-native
    else
        node "$ROOT/scripts/summarize-mixed-read.mjs" "$output" "$BASE_SHA" "$GITHUB_SHA" "$concurrency"
    fi
done

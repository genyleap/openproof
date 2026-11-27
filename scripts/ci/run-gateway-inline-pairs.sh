#!/usr/bin/env bash
# Experimental, same-source native/native comparison, only on a disposable CI runner.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ &&
   "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ && "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ ]] || exit 2
ROOT="$(git rev-parse --show-toplevel)"
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$GITHUB_SHA" ]] || exit 2
cd "$ROOT"
build="$ROOT/cmake-build-gcc-release"
binary="$build/apps/opp/opp"
control="$build/apps/opp/opp-inline-control"
out="$ROOT/gateway-inline-pairs"
mode="${1:-inline}"
[[ $# -le 1 && ( "$mode" == inline || "$mode" == combined ) ]] || exit 2
[[ -x "$binary" && ! -e "$control" ]] || exit 2
mkdir "$out"
cp "$binary" "$control"
trap 'rm -f -- "$control"' EXIT
# Existing verified packages and their evidence are already published to CI.
# Reconfigure the same build with one explicit option; keep all warning flags.
cmake --preset gcc-release -DOPENPROOF_EXPERIMENTAL_GATEWAY_LIMITED_INLINING=ON
cmake --build --preset gcc-release --parallel 2 -- -k 0
[[ -x "$binary" ]] || exit 2
controlHash="$(sha256sum "$control" | cut -d ' ' -f 1)"
candidateHash="$(sha256sum "$binary" | cut -d ' ' -f 1)"
[[ "$controlHash" != "$candidateHash" ]] || exit 2
printf 'commit=%s\ncontrol_sha256=%s\ncandidate_sha256=%s\n' "$GITHUB_SHA" "$controlHash" "$candidateHash" > "$out/provenance.txt"
# Run all non-destructive CTest gates again on the alternate linked binary.
ctest --preset gcc-release --output-on-failure -E '^PostgresIntegrationTest\.'
run_trial() (
    local side="$1" trial="$2" concurrency="$3" requests="$4" warmup="$5" output="$6" executable db
    local -a overrides=()
    case "$side" in
        control) executable="$control" ;;
        candidate) executable="$binary" ;;
        *) exit 2 ;;
    esac
    if [[ "$mode" == combined ]]; then
        case "$side" in
            control) overrides=(OPENPROOF_E2E_EXECUTION_PROFILE=auto) ;;
            candidate) overrides=(OPENPROOF_E2E_EXECUTION_PROFILE=minimal OPENPROOF_EXPERIMENTAL_REACTOR_THREADS=1 OPENPROOF_EXPERIMENTAL_HANDLER_THREADS=2 OPENPROOF_EXPERIMENTAL_REACTOR_PUBLIC_READS=1) ;;
        esac
    fi
    db="opp_e2e_inline_${GITHUB_RUN_ID}_${GITHUB_RUN_ATTEMPT}_${concurrency}_${trial}_${side}"
    [[ ${#db} -le 63 ]] || exit 2
    sudo -u postgres createdb -O openproof_ci "$db"
    trap 'sudo -u postgres dropdb --if-exists "$db"' EXIT
    env -u OPENPROOF_EXPERIMENTAL_HANDLER_THREADS -u OPENPROOF_EXPERIMENTAL_REACTOR_PUBLIC_READS \
        -u OPENPROOF_EXPERIMENTAL_CPU_BUDGET -u OPENPROOF_EXPERIMENTAL_REACTOR_THREADS \
        -u OPENPROOF_E2E_EXECUTION_PROFILE "${overrides[@]}" \
        OPENPROOF_E2E_POSTGRES="postgresql://openproof_ci:ci_disposable_only@127.0.0.1:5432/$db" \
        OPENPROOF_E2E_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE \
        OPENPROOF_E2E_OPP="$executable" OPENPROOF_E2E_COMMIT="$GITHUB_SHA" \
        OPENPROOF_E2E_EXPECT_LEGACY_AUTH=0 OPENPROOF_E2E_LOAD_REQUESTS="$requests" \
        OPENPROOF_E2E_LOAD_WARMUP="$warmup" OPENPROOF_E2E_LOAD_CONCURRENCY="$concurrency" \
        OPENPROOF_E2E_METRICS_FILE="$output/$side-$trial.json" \
        node "$ROOT/scripts/e2e-identity-platform.mjs"
    [[ -s "$output/$side-$trial.json" ]]
)
run_load() {
    local concurrency="$1" requests="$2" warmup="$3" output="$4" trial
    for trial in 1 2 3 4; do
        if (( trial % 2 == 1 )); then
            run_trial control "$trial" "$concurrency" "$requests" "$warmup" "$output"
            run_trial candidate "$trial" "$concurrency" "$requests" "$warmup" "$output"
        else
            run_trial candidate "$trial" "$concurrency" "$requests" "$warmup" "$output"
            run_trial control "$trial" "$concurrency" "$requests" "$warmup" "$output"
        fi
        node "$ROOT/scripts/compare-e2e-metrics.mjs" "$output/control-$trial.json" "$output/candidate-$trial.json"
    done
}
if [[ "$mode" == inline ]]; then
    run_load 24 600 0 "$out"
    node "$ROOT/scripts/summarize-gateway-inline-pairs.mjs" "$out" "$GITHUB_SHA"
else
    # The combined candidate is intentionally tested at high load too.
    # No relaxation of pending-handler, rate or connection limits.
    for concurrency in 1 8 32 128; do
        warmup=$(( (2*concurrency+5)/6*6 ))
        if (( warmup < 24 )); then warmup=24; fi
        output="$out/c$concurrency"
        mkdir "$output"
        cp "$out/provenance.txt" "$output/provenance.txt"
        echo "Combined qualification: concurrency $concurrency, warmup $warmup"
        run_load "$concurrency" 1536 "$warmup" "$output"
        node "$ROOT/scripts/summarize-gateway-inline-pairs.mjs" "$output" "$GITHUB_SHA" "$concurrency"
    done
fi

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
        reactor) override=(OPENPROOF_EXPERIMENTAL_REACTOR_PUBLIC_READS=1) ;;
        budget) override=(OPENPROOF_EXPERIMENTAL_CPU_BUDGET=1) ;;
        compact) override=(OPENPROOF_EXPERIMENTAL_CPU_BUDGET=1 OPENPROOF_EXPERIMENTAL_HANDLER_THREADS=2 OPENPROOF_EXPERIMENTAL_REACTOR_PUBLIC_READS=1) ;;
        minimal) override=(OPENPROOF_EXPERIMENTAL_REACTOR_THREADS=1 OPENPROOF_EXPERIMENTAL_HANDLER_THREADS=2 OPENPROOF_EXPERIMENTAL_REACTOR_PUBLIC_READS=1) ;;
        *) return 2 ;;
    esac
    db="openproof_e2e_pool_${GITHUB_RUN_ID}_${GITHUB_RUN_ATTEMPT}_${trial}_${profile}"
    [[ ${#db} -le 63 ]] || exit 2
    sudo -u postgres createdb -O openproof_ci "$db"
    env -u OPENPROOF_EXPERIMENTAL_HANDLER_THREADS -u OPENPROOF_EXPERIMENTAL_REACTOR_PUBLIC_READS \
        -u OPENPROOF_EXPERIMENTAL_CPU_BUDGET -u OPENPROOF_EXPERIMENTAL_REACTOR_THREADS "${override[@]}" \
        OPENPROOF_E2E_POSTGRES="postgresql://openproof_ci:ci_disposable_only@127.0.0.1:5432/$db" \
        OPENPROOF_E2E_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE \
        OPENPROOF_E2E_OPP="$binary" OPENPROOF_E2E_COMMIT="$GITHUB_SHA" \
        OPENPROOF_E2E_EXPECT_LEGACY_AUTH=0 OPENPROOF_E2E_EXECUTION_PROFILE="$profile" \
        OPENPROOF_E2E_LOAD_REQUESTS=600 OPENPROOF_E2E_LOAD_CONCURRENCY=24 \
        OPENPROOF_E2E_METRICS_FILE="$output/$profile-$trial.json" \
        node "$ROOT/scripts/e2e-identity-platform.mjs"
    [[ -s "$output/$profile-$trial.json" ]]
}
profiles=(auto two reactor budget compact minimal)
for profile in "${profiles[@]}"; do run_trial "$profile" 1; done
# Reverse the entire order so both composite profiles share the same
# same-binary control and symmetric position as the individual overrides.
for ((i=${#profiles[@]}-1; i>=0; --i)); do run_trial "${profiles[i]}" 2; done
node "$ROOT/scripts/summarize-executor-profiles.mjs" "$output" "$GITHUB_SHA"
for trial in 1 2; do
    echo "Exploratory same-binary handler pool comparison: pair $trial (auto vs two)"
    node "$ROOT/scripts/compare-e2e-metrics.mjs" \
        "$output/auto-$trial.json" "$output/two-$trial.json"
    echo "Exploratory same-binary reactor public-read comparison: pair $trial (auto vs reactor)"
    node "$ROOT/scripts/compare-e2e-metrics.mjs" \
        "$output/auto-$trial.json" "$output/reactor-$trial.json"
    for profile in budget compact minimal; do
        echo "Exploratory same-binary execution profile: pair $trial (auto vs $profile)"
        node "$ROOT/scripts/compare-e2e-metrics.mjs" \
            "$output/auto-$trial.json" "$output/$profile-$trial.json"
    done
done

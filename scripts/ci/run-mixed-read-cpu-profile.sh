#!/usr/bin/env bash
# Diagnostic only; do not compare sampled timings to acceptance measurements.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ &&
   "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ ]] || exit 2
ROOT="$(git rev-parse --show-toplevel)"
BASE_SHA=ccb396182936d717960fdca319999baf2f580ff9
BASE_DIR="${RUNNER_TEMP:?}/openproof-perf-baseline"
BASE="$BASE_DIR/cmake-build-gcc-release/apps/opp/opp"
CAND="$ROOT/cmake-build-gcc-release/apps/opp/opp"
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$GITHUB_SHA" &&
   "$(git -C "$BASE_DIR" rev-parse HEAD)" == "$BASE_SHA" &&
   -x "$BASE" && -x "$CAND" ]] || exit 2
grep -qx 'OPENPROOF_EXPERIMENTAL_GATEWAY_LIMITED_INLINING:BOOL=ON' "$ROOT/cmake-build-gcc-release/CMakeCache.txt"

# User-space process sampling only. Restore the disposable runner's policy
# even on failure; do not use this script on self-hosted/production systems.
previous="$(sysctl -n kernel.perf_event_paranoid)"
trap 'sudo sysctl -q -w "kernel.perf_event_paranoid=$previous"' EXIT
sudo sysctl -q -w kernel.perf_event_paranoid=1
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y linux-tools-common linux-tools-generic
PERF=""
while IFS= read -r candidate; do
    if "$candidate" stat -e cpu-clock:u -- true >/dev/null 2>&1; then
        PERF="$candidate"
        break
    fi
done < <(find /usr/lib/linux-tools -name perf -executable | sort -Vr)
[[ -n "$PERF" ]] || { echo "No usable user-space perf counter on this runner"; exit 2; }
OUT="$ROOT/cpu-hotspot-matrix"
mkdir "$OUT"
printf 'baseline_commit=%s\ncandidate_commit=%s\n' "$BASE_SHA" "$GITHUB_SHA" > "$OUT/provenance.txt"
sha256sum "$BASE" "$CAND" >> "$OUT/provenance.txt"
"$PERF" --version >> "$OUT/provenance.txt"
run_trial() (
    local side="$1" concurrency="$2" binary sha legacy db
    local -a overrides
    case "$side" in
        baseline) binary="$BASE"; sha="$BASE_SHA"; legacy=1; overrides=(OPENPROOF_E2E_EXECUTION_PROFILE=auto) ;;
        candidate) binary="$CAND"; sha="$GITHUB_SHA"; legacy=0; overrides=(OPENPROOF_E2E_EXECUTION_PROFILE=minimal OPENPROOF_EXPERIMENTAL_REACTOR_THREADS=1 OPENPROOF_EXPERIMENTAL_HANDLER_THREADS=2 OPENPROOF_EXPERIMENTAL_REACTOR_PUBLIC_READS=1) ;;
        *) exit 2 ;;
    esac
    db="opp_e2e_cpu_${GITHUB_RUN_ID}_${GITHUB_RUN_ATTEMPT}_${concurrency}_${side}"
    [[ ${#db} -le 63 ]] || exit 2
    sudo -u postgres createdb -O openproof_ci "$db"
    trap 'sudo -u postgres dropdb --if-exists "$db"' EXIT
    env -u OPENPROOF_EXPERIMENTAL_HANDLER_THREADS -u OPENPROOF_EXPERIMENTAL_REACTOR_PUBLIC_READS \
      -u OPENPROOF_EXPERIMENTAL_CPU_BUDGET -u OPENPROOF_EXPERIMENTAL_REACTOR_THREADS \
      -u OPENPROOF_E2E_EXECUTION_PROFILE -u OPENPROOF_E2E_STATEMENT_PROBE "${overrides[@]}" \
      OPENPROOF_E2E_POSTGRES="postgresql://openproof_ci:ci_disposable_only@127.0.0.1:5432/$db" \
      OPENPROOF_E2E_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE \
      OPENPROOF_E2E_OPP="$binary" OPENPROOF_E2E_COMMIT="$sha" OPENPROOF_E2E_EXPECT_LEGACY_AUTH="$legacy" \
      OPENPROOF_E2E_LOAD_REQUESTS=6144 OPENPROOF_E2E_LOAD_WARMUP=66 OPENPROOF_E2E_LOAD_CONCURRENCY="$concurrency" \
      OPENPROOF_E2E_PERF_BINARY="$PERF" OPENPROOF_E2E_CPU_PROFILE_FILE="$OUT/c${concurrency}-$side.txt" \
      OPENPROOF_E2E_METRICS_FILE="$OUT/c${concurrency}-$side.json" node "$ROOT/scripts/e2e-identity-platform.mjs"
    [[ -s "$OUT/c${concurrency}-$side.txt" && -s "$OUT/c${concurrency}-$side.json" ]]
    cat "$OUT/c${concurrency}-$side.txt"
)
run_trial baseline 1
run_trial candidate 1
run_trial candidate 32
run_trial baseline 32

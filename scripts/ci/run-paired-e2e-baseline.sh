#!/usr/bin/env bash
set -euo pipefail

# Reproducible candidate-vs-origin baseline smoke comparison on the SAME
# runner, database server and pinned GCC/Boost toolchain. Benchmark points
# are NOT a statistical significance test or a coroutine release approval.
BASE_SHA="${OPENPROOF_PERF_BASELINE_SHA:-ccb396182936d717960fdca319999baf2f580ff9}"
BASE_DIR="${RUNNER_TEMP:?RUNNER_TEMP must be set by the CI runner}/openproof-perf-baseline"
ROOT="$(git rev-parse --show-toplevel)"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID must be set by the CI runner}"
BASE_METRICS="${ROOT}/openproof-e2e-metrics-baseline.json"
CANDIDATE_METRICS="${ROOT}/openproof-e2e-metrics.json"

if [[ ! "${BASE_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Invalid pinned baseline commit" >&2
    exit 2
fi
if [[ ! -s "${CANDIDATE_METRICS}" ]]; then
    echo "Candidate real E2E metrics are missing: cannot compare" >&2
    exit 2
fi

git -C "${ROOT}" fetch --no-tags --depth=1 origin "${BASE_SHA}"
git -C "${ROOT}" worktree add --detach "${BASE_DIR}" "${BASE_SHA}"

(
    cd "${BASE_DIR}"
    cmake --preset gcc-release \
        -DCMAKE_PREFIX_PATH="${HOME}/.cache/openproof/boost-1.88.0/install"
    cmake --build --preset gcc-release --target opp --parallel 2
)

OUT="${ROOT}/mixed-read-bench"
CANDIDATE_SHA="$(git -C "${ROOT}" rev-parse HEAD)"
CANDIDATE_BIN="${ROOT}/cmake-build-gcc-release/apps/opp/opp"
BASE_BIN="${BASE_DIR}/cmake-build-gcc-release/apps/opp/opp"
[[ "${GITHUB_RUN_ID}" =~ ^[0-9]+$ ]]
[[ "${CANDIDATE_SHA}" != "${BASE_SHA}" ]]
[[ -x "${CANDIDATE_BIN}" && -x "${BASE_BIN}" ]]
mkdir "${OUT}"

# Keep the existing isolated E2E artifact as a smoke result only. Both
# sides below are fresh runs after both binaries have finished building.
# Four pairs at each load, with balanced alternating execution order.
run_trial() (
    set -euo pipefail
    local side="$1" concurrency="$2" trial="$3" requests="$4"
    local db="opbench_${GITHUB_RUN_ID}_${concurrency}_${trial}_${side}"
    local binary commit legacy
    if [[ "${side}" == "baseline" ]]; then
        binary="${BASE_BIN}"; commit="${BASE_SHA}"; legacy=1
    else
        binary="${CANDIDATE_BIN}"; commit="${CANDIDATE_SHA}"; legacy=0
    fi
    sudo -u postgres createdb -O openproof_ci "${db}"
    trap 'sudo -u postgres dropdb --if-exists "${db}"' EXIT
    OPENPROOF_E2E_POSTGRES="postgresql://openproof_ci:ci_disposable_only@127.0.0.1:5432/${db}" \
    OPENPROOF_E2E_OPP="${binary}" \
    OPENPROOF_E2E_DATABASE_ACK="YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE" \
    OPENPROOF_E2E_LOAD_REQUESTS="${requests}" \
    OPENPROOF_E2E_LOAD_CONCURRENCY="${concurrency}" \
    OPENPROOF_E2E_METRICS_FILE="${OUT}/${concurrency}-${trial}-${side}.json" \
    OPENPROOF_E2E_EXPECT_LEGACY_AUTH="${legacy}" \
    OPENPROOF_E2E_COMMIT="${commit}" \
        node "${ROOT}/scripts/e2e-identity-platform.mjs"
)

for concurrency in 24 96; do
    requests=600
    if (( concurrency == 96 )); then requests=1200; fi
    for trial in 1 2 3 4; do
        if (( trial % 2 == 1 )); then
            run_trial candidate "${concurrency}" "${trial}" "${requests}"
            run_trial baseline "${concurrency}" "${trial}" "${requests}"
        else
            run_trial baseline "${concurrency}" "${trial}" "${requests}"
            run_trial candidate "${concurrency}" "${trial}" "${requests}"
        fi
        node "${ROOT}/scripts/compare-e2e-metrics.mjs" \
            "${OUT}/${concurrency}-${trial}-baseline.json" \
            "${OUT}/${concurrency}-${trial}-candidate.json"
    done
done

# Compatibility artifact, explicitly a single trial, not the summary.
cp "${OUT}/24-1-baseline.json" "${BASE_METRICS}"
node "${ROOT}/scripts/summarize-mixed-read-bench.mjs" \
    "${OUT}" "${BASE_SHA}" "${CANDIDATE_SHA}"

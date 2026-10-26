#!/usr/bin/env bash
set -euo pipefail

# Reproducible candidate-vs-origin baseline smoke comparison on the SAME
# runner, database server and pinned GCC/Boost toolchain. Benchmark points
# are NOT a statistical significance test or a coroutine release approval.
BASE_SHA="${OPENPROOF_PERF_BASELINE_SHA:-ccb396182936d717960fdca319999baf2f580ff9}"
BASE_DIR="${RUNNER_TEMP:?RUNNER_TEMP must be set by the CI runner}/openproof-perf-baseline"
ROOT="$(git rev-parse --show-toplevel)"
BASE_DB="openproof_e2e_baseline_${GITHUB_RUN_ID:?}"
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

sudo -u postgres createdb -O openproof_ci "${BASE_DB}"

OPENPROOF_E2E_POSTGRES="postgresql://openproof_ci:ci_disposable_only@127.0.0.1:5432/${BASE_DB}" \
OPENPROOF_E2E_OPP="${BASE_DIR}/cmake-build-gcc-release/apps/opp/opp" \
OPENPROOF_E2E_DATABASE_ACK="YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE" \
OPENPROOF_E2E_LOAD_REQUESTS="600" \
OPENPROOF_E2E_LOAD_CONCURRENCY="24" \
OPENPROOF_E2E_METRICS_FILE="${BASE_METRICS}" \
OPENPROOF_E2E_COMMIT="${BASE_SHA}" \
    node "${ROOT}/scripts/e2e-identity-platform.mjs"

node "${ROOT}/scripts/compare-e2e-metrics.mjs" \
    "${BASE_METRICS}" "${CANDIDATE_METRICS}"

echo "Pairwise results above are preliminary single-run measures only."
echo "Release requires paired repetitions, matching security outcomes and all Coroutine gates."

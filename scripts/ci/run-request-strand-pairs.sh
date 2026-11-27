#!/usr/bin/env bash
# Matched native/native qualification; historical blocking baseline is separate.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ &&
   "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ && "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ ]] || exit 2
ROOT="$(git rev-parse --show-toplevel)"
BASE_SHA=e4c9624d4af9145a68f2819a96e0b4c8f83345b3
BASE_DIR="${RUNNER_TEMP:?}/openproof-strand-control"
OUT="$ROOT/request-strand-pairs"
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$GITHUB_SHA" && "$BASE_SHA" != "$GITHUB_SHA" ]] || exit 2
git -C "$ROOT" fetch --no-tags --depth=1 origin "$BASE_SHA"
# Refuse unrelated production-source differences: only the three intended
# translation units can differ. The same candidate harness measures both.
expected=$'src/gateway/http.cpp\nsrc/gateway/http_proxy.cpp\nsrc/storage/postgres/async_connection.cpp'
actual="$(git -C "$ROOT" diff --name-only "$BASE_SHA" "$GITHUB_SHA" -- src apps include migrations CMakeLists.txt CMakePresets.json cmake | LC_ALL=C sort)"
[[ "$actual" == "$expected" ]] || { echo "Unexpected native control source differences" >&2; exit 2; }
git -C "$ROOT" worktree add --detach "$BASE_DIR" "$BASE_SHA"
(
  cd "$BASE_DIR"
  cmake --preset gcc-release -DCMAKE_PREFIX_PATH="${HOME}/.cache/openproof/boost-1.88.0/install"
  cmake --build --preset gcc-release --target opp --parallel 2
)
base_binary="$BASE_DIR/cmake-build-gcc-release/apps/opp/opp"
candidate_binary="$ROOT/cmake-build-gcc-release/apps/opp/opp"
[[ -x "$base_binary" && -x "$candidate_binary" ]] || exit 2
mkdir "$OUT"
{
  printf 'control_commit=%s\ncandidate_commit=%s\n' "$BASE_SHA" "$GITHUB_SHA"
  sha256sum "$base_binary" "$candidate_binary"
} > "$OUT/provenance.txt"
run_trial() (
  local side="$1" trial="$2" binary sha db
  case "$side" in
    baseline) binary="$base_binary"; sha="$BASE_SHA" ;;
    candidate) binary="$candidate_binary"; sha="$GITHUB_SHA" ;;
    *) exit 2 ;;
  esac
  db="opp_e2e_strand_${GITHUB_RUN_ID}_${GITHUB_RUN_ATTEMPT}_${trial}_${side}"
  [[ ${#db} -le 63 ]] || exit 2
  sudo -u postgres createdb -O openproof_ci "$db"
  trap 'sudo -u postgres dropdb --if-exists "$db"' EXIT
  env -u OPENPROOF_EXPERIMENTAL_HANDLER_THREADS -u OPENPROOF_EXPERIMENTAL_REACTOR_PUBLIC_READS \
      -u OPENPROOF_EXPERIMENTAL_CPU_BUDGET -u OPENPROOF_EXPERIMENTAL_REACTOR_THREADS \
      -u OPENPROOF_E2E_EXECUTION_PROFILE \
      OPENPROOF_E2E_POSTGRES="postgresql://openproof_ci:ci_disposable_only@127.0.0.1:5432/$db" \
      OPENPROOF_E2E_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE \
      OPENPROOF_E2E_OPP="$binary" OPENPROOF_E2E_COMMIT="$sha" \
      OPENPROOF_E2E_EXPECT_LEGACY_AUTH=0 OPENPROOF_E2E_LOAD_REQUESTS=600 \
      OPENPROOF_E2E_LOAD_CONCURRENCY=24 OPENPROOF_E2E_METRICS_FILE="$OUT/$side-$trial.json" \
      node "$ROOT/scripts/e2e-identity-platform.mjs"
  [[ -s "$OUT/$side-$trial.json" ]]
)
for trial in 1 2 3 4 5; do
  if (( trial % 2 == 1 )); then
    run_trial baseline "$trial"
    run_trial candidate "$trial"
  else
    run_trial candidate "$trial"
    run_trial baseline "$trial"
  fi
done
node "$ROOT/scripts/summarize-mixed-read.mjs" "$OUT" "$BASE_SHA" "$GITHUB_SHA"

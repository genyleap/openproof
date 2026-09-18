#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="${OPENPROOF_FUZZ_RUNS:-100000}"
MAX_LENGTH="${OPENPROOF_FUZZ_MAX_LENGTH:-4096}"
ARTIFACTS="${OPENPROOF_FUZZ_ARTIFACTS:-${ROOT_DIR}/fuzz-artifacts}"

case "${RUNS}" in
    ''|*[!0-9]*) printf 'fuzz qualification: OPENPROOF_FUZZ_RUNS must be an integer\n' >&2; exit 2 ;;
esac
case "${MAX_LENGTH}" in
    ''|*[!0-9]*) printf 'fuzz qualification: OPENPROOF_FUZZ_MAX_LENGTH must be an integer\n' >&2; exit 2 ;;
esac
if (( RUNS < 1 || RUNS > 10000000 || MAX_LENGTH < 1 || MAX_LENGTH > 65536 )); then
    printf 'fuzz qualification: requested bounds are unsafe\n' >&2
    exit 2
fi

cmake --preset gcc-fuzz
cmake --build --preset gcc-fuzz --parallel
"${ROOT_DIR}/cmake-build-gcc-fuzz/fuzz/openproof_boundary_fuzzer" \
    --runs "${RUNS}" \
    --max-len "${MAX_LENGTH}" \
    --corpus "${ROOT_DIR}/fuzz/corpus" \
    --artifacts "${ARTIFACTS}"

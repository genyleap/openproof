#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
    printf 'production qualification: %s\n' "$1" >&2
    exit 1
}

[[ -n "${OPENPROOF_TEST_POSTGRES:-}" ]] \
    || fail "OPENPROOF_TEST_POSTGRES must name a disposable PostgreSQL test database"
[[ "${OPENPROOF_TEST_DATABASE_ACK:-}" == "YES_I_UNDERSTAND_THIS_DATABASE_IS_DESTRUCTIVE" ]] \
    || fail "set OPENPROOF_TEST_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_IS_DESTRUCTIVE"
[[ -n "${OPENPROOF_E2E_POSTGRES:-}" ]] \
    || fail "OPENPROOF_E2E_POSTGRES must name a second, empty disposable PostgreSQL database"
[[ "${OPENPROOF_E2E_DATABASE_ACK:-}" == "YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE" ]] \
    || fail "set OPENPROOF_E2E_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE"

# The PostgreSQL integration fixture truncates OpenProof tables. Never point this
# script at production, staging, or a shared development database.
printf 'OpenProof 1.1.0-rc2 production qualification\n'
printf 'PostgreSQL target: configured (value intentionally not printed)\n'

OPENPROOF_STATIC_ONLY=1 "${ROOT_DIR}/scripts/verify-release.sh"

run_preset() {
    local preset="$1"
    local build_dir="${ROOT_DIR}/cmake-build-${preset}"
    cmake --preset "${preset}"
    # CMake owns the clean operation and the preset fixes the build directory;
    # avoid a shell-recursive deletion whose target could be broadened by a
    # future path-editing mistake.
    cmake --build --preset "${preset}" --clean-first

    local ctest_log
    ctest_log="$(mktemp)"
    if ! ctest --preset "${preset}" 2>&1 | tee "${ctest_log}"; then
        rm -f "${ctest_log}"
        fail "CTest failed for ${preset}"
    fi
    if grep -Eq '(^|[[:space:]])Skipped([[:space:]]|$)|\[  SKIPPED \]' "${ctest_log}"; then
        cat "${ctest_log}" >&2
        rm -f "${ctest_log}"
        fail "a test was skipped for ${preset}; production qualification requires zero skips"
    fi
    rm -f "${ctest_log}"

    local test_binary="${build_dir}/tests/openproof_tests"
    [[ -x "${test_binary}" ]] || fail "test binary is missing for ${preset}"
    local pg_log
    pg_log="$(mktemp)"
    if ! "${test_binary}" --gtest_filter='PostgresIntegrationTest.*' 2>&1 | tee "${pg_log}"; then
        rm -f "${pg_log}"
        fail "PostgreSQL integration tests failed for ${preset}"
    fi
    if grep -q '\[  SKIPPED \]' "${pg_log}"; then
        cat "${pg_log}" >&2
        rm -f "${pg_log}"
        fail "PostgreSQL integration test skipped for ${preset}"
    fi
    rm -f "${pg_log}"
}

run_preset gcc-release
run_preset gcc-asan

if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    (cd "${ROOT_DIR}/sdk/javascript" && npm test)
else
    fail "Node/npm are required to qualify the JavaScript SDK"
fi

if [[ -x "${ROOT_DIR}/sdk/kotlin/gradlew" ]]; then
    (cd "${ROOT_DIR}/sdk/kotlin" && ./gradlew --no-daemon build)
else
    fail "the pinned Kotlin Gradle Wrapper is required to qualify the Kotlin SDK"
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
    command -v swift >/dev/null 2>&1 || fail "Swift is required on Darwin to qualify the Swift SDK"
    swift test --package-path "${ROOT_DIR}/sdk/swift"
fi

node "${ROOT_DIR}/scripts/e2e-identity-platform.mjs"

fuzz_artifacts="$(mktemp -d)"
OPENPROOF_FUZZ_RUNS="${OPENPROOF_QUALIFICATION_FUZZ_RUNS:-100000}" \
OPENPROOF_FUZZ_ARTIFACTS="${fuzz_artifacts}" \
    "${ROOT_DIR}/scripts/qualify-fuzzing.sh"
printf 'Coverage-guided fuzz artifacts retained for review: %s\n' "${fuzz_artifacts}"

printf 'OpenProof production qualification build/test/sanitizer/SDK/TLS-identity-E2E/fuzz gates passed.\n'
printf 'Remaining target launch gates are real-edge interoperability, target-environment product-shaped load/soak, an extended release fuzz campaign, independent security review and target secret-store/KMS rotation rehearsal.\n'

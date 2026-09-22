#!/bin/sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SETUP="$ROOT/installer/setup.sh"

bash -n "$SETUP" || {
  printf 'setup contract gate: installer/setup.sh has invalid Bash syntax\n' >&2
  exit 1
}

fail() {
  printf 'setup contract gate: %s\n' "$1" >&2
  exit 1
}

grep -Fq 'input_ok(){' "$SETUP" || fail "green accepted-input feedback is missing"
grep -Fq 'input_error(){' "$SETUP" || fail "red invalid-input feedback is missing"
grep -Fq 'retry_or_exit(){' "$SETUP" || fail "three-attempt retry/exit controller is missing"
grep -Fq 'if (( attempts_ref >= 3 )); then' "$SETUP" || fail "input retry limit is not three attempts"
grep -Fq 'option 1 "Try again"' "$SETUP" || fail "retry menu is missing Try again"
grep -Fq 'option 2 "Exit setup"' "$SETUP" || fail "retry menu is missing Exit setup"
grep -Fq 'validated_prompt(){' "$SETUP" || fail "validated text prompt helper is missing"
grep -Fq 'validated_secret(){' "$SETUP" || fail "validated secret prompt helper is missing"
grep -Fq 'prompt_choice(){' "$SETUP" || fail "validated menu-choice helper is missing"
grep -Fq 'password=$(prompt_owner_password)' "$SETUP" || fail "owner password does not use local retry flow"
grep -Fq 'input_ok "Owner password accepted"' "$SETUP" || fail "owner password success feedback is missing"

if grep -Fq 'die "owner passwords do not match"' "$SETUP"; then
  fail "owner password mismatch still aborts the entire setup"
fi
if grep -Fq 'die "owner password must contain at least 16 characters"' "$SETUP"; then
  fail "short owner password still aborts the entire setup"
fi

printf 'setup contract gate: ok\n'

#!/usr/bin/env bash
# Compatibility entrypoint for the isolated recovery-code PostgreSQL fixture.
# Keep all privilege-dropping, authentication and socket policy in one audited
# implementation. No database command or credential is accepted here.
set -euo pipefail
exec python3 "$(dirname "$0")/run-disposable-postgres-recovery-tests.py" "$@"

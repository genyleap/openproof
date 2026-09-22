#!/bin/sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SETUP="$ROOT/installer/setup.sh"
CLI="$ROOT/installer/openproof"

bash -n "$SETUP" || {
  printf 'setup contract gate: installer/setup.sh has invalid Bash syntax\n' >&2
  exit 1
}
bash -n "$CLI" || {
  printf 'setup contract gate: installer/openproof has invalid Bash syntax\n' >&2
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

grep -Fq 'configure_gateway(){' "$SETUP" || fail "production gateway setup is missing"
grep -Fq 'enabled = true' "$SETUP" || fail "generated production gateway is not enabled"
grep -Fq 'upstream_host = "$GATEWAY_HOST"' "$SETUP" || fail "generated gateway upstream host is missing"
grep -Fq 'upstream_port = $GATEWAY_PORT' "$SETUP" || fail "generated gateway upstream port is missing"
grep -Fq 'done < <(printf '"'"'%s\n'"'"' "$selected" | tr '"'"','"'"' '"'"'\n'"'"')' "$SETUP" \
  || fail "provider loop can drop the final selected provider"
grep -Fq 'done < <(printf '"'"'%s\n'"'"' "$raw" | tr '"'"','"'"' '"'"'\n'"'"')' "$SETUP" \
  || fail "provider-list validator can drop the final provider"
grep -Fq 'systemctl stop openproof.service' "$SETUP" \
  || fail "failed readiness does not stop the systemd restart loop"
grep -Fq 'already been initialized' "$SETUP" \
  || fail "setup rerun does not preserve an already-created initial owner"
grep -Fq 'reconcile_existing_bootstrap(){' "$SETUP" \
  || fail "setup rerun cannot reconcile initialized database identity state"
grep -Fq "action = 'bootstrap.initial-owner'" "$SETUP" \
  || fail "setup rerun does not identify the authoritative bootstrap organization"
grep -Fq 'DEPLOYMENT_ALREADY_INITIALIZED=1' "$SETUP" \
  || fail "setup rerun does not mark initialized deployments"
grep -Fq 'Existing initial owner preserved' "$SETUP" \
  || fail "setup rerun can unnecessarily recreate owner credentials"
grep -Fq 'This provider will remain disabled until you replace it' "$SETUP" \
  || fail "placeholder provider credentials can activate broken providers"

grep -Fq 'backup_config_file(){' "$CLI" || fail "management CLI does not back up editable configuration"
grep -Fq 'restart_openproof_or_rollback(){' "$CLI" || fail "management CLI lacks rollback after bad config edits"
grep -Fq 'You can add, replace, or remove provider credentials here at any time.' "$CLI" \
  || fail "provider configuration is not documented as editable after setup"

grep -Fq "X-Forwarded-For: 127.0.0.1" "$SETUP" \
  || fail "setup local readiness probe omits the trusted-proxy client header"
grep -Fq 'local_openproof_probe(){' "$CLI" \
  || fail "management CLI lacks the trusted local health probe helper"
grep -Fq "X-Forwarded-For: 127.0.0.1" "$CLI" \
  || fail "management CLI local readiness probes omit the trusted-proxy client header"
if grep -Fq 'curl -fsS --max-time 2 http://127.0.0.1:18443/health/ready' "$SETUP"; then
  fail "setup contains a direct readiness probe that bypasses trusted-proxy request requirements"
fi
if grep -Fq 'curl -fsS --max-time 3 http://127.0.0.1:18443/health/ready' "$CLI"; then
  fail "management CLI contains a direct readiness probe that bypasses trusted-proxy request requirements"
fi
grep -Fq 'reserved_tls_domain(){' "$SETUP" \
  || fail "setup does not recognize reserved/test domains before TLS provisioning"
grep -Fq 'Automatic public Let'"'"'s Encrypt issuance is not available' "$SETUP" \
  || fail "setup does not explain reserved-domain TLS fallback"
grep -Fq 'default_tls_mode=external' "$SETUP" \
  || fail "reserved/test domains do not default away from Let's Encrypt"

printf 'setup contract gate: ok\n'

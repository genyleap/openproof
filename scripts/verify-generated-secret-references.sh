#!/bin/sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)

fail() {
  printf 'secret reference gate: %s\n' "$1" >&2
  exit 1
}

grep -Fq 'random_secret(){ openssl rand -hex 32; }' "$ROOT/installer/setup.sh" \
  || fail "setup no longer generates 32-byte secrets as hexadecimal"

for key in credential_encryption_key password_pepper recovery_code_pepper audit_chain_key oauth_client_secret_key; do
  case "$key" in
    credential_encryption_key) file_name=credential-encryption.key ;;
    password_pepper) file_name=password-pepper.key ;;
    recovery_code_pepper) file_name=recovery-code-pepper.key ;;
    audit_chain_key) file_name=audit-chain.key ;;
    oauth_client_secret_key) file_name=oauth-client-secret.key ;;
  esac

  grep -Fq "$key = \"hexfile:\$CREDENTIAL_DIR/$file_name\"" "$ROOT/installer/setup.sh" \
    || fail "setup must decode generated $key through hexfile:"

  grep -Fq "$key = \"hexfile:/run/openproof/secrets/$file_name\"" "$ROOT/deploy/openproof.toml.example" \
    || fail "deployment template must use hexfile: for $key"
done

if grep -Eq '^(credential_encryption_key|password_pepper|recovery_code_pepper|audit_chain_key|oauth_client_secret_key) = "file:' "$ROOT/installer/setup.sh"; then
  fail "setup contains a raw file: reference for hex-encoded persistent key material"
fi

if grep -Eq '^(credential_encryption_key|password_pepper|recovery_code_pepper|audit_chain_key|oauth_client_secret_key) = "file:' "$ROOT/deploy/openproof.toml.example"; then
  fail "deployment template contains a raw file: reference for hex-encoded persistent key material"
fi

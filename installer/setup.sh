#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

CONFIG_DIR=/etc/openproof
CREDENTIAL_DIR=/etc/openproof/credentials
CONFIG_FILE=/etc/openproof/openproof.toml
PROVIDERS_FILE=/etc/openproof/providers.env
DELIVERY_FILE=/etc/openproof/delivery.env
INSTALL_ROOT=/opt/openproof
TEMPLATE_ROOT=/usr/share/openproof/templates
MARKER=/etc/openproof/.configured
NON_INTERACTIVE=0
DEPLOYMENT_ALREADY_INITIALIZED=0
TTY="${OPENPROOF_TTY:-${SUDO_TTY:-/dev/tty}}"
export PATH="$INSTALL_ROOT/bin:$PATH"

if [[ -t 1 && -z ${NO_COLOR:-} && ${TERM:-dumb} != dumb ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_CYAN=$'\033[36m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_RED=$'\033[31m'
  C_BLUE=$'\033[34m'
else
  C_RESET='' C_BOLD='' C_DIM='' C_CYAN='' C_GREEN='' C_YELLOW='' C_RED='' C_BLUE=''
fi

log(){ printf '%s\n' "$*"; }
ok(){ printf '%s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
info(){ printf '%s›%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
warn(){ printf '%s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die(){ printf '%s✗%s OpenProof setup: %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }
section(){ printf '\n%s%s%s%s\n' "$C_BOLD" "$C_BLUE" "$*" "$C_RESET"; }
option(){ printf '  %s%s)%s %s\n' "$C_CYAN" "$1" "$C_RESET" "$2" >"$TTY"; }
input_ok(){ printf '%s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*" >"$TTY"; }
input_error(){ printf '%s✗%s %s\n' "$C_RED" "$C_RESET" "$*" >"$TTY"; }

show_setup_header(){
  printf '\n%s%sOpenProof%s  %sconfiguration wizard%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET" "$C_DIM" "$C_RESET"
  printf '%sSelf-hosted identity infrastructure by Genyleap%s\n' "$C_DIM" "$C_RESET"

  section "Self-hosted operation"
  printf '  OpenProof runs on infrastructure you control. Genyleap does not operate\n'
  printf '  this instance, and normal runtime does not require a managed Genyleap\n'
  printf '  backend for your identity database, credentials, sessions, or keys.\n\n'
  printf '  You are responsible for hosting, security, backups, upgrades, compliance,\n'
  printf '  and any third-party providers or delivery services you configure.\n\n'
  printf '  %sDocs:%s    https://docs.genyleap.com/openproof/\n' "$C_DIM" "$C_RESET"
  printf '  %sPrivacy:%s https://genyleap.com/privacy\n' "$C_DIM" "$C_RESET"
  printf '  %sTerms:%s   https://genyleap.com/terms-of-use\n' "$C_DIM" "$C_RESET"

  section "Identity"
}

usage(){
cat <<'EOF'
Usage: sudo openproof setup [--non-interactive]

Non-interactive environment:
  OPENPROOF_DOMAIN
  OPENPROOF_ORGANIZATION_NAME
  OPENPROOF_ORGANIZATION_ID
  OPENPROOF_OWNER_SUBJECT
  OPENPROOF_ADMIN_PASSWORD
  OPENPROOF_DATABASE_MODE=local|external
  OPENPROOF_DATABASE_URL
  OPENPROOF_GATEWAY_UPSTREAM_HOST
  OPENPROOF_GATEWAY_UPSTREAM_PORT
  OPENPROOF_GATEWAY_UPSTREAM_TLS=true|false
  OPENPROOF_EMAIL_MODE=smtp|postfix|webhook|later
  OPENPROOF_TLS_MODE=letsencrypt|existing|external
  OPENPROOF_TLS_EMAIL
  OPENPROOF_TLS_CERT_FILE
  OPENPROOF_TLS_KEY_FILE
  OPENPROOF_PROVIDERS=google,github,microsoft,apple,linkedin,telegram,x,ethereum,farcaster
EOF
}

while (($#)); do
  case "$1" in
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run setup as root"
if (( NON_INTERACTIVE == 0 )) && [[ ! -r $TTY ]]; then
  die "interactive setup requires a terminal; use --non-interactive for automation"
fi

env_value(){ printenv "$1" 2>/dev/null || true; }

prompt(){
  local label=$1 default=$2 value=""
  if (( NON_INTERACTIVE )); then printf '%s' "$default"; return; fi
  if [[ -n $default ]]; then
    printf '%s%s%s %s[%s]%s: ' "$C_BOLD" "$label" "$C_RESET" "$C_DIM" "$default" "$C_RESET" >"$TTY"
  else
    printf '%s%s%s: ' "$C_BOLD" "$label" "$C_RESET" >"$TTY"
  fi
  IFS= read -r value <"$TTY"
  [[ -n $value ]] || value=$default
  printf '%s' "$value"
}

prompt_hidden(){
  local label=$1 value
  printf '%s%s%s: ' "$C_BOLD" "$label" "$C_RESET" >"$TTY"
  IFS= read -r -s value <"$TTY"
  printf '\n' >"$TTY"
  printf '%s' "$value"
}

operator_exit(){
  printf '\n%s›%s Setup exited by operator. Installed files and completed system changes were preserved.\n' "$C_CYAN" "$C_RESET" >"$TTY"
  exit 130
}

retry_or_exit(){
  local context=$1 choice
  printf '\n%s!%s Three unsuccessful attempts for %s.\n' "$C_YELLOW" "$C_RESET" "$context" >"$TTY"
  option 1 "Try again"
  option 2 "Exit setup"
  while :; do
    choice=$(prompt "Choose" "1")
    case "$choice" in
      1|r|R|retry|Retry) return 0 ;;
      2|e|E|exit|Exit) operator_exit ;;
      *) input_error "Choose 1 to try again or 2 to exit setup." ;;
    esac
  done
}

retry_failed(){
  local context=$1
  local -n attempts_ref=$2
  attempts_ref=$((attempts_ref + 1))
  if (( attempts_ref >= 3 )); then
    retry_or_exit "$context"
    attempts_ref=0
  fi
}

validated_prompt(){
  local label=$1 default=$2 validator=$3 error_message=$4
  local context=${5:-$label} value attempts=0
  while :; do
    value=$(prompt "$label" "$default")
    if "$validator" "$value"; then
      input_ok "$label accepted"
      printf '%s' "$value"
      return
    fi
    input_error "$error_message"
    retry_failed "$context" attempts
  done
}

validated_value(){
  local env_name=$1 label=$2 default=$3 validator=$4 error_message=$5
  local context=${6:-$label} value

  value=$(env_value "$env_name")
  if [[ -n $value ]]; then
    "$validator" "$value" || die "$env_name: $error_message"
    printf '%s' "$value"
    return
  fi

  if (( NON_INTERACTIVE )); then
    value=$default
    "$validator" "$value" || die "$env_name is required or invalid in non-interactive mode: $error_message"
    printf '%s' "$value"
    return
  fi

  validated_prompt "$label" "$default" "$validator" "$error_message" "$context"
}

validated_secret(){
  local label=$1 env_name=$2 validator=$3 error_message=$4
  local context=${5:-$label} value attempts=0

  value=$(env_value "$env_name")
  if [[ -n $value ]]; then
    "$validator" "$value" || die "$env_name: $error_message"
    printf '%s' "$value"
    return
  fi
  (( NON_INTERACTIVE == 0 )) || die "$env_name is required in non-interactive mode"

  while :; do
    value=$(prompt_hidden "$label")
    if "$validator" "$value"; then
      input_ok "$label accepted"
      printf '%s' "$value"
      return
    fi
    input_error "$error_message"
    retry_failed "$context" attempts
  done
}

prompt_choice(){
  local context=$1 default=$2 allowed=$3 value attempts=0 item valid
  local -a _allowed_values=()
  while :; do
    value=$(prompt "Choose" "$default")
    valid=0
    IFS=',' read -r -a _allowed_values <<<"$allowed"
    for item in "${_allowed_values[@]}"; do
      if [[ $value == "$item" ]]; then
        valid=1
        break
      fi
    done
    if (( valid )); then
      input_ok "Selection accepted"
      printf '%s' "$value"
      return
    fi
    input_error "Invalid selection. Choose one of: $allowed."
    retry_failed "$context" attempts
  done
}

slugify(){ printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g;s/^-+|-+$//g'; }
validate_nonempty(){ [[ -n $1 ]]; }
validate_domain(){ [[ $1 =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]; }
validate_org_id(){ [[ $1 =~ ^[a-zA-Z0-9._-]+$ ]]; }
validate_subject(){ [[ -n $1 && ${#1} -le 320 ]]; }
validate_email(){ [[ $1 =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; }
validate_port(){ [[ $1 =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
validate_database_url(){ [[ $1 == postgresql://* || $1 == postgres://* ]]; }
validate_host(){ [[ -n $1 && $1 != *[[:space:]]* ]]; }
validate_web_path(){ [[ $1 == /* && $1 != *[[:space:]]* ]]; }
validate_readable_file(){ [[ -r $1 ]]; }
validate_boolean(){ [[ $1 == true || $1 == false ]]; }
validate_owner_password(){ [[ $(printf '%s' "$1" | wc -c) -ge 16 ]]; }
validate_provider_list(){
  local raw=$1 p
  [[ -z $raw ]] && return 0
  raw=$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
  while IFS= read -r p; do
    case "$p" in
      google|github|microsoft|apple|linkedin|telegram|x|ethereum|farcaster) ;;
      *) return 1 ;;
    esac
  done < <(printf '%s\n' "$raw" | tr ',' '\n')
}

apt_install(){
  local log_file
  log_file=$(mktemp)
  export DEBIAN_FRONTEND=noninteractive

  info "Installing system packages: $*"
  if ! apt-get update -qq >"$log_file" 2>&1; then
    cat "$log_file" >&2
    rm -f "$log_file"
    die "package index update failed"
  fi
  if ! apt-get install -y -qq --no-install-recommends "$@" >>"$log_file" 2>&1; then
    cat "$log_file" >&2
    rm -f "$log_file"
    die "system package installation failed: $*"
  fi
  rm -f "$log_file"
  ok "System packages ready: $*"
}

ensure_user(){
  getent group openproof >/dev/null || groupadd --system openproof
  id openproof >/dev/null 2>&1 || useradd --system --gid openproof --home-dir /nonexistent --shell /usr/sbin/nologin openproof
  install -d -o root -g openproof -m 0750 "$CONFIG_DIR" "$CREDENTIAL_DIR"
}

secret_file(){
  local name value path
  name=$1
  value=$2
  path="$CREDENTIAL_DIR/$name"
  printf '%s' "$value" >"$path"
  chown root:openproof "$path"
  chmod 0640 "$path"
}

random_secret(){ openssl rand -hex 32; }

generate_secrets(){
  local name
  for name in master.key credential-encryption.key password-pepper.key recovery-code-pepper.key audit-chain.key oauth-client-secret.key metrics-bearer.token verification-webhook.token; do
    [[ -f "$CREDENTIAL_DIR/$name" ]] || secret_file "$name" "$(random_secret)"
  done
  if [[ ! -f "$CREDENTIAL_DIR/oidc-private.pem" ]]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$CREDENTIAL_DIR/oidc-private.pem" >/dev/null 2>&1
    chown root:openproof "$CREDENTIAL_DIR/oidc-private.pem"
    chmod 0640 "$CREDENTIAL_DIR/oidc-private.pem"
  fi
  install -d -o root -g openproof -m 0750 "$CONFIG_DIR/previous-oidc-keys"
  ok "Cryptographic material generated"
}

configure_local_database(){
  apt_install postgresql postgresql-client
  systemctl enable --now postgresql
  local db_password
  db_password=$(random_secret)
  if runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='openproof'" | grep -q 1; then
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 -c "ALTER ROLE openproof WITH LOGIN PASSWORD '$db_password';" >/dev/null
  else
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 -c "CREATE ROLE openproof WITH LOGIN PASSWORD '$db_password';" >/dev/null
  fi
  if ! runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname='openproof'" | grep -q 1; then
    runuser -u postgres -- createdb -O openproof openproof
  fi
  secret_file database.url "postgresql://openproof:$db_password@127.0.0.1:5432/openproof"
  ok "Local PostgreSQL configured"
}

configure_external_database(){
  local url
  url=$(
    validated_secret \
      "PostgreSQL connection URL" \
      OPENPROOF_DATABASE_URL \
      validate_database_url \
      "Database URL must use postgres:// or postgresql://." \
      "database connection URL"
  )
  secret_file database.url "$url"
  command -v psql >/dev/null 2>&1 || apt_install postgresql-client
  ok "External PostgreSQL configured"
}

database_query(){
  local sql=$1 url
  case "$DB_MODE" in
    local)
      runuser -u postgres -- psql -X -qAt -v ON_ERROR_STOP=1 -d openproof -c "$sql"
      ;;
    external)
      command -v psql >/dev/null 2>&1 || return 1
      url=$(<"$CREDENTIAL_DIR/database.url")
      PGDATABASE="$url" PGCONNECT_TIMEOUT=5 psql -X -qAt -v ON_ERROR_STOP=1 -c "$sql"
      ;;
    *) return 1 ;;
  esac
}

reconcile_existing_bootstrap(){
  local row existing_id existing_name existing_state existing_subject
  row=$(
    database_query "
WITH bootstrap_owner AS (
  SELECT organization_id, identity_id
  FROM openproof.audit_events
  WHERE action = 'bootstrap.initial-owner' AND outcome = 'success'
  ORDER BY sequence ASC
  LIMIT 1
)
SELECT o.id,
       o.name,
       o.state,
       COALESCE(e.external_subject, '')
FROM bootstrap_owner b
JOIN openproof.organizations o ON o.id = b.organization_id
LEFT JOIN openproof.external_identities e
  ON e.identity_id = b.identity_id AND e.provider = 'local'
LIMIT 1;
" 2>/dev/null
  ) || return 1

  [[ -n $row ]] || return 1
  IFS='|' read -r existing_id existing_name existing_state existing_subject <<<"$row"
  [[ -n $existing_id && -n $existing_name ]] || return 1

  if [[ $existing_state != 0 ]]; then
    die "the existing bootstrap organization '$existing_id' is not active; reactivate it before resuming setup"
  fi

  DEPLOYMENT_ALREADY_INITIALIZED=1

  if [[ $ORG_ID != "$existing_id" ]]; then
    warn "Organization ID '$ORG_ID' cannot replace the initialized database organization '$existing_id'. Reusing '$existing_id'."
  fi
  if [[ $ORG_NAME != "$existing_name" ]]; then
    warn "Organization name '$ORG_NAME' differs from the initialized database value '$existing_name'. Reusing '$existing_name'."
  fi
  if [[ -n $existing_subject && $OWNER_SUBJECT != "$existing_subject" ]]; then
    warn "Initial owner subject '$OWNER_SUBJECT' differs from the existing owner '$existing_subject'. Reusing the existing owner."
  fi

  ORG_ID=$existing_id
  ORG_NAME=$existing_name
  [[ -z $existing_subject ]] || OWNER_SUBJECT=$existing_subject

  section "Existing deployment detected"
  input_ok "Initialized OpenProof identity state found"
  printf '  %sOrganization%s  %s (%s)\n' "$C_DIM" "$C_RESET" "$ORG_NAME" "$ORG_ID"
  [[ -z $existing_subject ]] || printf '  %sOwner subject%s  %s\n' "$C_DIM" "$C_RESET" "$existing_subject"
  info "Setup will resume without recreating the organization or initial owner."
  return 0
}

configure_postfix_adapter(){
  local mode=$1 smtp_host smtp_port smtp_user smtp_password from brand

  from=$(
    validated_value \
      OPENPROOF_DELIVERY_FROM \
      "From address" \
      "no-reply@$DOMAIN" \
      validate_email \
      "Enter a valid email address." \
      "delivery From address"
  )
  brand=$(
    validated_value \
      OPENPROOF_DELIVERY_BRAND \
      "Email brand name" \
      "$ORG_NAME" \
      validate_nonempty \
      "Email brand name cannot be empty." \
      "email brand name"
  )

  if [[ $mode == smtp ]]; then
    section "SMTP relay"
    smtp_host=$(
      validated_value \
        OPENPROOF_SMTP_HOST \
        "SMTP host" \
        "" \
        validate_host \
        "SMTP host cannot be empty or contain whitespace." \
        "SMTP host"
    )
    smtp_port=$(
      validated_value \
        OPENPROOF_SMTP_PORT \
        "SMTP port" \
        "587" \
        validate_port \
        "SMTP port must be a number between 1 and 65535." \
        "SMTP port"
    )
    smtp_user=$(
      validated_value \
        OPENPROOF_SMTP_USERNAME \
        "SMTP username" \
        "" \
        validate_nonempty \
        "SMTP username is required." \
        "SMTP username"
    )
    smtp_password=$(
      validated_secret \
        "SMTP password" \
        OPENPROOF_SMTP_PASSWORD \
        validate_nonempty \
        "SMTP password cannot be empty." \
        "SMTP password"
    )
  else
    warn "Direct Postfix delivery requires correct PTR/rDNS, SPF, DKIM and DMARC."
  fi

  apt_install postfix php-cli libsasl2-modules

  if [[ $mode == smtp ]]; then
    postconf -e "relayhost = [$smtp_host]:$smtp_port"
    postconf -e "smtp_sasl_auth_enable = yes"
    postconf -e "smtp_sasl_security_options = noanonymous"
    postconf -e "smtp_tls_security_level = encrypt"
    postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
    printf '[%s]:%s %s:%s\n' "$smtp_host" "$smtp_port" "$smtp_user" "$smtp_password" >/etc/postfix/sasl_passwd
    chmod 0600 /etc/postfix/sasl_passwd
    postmap /etc/postfix/sasl_passwd
    rm -f /etc/postfix/sasl_passwd
    ok "Postfix configured as authenticated SMTP relay"
  fi

  systemctl enable --now postfix
  install -d -o root -g root -m 0755 "$INSTALL_ROOT/delivery"
  install -m 0644 "$TEMPLATE_ROOT/verification-delivery-postfix.php" "$INSTALL_ROOT/delivery/verification-delivery-postfix.php"
  cat >"$DELIVERY_FILE" <<EOF
OPENPROOF_DELIVERY_TOKEN_FILE=$CREDENTIAL_DIR/verification-webhook.token
OPENPROOF_DELIVERY_FROM=$from
OPENPROOF_DELIVERY_BRAND=$brand
OPENPROOF_DELIVERY_SIGNUP_URL=https://$DOMAIN/account?flow=verify-email
OPENPROOF_DELIVERY_CHANGE_EMAIL_URL=https://$DOMAIN/account?flow=change-email
OPENPROOF_DELIVERY_PASSWORD_RESET_URL=https://$DOMAIN/account?flow=reset-password
OPENPROOF_DELIVERY_SMTP_HOST=127.0.0.1
OPENPROOF_DELIVERY_SMTP_PORT=25
EOF
  chown root:openproof "$DELIVERY_FILE"
  chmod 0640 "$DELIVERY_FILE"
}

configure_delivery(){
  EMAIL_MODE=$(env_value OPENPROOF_EMAIL_MODE)
  if [[ -z $EMAIL_MODE ]]; then
    if (( NON_INTERACTIVE )); then
      EMAIL_MODE=later
    else
      section "Email delivery"
      option 1 "Authenticated SMTP relay via local delivery adapter"
      option 2 "Direct Postfix / MX via local delivery adapter"
      option 3 "Existing HTTPS delivery webhook (no local mail packages)"
      option 4 "Configure later"
      printf '  %sNote:%s options 1-2 install Postfix, PHP CLI and SASL runtime packages.\n' "$C_DIM" "$C_RESET"
      choice=$(prompt_choice "email delivery mode" "1" "1,2,3,4")
      case "$choice" in 1) EMAIL_MODE=smtp;; 2) EMAIL_MODE=postfix;; 3) EMAIL_MODE=webhook;; 4) EMAIL_MODE=later;; esac
    fi
  fi
  case "$EMAIL_MODE" in
    smtp|postfix)
      configure_postfix_adapter "$EMAIL_MODE"
      ACCOUNT_ENABLED=true; DELIVERY_HOST=127.0.0.1; DELIVERY_PORT=18444; DELIVERY_TLS=false; DELIVERY_PATH=/v1/openproof/verification
      ;;
    webhook)
      ACCOUNT_ENABLED=true
      DELIVERY_HOST=$(
        validated_value \
          OPENPROOF_DELIVERY_HOST \
          "Delivery webhook host" \
          "" \
          validate_host \
          "Delivery webhook host cannot be empty or contain whitespace." \
          "delivery webhook host"
      )
      DELIVERY_PORT=$(
        validated_value \
          OPENPROOF_DELIVERY_PORT \
          "Delivery webhook port" \
          "443" \
          validate_port \
          "Delivery webhook port must be a number between 1 and 65535." \
          "delivery webhook port"
      )
      DELIVERY_TLS=$(
        validated_value \
          OPENPROOF_DELIVERY_TLS \
          "Delivery webhook TLS (true/false)" \
          "true" \
          validate_boolean \
          "Enter true or false." \
          "delivery webhook TLS setting"
      )
      DELIVERY_PATH=$(
        validated_value \
          OPENPROOF_DELIVERY_PATH \
          "Delivery webhook path" \
          "/v1/openproof/verification" \
          validate_web_path \
          "Delivery webhook path must begin with / and contain no whitespace." \
          "delivery webhook path"
      )
      ;;
    later)
      ACCOUNT_ENABLED=false; DELIVERY_HOST=127.0.0.1; DELIVERY_PORT=18444; DELIVERY_TLS=false; DELIVERY_PATH=/v1/openproof/verification
      warn "Email/password self-service remains disabled until delivery is configured."
      ;;
    *) die "invalid email mode: $EMAIL_MODE" ;;
  esac
}

append_provider(){ printf '%s=%s\n' "$1" "$2" >>"$PROVIDERS_FILE"; }

looks_placeholder(){
  case "$1" in
    0|test|TEST|dummy|DUMMY|example|EXAMPLE|placeholder|PLACEHOLDER) return 0 ;;
    *) return 1 ;;
  esac
}

provider_value(){
  local label=$1 env_name=$2 value
  value=$(
    validated_value \
      "$env_name" \
      "$label" \
      "" \
      validate_nonempty \
      "$label cannot be empty." \
      "$label"
  )
  if looks_placeholder "$value"; then
    warn "$label looks like a placeholder. This provider will remain disabled until you replace it with: sudo openproof config providers"
    printf '%s' ""
    return
  fi
  printf '%s' "$value"
}

provider_secret(){
  local label=$1 env_name=$2 value
  value=$(
    validated_secret \
      "$label" \
      "$env_name" \
      validate_nonempty \
      "$label cannot be empty." \
      "$label"
  )
  if looks_placeholder "$value"; then
    warn "$label looks like a placeholder. This provider will remain disabled until you replace it with: sudo openproof config providers"
    printf '%s' ""
    return
  fi
  printf '%s' "$value"
}

configure_providers(){
  : >"$PROVIDERS_FILE"
  append_provider OPENPROOF_FEDERATION_CALLBACK_URI "https://$DOMAIN/auth/federated/callback"
  append_provider OPENPROOF_WEBAUTHN_RP_ID "$DOMAIN"
  append_provider OPENPROOF_WEBAUTHN_ORIGIN "https://$DOMAIN"
  append_provider OPENPROOF_WEBAUTHN_RP_NAME "$ORG_NAME"

  if (( NON_INTERACTIVE == 0 )); then
    section "External sign-in providers"
    printf '  %sAvailable:%s google, github, microsoft, apple, linkedin, telegram, x, ethereum, farcaster\n' "$C_DIM" "$C_RESET"
  fi
  selected=$(
    validated_value \
      OPENPROOF_PROVIDERS \
      "Comma-separated providers (blank = later)" \
      "" \
      validate_provider_list \
      "Use only: google, github, microsoft, apple, linkedin, telegram, x, ethereum, farcaster." \
      "external provider selection"
  )
  selected=$(printf '%s' "$selected" | tr '[:upper:]' '[:lower:]' | tr -d ' ')

  while IFS= read -r p; do
    [[ -n $p ]] || continue
    case "$p" in
      google)
        v=$(provider_value "Google Client ID" OPENPROOF_GOOGLE_CLIENT_ID); append_provider OPENPROOF_GOOGLE_CLIENT_ID "$v"
        append_provider OPENPROOF_GOOGLE_CLIENT_SECRET "$(provider_secret "Google Client Secret" OPENPROOF_GOOGLE_CLIENT_SECRET)"
        append_provider OPENPROOF_GOOGLE_ISSUER https://accounts.google.com
        ;;
      github)
        v=$(provider_value "GitHub Client ID" OPENPROOF_GITHUB_CLIENT_ID); append_provider OPENPROOF_GITHUB_CLIENT_ID "$v"
        append_provider OPENPROOF_GITHUB_CLIENT_SECRET "$(provider_secret "GitHub Client Secret" OPENPROOF_GITHUB_CLIENT_SECRET)"
        ;;
      microsoft)
        tenant=$(provider_value "Microsoft Tenant ID" OPENPROOF_MICROSOFT_TENANT_ID)
        v=$(provider_value "Microsoft Client ID" OPENPROOF_MICROSOFT_CLIENT_ID); append_provider OPENPROOF_MICROSOFT_CLIENT_ID "$v"
        append_provider OPENPROOF_MICROSOFT_CLIENT_SECRET "$(provider_secret "Microsoft Client Secret" OPENPROOF_MICROSOFT_CLIENT_SECRET)"
        append_provider OPENPROOF_MICROSOFT_ISSUER "https://login.microsoftonline.com/$tenant/v2.0"
        ;;
      apple)
        v=$(provider_value "Apple Services ID" OPENPROOF_APPLE_CLIENT_ID); append_provider OPENPROOF_APPLE_CLIENT_ID "$v"
        append_provider OPENPROOF_APPLE_CLIENT_SECRET "$(provider_secret "Apple client-secret JWT" OPENPROOF_APPLE_CLIENT_SECRET)"
        append_provider OPENPROOF_APPLE_ISSUER https://appleid.apple.com
        ;;
      linkedin)
        v=$(provider_value "LinkedIn Client ID" OPENPROOF_LINKEDIN_CLIENT_ID); append_provider OPENPROOF_LINKEDIN_CLIENT_ID "$v"
        append_provider OPENPROOF_LINKEDIN_CLIENT_SECRET "$(provider_secret "LinkedIn Client Secret" OPENPROOF_LINKEDIN_CLIENT_SECRET)"
        append_provider OPENPROOF_LINKEDIN_ISSUER https://www.linkedin.com/oauth
        ;;
      telegram)
        v=$(provider_value "Telegram Client ID" OPENPROOF_TELEGRAM_CLIENT_ID); append_provider OPENPROOF_TELEGRAM_CLIENT_ID "$v"
        append_provider OPENPROOF_TELEGRAM_CLIENT_SECRET "$(provider_secret "Telegram Client Secret" OPENPROOF_TELEGRAM_CLIENT_SECRET)"
        append_provider OPENPROOF_TELEGRAM_ISSUER https://oauth.telegram.org
        ;;
      x)
        v=$(provider_value "X API key" OPENPROOF_X_API_KEY); append_provider OPENPROOF_X_API_KEY "$v"
        append_provider OPENPROOF_X_API_SECRET "$(provider_secret "X API secret" OPENPROOF_X_API_SECRET)"
        ;;
      ethereum)
        append_provider OPENPROOF_WEB3_DOMAIN "$DOMAIN"
        append_provider OPENPROOF_WEB3_URI "https://$DOMAIN/auth/web3"
        append_provider OPENPROOF_ETHEREUM_WALLET_ENABLED true
        rpc=$(env_value OPENPROOF_ETHEREUM_RPC_ENDPOINTS)
        [[ -n $rpc ]] || { [[ $NON_INTERACTIVE -eq 1 ]] || rpc=$(prompt "Smart-wallet RPC mappings (optional)" ""); }
        [[ -z $rpc ]] || append_provider OPENPROOF_ETHEREUM_RPC_ENDPOINTS "$rpc"
        ;;
      farcaster)
        append_provider OPENPROOF_WEB3_DOMAIN "$DOMAIN"
        append_provider OPENPROOF_WEB3_URI "https://$DOMAIN/auth/web3"
        rpc=$(provider_value "Farcaster / Optimism RPC endpoint" OPENPROOF_FARCASTER_RPC_ENDPOINT)
        append_provider OPENPROOF_FARCASTER_RPC_ENDPOINT "$rpc"
        append_provider OPENPROOF_FARCASTER_CHAIN_ID 10
        ;;
      *) warn "Unknown provider '$p' skipped" ;;
    esac
  done < <(printf '%s\n' "$selected" | tr ',' '\n')

  chown root:openproof "$PROVIDERS_FILE"
  chmod 0640 "$PROVIDERS_FILE"
  ok "Provider configuration written"
  log "  Callback URI: https://$DOMAIN/auth/federated/callback"
}

configure_gateway(){
  section "Protected application upstream"
  printf '  %sOpenProof protects and proxies configured application routes to this upstream.%s\n' "$C_DIM" "$C_RESET"
  printf '  %sIf your application is not running yet, keep the defaults and update them later.%s\n' "$C_DIM" "$C_RESET"

  GATEWAY_HOST=$(
    validated_value \
      OPENPROOF_GATEWAY_UPSTREAM_HOST \
      "Upstream host" \
      "127.0.0.1" \
      validate_host \
      "Upstream host cannot be empty or contain whitespace." \
      "application upstream host"
  )
  GATEWAY_PORT=$(
    validated_value \
      OPENPROOF_GATEWAY_UPSTREAM_PORT \
      "Upstream port" \
      "18080" \
      validate_port \
      "Upstream port must be a number between 1 and 65535." \
      "application upstream port"
  )
  GATEWAY_TLS=$(
    validated_value \
      OPENPROOF_GATEWAY_UPSTREAM_TLS \
      "Upstream TLS (true/false)" \
      "false" \
      validate_boolean \
      "Enter true or false." \
      "application upstream TLS setting"
  )

  if looks_placeholder "$GATEWAY_HOST"; then
    warn "Upstream host '$GATEWAY_HOST' looks like a placeholder. Using 127.0.0.1 until you update it with: sudo openproof config main"
    GATEWAY_HOST=127.0.0.1
  fi
}

write_base_config(){
cat >"$CONFIG_FILE" <<EOF
[server]
bind_address = "127.0.0.1"
port = 18443
trust_proxy_client_ip = true

[logging]
level = "info"
console = true

[operations]
metrics_enabled = true
metrics_bearer_token = "file:$CREDENTIAL_DIR/metrics-bearer.token"
metrics_maximum_series = 512

[security]
token_signing_key = "file:$CREDENTIAL_DIR/master.key"
master_key_version = 1
credential_encryption_key = "hexfile:$CREDENTIAL_DIR/credential-encryption.key"
credential_encryption_key_version = 1
password_pepper = "hexfile:$CREDENTIAL_DIR/password-pepper.key"
recovery_code_pepper = "hexfile:$CREDENTIAL_DIR/recovery-code-pepper.key"
audit_chain_key = "hexfile:$CREDENTIAL_DIR/audit-chain.key"
oauth_client_secret_key = "hexfile:$CREDENTIAL_DIR/oauth-client-secret.key"

[database]
connection_string = "file:$CREDENTIAL_DIR/database.url"
pool_size = 16
migration_directory = "$INSTALL_ROOT/migrations"

[gateway]
enabled = true
route_prefix = "/"
upstream_host = "$GATEWAY_HOST"
upstream_port = $GATEWAY_PORT
upstream_tls = $GATEWAY_TLS
rate_limit_capacity = 1000
rate_limit_refill_per_second = 100
rate_limit_maximum_keys = 100000

[auth]
enabled = true
provider_id = "local"
organization_id = "$ORG_ID"
protected_route_prefix = "/api"

[[auth.route_policies]]
path_prefix = "/api"
methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
required_roles = ["member", "owner"]
role_match = "any"
minimum_assurance = "ial1"
required_scope = "api"
required_audience = "https://$DOMAIN/api"

[account]
enabled = $ACCOUNT_ENABLED
phone_provider_id = "phone"
delivery_host = "$DELIVERY_HOST"
delivery_port = $DELIVERY_PORT
delivery_tls = $DELIVERY_TLS
delivery_path = "$DELIVERY_PATH"
delivery_authorization = "file:$CREDENTIAL_DIR/verification-webhook.token"

[oidc]
enabled = true
issuer = "https://$DOMAIN"
key_id = "openproof-rs256-1"
signing_key = "file:$CREDENTIAL_DIR/oidc-private.pem"
previous_signing_keys_directory = "$CONFIG_DIR/previous-oidc-keys"
EOF
  chown root:openproof "$CONFIG_FILE"
  chmod 0640 "$CONFIG_FILE"
}

write_nginx_http(){
  install -d -m 0755 /var/www/openproof-acme
  cat >/etc/nginx/sites-available/openproof <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/openproof-acme; }
    location / {
        proxy_pass http://127.0.0.1:18443;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto http;
        proxy_set_header X-Forwarded-For \$remote_addr;
    }
}
EOF
  ln -sfn /etc/nginx/sites-available/openproof /etc/nginx/sites-enabled/openproof
  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx
}

write_nginx_tls(){
  local cert=$1 key=$2
  cat >/etc/nginx/sites-available/openproof <<EOF
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name $DOMAIN;
    ssl_certificate $cert;
    ssl_certificate_key $key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:openproof_tls:20m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    client_max_body_size 8m;
    server_tokens off;
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options nosniff always;
    location = /metrics { return 404; }
    location / {
        proxy_pass http://127.0.0.1:18443;
        proxy_http_version 1.1;
        proxy_connect_timeout 5s;
        proxy_send_timeout 20s;
        proxy_read_timeout 20s;
        proxy_buffering off;
        proxy_set_header Host \$host;
        proxy_set_header Connection "";
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Client-Cert-Sha256 "";
        proxy_set_header X-Forwarded-Client-Cert-Timestamp "";
        proxy_set_header X-Forwarded-Client-Cert-Nonce "";
        proxy_set_header X-Forwarded-Client-Cert-Signature "";
    }
}
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/openproof-acme; }
    location / { return 308 https://\$host\$request_uri; }
}
EOF
  nginx -t
  systemctl reload nginx
}

configure_tls(){
  TLS_MODE=$(env_value OPENPROOF_TLS_MODE); [[ -n $TLS_MODE ]] || TLS_MODE=letsencrypt
  if [[ $NON_INTERACTIVE -eq 0 ]]; then
    section "TLS"
    option 1 "Let's Encrypt (recommended)"
    option 2 "Existing certificate"
    option 3 "TLS is terminated by an external ingress"
    choice=$(prompt_choice "TLS mode" "1" "1,2,3")
    case "$choice" in 1) TLS_MODE=letsencrypt;; 2) TLS_MODE=existing;; 3) TLS_MODE=external;; esac
  fi
  case "$TLS_MODE" in
    letsencrypt)
      apt_install nginx certbot
      write_nginx_http
      email=$(
        validated_value \
          OPENPROOF_TLS_EMAIL \
          "Let's Encrypt email" \
          "" \
          validate_email \
          "Enter a valid email address for Let's Encrypt." \
          "Let's Encrypt email"
      )
      certbot certonly --webroot -w /var/www/openproof-acme -d "$DOMAIN" --non-interactive --agree-tos -m "$email"
      write_nginx_tls "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
      ;;
    existing)
      apt_install nginx
      cert=$(
        validated_value \
          OPENPROOF_TLS_CERT_FILE \
          "Certificate fullchain path" \
          "" \
          validate_readable_file \
          "Certificate file is not readable. Enter an existing readable path." \
          "TLS certificate path"
      )
      key=$(
        validated_value \
          OPENPROOF_TLS_KEY_FILE \
          "Certificate private-key path" \
          "" \
          validate_readable_file \
          "Private-key file is not readable. Enter an existing readable path." \
          "TLS private-key path"
      )
      write_nginx_tls "$cert" "$key"
      ;;
    external)
      warn "External ingress selected; proxy HTTPS traffic to 127.0.0.1:18443."
      ;;
    *) die "invalid TLS mode: $TLS_MODE" ;;
  esac
}

prompt_owner_password(){
  local password again attempts=0
  password=$(env_value OPENPROOF_ADMIN_PASSWORD)

  if [[ -n $password ]]; then
    validate_owner_password "$password" || die "OPENPROOF_ADMIN_PASSWORD must contain at least 16 bytes"
    printf '%s' "$password"
    return
  fi
  (( NON_INTERACTIVE == 0 )) || die "OPENPROOF_ADMIN_PASSWORD is required in non-interactive mode"

  while :; do
    password=$(prompt_hidden "Initial owner password (16+ characters)")
    if ! validate_owner_password "$password"; then
      input_error "Password must contain at least 16 characters."
      retry_failed "initial owner password" attempts
      continue
    fi

    again=$(prompt_hidden "Confirm initial owner password")
    if [[ $password != "$again" ]]; then
      input_error "Passwords do not match."
      retry_failed "initial owner password" attempts
      continue
    fi

    input_ok "Owner password accepted"
    printf '%s' "$password"
    return
  done
}

bootstrap_owner(){
  local password identity_id output

  section "Initial owner"
  if (( DEPLOYMENT_ALREADY_INITIALIZED )); then
    ok "Existing initial owner preserved"
    info "Owner credentials were not recreated or changed."
    return
  fi

  password=$(prompt_owner_password)
  identity_id="owner-$(openssl rand -hex 8)"
  log "Creating the initial owner..."
  if ! output=$(OPENPROOF_BOOTSTRAP_PASSWORD="$password" "$INSTALL_ROOT/bin/opp" bootstrap-admin --config "$CONFIG_FILE" --organization-name "$ORG_NAME" --identity-id "$identity_id" --subject "$OWNER_SUBJECT" 2>&1); then
    if [[ $output == *"[ALREADY_EXISTS]"* || $output == *"already been initialized"* ]]; then
      if reconcile_existing_bootstrap; then
        write_base_config
        "$INSTALL_ROOT/bin/opp" check-config --config "$CONFIG_FILE" >/dev/null
        warn "This database already has an initial OpenProof owner. Existing identity state was restored into the generated configuration."
        return
      fi
      die "the database is already initialized, but setup could not resolve its bootstrap organization; refusing to start with a mismatched organization"
    fi
    printf '%s\n' "$output" >&2
    die "initial owner bootstrap failed"
  fi
  printf '%s\n' "$output"
  ok "Initial owner created"
  warn "The TOTP enrollment secret above is shown once. Store it securely now."
}

health_check(){
  local i
  for i in $(seq 1 30); do
    if curl -fsS --max-time 2 http://127.0.0.1:18443/health/ready >/dev/null 2>&1; then ok "OpenProof readiness check passed"; return; fi
    sleep 1
  done
  journalctl -u openproof.service -n 30 --no-pager >&2 || true
  systemctl stop openproof.service >/dev/null 2>&1 || true
  die "OpenProof did not become ready; the service was stopped to avoid a restart loop"
}

[[ ! -f $MARKER ]] || die "this host is already configured; use 'openproof config main', 'openproof config providers', or 'openproof config delivery'"

if systemctl list-unit-files openproof.service >/dev/null 2>&1; then
  if systemctl is-active --quiet openproof.service || systemctl is-failed --quiet openproof.service; then
    systemctl stop openproof.service >/dev/null 2>&1 || true
    info "Paused the incomplete OpenProof service while setup resumes."
  fi
fi

show_setup_header

DOMAIN=$(
  validated_value \
    OPENPROOF_DOMAIN \
    "Identity domain" \
    "identity.example.com" \
    validate_domain \
    "Enter a valid DNS hostname such as identity.example.com." \
    "identity domain"
)

ORG_NAME=$(
  validated_value \
    OPENPROOF_ORGANIZATION_NAME \
    "Organization name" \
    "OpenProof" \
    validate_nonempty \
    "Organization name cannot be empty." \
    "organization name"
)
default_org=$(slugify "$ORG_NAME")
ORG_ID=$(
  validated_value \
    OPENPROOF_ORGANIZATION_ID \
    "Organization ID" \
    "$default_org" \
    validate_org_id \
    "Organization ID may contain only letters, numbers, dots, underscores and hyphens." \
    "organization ID"
)

OWNER_SUBJECT=$(
  validated_value \
    OPENPROOF_OWNER_SUBJECT \
    "Initial owner email / login subject" \
    "" \
    validate_subject \
    "Initial owner subject is required and must not exceed 320 characters." \
    "initial owner subject"
)

ensure_user
command -v curl >/dev/null 2>&1 || die "curl is required by setup"
command -v openssl >/dev/null 2>&1 || die "the bundled OpenSSL runtime is missing"
generate_secrets

DB_MODE=$(env_value OPENPROOF_DATABASE_MODE); [[ -n $DB_MODE ]] || DB_MODE=local
if [[ $NON_INTERACTIVE -eq 0 ]]; then
  section "Database"
  option 1 "Install local PostgreSQL"
  option 2 "Use existing PostgreSQL"
  choice=$(prompt_choice "database mode" "1" "1,2")
  [[ $choice == 2 ]] && DB_MODE=external || DB_MODE=local
fi
case "$DB_MODE" in local) configure_local_database;; external) configure_external_database;; *) die "invalid database mode: $DB_MODE";; esac

reconcile_existing_bootstrap || true

configure_delivery
configure_providers
configure_gateway
write_base_config

"$INSTALL_ROOT/bin/opp" check-config --config "$CONFIG_FILE"
ok "OpenProof configuration is valid"

bootstrap_owner
systemctl daemon-reload
if [[ $EMAIL_MODE == smtp || $EMAIL_MODE == postfix ]]; then systemctl enable --now openproof-delivery.service; fi
systemctl enable --now openproof.service
health_check
configure_tls

printf '%s\n' "$DOMAIN" >"$MARKER"
chown root:openproof "$MARKER"
chmod 0640 "$MARKER"

section "OpenProof is ready"
printf '  %sIdentity URL%s  https://%s\n' "$C_DIM" "$C_RESET" "$DOMAIN"
printf '  %sCallback URL%s  https://%s/auth/federated/callback\n' "$C_DIM" "$C_RESET" "$DOMAIN"
printf '  %sConfig%s        %s\n' "$C_DIM" "$C_RESET" "$CONFIG_FILE"
printf '\n%sNext commands%s\n' "$C_BOLD" "$C_RESET"
printf '  %ssudo openproof status%s\n' "$C_CYAN" "$C_RESET"
printf '  %ssudo openproof doctor%s\n' "$C_CYAN" "$C_RESET"
printf '  %ssudo openproof info%s\n' "$C_CYAN" "$C_RESET"
printf '  %ssudo openproof config providers%s\n' "$C_CYAN" "$C_RESET"
printf '\n%sDocs:%s https://docs.genyleap.com/openproof/\n' "$C_DIM" "$C_RESET"

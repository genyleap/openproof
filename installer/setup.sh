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
TTY=/dev/tty

log(){ printf '%s\n' "$*"; }
ok(){ printf '✓ %s\n' "$*"; }
warn(){ printf '! %s\n' "$*" >&2; }
die(){ printf 'OpenProof setup: %s\n' "$*" >&2; exit 1; }

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
  if [[ -n $default ]]; then printf '%s [%s]: ' "$label" "$default" >"$TTY"; else printf '%s: ' "$label" >"$TTY"; fi
  IFS= read -r value <"$TTY"
  [[ -n $value ]] || value=$default
  printf '%s' "$value"
}

prompt_secret(){
  local label=$1 env_name=$2 value
  value=$(env_value "$env_name")
  if (( NON_INTERACTIVE )); then
    [[ -n $value ]] || die "$env_name is required in non-interactive mode"
    printf '%s' "$value"
    return
  fi
  printf '%s: ' "$label" >"$TTY"
  IFS= read -r -s value <"$TTY"
  printf '\n' >"$TTY"
  printf '%s' "$value"
}

slugify(){ printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g;s/^-+|-+$//g'; }
validate_domain(){ [[ $1 =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]; }

apt_install(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends "$@"
}

ensure_user(){
  getent group openproof >/dev/null || groupadd --system openproof
  id openproof >/dev/null 2>&1 || useradd --system --gid openproof --home-dir /nonexistent --shell /usr/sbin/nologin openproof
  install -d -o root -g openproof -m 0750 "$CONFIG_DIR" "$CREDENTIAL_DIR"
}

secret_file(){
  local name=$1 value=$2 path="$CREDENTIAL_DIR/$name"
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
  url=$(env_value OPENPROOF_DATABASE_URL)
  [[ -n $url ]] || url=$(prompt_secret "PostgreSQL connection URL" OPENPROOF_DATABASE_URL)
  [[ $url == postgresql://* || $url == postgres://* ]] || die "database URL must use postgres:// or postgresql://"
  secret_file database.url "$url"
  apt_install postgresql-client
  ok "External PostgreSQL configured"
}

configure_postfix_adapter(){
  local mode=$1 smtp_host smtp_port smtp_user smtp_password from brand
  apt_install postfix php-cli libsasl2-modules
  if [[ $mode == smtp ]]; then
    smtp_host=$(env_value OPENPROOF_SMTP_HOST); [[ -n $smtp_host ]] || smtp_host=$(prompt "SMTP host" "")
    smtp_port=$(env_value OPENPROOF_SMTP_PORT); [[ -n $smtp_port ]] || smtp_port=$(prompt "SMTP port" "587")
    smtp_user=$(env_value OPENPROOF_SMTP_USERNAME); [[ -n $smtp_user ]] || smtp_user=$(prompt "SMTP username" "")
    smtp_password=$(env_value OPENPROOF_SMTP_PASSWORD); [[ -n $smtp_password ]] || smtp_password=$(prompt_secret "SMTP password" OPENPROOF_SMTP_PASSWORD)
    [[ -n $smtp_host && -n $smtp_user && -n $smtp_password ]] || die "SMTP host, username and password are required"
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
  else
    warn "Direct Postfix delivery requires correct PTR/rDNS, SPF, DKIM and DMARC."
  fi
  systemctl enable --now postfix
  install -d -o root -g root -m 0755 "$INSTALL_ROOT/delivery"
  install -m 0644 "$TEMPLATE_ROOT/verification-delivery-postfix.php" "$INSTALL_ROOT/delivery/verification-delivery-postfix.php"

  from=$(env_value OPENPROOF_DELIVERY_FROM); [[ -n $from ]] || from=$(prompt "From address" "no-reply@$DOMAIN")
  brand=$(env_value OPENPROOF_DELIVERY_BRAND); [[ -n $brand ]] || brand=$(prompt "Email brand name" "$ORG_NAME")
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
      log ""; log "Email delivery"
      log "  1) Authenticated SMTP relay"
      log "  2) Local Postfix / direct MX"
      log "  3) Existing HTTPS delivery webhook"
      log "  4) Configure later"
      choice=$(prompt "Choose" "1")
      case "$choice" in 1) EMAIL_MODE=smtp;; 2) EMAIL_MODE=postfix;; 3) EMAIL_MODE=webhook;; *) EMAIL_MODE=later;; esac
    fi
  fi
  case "$EMAIL_MODE" in
    smtp|postfix)
      configure_postfix_adapter "$EMAIL_MODE"
      ACCOUNT_ENABLED=true; DELIVERY_HOST=127.0.0.1; DELIVERY_PORT=18444; DELIVERY_TLS=false; DELIVERY_PATH=/v1/openproof/verification
      ;;
    webhook)
      ACCOUNT_ENABLED=true
      DELIVERY_HOST=$(env_value OPENPROOF_DELIVERY_HOST); [[ -n $DELIVERY_HOST ]] || DELIVERY_HOST=$(prompt "Delivery webhook host" "")
      DELIVERY_PORT=$(env_value OPENPROOF_DELIVERY_PORT); [[ -n $DELIVERY_PORT ]] || DELIVERY_PORT=$(prompt "Delivery webhook port" "443")
      DELIVERY_TLS=$(env_value OPENPROOF_DELIVERY_TLS); [[ -n $DELIVERY_TLS ]] || DELIVERY_TLS=true
      DELIVERY_PATH=$(env_value OPENPROOF_DELIVERY_PATH); [[ -n $DELIVERY_PATH ]] || DELIVERY_PATH=$(prompt "Delivery webhook path" "/v1/openproof/verification")
      [[ -n $DELIVERY_HOST ]] || die "delivery webhook host is required"
      ;;
    later)
      ACCOUNT_ENABLED=false; DELIVERY_HOST=127.0.0.1; DELIVERY_PORT=18444; DELIVERY_TLS=false; DELIVERY_PATH=/v1/openproof/verification
      warn "Email/password self-service remains disabled until delivery is configured."
      ;;
    *) die "invalid email mode: $EMAIL_MODE" ;;
  esac
}

append_provider(){ printf '%s=%s\n' "$1" "$2" >>"$PROVIDERS_FILE"; }

provider_secret(){
  local label=$1 env_name=$2 value
  value=$(env_value "$env_name")
  [[ -n $value ]] || value=$(prompt_secret "$label" "$env_name")
  printf '%s' "$value"
}

configure_providers(){
  : >"$PROVIDERS_FILE"
  append_provider OPENPROOF_FEDERATION_CALLBACK_URI "https://$DOMAIN/auth/federated/callback"
  append_provider OPENPROOF_WEBAUTHN_RP_ID "$DOMAIN"
  append_provider OPENPROOF_WEBAUTHN_ORIGIN "https://$DOMAIN"
  append_provider OPENPROOF_WEBAUTHN_RP_NAME "$ORG_NAME"

  selected=$(env_value OPENPROOF_PROVIDERS)
  if [[ -z $selected && $NON_INTERACTIVE -eq 0 ]]; then
    log ""; log "External sign-in providers"
    log "Available: google,github,microsoft,apple,linkedin,telegram,x,ethereum,farcaster"
    selected=$(prompt "Comma-separated providers (blank = later)" "")
  fi
  selected=$(printf '%s' "$selected" | tr '[:upper:]' '[:lower:]' | tr -d ' ')

  while IFS= read -r p; do
    [[ -n $p ]] || continue
    case "$p" in
      google)
        v=$(env_value OPENPROOF_GOOGLE_CLIENT_ID); [[ -n $v ]] || v=$(prompt "Google Client ID" ""); append_provider OPENPROOF_GOOGLE_CLIENT_ID "$v"
        append_provider OPENPROOF_GOOGLE_CLIENT_SECRET "$(provider_secret "Google Client Secret" OPENPROOF_GOOGLE_CLIENT_SECRET)"
        append_provider OPENPROOF_GOOGLE_ISSUER https://accounts.google.com
        ;;
      github)
        v=$(env_value OPENPROOF_GITHUB_CLIENT_ID); [[ -n $v ]] || v=$(prompt "GitHub Client ID" ""); append_provider OPENPROOF_GITHUB_CLIENT_ID "$v"
        append_provider OPENPROOF_GITHUB_CLIENT_SECRET "$(provider_secret "GitHub Client Secret" OPENPROOF_GITHUB_CLIENT_SECRET)"
        ;;
      microsoft)
        tenant=$(env_value OPENPROOF_MICROSOFT_TENANT_ID); [[ -n $tenant ]] || tenant=$(prompt "Microsoft Tenant ID" "")
        v=$(env_value OPENPROOF_MICROSOFT_CLIENT_ID); [[ -n $v ]] || v=$(prompt "Microsoft Client ID" ""); append_provider OPENPROOF_MICROSOFT_CLIENT_ID "$v"
        append_provider OPENPROOF_MICROSOFT_CLIENT_SECRET "$(provider_secret "Microsoft Client Secret" OPENPROOF_MICROSOFT_CLIENT_SECRET)"
        append_provider OPENPROOF_MICROSOFT_ISSUER "https://login.microsoftonline.com/$tenant/v2.0"
        ;;
      apple)
        v=$(env_value OPENPROOF_APPLE_CLIENT_ID); [[ -n $v ]] || v=$(prompt "Apple Services ID" ""); append_provider OPENPROOF_APPLE_CLIENT_ID "$v"
        append_provider OPENPROOF_APPLE_CLIENT_SECRET "$(provider_secret "Apple client-secret JWT" OPENPROOF_APPLE_CLIENT_SECRET)"
        append_provider OPENPROOF_APPLE_ISSUER https://appleid.apple.com
        ;;
      linkedin)
        v=$(env_value OPENPROOF_LINKEDIN_CLIENT_ID); [[ -n $v ]] || v=$(prompt "LinkedIn Client ID" ""); append_provider OPENPROOF_LINKEDIN_CLIENT_ID "$v"
        append_provider OPENPROOF_LINKEDIN_CLIENT_SECRET "$(provider_secret "LinkedIn Client Secret" OPENPROOF_LINKEDIN_CLIENT_SECRET)"
        append_provider OPENPROOF_LINKEDIN_ISSUER https://www.linkedin.com/oauth
        ;;
      telegram)
        v=$(env_value OPENPROOF_TELEGRAM_CLIENT_ID); [[ -n $v ]] || v=$(prompt "Telegram Client ID" ""); append_provider OPENPROOF_TELEGRAM_CLIENT_ID "$v"
        append_provider OPENPROOF_TELEGRAM_CLIENT_SECRET "$(provider_secret "Telegram Client Secret" OPENPROOF_TELEGRAM_CLIENT_SECRET)"
        append_provider OPENPROOF_TELEGRAM_ISSUER https://oauth.telegram.org
        ;;
      x)
        v=$(env_value OPENPROOF_X_API_KEY); [[ -n $v ]] || v=$(prompt "X API key" ""); append_provider OPENPROOF_X_API_KEY "$v"
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
        rpc=$(env_value OPENPROOF_FARCASTER_RPC_ENDPOINT); [[ -n $rpc ]] || rpc=$(prompt "Farcaster / Optimism RPC endpoint" "")
        append_provider OPENPROOF_FARCASTER_RPC_ENDPOINT "$rpc"
        append_provider OPENPROOF_FARCASTER_CHAIN_ID 10
        ;;
      *) warn "Unknown provider '$p' skipped" ;;
    esac
  done < <(printf '%s' "$selected" | tr ',' '\n')

  chown root:openproof "$PROVIDERS_FILE"
  chmod 0640 "$PROVIDERS_FILE"
  ok "Provider configuration written"
  log "  Callback URI: https://$DOMAIN/auth/federated/callback"
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
credential_encryption_key = "file:$CREDENTIAL_DIR/credential-encryption.key"
credential_encryption_key_version = 1
password_pepper = "file:$CREDENTIAL_DIR/password-pepper.key"
recovery_code_pepper = "file:$CREDENTIAL_DIR/recovery-code-pepper.key"
audit_chain_key = "file:$CREDENTIAL_DIR/audit-chain.key"
oauth_client_secret_key = "file:$CREDENTIAL_DIR/oauth-client-secret.key"

[database]
connection_string = "file:$CREDENTIAL_DIR/database.url"
pool_size = 16
migration_directory = "$INSTALL_ROOT/migrations"

[gateway]
enabled = false

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
    log ""; log "TLS"
    log "  1) Let's Encrypt (recommended)"
    log "  2) Existing certificate"
    log "  3) TLS is terminated by an external ingress"
    choice=$(prompt "Choose" "1")
    case "$choice" in 1) TLS_MODE=letsencrypt;; 2) TLS_MODE=existing;; 3) TLS_MODE=external;; esac
  fi
  case "$TLS_MODE" in
    letsencrypt)
      apt_install nginx certbot
      write_nginx_http
      email=$(env_value OPENPROOF_TLS_EMAIL); [[ -n $email ]] || email=$(prompt "Let's Encrypt email" "")
      [[ -n $email ]] || die "an email address is required for Let's Encrypt"
      certbot certonly --webroot -w /var/www/openproof-acme -d "$DOMAIN" --non-interactive --agree-tos -m "$email"
      write_nginx_tls "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
      ;;
    existing)
      apt_install nginx
      cert=$(env_value OPENPROOF_TLS_CERT_FILE); [[ -n $cert ]] || cert=$(prompt "Certificate fullchain path" "")
      key=$(env_value OPENPROOF_TLS_KEY_FILE); [[ -n $key ]] || key=$(prompt "Certificate private-key path" "")
      [[ -r $cert && -r $key ]] || die "existing certificate or key is not readable"
      write_nginx_tls "$cert" "$key"
      ;;
    external)
      warn "External ingress selected; proxy HTTPS traffic to 127.0.0.1:18443."
      ;;
    *) die "invalid TLS mode: $TLS_MODE" ;;
  esac
}

bootstrap_owner(){
  local password again identity_id output
  password=$(env_value OPENPROOF_ADMIN_PASSWORD)
  [[ -n $password ]] || password=$(prompt_secret "Initial owner password (16+ characters)" OPENPROOF_ADMIN_PASSWORD)
  if [[ $NON_INTERACTIVE -eq 0 ]]; then
    again=$(prompt_secret "Confirm initial owner password" OPENPROOF_ADMIN_PASSWORD)
    [[ $password == "$again" ]] || die "owner passwords do not match"
  fi
  [[ $(printf '%s' "$password" | wc -c) -ge 16 ]] || die "owner password must contain at least 16 characters"
  identity_id="owner-$(openssl rand -hex 8)"
  log ""; log "Creating the initial owner..."
  if ! output=$(OPENPROOF_BOOTSTRAP_PASSWORD="$password" "$INSTALL_ROOT/bin/opp" bootstrap-admin --config "$CONFIG_FILE" --organization-name "$ORG_NAME" --identity-id "$identity_id" --subject "$OWNER_SUBJECT" 2>&1); then
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
  die "OpenProof did not become ready"
}

[[ ! -f $MARKER ]] || die "this host is already configured; use 'openproof config providers' or 'openproof config email'"

log ""; log "OpenProof setup"; log "==============="; log ""

DOMAIN=$(env_value OPENPROOF_DOMAIN); [[ -n $DOMAIN ]] || DOMAIN=$(prompt "Identity domain" "identity.example.com")
validate_domain "$DOMAIN" || die "invalid domain: $DOMAIN"

ORG_NAME=$(env_value OPENPROOF_ORGANIZATION_NAME); [[ -n $ORG_NAME ]] || ORG_NAME=$(prompt "Organization name" "OpenProof")
default_org=$(slugify "$ORG_NAME")
ORG_ID=$(env_value OPENPROOF_ORGANIZATION_ID); [[ -n $ORG_ID ]] || ORG_ID=$(prompt "Organization ID" "$default_org")
[[ $ORG_ID =~ ^[a-zA-Z0-9._-]+$ ]] || die "invalid organization ID"

OWNER_SUBJECT=$(env_value OPENPROOF_OWNER_SUBJECT); [[ -n $OWNER_SUBJECT ]] || OWNER_SUBJECT=$(prompt "Initial owner email / login subject" "")
[[ -n $OWNER_SUBJECT ]] || die "initial owner subject is required"

ensure_user
apt_install ca-certificates curl openssl
generate_secrets

DB_MODE=$(env_value OPENPROOF_DATABASE_MODE); [[ -n $DB_MODE ]] || DB_MODE=local
if [[ $NON_INTERACTIVE -eq 0 ]]; then
  log ""; log "Database"; log "  1) Install local PostgreSQL"; log "  2) Use existing PostgreSQL"
  choice=$(prompt "Choose" "1"); [[ $choice == 2 ]] && DB_MODE=external || DB_MODE=local
fi
case "$DB_MODE" in local) configure_local_database;; external) configure_external_database;; *) die "invalid database mode: $DB_MODE";; esac

configure_delivery
configure_providers
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

log ""; log "OpenProof is ready"; log "=================="
log "Identity URL : https://$DOMAIN"
log "Callback URL : https://$DOMAIN/auth/federated/callback"
log "Config       : $CONFIG_FILE"
log ""; log "Next:"
log "  sudo openproof doctor"
log "  sudo openproof config providers"
log "  https://docs.genyleap.com/openproof/"

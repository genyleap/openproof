#!/bin/sh
set -eu

REPO="genyleap/openproof"
CHANNEL="auto"
REQUESTED_VERSION=""
NON_INTERACTIVE=0
NO_SETUP=0
PLAN_ONLY=0
GENYLEAP_RELEASES="https://genyleap.com/releases/openproof"
GITHUB_RELEASES="https://github.com/$REPO/releases/download"
DOCS_URL="https://docs.genyleap.com/openproof/"
PRODUCT_URL="https://genyleap.com/products/openproof"
PRIVACY_URL="https://genyleap.com/privacy"
TERMS_URL="https://genyleap.com/terms-of-use"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
  ESC=$(printf '\033')
  C_RESET="${ESC}[0m"
  C_BOLD="${ESC}[1m"
  C_DIM="${ESC}[2m"
  C_CYAN="${ESC}[36m"
  C_GREEN="${ESC}[32m"
  C_YELLOW="${ESC}[33m"
  C_RED="${ESC}[31m"
  C_BLUE="${ESC}[34m"
else
  C_RESET="" C_BOLD="" C_DIM="" C_CYAN="" C_GREEN="" C_YELLOW="" C_RED="" C_BLUE=""
fi

say() { printf '%s\n' "$*"; }
ok() { printf '%s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
info() { printf '%s›%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
warn() { printf '%s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die() { printf '%s✗%s OpenProof installer: %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

brand() {
  printf '\n%s%sOpenProof%s  %sself-hosted identity infrastructure%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET" "$C_DIM" "$C_RESET"
  printf '%sby Genyleap%s\n' "$C_DIM" "$C_RESET"
}

section() {
  printf '\n%s%s%s%s\n' "$C_BOLD" "$C_BLUE" "$*" "$C_RESET"
}

field() {
  printf '  %s%-12s%s %s\n' "$C_DIM" "$1" "$C_RESET" "$2"
}

show_notice() {
  brand
  section "Before installation"
  printf '  OpenProof is self-hosted software. This instance runs on infrastructure\n'
  printf '  you control; Genyleap does not operate or administer the installed service.\n\n'
  printf '  Normal OpenProof runtime does not require a managed Genyleap backend for\n'
  printf '  your identity database, credentials, sessions, or cryptographic keys.\n'
  printf '  You are responsible for hosting, security, backups, upgrades, compliance,\n'
  printf '  and any third-party providers or delivery services you configure.\n\n'
  printf '  Installation and upgrades may contact Genyleap and GitHub only to resolve\n'
  printf '  and download verified release artifacts.\n\n'
  printf '  %sDocs:%s    %s\n' "$C_DIM" "$C_RESET" "$DOCS_URL"
  printf '  %sPrivacy:%s %s\n' "$C_DIM" "$C_RESET" "$PRIVACY_URL"
  printf '  %sTerms:%s   %s\n' "$C_DIM" "$C_RESET" "$TERMS_URL"
}

usage() {
  brand
  printf '%sUsage%s\n' "$C_BOLD" "$C_RESET"
  cat <<'EOF'
  curl -fsSL https://genyleap.com/install/openproof | sudo sh
  curl -fsSL https://genyleap.com/install/openproof | sudo sh -s -- [options]

Options
  --version VERSION       Install an exact release
  --channel CHANNEL       auto (default), stable, or rc
  --non-interactive       Do not prompt during setup
  --no-setup              Install/update OpenProof files only
  --plan                  Print the detected installation plan and exit
  -h, --help              Show this help

The production installer uses verified prebuilt bundles. It never compiles
OpenProof or installs compiler/build dependencies on the target host.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) [ "$#" -ge 2 ] || die "--version requires a value"; REQUESTED_VERSION="$2"; shift 2 ;;
    --channel) [ "$#" -ge 2 ] || die "--channel requires a value"; CHANNEL="$2"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --no-setup) NO_SETUP=1; shift ;;
    --plan) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run this installer as root (for example via sudo)"

for command_name in curl sha256sum tar install cp mv rm mktemp uname systemctl getent addgroup adduser; do
  command -v "$command_name" >/dev/null 2>&1 || die "required base-system command not found: $command_name"
done

if [ -r /etc/os-release ]; then
  . /etc/os-release
else
  die "cannot determine the operating system"
fi

case "${ID:-}" in
  ubuntu)
    major=$(printf '%s' "${VERSION_ID:-0}" | cut -d. -f1)
    [ "$major" -ge 24 ] || die "Ubuntu 24.04 or newer is required"
    ;;
  debian)
    major=$(printf '%s' "${VERSION_ID:-0}" | cut -d. -f1)
    [ "$major" -ge 13 ] || die "Debian 13 or newer is required"
    ;;
  *)
    die "unsupported distribution: ${ID:-unknown}; supported: Ubuntu 24.04+ and Debian 13+"
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

show_notice

github_release_tags() {
  curl -fsSL --retry 3 --connect-timeout 10 "https://github.com/$REPO/releases.atom" 2>/dev/null |
    sed -n 's#.*href="[^"]*/releases/tag/\([^"]*\)".*#\1#p'
}

resolve_version() {
  if [ -n "$REQUESTED_VERSION" ]; then
    printf '%s\n' "$REQUESTED_VERSION" | sed 's/^v//'
    return
  fi

  tag=""
  case "$CHANNEL" in
    stable)
      tag=$(github_release_tags | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1) || true
      if [ -z "${tag:-}" ]; then
        tag=$(curl -fsSL --retry 3 --connect-timeout 10 "$GENYLEAP_RELEASES/stable" 2>/dev/null | head -n 1) || true
      fi
      [ -n "${tag:-}" ] || die "no stable OpenProof prebuilt release is available"
      ;;
    rc)
      tag=$(github_release_tags | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9A-Za-z.-]*$' | head -n 1) || true
      if [ -z "${tag:-}" ]; then
        tag=$(curl -fsSL --retry 3 --connect-timeout 10 "$GENYLEAP_RELEASES/rc" 2>/dev/null | head -n 1) || true
      fi
      [ -n "${tag:-}" ] || die "no OpenProof release-candidate build is available"
      ;;
    auto)
      tag=$(github_release_tags | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1) || true
      if [ -z "${tag:-}" ]; then
        tag=$(github_release_tags | head -n 1) || true
      fi
      if [ -z "${tag:-}" ]; then
        tag=$(curl -fsSL --retry 3 --connect-timeout 10 "$GENYLEAP_RELEASES/stable" 2>/dev/null | head -n 1) || true
      fi
      if [ -z "${tag:-}" ]; then
        tag=$(curl -fsSL --retry 3 --connect-timeout 10 "$GENYLEAP_RELEASES/latest" 2>/dev/null | head -n 1) || true
      fi
      [ -n "${tag:-}" ] || die "no OpenProof prebuilt release is available"
      ;;
    *) die "invalid channel '$CHANNEL'; use auto, stable, or rc" ;;
  esac

  printf '%s\n' "$tag" | sed 's/^v//'
}

TMP=$(mktemp -d)
NEW_ROOT=""
OLD_ROOT=""
cleanup() {
  rm -rf "$TMP"
  [ -z "$NEW_ROOT" ] || rm -rf "$NEW_ROOT"
}
trap cleanup EXIT INT TERM

OPENPROOF_VERSION=$(resolve_version)
TAG="v$OPENPROOF_VERSION"
ASSET="openproof_${OPENPROOF_VERSION}_linux_${ARCH}.tar.gz"
MIRROR_ASSET="openproof_${OPENPROOF_VERSION}_linux_${ARCH}.tgz"
BASE="$GENYLEAP_RELEASES/$TAG"
GITHUB_BASE="$GITHUB_RELEASES/$TAG"

if [ "$PLAN_ONLY" -eq 1 ]; then
  section "Installation plan"
  field "System" "${PRETTY_NAME:-$ID}"
  field "Architecture" "$ARCH"
  field "Release" "$OPENPROOF_VERSION"
  field "Mode" "verified prebuilt bundle"
  field "Asset" "$ASSET"
  field "Build" "never on the target host"
  exit 0
fi

section "Release"
field "Version" "$OPENPROOF_VERSION"
field "System" "${PRETTY_NAME:-$ID}"
field "Architecture" "$ARCH"
field "Mode" "verified prebuilt bundle"

section "Install"
info "Downloading release metadata..."
if ! curl -fsSL --retry 3 --connect-timeout 10 -o "$TMP/SHA256SUMS" "$GITHUB_BASE/SHA256SUMS"; then
  curl -fsSL --retry 2 --connect-timeout 10 -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS.txt" 2>/dev/null || true
fi
[ -s "$TMP/SHA256SUMS" ] || die "release metadata for $OPENPROOF_VERSION could not be downloaded; refusing to build from source"

info "Downloading $ASSET..."
if ! curl -fsSL --retry 3 --connect-timeout 10 -o "$TMP/$ASSET" "$GITHUB_BASE/$ASSET"; then
  curl -fsSL --retry 2 --connect-timeout 10 -o "$TMP/$ASSET" "$BASE/$MIRROR_ASSET" 2>/dev/null || true
fi
[ -s "$TMP/$ASSET" ] || die "no prebuilt $ARCH bundle exists for OpenProof $OPENPROOF_VERSION; refusing to build from source"

expected=$(awk -v asset="$ASSET" '$2 == asset {print $1}' "$TMP/SHA256SUMS" | head -n 1)
[ -n "$expected" ] || die "$ASSET is not listed in SHA256SUMS"
actual=$(sha256sum "$TMP/$ASSET" | awk '{print $1}')
[ "$expected" = "$actual" ] || die "checksum verification failed for $ASSET"
ok "Release checksum verified"

if tar -tzf "$TMP/$ASSET" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
  die "release archive contains an unsafe path"
fi

EXTRACT="$TMP/root"
mkdir -p "$EXTRACT"
tar -xzf "$TMP/$ASSET" -C "$EXTRACT"

for required in \
  opt/openproof/bin/opp \
  opt/openproof/bin/opp.real \
  opt/openproof/migrations \
  usr/sbin/openproof \
  usr/lib/openproof/setup.sh \
  lib/systemd/system/openproof.service
 do
  [ -e "$EXTRACT/$required" ] || die "release bundle is incomplete: missing $required"
done

if ! getent group openproof >/dev/null 2>&1; then
  addgroup --system openproof >/dev/null
fi
if ! id openproof >/dev/null 2>&1; then
  adduser --system --ingroup openproof --home /nonexistent --no-create-home --shell /usr/sbin/nologin openproof >/dev/null
fi
install -d -o root -g openproof -m 0750 /etc/openproof /etc/openproof/credentials

NEW_ROOT="/opt/openproof.new.$$"
OLD_ROOT="/opt/openproof.old.$$"
rm -rf "$NEW_ROOT" "$OLD_ROOT"
cp -a "$EXTRACT/opt/openproof" "$NEW_ROOT"

ALREADY_CONFIGURED=0
[ ! -f /etc/openproof/.configured ] || ALREADY_CONFIGURED=1

WAS_ACTIVE=0
WAS_DELIVERY_ACTIVE=0
if systemctl is-active --quiet openproof.service 2>/dev/null; then
  WAS_ACTIVE=1
  systemctl stop openproof.service
fi
if systemctl is-active --quiet openproof-delivery.service 2>/dev/null; then
  WAS_DELIVERY_ACTIVE=1
  systemctl stop openproof-delivery.service
fi

if [ -d /opt/openproof ]; then
  mv /opt/openproof "$OLD_ROOT"
fi
mv "$NEW_ROOT" /opt/openproof
NEW_ROOT=""

install -m 0755 "$EXTRACT/usr/sbin/openproof" /usr/sbin/openproof
install -d -m 0755 /usr/lib/openproof
install -m 0755 "$EXTRACT/usr/lib/openproof/setup.sh" /usr/lib/openproof/setup.sh
install -m 0755 "$EXTRACT/usr/lib/openproof/backup-postgres.sh" /usr/lib/openproof/backup-postgres.sh
install -m 0755 "$EXTRACT/usr/lib/openproof/restore-postgres.sh" /usr/lib/openproof/restore-postgres.sh

rm -rf /usr/share/openproof/templates
install -d -m 0755 /usr/share/openproof/templates
cp -a "$EXTRACT/usr/share/openproof/templates/." /usr/share/openproof/templates/

install -m 0644 "$EXTRACT/lib/systemd/system/openproof.service" /lib/systemd/system/openproof.service
install -m 0644 "$EXTRACT/lib/systemd/system/openproof-delivery.service" /lib/systemd/system/openproof-delivery.service
systemctl daemon-reload

rm -rf "$OLD_ROOT"
OLD_ROOT=""

ok "OpenProof prebuilt bundle installed"
ok "No compiler or build dependency was installed"

run_interactive_setup() {
  setup_tty="${SUDO_TTY:-/dev/tty}"

  if [ -n "${SUDO_TTY:-}" ] && [ -r "$setup_tty" ] && [ -w "$setup_tty" ]; then
    if command -v script >/dev/null 2>&1; then
      OPENPROOF_TTY="$setup_tty"
      export OPENPROOF_TTY
      script -q -e -c "/usr/sbin/openproof setup" /dev/null \
        <"$setup_tty" >"$setup_tty" 2>&1
      return
    fi
  fi

  OPENPROOF_TTY="$setup_tty" /usr/sbin/openproof setup
}

if [ "$NO_SETUP" -eq 0 ] && [ "$ALREADY_CONFIGURED" -eq 0 ]; then
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    /usr/sbin/openproof setup --non-interactive
  else
    run_interactive_setup
  fi
else
  if [ "$WAS_DELIVERY_ACTIVE" -eq 1 ]; then
    systemctl restart openproof-delivery.service
    ok "OpenProof delivery service restarted"
  fi
  if [ "$WAS_ACTIVE" -eq 1 ]; then
    systemctl restart openproof.service
    ok "OpenProof service restarted"
  fi
  if [ "$ALREADY_CONFIGURED" -eq 1 ]; then
    ok "Existing OpenProof configuration preserved"
  elif [ "$NO_SETUP" -eq 1 ]; then
    section "Next step"
    info "OpenProof files installed without configuration."
    printf '  Run: %ssudo openproof setup%s\n' "$C_CYAN" "$C_RESET"
  fi
fi

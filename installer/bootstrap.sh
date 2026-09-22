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

say() { printf '%s\n' "$*"; }
die() { printf 'OpenProof installer: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
OpenProof prebuilt installer

Usage:
  curl -fsSL https://genyleap.com/install/openproof | sudo sh
  curl -fsSL https://genyleap.com/install/openproof | sudo sh -s -- [options]

Options:
  --version VERSION       Install an exact release, for example 1.1.0 or 1.1.0-rc2
  --channel CHANNEL       auto (default), stable, or rc
  --non-interactive       Do not prompt during setup
  --no-setup              Install/update OpenProof files only
  --plan                  Print the detected installation plan and exit
  -h, --help              Show this help

This installer never builds OpenProof and never installs compiler/build dependencies.
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

resolve_version() {
  if [ -n "$REQUESTED_VERSION" ]; then
    printf '%s\n' "$REQUESTED_VERSION" | sed 's/^v//'
    return
  fi

  tag=""
  case "$CHANNEL" in
    stable)
      tag=$(curl -fsSL --retry 3 --connect-timeout 10 "$GENYLEAP_RELEASES/stable" 2>/dev/null | head -n 1) || true
      [ -n "${tag:-}" ] || die "no stable OpenProof prebuilt release is available"
      ;;
    rc)
      tag=$(curl -fsSL --retry 3 --connect-timeout 10 "$GENYLEAP_RELEASES/rc" 2>/dev/null | head -n 1) || true
      [ -n "${tag:-}" ] || die "no OpenProof release-candidate build is available"
      ;;
    auto)
      tag=$(curl -fsSL --retry 3 --connect-timeout 10 "$GENYLEAP_RELEASES/stable" 2>/dev/null | head -n 1) || true
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
BASE="$GENYLEAP_RELEASES/$TAG"
GITHUB_BASE="$GITHUB_RELEASES/$TAG"

if [ "$PLAN_ONLY" -eq 1 ]; then
  say "OpenProof installation plan"
  say "  system : ${PRETTY_NAME:-$ID}"
  say "  arch   : $ARCH"
  say "  mode   : verified prebuilt bundle"
  say "  release: $OPENPROOF_VERSION"
  say "  asset  : $ASSET"
  say "  build  : never on the target host"
  exit 0
fi

say ""
say "OpenProof"
say "  release : $OPENPROOF_VERSION"
say "  system  : ${PRETTY_NAME:-$ID}"
say "  arch    : $ARCH"
say "  mode    : prebuilt bundle"
say ""

say "Downloading release metadata..."
if ! curl -fsSL --retry 3 --connect-timeout 10 -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"; then
  curl -fsSL --retry 2 --connect-timeout 10 -o "$TMP/SHA256SUMS" "$GITHUB_BASE/SHA256SUMS" 2>/dev/null || true
fi
[ -s "$TMP/SHA256SUMS" ] || die "release metadata for $OPENPROOF_VERSION could not be downloaded; refusing to build from source"

say "Downloading $ASSET..."
if ! curl -fsSL --retry 3 --connect-timeout 10 -o "$TMP/$ASSET" "$BASE/$ASSET"; then
  curl -fsSL --retry 2 --connect-timeout 10 -o "$TMP/$ASSET" "$GITHUB_BASE/$ASSET" 2>/dev/null || true
fi
[ -s "$TMP/$ASSET" ] || die "no prebuilt $ARCH bundle exists for OpenProof $OPENPROOF_VERSION; refusing to build from source"

expected=$(awk -v asset="$ASSET" '$2 == asset {print $1}' "$TMP/SHA256SUMS" | head -n 1)
[ -n "$expected" ] || die "$ASSET is not listed in SHA256SUMS"
actual=$(sha256sum "$TMP/$ASSET" | awk '{print $1}')
[ "$expected" = "$actual" ] || die "checksum verification failed for $ASSET"
say "✓ Release checksum verified"

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

say "✓ OpenProof prebuilt bundle installed"
say "✓ No compiler or build dependency was installed"

if [ "$NO_SETUP" -eq 0 ] && [ "$ALREADY_CONFIGURED" -eq 0 ]; then
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    /usr/sbin/openproof setup --non-interactive
  else
    /usr/sbin/openproof setup
  fi
else
  if [ "$WAS_DELIVERY_ACTIVE" -eq 1 ]; then
    systemctl restart openproof-delivery.service
    say "✓ OpenProof delivery service restarted"
  fi
  if [ "$WAS_ACTIVE" -eq 1 ]; then
    systemctl restart openproof.service
    say "✓ OpenProof service restarted"
  fi
  if [ "$ALREADY_CONFIGURED" -eq 1 ]; then
    say "✓ Existing OpenProof configuration preserved"
  elif [ "$NO_SETUP" -eq 1 ]; then
    say ""
    say "OpenProof files installed without configuration."
    say "Run: sudo openproof setup"
  fi
fi

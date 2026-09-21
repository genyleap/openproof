#!/bin/sh
set -eu

REPO="genyleap/openproof"
CHANNEL="auto"
REQUESTED_VERSION=""
NON_INTERACTIVE=0
NO_SETUP=0
PLAN_ONLY=0
API="https://api.github.com/repos/$REPO"
RELEASES="https://github.com/$REPO/releases/download"
GENYLEAP_RELEASES="https://genyleap.com/releases/openproof"
SOURCE_INSTALLER="https://genyleap.com/install/openproof-source"

say() { printf '%s\n' "$*"; }
die() { printf 'OpenProof installer: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
OpenProof bootstrap installer

Usage:
  curl -fsSL https://genyleap.com/install/openproof | sudo sh
  curl -fsSL https://genyleap.com/install/openproof | sudo sh -s -- [options]

Options:
  --version VERSION       Install an exact release, for example 1.1.0 or 1.1.0-rc1
  --channel CHANNEL       auto (default), stable, or rc
  --non-interactive       Do not prompt during setup
  --no-setup              Install the package only
  --plan                  Print the detected installation plan and exit
  -h, --help              Show this help
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
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
command -v apt-get >/dev/null 2>&1 || die "this installer currently supports Debian/Ubuntu systems"

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

api_get() {
  curl -fsSL     -H "Accept: application/vnd.github+json"     -H "User-Agent: OpenProof-Installer"     "$1"
}

extract_tag() {
  sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

resolve_version() {
  if [ -n "$REQUESTED_VERSION" ]; then
    printf '%s\n' "$REQUESTED_VERSION" | sed 's/^v//'
    return
  fi

  tag=""
  case "$CHANNEL" in
    stable)
      tag=$(curl -fsSL "$GENYLEAP_RELEASES/stable" 2>/dev/null | head -n 1) || true
      if [ -z "${tag:-}" ]; then
        tag=$(api_get "$API/releases/latest" 2>/dev/null | extract_tag) || true
      fi
      [ -n "${tag:-}" ] || die "no stable OpenProof release is available"
      ;;
    rc)
      tag=$(curl -fsSL "$GENYLEAP_RELEASES/rc" 2>/dev/null | head -n 1) || true
      if [ -z "${tag:-}" ]; then
        tag=$(api_get "$API/releases?per_page=20" 2>/dev/null | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*-rc[^"]*\)".*/\1/p' | head -n 1) || true
      fi
      [ -n "${tag:-}" ] || die "no release-candidate build is available"
      ;;
    auto)
      tag=$(curl -fsSL "$GENYLEAP_RELEASES/stable" 2>/dev/null | head -n 1) || true
      if [ -z "${tag:-}" ]; then
        tag=$(curl -fsSL "$GENYLEAP_RELEASES/latest" 2>/dev/null | head -n 1) || true
      fi
      if [ -z "${tag:-}" ]; then
        tag=$(api_get "$API/releases/latest" 2>/dev/null | extract_tag) || true
      fi
      if [ -z "${tag:-}" ]; then
        tag=$(api_get "$API/releases?per_page=1" 2>/dev/null | extract_tag) || true
      fi
      ;;
    *) die "invalid channel '$CHANNEL'; use auto, stable, or rc" ;;
  esac

  printf '%s\n' "$tag" | sed 's/^v//'
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

OPENPROOF_VERSION=$(resolve_version)

if [ "$PLAN_ONLY" -eq 1 ]; then
  say "OpenProof installation plan"
  say "  system : ${PRETTY_NAME:-$ID}"
  say "  arch   : $ARCH"
  if [ -n "$OPENPROOF_VERSION" ]; then
    say "  mode   : prebuilt release"
    say "  release: $OPENPROOF_VERSION"
  else
    say "  mode   : automatic source build"
    say "  ref    : main"
  fi
  exit 0
fi

if [ -z "$OPENPROOF_VERSION" ]; then
  say ""
  say "No prebuilt GitHub release is available yet."
  say "Using the automatic Ubuntu source installer instead."
  say ""
  SOURCE_ARGS=""
  [ "$NON_INTERACTIVE" -eq 0 ] || SOURCE_ARGS="$SOURCE_ARGS --non-interactive"
  [ "$NO_SETUP" -eq 0 ] || SOURCE_ARGS="$SOURCE_ARGS --no-setup"
  SOURCE_SCRIPT="$TMP/source-install.sh"
  curl -fsSL --retry 3 --connect-timeout 10 -o "$SOURCE_SCRIPT" "$SOURCE_INSTALLER"
  exec bash "$SOURCE_SCRIPT" $SOURCE_ARGS
fi

TAG="v$OPENPROOF_VERSION"
ASSET="openproof_${OPENPROOF_VERSION}_${ARCH}.deb"
BASE="$GENYLEAP_RELEASES/$TAG"
GITHUB_BASE="$RELEASES/$TAG"

say ""
say "OpenProof"
say "  release : $OPENPROOF_VERSION"
say "  system  : ${PRETTY_NAME:-$ID}"
say "  arch    : $ARCH"
say ""

say "Downloading release metadata..."
if ! curl -fsSL --retry 3 --connect-timeout 10 -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"; then
  curl -fsSL --retry 2 --connect-timeout 10 -o "$TMP/SHA256SUMS" "$GITHUB_BASE/SHA256SUMS" 2>/dev/null || true
fi
if [ ! -s "$TMP/SHA256SUMS" ]; then
  if [ "$CHANNEL" = "auto" ] && [ -z "$REQUESTED_VERSION" ]; then
    say "! Prebuilt release metadata is unavailable; using the Ubuntu source installer."
    SOURCE_ARGS=""
    [ "$NON_INTERACTIVE" -eq 0 ] || SOURCE_ARGS="$SOURCE_ARGS --non-interactive"
    [ "$NO_SETUP" -eq 0 ] || SOURCE_ARGS="$SOURCE_ARGS --no-setup"
    SOURCE_ARGS="$SOURCE_ARGS --ref $TAG"
    SOURCE_SCRIPT="$TMP/source-install.sh"
    curl -fsSL --retry 3 --connect-timeout 10 -o "$SOURCE_SCRIPT" "$SOURCE_INSTALLER"
    exec bash "$SOURCE_SCRIPT" $SOURCE_ARGS
  fi
  die "release metadata for $OPENPROOF_VERSION could not be downloaded"
fi

if ! curl -fsSL --retry 3 --connect-timeout 10 -o "$TMP/$ASSET" "$BASE/$ASSET" 2>/dev/null; then
  curl -fsSL --retry 2 --connect-timeout 10 -o "$TMP/$ASSET" "$GITHUB_BASE/$ASSET" 2>/dev/null || true
fi
if [ ! -s "$TMP/$ASSET" ]; then
  if [ "$CHANNEL" = "auto" ] && [ -z "$REQUESTED_VERSION" ]; then
    say "! No prebuilt $ARCH package exists for $OPENPROOF_VERSION; using the Ubuntu source installer."
    SOURCE_ARGS=""
    [ "$NON_INTERACTIVE" -eq 0 ] || SOURCE_ARGS="$SOURCE_ARGS --non-interactive"
    [ "$NO_SETUP" -eq 0 ] || SOURCE_ARGS="$SOURCE_ARGS --no-setup"
    SOURCE_ARGS="$SOURCE_ARGS --ref $TAG"
    SOURCE_SCRIPT="$TMP/source-install.sh"
    curl -fsSL --retry 3 --connect-timeout 10 -o "$SOURCE_SCRIPT" "$SOURCE_INSTALLER"
    exec bash "$SOURCE_SCRIPT" $SOURCE_ARGS
  fi
  die "$ASSET could not be downloaded"
fi

expected=$(awk -v asset="$ASSET" '$2 == asset {print $1}' "$TMP/SHA256SUMS" | head -n 1)
[ -n "$expected" ] || die "$ASSET is not listed in SHA256SUMS"
actual=$(sha256sum "$TMP/$ASSET" | awk '{print $1}')
[ "$expected" = "$actual" ] || die "checksum verification failed for $ASSET"
say "✓ Release checksum verified"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y "$TMP/$ASSET"

say "✓ OpenProof package installed"

if [ "$NO_SETUP" -eq 0 ]; then
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    /usr/sbin/openproof setup --non-interactive
  else
    /usr/sbin/openproof setup
  fi
else
  say ""
  say "Package installed without configuration."
  say "Run: sudo openproof setup"
fi

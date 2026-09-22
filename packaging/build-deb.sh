#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD_DIR="$ROOT/cmake-build-gcc-release"
OUT_DIR="$ROOT/dist"
ARCH=$(dpkg --print-architecture)
if (($# >= 1)); then BUILD_DIR=$1; fi
if (($# >= 2)); then OUT_DIR=$2; fi
if (($# >= 3)); then ARCH=$3; fi

RAW_VERSION=$(tr -d '[:space:]' <"$ROOT/VERSION")
DEB_VERSION=$(printf '%s' "$RAW_VERSION" | sed -E 's/-rc/~rc/')
BINARY="$BUILD_DIR/apps/opp/opp"

[[ -x $BINARY ]] || { printf 'missing built binary: %s\n' "$BINARY" >&2; exit 1; }
"$ROOT/scripts/verify-generated-secret-references.sh"
"$ROOT/scripts/verify-setup-contract.sh"
[[ $ARCH == amd64 || $ARCH == arm64 ]] || { printf 'unsupported Debian architecture: %s\n' "$ARCH" >&2; exit 1; }

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/pkg"

install -d \
  "$PKG/DEBIAN" \
  "$PKG/opt/openproof/bin" \
  "$PKG/opt/openproof/lib" \
  "$PKG/opt/openproof/migrations" \
  "$PKG/opt/openproof/docs" \
  "$PKG/usr/sbin" \
  "$PKG/usr/lib/openproof" \
  "$PKG/usr/share/openproof/templates" \
  "$PKG/lib/systemd/system"

install -m 0755 "$BINARY" "$PKG/opt/openproof/bin/opp.real"

cat >"$PKG/opt/openproof/bin/opp" <<'EOF'
#!/bin/sh
export LD_LIBRARY_PATH="/opt/openproof/lib:$LD_LIBRARY_PATH"
exec /opt/openproof/bin/opp.real "$@"
EOF
chmod 0755 "$PKG/opt/openproof/bin/opp"

COMPILER=""
if [[ -n "${OPENPROOF_GCC_ROOT:-}" ]]; then
  for candidate in "$OPENPROOF_GCC_ROOT/bin/g++-16" "$OPENPROOF_GCC_ROOT/bin/g++"; do
    if [[ -x $candidate ]]; then COMPILER=$candidate; break; fi
  done
fi
if [[ -z $COMPILER ]]; then
  COMPILER=$(command -v g++-16 || command -v g++ || true)
fi

for soname in libstdc++.so.6 libgcc_s.so.1; do
  path=""
  if [[ -n $COMPILER ]]; then
    path=$("$COMPILER" -print-file-name="$soname")
    [[ $path = /* && -r $path ]] || path=""
  fi
  if [[ -z $path ]]; then
    path=$(ldd "$BINARY" | awk -v name="$soname" '$1 == name {print $3; exit}')
  fi
  if [[ -n $path && -r $path ]]; then cp -L "$path" "$PKG/opt/openproof/lib/$soname"; fi
done

cp -a "$ROOT/migrations/." "$PKG/opt/openproof/migrations/"
find "$PKG/opt/openproof/migrations" -type d -exec chmod 0755 {} +
find "$PKG/opt/openproof/migrations" -type f -exec chmod 0644 {} +
install -m 0644 "$ROOT/docs/OPERATIONS.md" "$PKG/opt/openproof/docs/OPERATIONS.md"
install -m 0644 "$ROOT/docs/CONFIGURATION.md" "$PKG/opt/openproof/docs/CONFIGURATION.md"

install -m 0755 "$ROOT/installer/openproof" "$PKG/usr/sbin/openproof"
install -m 0755 "$ROOT/installer/setup.sh" "$PKG/usr/lib/openproof/setup.sh"
install -m 0755 "$ROOT/scripts/backup-postgres.sh" "$PKG/usr/lib/openproof/backup-postgres.sh"
install -m 0755 "$ROOT/scripts/restore-postgres.sh" "$PKG/usr/lib/openproof/restore-postgres.sh"

install -m 0644 "$ROOT/deploy/openproof.service" "$PKG/lib/systemd/system/openproof.service"
install -m 0644 "$ROOT/deploy/openproof-delivery.service" "$PKG/lib/systemd/system/openproof-delivery.service"

install -m 0644 "$ROOT/deploy/openproof.toml.example" "$PKG/usr/share/openproof/templates/openproof.toml.example"
install -m 0644 "$ROOT/deploy/providers.env.example" "$PKG/usr/share/openproof/templates/providers.env.example"
install -m 0644 "$ROOT/deploy/openproof-delivery.env.example" "$PKG/usr/share/openproof/templates/openproof-delivery.env.example"
install -m 0644 "$ROOT/deploy/verification-delivery-postfix.php" "$PKG/usr/share/openproof/templates/verification-delivery-postfix.php"
install -m 0644 "$ROOT/deploy/nginx-openproof.conf" "$PKG/usr/share/openproof/templates/nginx-openproof.conf"

cat >"$PKG/DEBIAN/control" <<EOF
Package: openproof
Version: $DEB_VERSION-1
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: Genyleap <support@genyleap.com>
Depends: adduser, systemd, ca-certificates, curl, openssl, libpq5, libssl3t64 | libssl3, libldap2, libxml2, zlib1g
Recommends: nginx, postgresql
Description: Self-hosted identity infrastructure
 OpenProof provides canonical identity, authentication, OAuth/OIDC, passkeys,
 Web3 federation, enterprise identity, sessions and policy enforcement.
EOF

cat >"$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if ! getent group openproof >/dev/null; then addgroup --system openproof >/dev/null; fi
if ! id openproof >/dev/null 2>&1; then
  adduser --system --ingroup openproof --home /nonexistent --no-create-home --shell /usr/sbin/nologin openproof >/dev/null
fi
install -d -o root -g openproof -m 0750 /etc/openproof /etc/openproof/credentials
systemctl daemon-reload >/dev/null 2>&1 || true
printf '\nOpenProof installed. Run: sudo openproof setup\n'
EOF
chmod 0755 "$PKG/DEBIAN/postinst"

cat >"$PKG/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = deconfigure ]; then
  systemctl disable --now openproof.service >/dev/null 2>&1 || true
  systemctl disable --now openproof-delivery.service >/dev/null 2>&1 || true
fi
EOF
chmod 0755 "$PKG/DEBIAN/prerm"

mkdir -p "$OUT_DIR"
ASSET="$OUT_DIR/openproof_"$RAW_VERSION"_"$ARCH".deb"
dpkg-deb --build --root-owner-group "$PKG" "$ASSET" >/dev/null
sha256sum "$ASSET"
printf 'Built %s\n' "$ASSET"

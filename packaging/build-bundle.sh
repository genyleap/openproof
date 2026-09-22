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

VERSION=$(tr -d '[:space:]' <"$ROOT/VERSION")
BINARY="$BUILD_DIR/apps/opp/opp"

[[ -x $BINARY ]] || { printf 'missing built binary: %s\n' "$BINARY" >&2; exit 1; }
[[ $ARCH == amd64 || $ARCH == arm64 ]] || { printf 'unsupported architecture: %s\n' "$ARCH" >&2; exit 1; }

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
ROOTFS="$STAGE/root"

install -d \
  "$ROOTFS/opt/openproof/bin" \
  "$ROOTFS/opt/openproof/lib" \
  "$ROOTFS/opt/openproof/migrations" \
  "$ROOTFS/opt/openproof/docs" \
  "$ROOTFS/usr/sbin" \
  "$ROOTFS/usr/lib/openproof" \
  "$ROOTFS/usr/share/openproof/templates" \
  "$ROOTFS/lib/systemd/system"

install -m 0755 "$BINARY" "$ROOTFS/opt/openproof/bin/opp.real"

cat >"$ROOTFS/opt/openproof/bin/opp" <<'EOF'
#!/bin/sh
OPENPROOF_ROOT=/opt/openproof
export LD_LIBRARY_PATH="$OPENPROOF_ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$OPENPROOF_ROOT/bin/opp.real" "$@"
EOF
chmod 0755 "$ROOTFS/opt/openproof/bin/opp"

OPENSSL_BIN=$(command -v openssl || true)
if [[ -n $OPENSSL_BIN ]]; then
  install -m 0755 "$OPENSSL_BIN" "$ROOTFS/opt/openproof/bin/openssl.real"
  cat >"$ROOTFS/opt/openproof/bin/openssl" <<'EOF'
#!/bin/sh
OPENPROOF_ROOT=/opt/openproof
export LD_LIBRARY_PATH="$OPENPROOF_ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$OPENPROOF_ROOT/bin/openssl.real" "$@"
EOF
  chmod 0755 "$ROOTFS/opt/openproof/bin/openssl"
fi

is_glibc_runtime() {
  case "$1" in
    libc.so.*|libm.so.*|libpthread.so.*|libdl.so.*|librt.so.*|libresolv.so.*|libnss_*.so.*|ld-linux*.so.*|ld-*.so)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

copy_runtime_closure() {
  local queue=("$@")
  local cursor=0 item dep base dest
  declare -A seen=()

  while (( cursor < ${#queue[@]} )); do
    item=${queue[$cursor]}
    cursor=$((cursor + 1))
    [[ -r $item ]] || continue

    while IFS= read -r dep; do
      [[ -n $dep && -r $dep ]] || continue
      base=$(basename "$dep")
      is_glibc_runtime "$base" && continue
      [[ -z ${seen[$base]:-} ]] || continue
      seen[$base]=1
      dest="$ROOTFS/opt/openproof/lib/$base"
      cp -L "$dep" "$dest"
      chmod 0644 "$dest"
      queue+=("$dest")
    done < <(
      ldd "$item" 2>/dev/null | awk '
        /=> \/.* \(0x/ { print $3; next }
        /^\/[[:graph:]]+ \(0x/ { print $1 }
      '
    )
  done
}

runtime_roots=("$BINARY")
if [[ -n $OPENSSL_BIN ]]; then runtime_roots+=("$OPENSSL_BIN"); fi
copy_runtime_closure "${runtime_roots[@]}"

cp -a "$ROOT/migrations/." "$ROOTFS/opt/openproof/migrations/"
find "$ROOTFS/opt/openproof/migrations" -type d -exec chmod 0755 {} +
find "$ROOTFS/opt/openproof/migrations" -type f -exec chmod 0644 {} +
install -m 0644 "$ROOT/docs/OPERATIONS.md" "$ROOTFS/opt/openproof/docs/OPERATIONS.md"
install -m 0644 "$ROOT/docs/CONFIGURATION.md" "$ROOTFS/opt/openproof/docs/CONFIGURATION.md"
printf '%s\n' "$VERSION" >"$ROOTFS/opt/openproof/VERSION"

install -m 0755 "$ROOT/installer/openproof" "$ROOTFS/usr/sbin/openproof"
install -m 0755 "$ROOT/installer/setup.sh" "$ROOTFS/usr/lib/openproof/setup.sh"
install -m 0755 "$ROOT/scripts/backup-postgres.sh" "$ROOTFS/usr/lib/openproof/backup-postgres.sh"
install -m 0755 "$ROOT/scripts/restore-postgres.sh" "$ROOTFS/usr/lib/openproof/restore-postgres.sh"

install -m 0644 "$ROOT/deploy/openproof.service" "$ROOTFS/lib/systemd/system/openproof.service"
install -m 0644 "$ROOT/deploy/openproof-delivery.service" "$ROOTFS/lib/systemd/system/openproof-delivery.service"

install -m 0644 "$ROOT/deploy/openproof.toml.example" "$ROOTFS/usr/share/openproof/templates/openproof.toml.example"
install -m 0644 "$ROOT/deploy/providers.env.example" "$ROOTFS/usr/share/openproof/templates/providers.env.example"
install -m 0644 "$ROOT/deploy/openproof-delivery.env.example" "$ROOTFS/usr/share/openproof/templates/openproof-delivery.env.example"
install -m 0644 "$ROOT/deploy/verification-delivery-postfix.php" "$ROOTFS/usr/share/openproof/templates/verification-delivery-postfix.php"
install -m 0644 "$ROOT/deploy/nginx-openproof.conf" "$ROOTFS/usr/share/openproof/templates/nginx-openproof.conf"

cat >"$ROOTFS/opt/openproof/BUNDLE-METADATA" <<EOF
version=$VERSION
arch=$ARCH
format=1
runtime=glibc-host-plus-bundled-libraries
EOF
chmod 0644 "$ROOTFS/opt/openproof/BUNDLE-METADATA"

mkdir -p "$OUT_DIR"
ASSET="$OUT_DIR/openproof_${VERSION}_linux_${ARCH}.tar.gz"

tar \
  --sort=name \
  --owner=0 --group=0 --numeric-owner \
  -C "$ROOTFS" \
  -czf "$ASSET" .

sha256sum "$ASSET"
printf 'Built %s\n' "$ASSET"
printf 'Bundled runtime libraries:\n'
find "$ROOTFS/opt/openproof/lib" -maxdepth 1 -type f -printf '  %f\n' | sort

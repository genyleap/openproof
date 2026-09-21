#!/usr/bin/env bash
set -Eeuo pipefail

NON_INTERACTIVE=0
NO_SETUP=0
PLAN_ONLY=0

say(){ printf '%s\n' "$*"; }
die(){ printf 'OpenProof installer: %s\n' "$*" >&2; exit 1; }

while (($#)); do
  case "$1" in
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --no-setup) NO_SETUP=1; shift ;;
    --plan) PLAN_ONLY=1; shift ;;
    *) die "unknown source-install option: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run this installer as root"

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
else
  die "cannot determine the operating system"
fi

[[ "$ID" == "ubuntu" ]] || die "automatic source installation currently supports Ubuntu only"

major=$(printf '%s' "$VERSION_ID" | cut -d. -f1)
[[ "$major" -ge 24 ]] || die "Ubuntu 24.04 or newer is required"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  say "OpenProof source-build plan"
  say "  system : $PRETTY_NAME"
  say "  arch   : $ARCH"
  say "  compiler: GCC 16"
  say "  boost  : 1.88"
  say "  source : github.com/genyleap/openproof (main)"
  exit 0
fi

export DEBIAN_FRONTEND=noninteractive

say ""
say "OpenProof Linux installer"
say "  system : $PRETTY_NAME"
say "  arch   : $ARCH"
say ""
say "Installing build and runtime dependencies..."

apt-get update -qq
apt-get install -y --no-install-recommends \
  ca-certificates curl git software-properties-common ninja-build \
  python3 python3-pip bzip2 xz-utils build-essential flex bison gawk texinfo wget \
  libzstd-dev libssl-dev libpq-dev libtomlplusplus-dev libxml2-dev zlib1g-dev \
  libldap2-dev postgresql-client

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

GCC_ROOT=/usr

build_gcc16() {
  GCC_VERSION=16.2.0
  GCC_PREFIX="$WORK/gcc-$GCC_VERSION-install"

  say ""
  say "GCC 16 is not available as an Ubuntu package on this release."
  say "Building GCC $GCC_VERSION automatically. This can take a while on smaller ARM systems."
  say ""

  curl -fL --retry 3 --connect-timeout 15 \
    -o "$WORK/gcc.tar.xz" \
    "https://ftp.gnu.org/gnu/gcc/gcc-$GCC_VERSION/gcc-$GCC_VERSION.tar.xz"
  tar -xJf "$WORK/gcc.tar.xz" -C "$WORK"

  (
    cd "$WORK/gcc-$GCC_VERSION"
    ./contrib/download_prerequisites
  )

  mkdir -p "$WORK/gcc-build"
  (
    cd "$WORK/gcc-build"
    "$WORK/gcc-$GCC_VERSION/configure" \
      --prefix="$GCC_PREFIX" \
      --enable-languages=c,c++ \
      --disable-multilib \
      --disable-bootstrap \
      --enable-checking=release \
      --with-system-zlib \
      --enable-default-pie \
      --enable-default-ssp
    make -j"$(nproc)"
    make install
  )

  GCC_ROOT="$GCC_PREFIX"
}

if command -v g++-16 >/dev/null 2>&1; then
  GCC_ROOT=$(dirname "$(dirname "$(command -v g++-16)")")
else
  say "Looking for the qualified GCC 16 toolchain..."
  if apt-get install -y gcc-16 g++-16; then
    GCC_ROOT=/usr
  elif [[ "$VERSION_CODENAME" == "noble" ]]; then
    add-apt-repository -y ppa:ubuntu-toolchain-r/test
    apt-get update -qq
    if apt-get install -y gcc-16 g++-16; then
      GCC_ROOT=/usr
    else
      build_gcc16
    fi
  else
    build_gcc16
  fi
fi

cmake_ok=0
if command -v cmake >/dev/null 2>&1; then
  cmake_version=$(cmake --version | head -n1 | awk '{print $3}')
  cmake_major=$(printf '%s' "$cmake_version" | cut -d. -f1)
  cmake_minor=$(printf '%s' "$cmake_version" | cut -d. -f2)
  if [[ "$cmake_major" -gt 3 ]] || { [[ "$cmake_major" -eq 3 ]] && [[ "$cmake_minor" -ge 30 ]]; }; then
    cmake_ok=1
  fi
fi

if [[ "$cmake_ok" -ne 1 ]]; then
  say "Installing CMake 3.30+..."
  python3 -m pip install --break-system-packages --upgrade "cmake>=3.30,<4"
fi

SOURCE="$WORK/openproof"
BUILD="$WORK/build"
DIST="$WORK/dist"
BOOST_PREFIX="$WORK/boost-1.88"

say "Downloading OpenProof source..."
git clone --depth 1 https://github.com/genyleap/openproof.git "$SOURCE"
OPENPROOF_VERSION=$(tr -d '[:space:]' <"$SOURCE/VERSION")

say "Preparing Boost 1.88..."
curl -fL --retry 3 --connect-timeout 15 \
  -o "$WORK/boost.tar.bz2" \
  https://archives.boost.io/release/1.88.0/source/boost_1_88_0.tar.bz2
tar -xjf "$WORK/boost.tar.bz2" -C "$WORK"
(
  cd "$WORK/boost_1_88_0"
  ./bootstrap.sh --prefix="$BOOST_PREFIX"
  ./b2 install --prefix="$BOOST_PREFIX" \
    --with-system --with-json --with-container \
    -j"$(nproc)"
)

say "Configuring OpenProof $OPENPROOF_VERSION..."
OPENPROOF_GCC_ROOT="$GCC_ROOT" cmake -S "$SOURCE" -B "$BUILD" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$SOURCE/cmake/toolchains/gcc.cmake" \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENPROOF_BUILD_TESTS=OFF \
  -DOPENPROOF_BUILD_EXAMPLES=OFF \
  -DCMAKE_PREFIX_PATH="$BOOST_PREFIX"

say "Compiling OpenProof..."
cmake --build "$BUILD" --target opp --parallel "$(nproc)"

say "Building Debian package..."
mkdir -p "$DIST"
OPENPROOF_GCC_ROOT="$GCC_ROOT" "$SOURCE/packaging/build-deb.sh" "$BUILD" "$DIST" "$ARCH"
PACKAGE=$(find "$DIST" -maxdepth 1 -name "openproof_*_"$ARCH".deb" -print -quit)
[[ -n "$PACKAGE" ]] || die "build completed but no Debian package was produced"

apt-get install -y "$PACKAGE"

say ""
say "✓ OpenProof $OPENPROOF_VERSION installed"

if [[ "$NO_SETUP" -eq 1 ]]; then
  say "Run: sudo openproof setup"
  exit 0
fi

if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
  /usr/sbin/openproof setup --non-interactive
else
  /usr/sbin/openproof setup
fi

#!/usr/bin/env bash
set -Eeuo pipefail

CI_JOBS=${OPENPROOF_CI_JOBS:-2}
CACHE_ROOT="$HOME/.cache/openproof/boost-1.88.0"
GCC_VERSION=16.2.0
GCC_ROOT="$CACHE_ROOT/gcc-$GCC_VERSION/install"
BOOST_ROOT="$CACHE_ROOT/install"

sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
  ca-certificates curl git ninja-build python3-pip \
  build-essential flex bison gawk texinfo wget \
  xz-utils bzip2 libzstd-dev \
  libssl-dev libpq-dev libtomlplusplus-dev postgresql-client \
  libxml2-dev zlib1g-dev libldap2-dev

sudo python3 -m pip install --break-system-packages --upgrade "cmake>=3.30,<4"

mkdir -p "$CACHE_ROOT"

if [[ ! -x "$GCC_ROOT/bin/g++" ]]; then
  echo "GCC $GCC_VERSION cache miss; building the qualified compiler toolchain."
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT

  curl -fsSL --retry 3 --connect-timeout 15 \
    -o "$work/gcc.tar.xz" \
    "https://ftp.gnu.org/gnu/gcc/gcc-$GCC_VERSION/gcc-$GCC_VERSION.tar.xz"
  tar -xJf "$work/gcc.tar.xz" -C "$work"

  (
    cd "$work/gcc-$GCC_VERSION"
    ./contrib/download_prerequisites
  )

  mkdir -p "$work/gcc-build"
  (
    cd "$work/gcc-build"
    "$work/gcc-$GCC_VERSION/configure" \
      --prefix="$GCC_ROOT" \
      --enable-languages=c,c++ \
      --disable-multilib \
      --disable-bootstrap \
      --enable-checking=release \
      --with-system-zlib \
      --enable-default-pie \
      --enable-default-ssp
    make -j"$CI_JOBS"
    make install
  )

  rm -rf "$work"
  trap - EXIT
fi

sudo ln -sfn "$GCC_ROOT/bin/gcc" /usr/local/bin/gcc-16
sudo ln -sfn "$GCC_ROOT/bin/g++" /usr/local/bin/g++-16
export PATH="$GCC_ROOT/bin:$PATH"

if [[ ! -f "$BOOST_ROOT/include/boost/version.hpp" ]]; then
  echo "Boost 1.88 cache miss; building Boost with the qualified GCC toolchain."
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT

  curl -fsSL --retry 3 --connect-timeout 15 \
    -o "$work/boost.tar.bz2" \
    https://archives.boost.io/release/1.88.0/source/boost_1_88_0.tar.bz2
  tar -xjf "$work/boost.tar.bz2" -C "$work"

  (
    cd "$work/boost_1_88_0"
    ./bootstrap.sh --prefix="$BOOST_ROOT"
    ./b2 install -j"$CI_JOBS" --prefix="$BOOST_ROOT"
  )

  rm -rf "$work"
  trap - EXIT
fi

"$GCC_ROOT/bin/g++" --version | head -n 1
cmake --version | head -n 1
printf 'OPENPROOF_GCC_ROOT=%s\n' "$GCC_ROOT"
printf 'BOOST_ROOT=%s\n' "$BOOST_ROOT"

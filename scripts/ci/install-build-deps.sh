#!/usr/bin/env bash
set -Eeuo pipefail

CI_JOBS=${OPENPROOF_CI_JOBS:-$(nproc)}
CACHE_ROOT="$HOME/.cache/openproof/boost-1.88.0"
BOOST_ROOT="$CACHE_ROOT/install"
GCC_VERSION=16.2.0
GCC_ROOT="$CACHE_ROOT/gcc-$GCC_VERSION"

sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
  ca-certificates curl git ninja-build python3-pip \
  build-essential bzip2 xz-utils flex bison gawk texinfo wget \
  libzstd-dev libssl-dev libpq-dev libtomlplusplus-dev postgresql-client \
  libxml2-dev zlib1g-dev libldap2-dev

sudo python3 -m pip install --break-system-packages --upgrade "cmake>=3.30,<4"

mkdir -p "$CACHE_ROOT"

if [[ ! -x "$GCC_ROOT/bin/g++" ]]; then
  echo "GCC $GCC_VERSION cache miss; building the qualified compiler once."
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

  mkdir -p "$work/build"
  (
    cd "$work/build"
    "$work/gcc-$GCC_VERSION/configure" \
      --prefix="$GCC_ROOT" \
      --enable-languages=c,c++ \
      --disable-multilib \
      --disable-bootstrap \
      --enable-checking=release \
      --with-system-zlib
    make -j"$CI_JOBS"
    make install
  )

  ln -sfn gcc "$GCC_ROOT/bin/gcc-16"
  ln -sfn g++ "$GCC_ROOT/bin/g++-16"
  rm -rf "$work"
  trap - EXIT
fi

export PATH="$GCC_ROOT/bin:$PATH"
export LD_LIBRARY_PATH="$GCC_ROOT/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

if [[ ! -f "$BOOST_ROOT/include/boost/version.hpp" ]]; then
  echo "Boost 1.88 cache miss; preparing required libraries."
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT

  curl -fsSL --retry 3 --connect-timeout 15 \
    -o "$work/boost.tar.bz2" \
    https://archives.boost.io/release/1.88.0/source/boost_1_88_0.tar.bz2
  tar -xjf "$work/boost.tar.bz2" -C "$work"

  (
    cd "$work/boost_1_88_0"
    ./bootstrap.sh --prefix="$BOOST_ROOT"
    ./b2 install -j"$CI_JOBS" --prefix="$BOOST_ROOT" \
      toolset=gcc-16 \
      --with-system --with-json --with-container
  )

  rm -rf "$work"
  trap - EXIT
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'OPENPROOF_GCC_ROOT=%s\n' "$GCC_ROOT" >> "$GITHUB_ENV"
  printf 'LD_LIBRARY_PATH=%s/lib64\n' "$GCC_ROOT" >> "$GITHUB_ENV"
fi

if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s/bin\n' "$GCC_ROOT" >> "$GITHUB_PATH"
fi

"$GCC_ROOT/bin/g++" --version | head -n 1
cmake --version | head -n 1
printf 'OPENPROOF_GCC_ROOT=%s\n' "$GCC_ROOT"
printf 'BOOST_ROOT=%s\n' "$BOOST_ROOT"

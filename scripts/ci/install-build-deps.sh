#!/usr/bin/env bash
set -Eeuo pipefail

CI_JOBS=${OPENPROOF_CI_JOBS:-2}
CACHE_ROOT="$HOME/.cache/openproof/boost-1.88.0"
BOOST_ROOT="$CACHE_ROOT/install"

sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
  software-properties-common ca-certificates curl git ninja-build python3-pip \
  build-essential bzip2 \
  libssl-dev libpq-dev libtomlplusplus-dev postgresql-client \
  libxml2-dev zlib1g-dev libldap2-dev

# GitHub's Ubuntu 24.04 images do not ship GCC 16 by default. The
# ubuntu-toolchain-r/test PPA publishes native gcc-16/g++-16 packages for Noble
# on both amd64 and arm64, so CI installs the qualified compiler instead of
# spending close to an hour building GCC itself.
if ! command -v g++-16 >/dev/null 2>&1; then
  sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends gcc-16 g++-16
fi

sudo python3 -m pip install --break-system-packages --upgrade "cmake>=3.30,<4"

mkdir -p "$CACHE_ROOT"

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

g++-16 --version | head -n 1
cmake --version | head -n 1
printf 'OPENPROOF_GCC_ROOT=/usr\n'
printf 'BOOST_ROOT=%s\n' "$BOOST_ROOT"

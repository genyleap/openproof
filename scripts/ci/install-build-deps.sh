#!/usr/bin/env bash
set -Eeuo pipefail

sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
  software-properties-common ca-certificates curl git ninja-build python3-pip \
  libssl-dev libpq-dev libtomlplusplus-dev postgresql-client xz-utils bzip2

if ! command -v g++-16 >/dev/null 2>&1; then
  sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
  sudo apt-get update -qq
  sudo apt-get install -y gcc-16 g++-16
fi

python3 -m pip install --break-system-packages --upgrade "cmake>=3.30,<4"

BOOST_ROOT="$HOME/.cache/openproof/boost-1.88.0/install"
if [[ ! -f "$BOOST_ROOT/include/boost/version.hpp" ]]; then
  mkdir -p "$HOME/.cache/openproof"
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  curl -fL --retry 3 -o "$work/boost.tar.bz2" \
    https://archives.boost.io/release/1.88.0/source/boost_1_88_0.tar.bz2
  tar -xjf "$work/boost.tar.bz2" -C "$work"
  cd "$work/boost_1_88_0"
  ./bootstrap.sh --prefix="$BOOST_ROOT"
  ./b2 install -j2 --prefix="$BOOST_ROOT"
fi

printf 'BOOST_ROOT=%s\n' "$BOOST_ROOT"

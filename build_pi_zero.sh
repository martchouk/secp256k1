#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

OS="$(uname -s)"
ARCH="$(uname -m)"

if [[ "$OS" != "Linux" || "$ARCH" != "armv6l" ]]; then
  echo "This script is intended for Raspberry Pi Zero (Linux armv6l)."
  echo "Detected: OS=$OS ARCH=$ARCH"
  exit 1
fi

# Strong clean to avoid stale generated/LTO/libtool artifacts
rm -f src/precomputed_ecmult.c src/precomputed_ecmult_gen.c
rm -f precompute_ecmult precompute_ecmult_gen
rm -rf .libs src/.libs src/_libs src/asm/.libs src/asm/_libs
rm -rf src/.deps .deps autom4te.cache
rm -f src/*.o src/*.lo *.o *.lo
rm -f config.status config.cache config.log Makefile libtool libsecp256k1.pc
rm -f stamp-h1

./autogen.sh

BUILD_TRIPLE="$(./autotools-aux/config.guess)"

export CC=gcc
export AR=ar
export RANLIB=ranlib
export NM=nm
export STRIP=strip

# Conservative, Pi Zero-safe flags
export CFLAGS="-O3 -DNDEBUG -std=c11 -mcpu=arm1176jzf-s -fno-pie"
export LDFLAGS="-no-pie"

./configure \
  --build="$BUILD_TRIPLE" \
  --host="$BUILD_TRIPLE" \
  --enable-experimental \
  --with-ecmult-gen-kb=22 \
  --with-ecmult-window=15 \
  --with-asm=auto \
  --disable-shared \
  --enable-static \
  --disable-benchmark \
  --disable-tests \
  --disable-exhaustive-tests

make -j1

test -f .libs/libsecp256k1.a
file .libs/libsecp256k1.a
nm -A .libs/libsecp256k1.a | head || true
echo "OK: built .libs/libsecp256k1.a for Raspberry Pi Zero"

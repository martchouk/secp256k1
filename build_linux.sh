#!/usr/bin/env bash
set -euo pipefail

cd "$HOME/git/secp256k1"

# ---- Clean (strong clean; avoids stale libtool/LTO artifacts) ----
rm -f src/precomputed_ecmult.c src/precomputed_ecmult_gen.c
rm -f precompute_ecmult precompute_ecmult_gen
rm -rf .libs src/.libs src/_libs src/asm/.libs src/asm/_libs
rm -rf src/.deps .deps autom4te.cache
rm -f  src/*.o src/*.lo *.o *.lo
rm -f  config.status config.cache config.log Makefile libtool libsecp256k1.pc
rm -f  stamp-h1

./autogen.sh

BUILD_TRIPLE="$(./autotools-aux/config.guess)"

# Use native Linux toolchain
export CC="gcc"
export AR="ar"
export RANLIB="ranlib"
export NM="nm"
export STRIP="strip"

# Keep flags conservative first
export CFLAGS="-O3 -DNDEBUG -std=c11"
export LDFLAGS=""

./configure \
  --build="$BUILD_TRIPLE" \
  --host="$BUILD_TRIPLE" \
  --enable-experimental \
  --with-ecmult-gen-kb=86 \
  --with-ecmult-window=15 \
  --with-asm=auto \
  --disable-shared \
  --enable-static \
  --disable-benchmark \
  --disable-tests \
  --disable-exhaustive-tests

make -j"$(nproc)"

test -f .libs/libsecp256k1.a
nm -A .libs/libsecp256k1.a | head
echo "OK: built .libs/libsecp256k1.a on Linux"


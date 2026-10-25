#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# build-android-linguist.sh: the on-device model server for vaikor-android (WP 9b).
#
#   bash scripts/build-android-linguist.sh            # after setup-companion-toolchain.sh --with-llama
#
# Cross-builds llama-server from the pinned llama.cpp checkout for arm64-v8a (CPU only, no
# OpenMP, no curl), strips it and places it in the APK's jniLibs as libllama_server.so. The
# app runs it from its native library directory on a Unix socket in its private data
# directory (companion/vaikor-companion-app/src/local_model.rs); the weights are not
# bundled: put a GGUF at <app data>/models/linguist.gguf (see companion/README.md).
set -euo pipefail

TOOLCHAIN=${VAIKOR_TOOLCHAIN:-$HOME/.local/share/vaikor-toolchain}
LLAMA_COMMIT=d81235049384534c167caea52b85a694f6103d14
here=$(cd "$(dirname "$0")/.." && pwd)
src=$TOOLCHAIN/llama.cpp
out=$here/companion/vaikor-companion-app/gen/android/app/src/main/jniLibs/arm64-v8a

# shellcheck source=/dev/null
. "$TOOLCHAIN/env.sh"
[[ -d $src ]] || { echo "llama.cpp missing: bash scripts/setup-companion-toolchain.sh --with-llama" >&2; exit 1; }
[[ $(git -C "$src" rev-parse HEAD) == "$LLAMA_COMMIT" ]] || { echo "llama.cpp is not at $LLAMA_COMMIT" >&2; exit 1; }
command -v cmake >/dev/null || { echo "cmake is required (e.g. pip install cmake==4.4.4)" >&2; exit 1; }

cmake -S "$src" -B "$src/build-android" \
  -DCMAKE_TOOLCHAIN_FILE="$NDK_HOME/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-28 -DCMAKE_BUILD_TYPE=Release \
  -DGGML_OPENMP=OFF -DGGML_NATIVE=OFF -DGGML_CPU_ARM_ARCH=armv8.2-a+dotprod+fp16 \
  -DLLAMA_CURL=OFF -DBUILD_SHARED_LIBS=OFF -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF >/dev/null
cmake --build "$src/build-android" --target llama-server -j "$(nproc)" >/dev/null

mkdir -p "$out"
"$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip" \
  -o "$out/libllama_server.so" "$src/build-android/bin/llama-server"
echo "$out/libllama_server.so ($(du -h "$out/libllama_server.so" | cut -f1), sha256 $(sha256sum "$out/libllama_server.so" | cut -d' ' -f1))"

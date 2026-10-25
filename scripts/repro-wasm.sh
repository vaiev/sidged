#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# repro-wasm.sh: build the browser verifier (site/vaikor-wasm) reproducibly (WP 26).
#
#   bash scripts/repro-wasm.sh [<git rev>]        # default HEAD; prints the module's SHA-256
#
# The module is bit-for-bit reproducible from a git revision when it is built from that
# revision's tracked files at one fixed path with the pinned toolchain (rust-toolchain.toml)
# and the locked dependencies. A fixed path is needed because cargo hashes the absolute path
# of path dependencies into symbol names; --remap-path-prefix removes the remaining paths
# (source, registry, sysroot) from panic locations. Two people running this on the same
# revision get the same digest; the digest is what vaikor.com publishes next to the module.
set -euo pipefail
rev=${1:-HEAD}
here=$(cd "$(dirname "$0")/.." && pwd)
src=/tmp/vaikor-repro/src
target=/tmp/vaikor-repro/target
cargo_home=${CARGO_HOME:-$HOME/.cargo}

rm -rf /tmp/vaikor-repro && mkdir -p "$src"
git -C "$here" archive --format=tar "$rev" | tar -x -C "$src"
sysroot=$(cd "$src" && rustc --print sysroot)
(
  cd "$src"
  RUSTFLAGS="--remap-path-prefix=$src=/vaikor --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$sysroot=/rust" \
  CARGO_TARGET_DIR=$target SOURCE_DATE_EPOCH=0 \
    cargo build --quiet --manifest-path site/Cargo.toml --release --target wasm32-unknown-unknown --locked
)
wasm=$target/wasm32-unknown-unknown/release/vaikor_wasm.wasm
if grep -aqE "$src|$cargo_home|$HOME" "$wasm"; then
  echo "repro-wasm: a build path is still in the module" >&2
  exit 1
fi
echo "vaikor_wasm.wasm $(git -C "$here" rev-parse --short "$rev") $(rustc -V | cut -d' ' -f2) sha256 $(sha256sum "$wasm" | cut -d' ' -f1)"

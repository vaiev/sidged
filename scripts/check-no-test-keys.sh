#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# The shipped binaries, image and build context must not carry the published
# RFC 8032 test seeds (spec/test-vectors/keys/*.json). Fail closed.
#   scripts/check-no-test-keys.sh PATH...        scan files, trees or tars
#   scripts/check-no-test-keys.sh --paths-only   (no paths) -> FAIL
#   scripts/check-no-test-keys.sh --context      scan the EFFECTIVE build
#       context (built through the real Containerfile.dockerignore); seeds may
#       appear only in Rust test sources, never under spec/test-vectors or in
#       any other file.
#   scripts/check-no-test-keys.sh                host release build + context
set -euo pipefail
cd "$(dirname "$0")/.."
scan() { python3 scripts/check-no-test-keys.py "$@"; }

context() {
  # Scratch under $RUNNER_TEMP, where rootless podman can see it; an EXIT
  # trap, as a failing build ends the script before a RETURN trap would run.
  . scripts/podman-store.sh
  out="$(sidged_scratch_dir context)"
  trap 'rm -rf "$out"' EXIT
  printf 'FROM scratch\nCOPY . /ctx\n' > "$out/Context.Containerfile"
  # Rootless podman only (no docker).
  command -v podman >/dev/null || { echo "FAIL: need podman to evaluate the build context" >&2; return 1; }
  podman build -q --ignorefile Containerfile.dockerignore -f "$out/Context.Containerfile" -o "type=local,dest=$out/fs" . >/dev/null
  [ -d "$out/fs/ctx" ] || { echo "FAIL: build context export is empty" >&2; return 1; }
  if [ -e "$out/fs/ctx/spec/test-vectors" ]; then
    echo "FAIL: build context contains spec/test-vectors" >&2; return 1
  fi
  scan --allow-rust-sources "$out/fs/ctx"
}

case "${1:-}" in
  --paths-only) shift; scan "$@" ;;
  --context) context ;;
  "")
    cargo build --manifest-path runtime/Cargo.toml --locked --release -p sidged-guard -q
    scan runtime/target/release/sidged && context ;;
  *) scan "$@" ;;
esac

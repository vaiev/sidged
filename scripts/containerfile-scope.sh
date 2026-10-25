#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# Cache trust split: write the Containerfile for one cache scope.
# Usage: scripts/containerfile-scope.sh <scope> <in> <out>
#   ""      trusted build (push to main, schedule, release, dispatch):
#           <in> unchanged, no cache mounts.
#   pr<N>   pull-request build: the build RUN gets cache mounts with literal
#           ids vaikor-cargo-reg-pr<N> and vaikor-cargo-target-pr<N>, which
#           trusted builds never mount; target/ is the cache, so the
#           in-RUN `rm -rf runtime/target` is dropped.
# Anything else, or an input without the marked lines, fails.
set -euo pipefail
[ $# = 3 ] || { echo "usage: $0 <scope> <in> <out>" >&2; exit 2; }
scope=$1 in=$2 out=$3
if [ -z "$scope" ]; then cp -- "$in" "$out"; exit 0; fi
[[ "$scope" =~ ^pr[1-9][0-9]*$ ]] || { echo "cache scope must be pr<N> or empty: '$scope'" >&2; exit 1; }
python3 - "$scope" "$in" "$out" <<'PY'
import sys
scope, src, dst = sys.argv[1:]
lines = open(src).read().split("\n")
marker = "# vaikor-cache: run"
run = "RUN read -r _ triple clang_target < /target \\"
drop = " && rm -rf runtime/target"
idx = [i for i, l in enumerate(lines) if l == marker]
if len(idx) != 1 or idx[0] + 1 >= len(lines) or lines[idx[0] + 1] != run or lines.count(drop) != 1:
    sys.exit("Containerfile has no single marked build RUN (# vaikor-cache: run)")
i = idx[0] + 1
lines[i:i + 1] = [
    f"RUN --mount=type=cache,id=vaikor-cargo-reg-{scope},sharing=locked,target=/usr/local/cargo/registry \\",
    f"    --mount=type=cache,id=vaikor-cargo-target-{scope},sharing=locked,target=/src/runtime/target \\",
    "    if [ \"$(du -sm runtime/target | cut -f1)\" -gt 8192 ]; then \\",
    "      echo \"target cache over 8 GiB, emptied\"; find runtime/target -mindepth 1 -delete; \\",
    "    fi \\",
    " && read -r _ triple clang_target < /target \\",
]
j = lines.index(drop)
# the line before ends with a continuation that now ends the RUN
assert lines[j - 1].endswith(" \\")
lines[j - 1] = lines[j - 1][:-2]
del lines[j]
open(dst, "w").write("\n".join(lines))
PY

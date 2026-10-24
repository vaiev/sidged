#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# Negative/positive fixtures for scripts/check-no-test-keys.sh (fail closed).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
check=scripts/check-no-test-keys.sh
fail=0
expect() { # want-exit description args...
  local want="$1" what="$2"; shift 2
  "$check" "$@" >"$t/out" 2>&1; local got=$?
  if [ "$want" = 0 ] && [ "$got" = 0 ]; then echo "ok   $what"
  elif [ "$want" != 0 ] && [ "$got" != 0 ]; then echo "ok   $what (refused)"
  else echo "FAIL $what: exit $got"; cat "$t/out"; fail=1; fi
}
seed() { python3 -c "import json;print(json.load(open('spec/test-vectors/keys/$1'))['keys'][$2]['secret_key_hex'])"; }
printf 'clean binary bytes\0\1\2' > "$t/clean"
mkdir -p "$t/tree/a"; cp "$t/clean" "$t/tree/a/bin"
expect 0 "clean file" "$t/clean"
expect 0 "clean directory tree" "$t/tree"
expect 1 "missing binary" "$t/absent"
expect 1 "no paths at all" --paths-only
s1="$(seed rfc8032-test-keys.json 0)"; x1="$(seed rfc8032-section7-1-extra.json 0)"; x2="$(seed rfc8032-section7-1-extra.json 1)"
printf 'pre%spost' "$s1" > "$t/hex"; expect 1 "hex seed" "$t/hex"
printf 'pre%spost' "${s1^^}" > "$t/HEX"; expect 1 "uppercase hex seed" "$t/HEX"
python3 -c "import sys;open(sys.argv[1],'wb').write(b'\x00'+bytes.fromhex(sys.argv[2])+b'\x00')" "$t/raw" "$s1"; expect 1 "raw 32-byte seed" "$t/raw"
python3 -c "import sys;open(sys.argv[1],'wb').write(bytes.fromhex(sys.argv[2]))" "$t/raw1024" "$x1"; expect 1 "TEST 1024 seed (raw)" "$t/raw1024"
printf '%s' "$x2" > "$t/abc"; expect 1 "TEST SHA(abc) seed (hex)" "$t/abc"
cp "$t/raw" "$t/tree/a/deep"; expect 1 "seed deep in a directory" "$t/tree"
tar -C "$t/tree" -cf "$t/fs.tar" .; expect 1 "seed inside an image tar" "$t/fs.tar"
exit "$fail"

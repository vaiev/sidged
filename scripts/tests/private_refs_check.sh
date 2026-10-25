#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# private_refs_check.sh: fixture tests for scripts/check-no-private-refs.sh.
# Standalone: bash scripts/tests/private_refs_check.sh
#
# Builds two throwaway git repositories: a passing one (colours, headings,
# Rust attributes, an allowlisted hit, an excluded Cargo.lock) and a failing
# one (an issue number in a comment, and one on the same line as an
# allowlisted colour). An invalid root must fail too. The issue numbers are
# assembled at run time so this file does not trip the check itself.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
check=$root/scripts/check-no-private-refs.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() { echo "private_refs_check: FAIL: $*" >&2; fail=1; }

h='#'
mkrepo() { # dir: an empty git repository with an empty allowlist
  mkdir -p "$1/scripts"
  git -C "$1" init -q
  : > "$1/scripts/private-refs-allow.txt"
}
track() { git -C "$1" add -A; }

# Passing fixture.
pass=$tmp/pass
mkrepo "$pass"
cat > "$pass/style.css" <<EOF
.a { color: ${h}0f0; background: ${h}1e88e5; }
.b { border: 1px solid ${h}333; }
EOF
cat > "$pass/lib.rs" <<EOF
#[derive(Debug)]
struct A; // the cache trust split
EOF
printf '# Title\n\n## 2. Section\n' > "$pass/README.md"
printf 'checksum = "x (%s12)"\n' "$h" > "$pass/Cargo.lock"
printf 'style.css:%s333  -- CSS colour, not an issue\n' "$h" >> "$pass/scripts/private-refs-allow.txt"
track "$pass"
if ! out=$(bash "$check" "$pass" 2>&1); then
  bad "passing fixture refused:"; echo "$out" >&2
fi

# Failing fixture: a reference in a comment, one with a letter suffix, a
# cross-repository one and one that shares its line with an allowlisted
# colour (the allowlist entry must not cover the rest of the line).
failing=$tmp/fail
mkrepo "$failing"
printf '// zeroized on drop (%s93 N2)\nfn f() {}\n' "$h" > "$failing/lib.rs"
printf '# follow-up %s93c\n' "$h" > "$failing/run.sh"
printf 'merged via vaiev/vaikor%s36.\n' "$h" > "$failing/spec.md"
printf '.tag { border: 1px solid %s333; } <!-- See %s75 -->\n' "$h" "$h" > "$failing/style.css"
printf 'style.css:%s333  -- CSS colour, not an issue\n' "$h" >> "$failing/scripts/private-refs-allow.txt"
track "$failing"
if out=$(bash "$check" "$failing" 2>&1); then
  bad "failing fixture passed"
else
  grep -q 'lib.rs:1:' <<< "$out" || bad "lib.rs:1 not reported: $out"
  grep -q 'run.sh:1:' <<< "$out" || bad "run.sh:1 not reported: $out"
  grep -q 'spec.md:1:' <<< "$out" || bad "spec.md:1 not reported: $out"
  grep -q 'style.css:1:' <<< "$out" || bad "style.css:1 not reported: $out"
fi

# An invalid root is an error, not a clean scan.
if out=$(bash "$check" "$tmp/does-not-exist" 2>&1); then
  bad "invalid root passed: $out"
fi

# Without its allowlist entry the colour is reported (the allowlist is used).
: > "$pass/scripts/private-refs-allow.txt"
bash "$check" "$pass" >/dev/null 2>&1 && bad "hit without allowlist entry passed"
printf 'style.css:%s333  -- CSS colour, not an issue\n' "$h" > "$pass/scripts/private-refs-allow.txt"

# An untracked file is not scanned.
printf '(%s7)\n' "$h" > "$pass/untracked.txt"
bash "$check" "$pass" >/dev/null 2>&1 || bad "untracked file was scanned"

if (( fail )); then exit 1; fi
echo "private_refs_check: OK"

#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# Tracked files must not cite issues or pull requests of the private
# development repository: in the public repository such a number would link to
# a missing or unrelated issue. Fails on a "#" followed by 1-3 digits (and an
# optional letter suffix) after "(", after whitespace, after "sidged" (a
# cross-repository reference) or at line start.
#   scripts/check-no-private-refs.sh [ROOT]   ROOT: a git work tree (default: this repo)
#
# Skipped: binary files, Cargo.lock, *.svg, *.png, untracked files and the
# allowlist itself. Allowlist: ROOT/scripts/private-refs-allow.txt, one entry
# per line, "path:text  -- reason". In a line of <path>, every occurrence of
# <text> is removed before the line is checked again, so a reference next to
# an allowlisted text still fails. Blank lines and lines starting with "#" are
# ignored. A git error (for example an invalid ROOT) fails the check.
set -euo pipefail

root=${1:-$(cd "$(dirname "$0")/.." && pwd)}
allow=$root/scripts/private-refs-allow.txt
pattern='(^|\(|[[:space:]]|sidged)#[0-9]{1,3}[a-z]?\b'

# git grep exits 1 when nothing matches; any other non-zero status is an error.
status=0
hits=$(git -C "$root" grep -n -I -E "$pattern" -- . \
  ':(exclude,glob)**/Cargo.lock' ':(exclude,glob)**/*.svg' ':(exclude,glob)**/*.png' \
  ':(exclude)scripts/private-refs-allow.txt') || status=$?
if (( status > 1 )); then
  echo "check-no-private-refs: FAIL: git grep failed (status $status) in $root" >&2
  exit 2
fi

left=$(awk -v allowfile="$allow" '
  BEGIN {
    n = 0
    while ((getline l < allowfile) > 0) {
      if (l ~ /^[[:space:]]*$/ || l ~ /^#/) continue
      sub(/[[:space:]]+-- .*$/, "", l)
      c = index(l, ":")
      if (c < 2) { print "check-no-private-refs: bad allowlist line: " l > "/dev/stderr"; exit 2 }
      n++; ap[n] = substr(l, 1, c - 1); at[n] = substr(l, c + 1)
    }
  }
  {
    c = index($0, ":"); path = substr($0, 1, c - 1)
    rest = substr($0, c + 1); text = substr(rest, index(rest, ":") + 1)
    allowed = 0
    for (i = 1; i <= n; i++) {
      if (ap[i] != path || at[i] == "") continue
      while ((p = index(text, at[i])) > 0) {
        text = substr(text, 1, p - 1) substr(text, p + length(at[i])); allowed = 1
      }
    }
    # The same pattern as above, with the trailing \b spelled out for awk.
    if (allowed && text !~ /(^|[(]|[[:space:]]|sidged)#[0-9][0-9]?[0-9]?[a-z]?([^[:alnum:]_]|$)/) next
    print
  }' <<< "$hits")

if [[ -n $left ]]; then
  echo "check-no-private-refs: FAIL: private issue references (remove them or allowlist a genuine non-reference in scripts/private-refs-allow.txt):" >&2
  echo "$left" >&2
  exit 1
fi
echo "check-no-private-refs: OK"

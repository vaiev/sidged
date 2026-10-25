#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# Parser and verdict fixtures for scripts/check-base-index.sh (no network): FROM
# flags must not hide a base, an unpinned registry base fails, and each failure
# fails for its own reason. Every case runs in both storage modes of
# scripts/podman-store.sh, whatever the calling step sets: shared store
# (local, pull request) and trusted throwaway store (podman runs through a
# wrapper that adds --root/--runroot).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
mkdir -p "$t/bin" "$t/rt"
# Fake podman: strips the store wrapper's global flags like the real CLI,
# logs the call, then answers `manifest inspect` from the fixture name:
# "good" a full index, "noarm" an index without arm64, "gone" an inspect
# error, anything else a single-arch manifest.
cat > "$t/bin/podman" <<'F'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_CALLS"
while [ "${1:-}" = --root ] || [ "${1:-}" = --runroot ]; do shift 2; done
[ "${1:-} ${2:-}" = "manifest inspect" ] || exit 2
case "${3##*/}" in
  good@*) echo '{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"platform":{"os":"linux","architecture":"amd64"}},{"platform":{"os":"linux","architecture":"arm64"}}]}' ;;
  noarm@*) echo '{"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","manifests":[{"platform":{"os":"linux","architecture":"amd64"}}]}' ;;
  gone@*) echo "Error: no such manifest" >&2; exit 125 ;;
  *) echo '{"mediaType":"application/vnd.oci.image.manifest.v1+json"}' ;;
esac
F
chmod +x "$t/bin/podman"
d=sha256:$(printf 'a%.0s' $(seq 64))
fail=0
run1() { # mode want reason file-content label
  local mode=$1 want=$2 reason=$3 got
  : > "$t/calls"
  printf '%b' "$4" > "$t/Containerfile"
  if [ "$mode" = trusted ]; then
    env -u VAIKOR_PODMAN_WRAPPER VAIKOR_CI_RUN=t-1 VAIKOR_CACHE_SCOPE= RUNNER_TEMP="$t/rt" \
      PATH="$t/bin:$PATH" FAKE_CALLS="$t/calls" CONTAINERFILE="$t/Containerfile" \
      scripts/check-base-index.sh >"$t/out" 2>&1; got=$?
  else
    env -u VAIKOR_PODMAN_WRAPPER -u VAIKOR_CI_RUN -u VAIKOR_CACHE_SCOPE \
      PATH="$t/bin:$PATH" FAKE_CALLS="$t/calls" CONTAINERFILE="$t/Containerfile" \
      scripts/check-base-index.sh >"$t/out" 2>&1; got=$?
  fi
  local why=""
  if [ "$want" = 0 ]; then [ "$got" = 0 ] || why="exit $got"
  else [ "$got" != 0 ] || why="exit 0"; fi
  [ -n "$why" ] || grep -qF -- "$reason" "$t/out" || why="output lacks '$reason'"
  if [ -n "$why" ] || [ "$mode" != trusted ]; then :
  elif grep -Ev -- "^--root $t/rt/vaikor-store\.[^ /]+/root --runroot $t/rt/vaikor-store\.[^ /]+/run " "$t/calls" | grep -q .; then
    why="a podman call bypassed the throwaway store"
  elif ls -d "$t/rt"/vaikor-store.* >/dev/null 2>&1; then why="throwaway store left behind"
  fi
  if [ -z "$why" ] && [ "$mode" != trusted ] && grep -Eq -- '--(root|runroot)' "$t/calls"; then
    why="shared mode used a throwaway store"
  fi
  if [ -z "$why" ]; then echo "ok   [$mode] $5"
  else echo "FAIL [$mode] $5 ($why)"; cat "$t/out"; fail=1; fi
}
run() { run1 shared "$@"; run1 trusted "$@"; }
run 0 "ok: good@$d" "FROM good@$d AS build\nFROM scratch AS musl\nFROM build AS core\n" "pinned index, scratch and stages"
run 0 "ok: docker.io/x/good:1@$d" "FROM --platform=\$BUILDPLATFORM docker.io/x/good:1@$d AS build\n" "tag and digest: the digest is inspected"
run 1 "bad@$d: not an index" "FROM good@$d AS build\nFROM --platform=linux/amd64 bad@$d\n" "flagged single-arch base is checked"
run 1 "bad@$d: not an index" "FROM --platform=\$BUILDPLATFORM bad@$d AS build\n" "flag before the only base"
run 1 "index lacks linux/arm64" "FROM noarm@$d AS build\n" "index without arm64"
run 1 "cannot inspect gone@$d" "FROM gone@$d AS build\n" "inspect error fails closed"
run 1 "not pinned by digest" "FROM good@$d AS build\nFROM docker.io/library/alpine:3.22\n" "unpinned registry base"
run 1 "no digest-pinned FROM" "FROM scratch\n" "no pinned base at all"
exit "$fail"

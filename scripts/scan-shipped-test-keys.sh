#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# Test-key scan: scan what ships for one platform, with rootless podman: the musl
# binary exported from the image build and the flattened core image
# filesystem (podman create + export), plus the effective build context.
# Same head checkout and SIDGED_GIT_SHA build arg as the image test.
#   scripts/scan-shipped-test-keys.sh <platform>
set -euo pipefail
cd "$(dirname "$0")/.."
platform="${1:?usage: scan-shipped-test-keys.sh <platform>}"
sha="${SIDGED_GIT_SHA:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
cid=""
# Per-run tag: derived from the CI run's SIDGED_MANIFEST, removed on exit.
tag="${SIDGED_MANIFEST:-localhost/sidged-core:scan}-scan-${platform//\//-}"
# Storage trust split: trusted runs use a throwaway store ($PODMAN), removed on exit.
. scripts/podman-store.sh
# The scoped Containerfile and the build output live in a scratch dir under
# $RUNNER_TEMP that podman can see (sidged_scratch_dir), removed on exit.
out="$(sidged_scratch_dir scan)"; scoped="$out/Containerfile"
trap '[ -z "$cid" ] || "$PODMAN" rm -f "$cid" >/dev/null 2>&1; "$PODMAN" rmi -f "$tag" >/dev/null 2>&1; rm -rf "$out"; sidged_store_close' EXIT
sidged_store_open
# Same cache trust split and run label as container-test.sh.
scripts/containerfile-scope.sh "${SIDGED_CACHE_SCOPE:-}" Containerfile "$scoped"
extra=()
if [ -n "${SIDGED_CI_RUN:-}" ]; then
  extra+=(--layers=false --label "sidged.ci.run=${SIDGED_CI_RUN}")
  [ -n "${SIDGED_CACHE_SCOPE:-}" ] || extra+=(--no-cache)
fi
sidged_store_pull_bases "$platform" "$scoped"
"$PODMAN" build -q --platform "$platform" --build-arg SIDGED_GIT_SHA="$sha" "${extra[@]}" -f "$scoped" --target musl -o "type=local,dest=$out/musl" . >/dev/null
"$PODMAN" build -q --platform "$platform" --build-arg SIDGED_GIT_SHA="$sha" "${extra[@]}" -f "$scoped" --target core -t "$tag" . >/dev/null
cid="$("$PODMAN" create --platform "$platform" "$tag")"
"$PODMAN" export -o "$out/core.tar" "$cid"
scripts/check-no-test-keys.sh --paths-only "$out/musl/sidged" "$out/core.tar"
scripts/check-no-test-keys.sh --context
echo "PASS: no RFC 8032 test seeds in ${platform} binary, image or build context"

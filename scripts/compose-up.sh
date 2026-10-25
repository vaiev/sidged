#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# Build the compose core image under the cache trust split,
# then start the project without letting compose build anything.
#   scripts/compose-up.sh <project>
# podman-compose cannot pass --no-cache/--layers/--label/-f per build, so
# the image is built here with podman build and tagged
# localhost/vaikor-core:$VAIKOR_TAG, which docker-compose.yml references;
# compose then runs `up -d --no-build`.
#   VAIKOR_CACHE_SCOPE  ""/unset: trusted (committed Containerfile, no cache
#                       mounts; --no-cache in CI); pr<N>: PR-scoped mounts.
#   VAIKOR_CI_RUN       <run_id>-<attempt>: --layers=false, label
#                       vaikor.ci.run=<run>, tag ci-<run>; cleanup by label.
set -euo pipefail
cd "$(dirname "$0")/.."
project="${1:?usage: compose-up.sh <project>}"
: "${ENGINE_COMPOSE:?ENGINE_COMPOSE is required}"
sha="${VAIKOR_GIT_SHA:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
if [ -n "${VAIKOR_CI_RUN:-}" ]; then export VAIKOR_TAG="ci-${VAIKOR_CI_RUN}"
else export VAIKOR_TAG="${VAIKOR_TAG:-dev}"; fi
# Storage trust split: a trusted run builds and starts in the throwaway store
# opened by the caller (compose-test.sh), which removes it after `down`.
. scripts/podman-store.sh
if vaikor_store_trusted && [ -z "${VAIKOR_PODMAN_WRAPPER:-}" ]; then
  echo "FAIL: trusted compose-up needs the caller's throwaway store (run compose-test.sh)" >&2; exit 1
fi
vaikor_store_open
read -r -a compose <<<"$ENGINE_COMPOSE"   # "podman compose" or a path; no globbing
[ "$PODMAN" = podman ] || compose+=(--podman-path "$PODMAN")
# The scoped Containerfile lives where podman can see it (vaikor_scratch_dir).
work="$(vaikor_scratch_dir compose)"; trap 'rm -rf "$work"' EXIT
scoped="$work/Containerfile"
scripts/containerfile-scope.sh "${VAIKOR_CACHE_SCOPE:-}" Containerfile "$scoped"
extra=()
if [ -n "${VAIKOR_CI_RUN:-}" ]; then
  extra+=(--layers=false --label "vaikor.ci.run=${VAIKOR_CI_RUN}")
  [ -n "${VAIKOR_CACHE_SCOPE:-}" ] || extra+=(--no-cache)
fi
arch="$(uname -m)"; case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
vaikor_store_pull_bases "linux/$arch" "$scoped"
"$PODMAN" build --target core --build-arg VAIKOR_GIT_SHA="$sha" "${extra[@]}" \
  -t "localhost/vaikor-core:${VAIKOR_TAG}" -f "$scoped" .
"${compose[@]}" -f docker-compose.yml -p "$project" up -d --no-build

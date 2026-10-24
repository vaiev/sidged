#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# Container acceptance test for the v1 packaging (V1 spec L1).
# For each platform and image target (core) it builds the
# Containerfile and asserts:
#   1. the image runs as a non-root user,
#   2. no secret-like files or environment variables are baked in,
#   3. `sidged --version` works and embeds the SIDGED_GIT_SHA build arg.
#
# Usage: scripts/container-test.sh [platform ...]
#   default platforms: linux/amd64 linux/arm64
#   Rootless podman only (no docker, no sudo).
#   Each platform is built on its own into one manifest list
#   (podman build --platform <p> --manifest, one at a time); each instance
#   is then tested.
#   Foreign platforms need qemu-user-static binfmt emulation on the host.
set -euo pipefail

cd "$(dirname "$0")/.."
command -v podman >/dev/null || { echo "FAIL: podman is required" >&2; exit 1; }
# Storage trust split: trusted runs use a throwaway store ($PODMAN), removed on exit.
. scripts/podman-store.sh
# Scoped Containerfiles go to a scratch dir podman can see (sidged_scratch_dir).
work=""
trap '[ -z "$work" ] || rm -rf "$work"; sidged_store_close' EXIT
sidged_store_open
work="$(sidged_scratch_dir build)"
PLATFORMS=("$@")
[ ${#PLATFORMS[@]} -gt 0 ] || PLATFORMS=(linux/amd64 linux/arm64)
# CI passes the PR head SHA (not the merge commit); locally fall back to HEAD.
SHA="${SIDGED_GIT_SHA:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
fail=0
err() { echo "FAIL: $*" >&2; fail=1; }

# Files that must never be inside an image (keys come from a volume).
SECRET_FILES='(\.key|\.pem|\.p12|\.pfx|\.seed|id_ed25519|id_rsa|log-key[^/]*|\.env)$'
SECRET_ENV='(KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|SEED)'

# shellcheck disable=SC2043 # one target today; the body is the per-target build
for target in core; do
  # CI passes a per-run name so parallel/ephemeral runs never share one.
  manifest="${SIDGED_MANIFEST:-localhost/sidged-${target}:test}"
  "$PODMAN" manifest rm "$manifest" >/dev/null 2>&1 || true
  platforms="$(IFS=,; echo "${PLATFORMS[*]}")"
  echo "== ${target} ${platforms} -> manifest ${manifest}"
  # One platform per build: only one build peak on disk at a time;
  # each build adds its instance to the same manifest list.
  # Cache trust split: cache scope. Empty = trusted build from the committed file (no
  # cache mounts) and, in CI, without the layer cache either; pr<N> = cache
  # mounts scoped to that pull request (scripts/containerfile-scope.sh).
  scoped="$work/Containerfile.${target}"
  scripts/containerfile-scope.sh "${SIDGED_CACHE_SCOPE:-}" Containerfile "$scoped" \
    || { err "cache scope"; continue; }
  extra=()
  if [ -n "${SIDGED_CI_RUN:-}" ]; then
    # Label everything this run builds and keep no intermediate layer
    # images, so cleanup removes exactly this run's images.
    extra+=(--layers=false --label "sidged.ci.run=${SIDGED_CI_RUN}")
    [ -n "${SIDGED_CACHE_SCOPE:-}" ] || extra+=(--no-cache)
  fi
  built=1
  for platform in "${PLATFORMS[@]}"; do
    sidged_store_pull_bases "$platform" "$scoped" || { err "pull pinned bases ${platform}"; built=0; break; }
    "$PODMAN" build --platform "$platform" --manifest "$manifest" --target "$target" \
      --build-arg SIDGED_GIT_SHA="$SHA" "${extra[@]}" -f "$scoped" . \
      || { err "build ${target} ${platform}"; built=0; break; }
  done
  rm -f "$scoped"
  [ "$built" = 1 ] || continue
  for platform in "${PLATFORMS[@]}"; do
    # The manifest instance for this platform, as a local image ID.
    digest="$("$PODMAN" manifest inspect "$manifest" | python3 -c '
import json, sys
os_, arch = sys.argv[1].split("/")
for m in json.load(sys.stdin)["manifests"]:
    p = m.get("platform") or {}
    if p.get("os") == os_ and p.get("architecture") == arch:
        print(m["digest"]); break
' "$platform")"
    [ -n "$digest" ] || { err "${manifest}: no ${platform} instance"; continue; }
    tag="${manifest}-${platform//\//-}"
    # awk reads to the end: an early exit would kill podman with SIGPIPE,
    # which pipefail turns into a failed step (exit 141).
    id="$("$PODMAN" images --digests --no-trunc --format '{{.Digest}} {{.ID}}' | awk -v d="$digest" '$1==d && id=="" {id=$2} END {print id}')"
    [ -n "$id" ] || { err "${manifest}: ${platform} image ${digest} not in local storage"; continue; }
    "$PODMAN" tag "$id" "$tag"
    echo "-- ${platform} ${digest}"

    arch="$("$PODMAN" image inspect -f '{{.Architecture}}' "$tag")"
    [ "linux/${arch}" = "$platform" ] || err "${tag}: architecture ${arch}, want ${platform}"

    user="$("$PODMAN" image inspect -f '{{.Config.User}}' "$tag")"
    case "$user" in
      ""|0|root|0:*|root:*) err "${tag}: runs as root (User='${user}')" ;;
    esac

    env="$("$PODMAN" image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$tag")"
    # Here-strings, not `echo | grep -q`: under pipefail a SIGPIPE on echo
    # would turn a match into "no match" (fail open).
    env_names="$(cut -d= -f1 <<<"$env")"
    if grep -Eiq "$SECRET_ENV" <<<"$env_names"; then
      err "${tag}: secret-like env var baked in: $(grep -Ei "$SECRET_ENV" <<<"$env_names" | tr '\n' ' ')"
    fi

    cid="$("$PODMAN" create --platform "$platform" "$tag")"
    # Scans the final flattened filesystem only. Sufficient because the runtime
    # stage copies nothing but the sidged binary; build-stage layers are not shipped.
    # Exported to a file, not piped: tar may stop reading at the end-of-archive
    # marker, and a SIGPIPE on podman would fail the step (exit 141).
    "$PODMAN" export -o "$work/rootfs.tar" "$cid"
    "$PODMAN" rm -f "$cid" >/dev/null
    files="$(tar -tf "$work/rootfs.tar")"
    rm -f "$work/rootfs.tar"
    if grep -Eiq "$SECRET_FILES" <<<"$files"; then
      err "${tag}: secret-like file baked in: $(grep -Ei "$SECRET_FILES" <<<"$files" | tr '\n' ' ')"
    fi

    out="$("$PODMAN" run --rm --platform "$platform" --network none "$tag" --version)" \
      || err "${tag}: sidged --version failed"
    echo "   ${out}"
    [[ "$out" =~ ^sidged\ [0-9]+\.[0-9]+\.[0-9]+\ \(([0-9a-f]{40}|unknown)\)$ ]] \
      || err "${tag}: unexpected --version output"
    [ "$SHA" = unknown ] || [[ "$out" == *"($SHA)" ]] \
      || err "${tag}: --version does not embed build-arg SHA ${SHA}"
  done
done

[ "$fail" = 0 ] && echo "PASS: ${PLATFORMS[*]}"
exit "$fail"

# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
#
# Storage trust split, sourced by every script that runs podman.
# PR runs and trusted runs share the runner user's podman storage, so PR
# code could tamper with stored base layers that a later trusted build
# reuses even with --no-cache. Trusted runs (SIDGED_CI_RUN set, empty
# SIDGED_CACHE_SCOPE: push to main, schedule, release, workflow_dispatch)
# therefore get a fresh, throwaway store per job under $RUNNER_TEMP:
# $PODMAN is a wrapper that adds --root/--runroot to every call, and the
# base images are pulled by their pinned digests. PR runs and local use keep
# the shared store ($PODMAN=podman).
#
#   . scripts/podman-store.sh
#   sidged_store_open            # sets PODMAN (reuses a parent's store)
#   sidged_store_pull_bases <platform> [containerfile]
#   sidged_store_close           # removes the store this process opened
#   sidged_store_remove <dir>    # removes a leftover store (always() sweep)
#   dir="$(sidged_scratch_dir <name>)"   # scratch for podman; caller removes it
# podman-compose: pass --podman-path "$PODMAN" (it runs every podman call,
# including its --version probe, through that path).

PODMAN=podman
SIDGED_STORE_OWNED=""

# Scratch directory for files podman reads or writes (a generated
# Containerfile, build output), under $RUNNER_TEMP in CI. Not /tmp: rootless
# podman (4.9 and 5.x) re-executes itself in the user and mount namespace of
# its pause process, and when that process was started from another session
# (a runner service with a private /tmp) its /tmp is not the caller's, so a
# file the caller made there is missing for podman.
sidged_scratch_dir() { # name
  [[ "$1" =~ ^[a-z]+$ ]] || { echo "FAIL: scratch name must be [a-z]+: '$1'" >&2; return 1; }
  mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sidged-$1.XXXXXX"
}

sidged_store_trusted() { [ -n "${SIDGED_CI_RUN:-}" ] && [ -z "${SIDGED_CACHE_SCOPE:-}" ]; }

sidged_store_open() {
  sidged_store_trusted || { PODMAN=podman; return 0; }
  if [ -n "${SIDGED_PODMAN_WRAPPER:-}" ] && [ -x "$SIDGED_PODMAN_WRAPPER" ]; then
    PODMAN="$SIDGED_PODMAN_WRAPPER"; return 0   # the parent owns the store
  fi
  local real store base="${RUNNER_TEMP:-${TMPDIR:-/tmp}}" major
  real="$(command -v podman)" || { echo "FAIL: podman is required" >&2; return 1; }
  store="$(mktemp -d "$base/sidged-store.XXXXXX")"
  mkdir -p "$store/root" "$store/run"
  # The runroot holds the rootless network namespace. Podman 4.9 joins it
  # with slirp4netns; podman 5 uses pasta, and the Debian/Ubuntu AppArmor
  # profile lets pasta open files only under /tmp and /run/user/<uid>
  # (under $RUNNER_TEMP: "Couldn't open network namespace ... Permission
  # denied"). So on 5.x the runroot is a fresh directory there (podman's
  # own default places), linked as $store/run; the store's paths stay the
  # same for both versions. The probe is the client flag --version: it
  # writes nothing to the store, unlike `podman version`, which may fill
  # the runroot before it is linked.
  major="$("$real" --root "$store/root" --runroot "$store/run" --version 2>/dev/null)" || major=""
  major="${major##* }"; major="${major%%.*}"
  if [[ "$major" =~ ^[0-9]+$ ]] && [ "$major" -ge 5 ]; then
    local run
    if ! run="$(mktemp -d "$(sidged_store_runbase)/sidged-run.XXXXXX")" \
       || ! rmdir "$store/run" || ! ln -s "$run" "$store/run"; then
      echo "FAIL: cannot place the podman 5 runroot" >&2
      rm -rf "$store" ${run:+"$run"}; return 1
    fi
  fi
  printf '#!/bin/sh\nexec %q --root %q --runroot %q "$@"\n' \
    "$real" "$store/root" "$store/run" > "$store/podman"
  chmod 0700 "$store/podman"
  SIDGED_STORE_OWNED="$store"
  export SIDGED_PODMAN_WRAPPER="$store/podman"
  PODMAN="$store/podman"
}

sidged_store_pull_bases() { # platform [containerfile]
  sidged_store_trusted || return 0
  local ref
  # podman cannot pull tag+digest; the digest is the pin.
  while read -r ref; do
    "$PODMAN" pull -q --platform "$1" "$ref" </dev/null >/dev/null || return 1
  done < <(sed -nE 's/^FROM +(--[^ ]+ +)*([^ ]+@sha256:[0-9a-f]{64}).*/\2/p' "${2:-Containerfile}" \
             | sed -E 's/:[^:@/]+@/@/' | sort -u)
}

# Where a podman 5 runroot is made: $XDG_RUNTIME_DIR, else /tmp.
sidged_store_runbase() {
  if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "$XDG_RUNTIME_DIR" ] && [ -w "$XDG_RUNTIME_DIR" ]; then
    printf '%s\n' "$XDG_RUNTIME_DIR"
  else
    printf '/tmp\n'
  fi
}

sidged_store_remove() { # store-dir
  local d=$1 run="$1/run" real
  [ -d "$d" ] || return 0
  real="$(command -v podman)" || real=podman
  # A linked runroot is removed only if it is one this script makes.
  if [ -L "$d/run" ]; then
    run="$(readlink "$d/run")"
    [[ "$run" =~ ^(/tmp|"${XDG_RUNTIME_DIR:-/tmp}")/sidged-run\.[A-Za-z0-9]{6}$ ]] || run=""
  fi
  # Rootless store files belong to sub-uids: remove them inside the user
  # namespace, then the directory itself.
  "$real" --root "$d/root" --runroot "$d/run" unshare rm -rf "$d/root" ${run:+"$run"} >/dev/null 2>&1 || true
  rm -rf "$d" ${run:+"$run"} 2>/dev/null || true
}

sidged_store_close() {
  [ -n "$SIDGED_STORE_OWNED" ] || return 0
  sidged_store_remove "$SIDGED_STORE_OWNED"
  unset SIDGED_PODMAN_WRAPPER
  SIDGED_STORE_OWNED=""
}

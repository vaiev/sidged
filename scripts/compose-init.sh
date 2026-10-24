#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# Operator init step: set the owner and mode of every named volume from
# the `x-sidged-volume-init` table in docker-compose.yml, before `up`. This
# runs on the host, not as a compose service, so no service needs uid 0 or
# cap_add. Rootless podman applies it with `podman unshare`; rootful engines
# need an operator with rights on the volume mountpoints.
#
# --secret <src> (cloud mode): place the provider key at
# ${SIDGED_XAI_API_KEY_FILE:-./secrets/xai_api_key} with owner = control's uid
# (the process that reads it; 65532) and mode 0400. A non-swarm compose file
# secret is a bind mount that keeps host owner and mode, so this is the one
# layout control can read and nobody else can. Rootless podman: the owner is
# set inside `podman unshare`, so the container sees 65532.
#
#   scripts/compose-init.sh [--dry-run] [--secret <src>] [-p <project>] [docker-compose.yml]
# Env: ENGINE (podman|docker, default podman). The volume prefix is compose's
# project name: -p, else COMPOSE_PROJECT_NAME, else the directory name,
# normalised like compose (lowercase, only [a-z0-9_-], leading [a-z0-9]).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
dry=0 secret="" project="${COMPOSE_PROJECT_NAME:-${COMPOSE_PROJECT:-}}"
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) dry=1; shift ;;
    --secret) secret="$2"; shift 2 ;;
    -p) project="$2"; shift 2 ;;
    *) break ;;
  esac
done
file="${1:-docker-compose.yml}"
[ -n "$project" ] || project="$(basename "$PWD")"
project="$(printf '%s' "$project" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-' | sed 's/^[^a-z0-9]*//')"
[ -n "$project" ] || { echo "compose-init: empty project name" >&2; exit 2; }
PY="${PYTHON:-python3}"
plan="$("$PY" - "$file" <<'PYEOF'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1])) or {}
for vol, e in (doc.get("x-sidged-volume-init") or {}).items():
    mode = str(e["mode"])
    if mode not in ("0700", "0500"):
        sys.exit(f"volume {vol}: mode must be 0700 or 0500")
    print(f"{vol} {int(e['uid'])}:{int(e['gid'])} {mode}")
PYEOF
)"
control_uid="$("$PY" - "$file" <<'PYEOF'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1])) or {}
print(int(str(doc["services"]["control"]["user"]).split(":")[0]))
PYEOF
)"
dest="${SIDGED_XAI_API_KEY_FILE:-./secrets/xai_api_key}"
if [ "$dry" = 1 ]; then
  echo "project ${project}"
  printf '%s\n' "$plan"
  [ -z "$secret" ] || echo "secret ${dest} ${control_uid} 0400"
  exit 0
fi
ENGINE="${ENGINE:-podman}"
as_engine() { # run a file operation in the engine's uid namespace
  # podman or the trusted-store wrapper, which must be used for
  # unshare too so it sees the same store.
  case "$ENGINE" in
    podman|*/podman) if [ "$(id -u)" != 0 ]; then "$ENGINE" unshare "$@"; else "$@"; fi ;;
    *) "$@" ;;
  esac
}
while read -r vol owner mode; do
  name="${project}_${vol}"
  "$ENGINE" volume inspect "$name" >/dev/null 2>&1 || "$ENGINE" volume create "$name" >/dev/null
  mp="$("$ENGINE" volume inspect -f '{{.Mountpoint}}' "$name")"
  as_engine chown "$owner" "$mp"
  as_engine chmod "$mode" "$mp"
  # 0010 R4: files already in the volume must belong to its service
  # uid, mode 0600 (files) / 0700 (dirs); anything else refuses.
  bad="$(as_engine find "$mp" -mindepth 1 \( -not -uid "${owner%%:*}" -o -type l -o \( -type f -not -perm 0600 -not -perm 0400 \) -o \( -type d -not -perm 0700 -not -perm 0500 \) \) -print)"
  [ -z "$bad" ] || { echo "compose-init: ${name}: entries not owned by ${owner%%:*} with mode 0600/0400 (dirs 0700/0500), or symlinks:" >&2; echo "$bad" >&2; exit 1; }
  echo "init ${name}: ${owner} ${mode}"
done <<<"$plan"
if [ -n "$secret" ]; then
  if [ ! -f "$secret" ] || [ -L "$secret" ]; then
    echo "compose-init: --secret must be a regular file" >&2; exit 1
  fi
  mkdir -p "$(dirname "$dest")"
  ( umask 077; cp -- "$secret" "$dest.tmp.$$" )
  as_engine chown "$control_uid" "$dest.tmp.$$"
  as_engine chmod 0400 "$dest.tmp.$$"
  mv -f -- "$dest.tmp.$$" "$dest"
  ENGINE="$ENGINE" "$PY" "$here/scripts/compose-check.py" --secret-file "$dest" "$file"
  echo "secret ${dest}: owner ${control_uid} mode 0400"
fi

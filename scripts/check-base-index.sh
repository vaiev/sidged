#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# Verify that every digest-pinned base image is a multi-arch INDEX (OCI image
# index or Docker manifest list) containing linux/amd64 and linux/arm64, not a
# single-arch manifest. Usage: scripts/check-base-index.sh [image@sha256:...]...
# Without arguments, checks every `FROM ...@sha256:` in Containerfile.
set -euo pipefail
cd "$(dirname "$0")/.."
refs=("$@")
# Skip FROM flags (--platform=...); every digest-pinned image is checked.
# CONTAINERFILE overrides the file (tests). A FROM with a registry image that
# is not digest-pinned is a FAIL, never skipped.
file="${CONTAINERFILE:-Containerfile}"
if [ ${#refs[@]} -eq 0 ]; then
  mapfile -t refs < <(awk 'toupper($1)=="FROM" { i=2; while ($i ~ /^--/) i++; print $i }' "$file")
  stages="$(awk 'toupper($1)=="FROM" { for (i=2;i<NF;i++) if (toupper($i)=="AS") print $(i+1) }' "$file")"
  for ref in "${refs[@]}"; do
    [[ "$ref" == *@sha256:* || "$ref" == scratch ]] && continue
    grep -qxF -- "$ref" <<<"$stages" && continue
    echo "FAIL: base image $ref is not pinned by digest" >&2; exit 1
  done
  mapfile -t refs < <(printf '%s\n' "${refs[@]}" | grep '@sha256:')
fi
[ ${#refs[@]} -gt 0 ] || { echo "FAIL: no digest-pinned FROM found" >&2; exit 1; }
# Storage trust split: in trusted runs a throwaway store, so no local manifest list a PR
# left behind can answer for a base digest.
. scripts/podman-store.sh
if command -v podman >/dev/null; then vaikor_store_open; trap vaikor_store_close EXIT; fi

raw() { # the digest is authoritative; drop the tag (podman rejects tag+digest)
  local repo="${1%@*}" digest="${1#*@}" last
  last="${repo##*/}"; [[ "$last" == *:* ]] && repo="${repo%:*}"
  set -- "$repo@$digest"
  # Rootless podman (no docker); skopeo as fallback.
  if command -v podman >/dev/null; then "$PODMAN" manifest inspect "$1"
  elif command -v skopeo >/dev/null; then skopeo inspect --raw "docker://$1"
  else echo "no podman or skopeo" >&2; return 1; fi
}

fail=0
for ref in "${refs[@]}"; do
  json="$(raw "$ref")" || { echo "FAIL: cannot inspect $ref" >&2; fail=1; continue; }
  if ! verdict="$(python3 -c '
import json, sys
m = json.loads(sys.stdin.read())
kinds = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
mt = m.get("mediaType") or ("application/vnd.oci.image.index.v1+json" if "manifests" in m else "")
if mt not in kinds:
    sys.exit("not an index (mediaType %r)" % mt)
plats = {(p.get("platform") or {}).get("os", "") + "/" + (p.get("platform") or {}).get("architecture", "") for p in m.get("manifests", [])}
missing = {"linux/amd64", "linux/arm64"} - plats
if missing:
    sys.exit("index lacks " + ", ".join(sorted(missing)))
print(mt)
' <<<"$json" 2>&1)"; then
    echo "FAIL: $ref: $verdict" >&2; fail=1
  else
    echo "ok: $ref ($verdict, amd64+arm64)"
  fi
done
exit "$fail"

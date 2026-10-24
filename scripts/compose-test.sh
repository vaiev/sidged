#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# Compose acceptance test (V1 spec L1).
#  1. Static policy check of docker-compose.yml (scripts/compose-check.py).
#  2. The checker rejects a known-bad config (guards against a vacuous pass).
#  3. The compose engine accepts the file (`compose config`), if available.
#  4. With COMPOSE_UP=1: build the image, `up`, and require each service to
#     print `sidged --version` with the build SHA (no daemon mode exists yet).
# Needs python3 with PyYAML. ENGINE_COMPOSE defaults to "podman compose"
# (rootless podman with the podman-compose provider; no docker).
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"

"$PY" scripts/compose-check.py docker-compose.yml
"$PY" scripts/compose-check.py --override docker-compose.cloud.yml docker-compose.yml
scripts/test-compose-check.sh

bad="$(mktemp)"; trap 'rm -f "$bad"' EXIT
cat > "$bad" <<'YAML'
services:
  control:
    image: localhost/sidged-core:dev
    user: "0"
    ports: ["8443:8443"]
    environment: { SIDGED_LOG_KEY: abc }
  worker:
    image: localhost/other:dev
    ports: ["9000:9000"]
YAML
if "$PY" scripts/compose-check.py "$bad" 2>/dev/null; then
  echo "FAIL: checker accepted a bad compose file" >&2; exit 1
fi
cat > "$bad" <<'YAML'
services:
  control: {image: localhost/sidged-core:dev, user: "65532", read_only: true, cap_drop: [ALL], security_opt: ["no-new-privileges:true"], networks: [edges], ports: [{target: 1, published: 1, host_ip: 127.0.0.1}], volumes: [{type: volume, source: k1, target: /keys, read_only: true}, {type: volume, source: k2, target: /data}]}
  worker: {image: localhost/sidged-core:dev, user: "65532", read_only: true, cap_drop: [ALL], security_opt: ["no-new-privileges:true"], networks: [edges], volumes: [{type: volume, source: k2, target: /keys, read_only: true}]}
networks: {edges: {internal: true}}
volumes: {k1: {name: same}, k2: {name: same}}
YAML
if "$PY" scripts/compose-check.py "$bad" 2>/dev/null; then
  echo "FAIL: checker accepted shared or re-mounted key volumes" >&2; exit 1
fi
cat > "$bad" <<'YAML'
services:
  control:
    build: {context: .}
    image: localhost/sidged-core:dev
    user: "65532"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    networks: [edges]
    environment: {SIDGED_LOCAL: "0", SIDGED_XAI_API_KEY: x}
    ports: [{target: 2222, published: 2222, host_ip: 127.0.0.1}]
    volumes: [{type: volume, source: k1, target: /keys, read_only: true}]
  worker:
    image: localhost/sidged-core:dev
    user: "65532"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    networks: [edges, egress]
    environment: {SIDGED_LOCAL: "1"}
    volumes: [{type: volume, source: k2, target: /keys, read_only: true}]
  llama:
    image: ghcr.io/ggml-org/llama.cpp:server
    user: "65531"
    networks: [edges]
networks: {edges: {internal: true}, egress: {}}
volumes: {k1: {}, k2: {}}
YAML
report="$("$PY" scripts/compose-check.py "$bad" 2>&1 || true)"
for rule in "share uid" "SIDGED_LOCAL must default" "secret-like environment" "2222" "digest-pinned" "only internal networks"; do
  grep -q -- "$rule" <<<"$report" \
    || { echo "FAIL: checker missed audit rule: ${rule}" >&2; exit 1; }
done
echo "PASS: checker rejects bad compose files"

unset COMPOSE_FILE
if [ -z "${ENGINE_COMPOSE:-}" ]; then
  if podman compose version >/dev/null 2>&1; then ENGINE_COMPOSE="podman compose"; fi
fi
if [ -z "${ENGINE_COMPOSE:-}" ]; then
  echo "SKIP: no compose engine; static checks only"; exit 0
fi
$ENGINE_COMPOSE -f docker-compose.yml config >/dev/null
echo "PASS: ${ENGINE_COMPOSE} config"

[ "${COMPOSE_UP:-0}" = 1 ] || exit 0
export SIDGED_GIT_SHA="${SIDGED_GIT_SHA:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
# Local mode needs no secret file at all; volumes get owner/mode first.
project="sidged-compose-test-$$"
# The container engine is always rootless podman; ENGINE_COMPOSE may be the
# venv's podman-compose binary itself (CI) or "podman compose".
# Storage trust split: trusted runs (CI, no PR cache scope) use one throwaway
# podman store for init, build, up, logs and down; removed after down.
. scripts/podman-store.sh
sidged_store_open
read -r -a compose_cmd <<<"$ENGINE_COMPOSE"
if [ "$PODMAN" != podman ]; then
  # Only podman-compose can be pointed at the store wrapper.
  [ "$ENGINE_COMPOSE" != "podman compose" ] \
    || { echo "FAIL: trusted compose needs podman-compose (--podman-path)" >&2; sidged_store_close; exit 1; }
  compose_cmd+=(--podman-path "$PODMAN")
fi
ENGINE="$PODMAN" COMPOSE_PROJECT="$project" scripts/compose-init.sh
cleanup() { "${compose_cmd[@]}" -f docker-compose.yml -p "$project" down -v >/dev/null 2>&1 || true; rm -f "$bad"; sidged_store_close; }
trap cleanup EXIT
# Build under the cache trust split, then up --no-build.
# Same tag as compose-up.sh, so later logs/down name the same image.
if [ -n "${SIDGED_CI_RUN:-}" ]; then export SIDGED_TAG="ci-${SIDGED_CI_RUN}"; fi
scripts/compose-up.sh "$project"
engine="$PODMAN"
ids="$("$engine" ps -aq --filter "label=com.docker.compose.project=${project}")"
[ "$(echo "$ids" | wc -w)" -ge 2 ] || { echo "FAIL: expected control and worker containers" >&2; exit 1; }
for id in $ids; do
  code="$(timeout 60 "$engine" wait "$id")"
  [ "$code" = 0 ] || { echo "FAIL: container ${id} exited ${code}" >&2; exit 1; }
done
for svc in control worker; do
  out="$("${compose_cmd[@]}" -f docker-compose.yml -p "$project" logs "$svc" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
  grep -Eq "sidged [0-9]+\.[0-9]+\.[0-9]+ \(${SIDGED_GIT_SHA}\)" <<<"$out" \
    || { echo "FAIL: ${svc} printed no version with ${SIDGED_GIT_SHA}" >&2; echo "$out" >&2; exit 1; }
  echo "   ${svc}: $(echo "$out" | grep -Eo 'sidged [0-9.]+ \([0-9a-f]+\)' | tail -1)"
done
echo "PASS: compose up"

#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# Fixture tests for scripts/compose-check.py: no llama
# exemption, cap_add and uid/gid 0 refused (compared numerically), key/state
# volume owner and mode from an init table, no file secret in the local base
# file (cloud opt-in override only), host secret file mode, separate approver
# uid and operator-provisioned approval dir (0004 R9/R9c).
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fail=0

# A minimal valid base file; each case patches one thing.
base() {
cat <<'YAML'
x-sidged-volume-init:
  k1: {uid: 65532, gid: 65532, mode: "0700"}
  s1: {uid: 65532, gid: 65532, mode: "0700"}
  k2: {uid: 65533, gid: 65533, mode: "0700"}
x-sidged-approval:
  approver_uid: 65540
  dir: /run/sidged/approval
services:
  control:
    build: {context: .}
    image: localhost/sidged-core:dev
    user: "65532:65532"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    networks: [edges, model]
    environment: {SIDGED_LOCAL: "${SIDGED_LOCAL:-1}"}
    ports: [{target: 8443, published: 8443, host_ip: 127.0.0.1}]
    volumes:
      - {type: volume, source: k1, target: /keys, read_only: true}
      - {type: volume, source: s1, target: /home/nonroot/state}
  worker:
    image: localhost/sidged-core:dev
    user: "65533:65533"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    networks: [edges]
    environment: {SIDGED_LOCAL: "${SIDGED_LOCAL:-1}"}
    volumes: [{type: volume, source: k2, target: /keys, read_only: true}]
  llama:
    image: ghcr.io/ggml-org/llama.cpp:server@sha256:e83cbdc66e692129e17aad70293366cb00e3acca94b9f197c91a8a56e92201c3
    user: "65531:65531"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    networks: [model]
networks: {edges: {internal: true}, model: {internal: true}}
volumes: {k1: {}, s1: {}, k2: {}}
YAML
}

expect() { # expect pass|fail "rule" file [extra args]
  local want="$1" rule="$2" file="$3"; shift 3
  local out rc=0
  out="$("$PY" scripts/compose-check.py "$@" "$file" 2>&1)" || rc=$?
  if [ "$want" = pass ] && [ "$rc" -ne 0 ]; then
    echo "FAIL: expected pass: $rule"; echo "$out"; fail=1
  elif [ "$want" = fail ] && { [ "$rc" -eq 0 ] || ! grep -q -- "$rule" <<<"$out"; }; then
    echo "FAIL: expected '$rule'"; echo "$out"; fail=1
  else
    echo "ok   $want: $rule"
  fi
}
case_file() { # case_file name sed-expression
  base | sed "$2" > "$tmp/$1.yml"; echo "$tmp/$1.yml"
}

base > "$tmp/ok.yml"
expect pass "valid base" "$tmp/ok.yml"

# No llama exemption: every generic rule applies to llama too.
expect fail "llama: cap_add" "$(case_file llama-cap 's|^    user: "65531:65531"|    user: "65531:65531"\n    cap_add: [NET_ADMIN]|')"
expect fail "llama: secret-like environment" "$(case_file llama-env 's|^    user: "65531:65531"|    user: "65531:65531"\n    environment: {HF_TOKEN: x}|')"
expect fail "llama: read_only" "$(case_file llama-ro '/^  llama:/,$ s|^    read_only: true|    read_only: false|')"
expect fail "llama: must not mount a key volume" "$(case_file llama-key 's|^    user: "65531:65531"|    user: "65531:65531"\n    volumes: [{type: volume, source: k1, target: /keys, read_only: true}]|')"
expect fail "control: cap_add" "$(case_file ctl-cap 's|^    user: "65532:65532"|    user: "65532:65532"\n    cap_add: [CHOWN]|')"

# uid/gid 0 in any spelling, compared numerically; names refused.
for u in '0' '00' '0:0' '65532:0' '000:65532' 'root' '' '65532:root'; do
  expect fail "worker: must run as a numeric non-root uid:gid" \
    "$(case_file "uid-${u//[:]/_}" "s|^    user: \"65533:65533\"|    user: \"$u\"|")"
done
expect fail "share uid 65532" "$(case_file uid-dup 's|^    user: "65533:65533"|    user: "065532:65533"|')"

# Key/state volume owner and mode come from the init table.
expect fail "volume k2: no x-sidged-volume-init entry" "$(case_file init-miss '/^  k2: {uid/d')"
expect fail "volume k2: init uid 65532 is not the uid of worker (65533)" "$(case_file init-uid 's|^  k2: {uid: 65533|  k2: {uid: 65532|')"
expect fail "volume k1: init mode must be 0700 or 0500" "$(case_file init-mode 's|^  k1: {uid: 65532, gid: 65532, mode: "0700"}|  k1: {uid: 65532, gid: 65532, mode: "0755"}|')"

# No file secret in the local base file; cloud is an opt-in override.
expect fail "base file must not declare secrets" "$(base | sed 's|^volumes:|secrets: {xai_api_key: {file: ./secrets/xai_api_key}}\nvolumes:|' > "$tmp/sec.yml"; echo "$tmp/sec.yml")"
expect fail "control: no secrets in the base file" "$(case_file sec-svc 's|^    networks: \[edges, model\]|    networks: [edges, model]\n    secrets: [xai_api_key]|')"
cat > "$tmp/cloud.yml" <<'YAML'
services:
  control:
    environment: {SIDGED_LOCAL: "0", SIDGED_API_KEY_FILE: /run/secrets/xai_api_key}
    networks: [edges, model, egress]
    secrets: [{source: xai_api_key, target: xai_api_key}]
networks: {egress: {}}
secrets:
  xai_api_key: {file: "${SIDGED_XAI_API_KEY_FILE:-./secrets/xai_api_key}"}
YAML
expect pass "cloud override" "$tmp/ok.yml" --override "$tmp/cloud.yml"
sed 's|SIDGED_LOCAL: "0"|SIDGED_LOCAL: "1"|' "$tmp/cloud.yml" > "$tmp/cloud-local.yml"
expect fail "override: cloud override must set SIDGED_LOCAL 0" "$tmp/ok.yml" --override "$tmp/cloud-local.yml"
sed 's|{file: .*}|{environment: XAI_KEY}|' "$tmp/cloud.yml" > "$tmp/cloud-env.yml"
expect fail "secret xai_api_key: must be file-based only" "$tmp/ok.yml" --override "$tmp/cloud-env.yml"
printf 'services:\n  worker:\n    secrets: [xai_api_key]\n' > "$tmp/cloud-worker.yml"
expect fail "override: only control may receive secrets" "$tmp/ok.yml" --override "$tmp/cloud-worker.yml"

# Cloud egress: control gets the egress network only in the override.
expect fail "control: the egress network belongs in the cloud override" "$(case_file egress-base 's|^    networks: \[edges, model\]|    networks: [edges, model, egress]|; s|^networks: {edges: {internal: true}, model: {internal: true}}|networks: {edges: {internal: true}, model: {internal: true}, egress: {}}|')"
sed 's|    networks: \[edges, model, egress\]|    networks: [edges, model]|' "$tmp/cloud.yml" > "$tmp/cloud-noegress.yml"
expect fail "override: control needs the egress network in cloud mode" "$tmp/ok.yml" --override "$tmp/cloud-noegress.yml"
sed 's|SIDGED_API_KEY_FILE: /run/secrets/xai_api_key|SIDGED_API_KEY_FILE: /keys/x|' "$tmp/cloud.yml" > "$tmp/cloud-keyfile.yml"
expect fail "override: SIDGED_API_KEY_FILE must name a declared secret under /run/secrets/" "$tmp/ok.yml" --override "$tmp/cloud-keyfile.yml"
sed 's|SIDGED_API_KEY_FILE: /run/secrets/xai_api_key|XAI_API_KEY: abc|' "$tmp/cloud.yml" > "$tmp/cloud-envkey.yml"
expect fail "override: secret-like environment variable XAI_API_KEY" "$tmp/ok.yml" --override "$tmp/cloud-envkey.yml"

# llama only on its own internal network with control.
expect fail "llama: must join only the model network" "$(case_file llama-edges '/^  llama:/,$ s|^    networks: \[model\]|    networks: [edges, model]|')"
expect fail "worker: must not join the model network" "$(case_file worker-model 's|^    networks: \[edges\]$|    networks: [edges, model]|')"
expect fail "the model network must exist and be internal" "$(case_file model-ext 's|model: {internal: true}}|model: {}}|')"
expect fail "llama: must not publish ports" "$(case_file llama-port '/^  llama:/,$ s|^    networks: \[model\]|    networks: [model]\n    ports: ["127.0.0.1:8080:8080"]|')"

# Host secret file: one layout. Owner = the euid of the process that
# reads it (control's uid, 65532 here), not the operator; 0400/0600; no symlink.
export ENGINE=docker  # host uid namespace for the fixtures (no podman unshare)
umask 077; printf 'k' > "$tmp/key"; chmod 0400 "$tmp/key"
expect fail "secret file must be owned by control uid 65532" "$tmp/ok.yml" --secret-file "$tmp/key"
me="$(id -u)"
case_file me 's|"65532:65532"|"'"$me:$me"'"|; s|^  k1: {uid: 65532, gid: 65532|  k1: {uid: '"$me"', gid: '"$me"'|; s|^  s1: {uid: 65532, gid: 65532|  s1: {uid: '"$me"', gid: '"$me"'|' >/dev/null
expect pass "secret file 0400" "$tmp/me.yml" --secret-file "$tmp/key"
chmod 0600 "$tmp/key"; expect pass "secret file 0600" "$tmp/me.yml" --secret-file "$tmp/key"
chmod 0640 "$tmp/key"; expect fail "secret file mode must be 0400 or 0600" "$tmp/me.yml" --secret-file "$tmp/key"
chmod 0400 "$tmp/key"; ln -s "$tmp/key" "$tmp/key-link"
expect fail "secret file must be a regular file, not a symlink" "$tmp/me.yml" --secret-file "$tmp/key-link"
expect fail "secret file must be a regular file, not a symlink" "$tmp/me.yml" --secret-file "$tmp/absent"

# Approver model (0004 R9/R9c): separate approver uid, operator-provisioned dir.
expect fail "approver uid must differ from every service uid" "$(case_file appr-same 's|^  approver_uid: 65540|  approver_uid: 65533|')"
expect fail "approver uid must be a non-zero numeric uid" "$(case_file appr-zero 's|^  approver_uid: 65540|  approver_uid: 0|')"
expect fail "x-sidged-approval is required" "$(case_file appr-miss '/^x-sidged-approval:/,/^  dir:/d')"
expect fail "control: the approval dir is operator-provisioned" "$(case_file appr-mount 's|^      - {type: volume, source: s1, target: /home/nonroot/state}|      - {type: volume, source: s1, target: /home/nonroot/state}\n      - {type: tmpfs, target: /run/sidged/approval}|')"

# The init script applies exactly the table (dry run).
plan="$(scripts/compose-init.sh --dry-run "$tmp/ok.yml")"
for line in "k1 65532:65532 0700" "s1 65532:65532 0700" "k2 65533:65533 0700"; do
  grep -qx -- "$line" <<<"$plan" || { echo "FAIL: init plan lacks '$line'"; echo "$plan"; fail=1; }
done
echo "ok   init dry run"

# The init step places the secret file: owner = control uid, mode 0400.
plan="$(scripts/compose-init.sh --dry-run --secret "$tmp/key" "$tmp/ok.yml")"
grep -qx -- "secret ./secrets/xai_api_key 65532 0400" <<<"$plan" \
  || { echo "FAIL: init plan lacks the secret placement"; echo "$plan"; fail=1; }
echo "ok   init places the secret (dry run)"

# Volume names use compose's project-name normalisation.
plan="$(COMPOSE_PROJECT_NAME="My Proj.X" scripts/compose-init.sh --dry-run "$tmp/ok.yml")"
grep -qx -- "project myprojx" <<<"$plan" || { echo "FAIL: project name not normalised"; echo "$plan"; fail=1; }
repo="$PWD"; plan="$(mkdir -p "$tmp/Dir.Name" && cp "$tmp/ok.yml" "$tmp/Dir.Name/docker-compose.yml" && cd "$tmp/Dir.Name" && env -u COMPOSE_PROJECT_NAME -u COMPOSE_PROJECT "$repo/scripts/compose-init.sh" --dry-run docker-compose.yml)"
grep -qx -- "project dirname" <<<"$plan" || { echo "FAIL: directory project name not normalised"; echo "$plan"; fail=1; }
echo "ok   init project name"

[ "$fail" = 0 ] && echo "PASS: compose-check fixtures" || { echo "FAIL: compose-check fixtures" >&2; exit 1; }

#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# serve-local-linguist.sh: run Model -1 as the node's local model endpoint (0004 R9d, 0017).
#
#   bash scripts/serve-local-linguist.sh <model.gguf> [--workspace <dir>]
#
# Serves the GGUF with llama-server on a private AF_UNIX socket (no TCP port) and, with
# --workspace, sets model.endpoint (unix:<socket>, uid) in that node's config.json, which
# the companion's linguist.run reads, and model.output from the GGUF's vaikor.linguist.output
# key (0017 L3b; absent means full). A GGUF that declares any other form is not served. The
# model's replies stay proposals: the Core checks them whatever form it asked for.
# Desktop node workspace: ~/.local/share/com.vaikor.companion/workspace
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)

toolchain=${VAIKOR_TOOLCHAIN:-$HOME/.local/share/vaikor-toolchain}
bin=$toolchain/llama.cpp/build/bin
model=${1:-}
workspace=
shift || true
while (( $# )); do
  case $1 in
    --workspace) workspace=${2:?--workspace needs a directory}; shift 2 ;;
    *) echo "usage: $0 <model.gguf> [--workspace <dir>]" >&2; exit 2 ;;
  esac
done
[[ -f $model ]] || { echo "usage: $0 <model.gguf> [--workspace <dir>]" >&2; exit 2; }
[[ -x $bin/llama-server ]] || { echo "llama-server missing: bash scripts/setup-companion-toolchain.sh --with-llama" >&2; exit 1; }

dir=${XDG_RUNTIME_DIR:-$HOME/.cache}/vaikor
mkdir -p "$dir" && chmod 700 "$dir"
socket=$dir/linguist.sock
rm -f "$socket"
echo "model $(sha256sum "$model" | cut -d' ' -f1)  $model"
output=$(python3 -I "$root/local-training/gguf_output_form.py" read "$model")
echo "output form $output"

if [[ -n $workspace ]]; then
  [[ -f $workspace/manifest.json ]] || { echo "$workspace is not a Vaikor node (no manifest.json)" >&2; exit 1; }
  python3 -I - "$workspace/config.json" "$socket" "$(id -u)" "$output" <<'PY'
import json, pathlib, sys
path, socket, uid, output = pathlib.Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4]
config = json.loads(path.read_text()) if path.exists() else {}
config["model"] = {"endpoint": f"unix:{socket}", "uid": uid}
if output == "compact":
    config["model"]["output"] = "compact"
path.write_text(json.dumps(config, indent=2) + "\n")
path.chmod(0o600)
print(f"{path}: model.endpoint unix:{socket} uid {uid} output {output}")
PY
fi

exec env LD_LIBRARY_PATH="$bin" "$bin/llama-server" -m "$model" --host "$socket" \
  -c 4096 -t "$(( $(nproc) / 2 ))" --jinja --no-webui

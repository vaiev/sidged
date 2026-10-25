#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# run-local-model0.sh: start the local Edge LLM ("Model 0" / Thinking Planner)
# over an AF_UNIX domain socket so `vaikor-gateway` connects with SO_PEERCRED
# verification (0004 R9, 0005 R8) and zero open TCP ports.
#
# Usage: scripts/run-local-model0.sh --model <path/to/model.gguf> [--socket /run/vaikor/model0.sock] [--lora <adapter.gguf>]
set -euo pipefail

model=""
socket="/run/vaikor/model0.sock"
lora=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --model) model="${2:?missing model path}"; shift 2 ;;
    --socket) socket="${2:?missing socket path}"; shift 2 ;;
    --lora) lora="${2:?missing lora path}"; shift 2 ;;
    *) echo "usage: $0 --model <model.gguf> [--socket <unix-path>] [--lora <adapter.gguf>]" >&2; exit 2 ;;
  esac
done

[[ -n "$model" && -f "$model" ]] || { echo "run-local-model0: model file not found: $model" >&2; exit 1; }
command -v llama-server >/dev/null || { echo "run-local-model0: llama-server not found in PATH" >&2; exit 1; }

umask 0077
rm -f "$socket"
args=(
  --model "$model"
  --host "$socket"
  --ctx-size 2048
  --temp 0.0
)
if [[ -n "$lora" ]]; then
  [[ -f "$lora" ]] || { echo "run-local-model0: lora file not found: $lora" >&2; exit 1; }
  args+=(--lora "$lora")
fi

exec llama-server "${args[@]}"

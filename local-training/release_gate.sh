#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
# release_gate.sh: export a trained linguist run to the shipped GGUFs and run the release gate
# (ROADMAP 13e) on each, served by llama-server through the runtime request and judged by the Core.
#
#   local-training/release_gate.sh <run-dir> <blind.jsonl> [--manifest <manifest.json>]
#
# <run-dir> holds `merged/` (train_companion_linguist.py output). Writes in <run-dir>:
# sidged-linguist-{f16,q8_0,q4_k_m}.gguf, gate-<quant>.json and gate-<quant>.txt.
# Each GGUF declares its output form in `sidged.linguist.output` (0017 L3b): compact when the run
# manifest (--manifest, else <run-dir>/manifest.json) has target_format compact, else full. The gate
# refuses to run when the form it serves (compact for a compact blind split) differs from the key.
# Needs the companion toolchain (llama.cpp with llama-server and llama-quantize).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
run=${1:?usage: release_gate.sh <run-dir> <blind.jsonl> [--manifest <file>]}
blind=${2:?usage: release_gate.sh <run-dir> <blind.jsonl> [--manifest <file>]}
shift 2
manifest=()
[[ ${1:-} == --manifest ]] && manifest=(--manifest "${2:?--manifest needs a file}")
llama=${SIDGED_LLAMA:-$HOME/.local/share/sidged-toolchain/llama.cpp}
python=${PYTHON:-python3}
[[ -d $run/merged ]] || { echo "release_gate: $run/merged missing" >&2; exit 2; }
[[ -f $blind ]] || { echo "release_gate: $blind missing" >&2; exit 2; }

run_manifest=${manifest[1]:-$run/manifest.json}
stamp=(--form full)
[[ -f $run_manifest ]] && stamp=(--manifest "$run_manifest")

f16=$run/sidged-linguist-f16.gguf
if [[ ! -f $f16 ]]; then
  "$python" "$llama/convert_hf_to_gguf.py" "$run/merged" --outtype f16 --outfile "$f16"
  "$python" -I "$here/gguf_output_form.py" stamp "${stamp[@]}" "$f16"
fi
[[ -f $run/sidged-linguist-q8_0.gguf ]] || "$llama/build/bin/llama-quantize" "$f16" "$run/sidged-linguist-q8_0.gguf" q8_0
[[ -f $run/sidged-linguist-q4_k_m.gguf ]] || "$llama/build/bin/llama-quantize" "$f16" "$run/sidged-linguist-q4_k_m.gguf" Q4_K_M
# The quantised files inherit the key; stamping again also covers files exported before it existed.
"$python" -I "$here/gguf_output_form.py" stamp "${stamp[@]}" "$f16" \
  "$run/sidged-linguist-q8_0.gguf" "$run/sidged-linguist-q4_k_m.gguf"
sync

# A blind split of compact targets (0017 L3a) is served with the compact request and its decoding grammar.
form=()
served=full
head -n1 "$blind" | "$python" -I -c 'import json,sys; r=json.loads(sys.stdin.read()); sys.exit(json.loads(r["messages"][2]["content"])["v"] != "0.2")' \
  && form=(--compact) && served=compact
"$python" -I "$here/gguf_output_form.py" check --form "$served" \
  "$run/sidged-linguist-q8_0.gguf" "$run/sidged-linguist-q4_k_m.gguf" \
  || { echo "release_gate: the blind split is $served, the GGUFs declare otherwise" >&2; exit 1; }

cargo build -q --locked --release --manifest-path "$root/runtime/Cargo.toml" -p sidged-guard --bin sidged
export SIDGED_BIN=$root/runtime/target/release/sidged
socket=${XDG_RUNTIME_DIR:-$HOME/.cache}/sidged/linguist.sock

for quant in q8_0 q4_k_m; do
  gguf=$run/sidged-linguist-$quant.gguf
  bash "$root/scripts/serve-local-linguist.sh" "$gguf" >"$run/server-$quant.log" 2>&1 &
  server=$!
  trap 'kill $server 2>/dev/null || true' EXIT
  for _ in $(seq 1 120); do grep -q "listening on" "$run/server-$quant.log" && break; sleep 1; done
  grep -q "listening on" "$run/server-$quant.log" || { echo "release_gate: llama-server did not start" >&2; exit 1; }
  "$python" -I "$here/eval_linguist.py" --data "$blind" "${manifest[@]}" "${form[@]}" --gguf "$gguf" \
    --socket "$socket" --out "$run/gate-$quant.json" | tee "$run/gate-$quant.txt"
  pkill -P "$server" 2>/dev/null || true
  kill "$server" 2>/dev/null || true
  wait "$server" 2>/dev/null || true
done
echo "release_gate: reports in $run/gate-q8_0.txt and $run/gate-q4_k_m.txt"

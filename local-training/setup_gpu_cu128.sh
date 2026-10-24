#!/usr/bin/env bash
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
#
# setup_gpu_cu128.sh: Python environment for local training on the user's PC
# (turnkey WP f). Target: NVIDIA RTX 5060 Ti 16 GB (Blackwell, sm_120),
# 64 GB RAM, Linux or WSL2. Blackwell needs CUDA 12.8 builds: stable PyTorch
# cu128 wheels from the PyTorch index (release builds only, no pre-releases,
# no installs from source repositories).
#
# It installs packages only; it does not train and downloads no model.
# Generate the full hashed requirements.lock before setup (see README).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
venv=$here/.venv-sidged-train
python=${PYTHON:-python3}

die() { echo "setup_gpu_cu128: $*" >&2; exit 1; }

command -v nvidia-smi >/dev/null || die "nvidia-smi not found (install the NVIDIA driver; on WSL2 the Windows driver with WSL support)"
nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader
"$python" -c 'import sys; sys.exit(0 if (3, 10) <= sys.version_info[:2] <= (3, 12) else 1)' \
  || die "Python 3.10-3.12 required (set PYTHON=...)"

"$python" -m venv "$venv"
# shellcheck disable=SC1091
. "$venv/bin/activate"
# Install every package from the generated hashed lock, including CUDA wheels.
python -m pip install --require-hashes -r "$here/requirements.lock" \
  --extra-index-url https://download.pytorch.org/whl/cu128

python - <<'EOF'
import torch
print("torch", torch.__version__, "cuda", torch.version.cuda)
if not torch.cuda.is_available():
    raise SystemExit("CUDA is not available in this environment")
cap = torch.cuda.get_device_capability(0)
print("device", torch.cuda.get_device_name(0), "capability", cap)
if cap < (12, 0):
    print("note: not a Blackwell (sm_120) GPU; cu128 wheels still work on older GPUs")
EOF
echo "environment ready: $venv (no training was run)"

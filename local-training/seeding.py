# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Seed every random generator a trainer uses, and say what was seeded. Stdlib only.

Trainers call seed_everything() before they create the model and the LoRA adapter, so the
adapter initialisation and the data order are reproducible, and record its result plus
library_versions() in the run manifest.
"""
import importlib
import importlib.metadata
import platform
import random

LIBRARIES = ("torch", "transformers", "peft", "trl", "datasets", "accelerate", "numpy", "unsloth")


def _module(name):
    try:
        return importlib.import_module(name)
    except ImportError:
        return None


def seed_everything(seed, require=("numpy", "torch")):
    """Seed Python random, NumPy and Torch (CPU and every CUDA device); refuse if a required one is missing."""
    random.seed(seed)
    seeded = {"python_random": seed}
    numpy = _module("numpy")
    if numpy is not None:
        numpy.random.seed(seed)
        seeded["numpy"] = seed
    torch = _module("torch")
    if torch is not None:
        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
        seeded["torch"] = seed
        seeded["torch_cuda"] = seed
    missing = [name for name in require if name not in seeded]
    if missing:
        raise SystemExit(f"cannot seed {', '.join(missing)}: not installed")
    return seeded


def library_versions(names=LIBRARIES):
    """Installed versions (None when absent) and the Python version, without importing the libraries."""
    versions = {"python": platform.python_version()}
    for name in names:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return versions

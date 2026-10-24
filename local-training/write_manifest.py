# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Training provenance manifest (turnkey WP f). Stdlib only.

Records what a reviewer needs to identify the trained weights (0011 R8:
weights identified by hash; 0009 R1: the model stays a proposer): base model
id + commit revision + licence, dataset and script SHA-256, hyperparameters,
the registry the data was limited to, and the GGUF digest. Deterministic: no
timestamps, sorted keys, file names without directories. Digests use the
module-manifest form {"alg": "sha-256", "value": <unpadded base64url>}.

A held-out blind split (the release gate's data, make_dataset_linguist.py)
is recorded by digest too (--blind; split_digests() for the linguist run), so
a gate run can prove it scored exactly that file.

This is not a signed module manifest; packaging the weights as a `model`
module (0011, 0014) is a separate step.

Usage: python3 -I write_manifest.py --base-model Qwen/Qwen3-0.6B --revision <40-hex>
         --dataset data.jsonl --script make_dataset.py --script experimental/train_edge_llm.py
         [--blind blind.jsonl] [--gguf model.gguf] --out manifest.json
"""
import argparse
import base64
import hashlib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import validate_dataset  # noqa: E402

LICENCES = {
    "Qwen/Qwen3-0.6B": "Apache-2.0",
    "Qwen/Qwen3.5-0.8B": "Apache-2.0",
    "google/functiongemma-270m-it": "Gemma Terms of Use",
    "google/gemma-4-E2B-it": "Apache-2.0",
    "google/gemma-4-E4B-it": "Apache-2.0",
}


def digest(path):
    h = hashlib.sha256()
    with pathlib.Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return {"alg": "sha-256", "value": base64.urlsafe_b64encode(h.digest()).decode().rstrip("=")}


def split_digests(paths):
    """{split: {"path": file name, "digest": SHA-256}} for generated data splits."""
    return {split: {"path": pathlib.Path(path).name, "digest": digest(path)} for split, path in paths.items()}


def build(base_model, revision, dataset, scripts, hyperparameters, gguf=None, blind=None):
    if base_model not in LICENCES:
        raise ValueError(f"unknown base model {base_model!r}; known: {sorted(LICENCES)}")
    if not re.fullmatch(r"[0-9a-f]{40}", revision or ""):
        raise ValueError("revision must be the 40-hex commit of the base model, not a branch or tag")
    return {
        "v": "0.1",
        "kind": "model-training-provenance",
        "base_model": {"id": base_model, "revision": revision, "licence": LICENCES[base_model]},
        "dataset": {"path": pathlib.Path(dataset).name, "digest": digest(dataset)},
        "scripts": [{"path": pathlib.Path(s).name, "digest": digest(s)} for s in scripts],
        "hyperparameters": dict(hyperparameters),
        "blind": None if blind is None else {"path": pathlib.Path(blind).name, "digest": digest(blind)},
        "registry": {
            "components": sorted(validate_dataset.COMPONENTS),
            "routes": sorted(validate_dataset.ROUTES),
        },
        "model": {
            "format": "gguf",
            "weights": None if gguf is None else [
                {"path": pathlib.Path(gguf).name, "digest": digest(gguf)}
            ],
        },
    }


def dumps(manifest):
    return json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-model", required=True, choices=sorted(LICENCES))
    parser.add_argument("--revision", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--script", action="append", required=True)
    parser.add_argument("--gguf")
    parser.add_argument("--blind", help="held-out blind split the release gate scores")
    parser.add_argument("--hyperparameters",
                        help="JSON file; default: experimental/train_edge_llm.HYPERPARAMETERS")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    if args.hyperparameters:
        hyper = json.loads(pathlib.Path(args.hyperparameters).read_text())
    else:
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "experimental"))
        import train_edge_llm
        hyper = train_edge_llm.HYPERPARAMETERS
    manifest = build(args.base_model, args.revision, args.dataset, args.script, hyper, args.gguf, args.blind)
    pathlib.Path(args.out).write_text(dumps(manifest))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

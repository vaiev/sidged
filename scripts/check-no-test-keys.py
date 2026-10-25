#!/usr/bin/env python3
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed scan for the published RFC 8032 test seeds.

Every seed from spec/test-vectors/keys/*.json is searched as raw 32 bytes and
as hex (case-insensitive) in each given file, directory tree (recursively) or
tar archive (each member). A missing or unreadable path is a FAIL. The seed
list must match the public keys the runtime refuses (vaikor-guard lib.rs).
"""
import json, pathlib, re, sys, tarfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
KEYS = ROOT / "spec/test-vectors/keys"
RUNTIME = ROOT / "runtime/vaikor-guard/src/lib.rs"


def load_seeds():
    seeds, publics = [], set()
    for path in sorted(KEYS.glob("*.json")):
        for key in json.loads(path.read_text())["keys"]:
            if "secret_key_hex" in key:
                seeds.append((key["name"], bytes.fromhex(key["secret_key_hex"])))
                publics.add(key["public_key_hex"].lower())
    if len(seeds) < 5:
        sys.exit(f"FAIL: expected the 5 RFC 8032 seeds, found {len(seeds)}")
    text = RUNTIME.read_text()
    block = text[text.index("pub const RFC8032_TEST_PUBLIC_KEYS"):]
    block = block[: block.index("];")]
    runtime = set(re.findall(r'"([0-9a-f]{64})"', block))
    if runtime != publics:
        sys.exit(f"FAIL: seed list and runtime refusal list differ: {sorted(runtime ^ publics)}")
    return seeds


def hits(data, seeds):
    lower = data.lower()
    found = []
    for name, seed in seeds:
        if seed in data:
            found.append(f"{name} (raw bytes)")
        if seed.hex().encode() in lower:
            found.append(f"{name} (hex)")
    return found


def blobs(path):
    """Yield (label, bytes). Raise on anything that cannot be read."""
    if path.is_symlink():
        return
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file() and not child.is_symlink():
                yield str(child), child.read_bytes()
        return
    if not path.is_file():
        raise FileNotFoundError(f"{path} is missing or not a regular file")
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as archive:
            for member in archive:
                if member.isfile():
                    yield f"{path}:{member.name}", archive.extractfile(member).read()
        return
    yield str(path), path.read_bytes()


def main(argv):
    allow_rs = False
    if argv and argv[0] == "--allow-rust-sources":
        allow_rs, argv = True, argv[1:]
    if not argv:
        print("FAIL: nothing to scan", file=sys.stderr)
        return 1
    seeds = load_seeds()
    fail = False
    scanned = 0
    for arg in argv:
        try:
            for label, data in blobs(pathlib.Path(arg)):
                scanned += 1
                found = hits(data, seeds)
                if found and allow_rs and label.endswith(".rs"):
                    print(f"note: {label}: test seed in Rust source (test code, compiled out; binary scan is the guarantee)")
                elif found:
                    print(f"FAIL: {label}: {', '.join(found)}", file=sys.stderr)
                    fail = True
        except (OSError, tarfile.TarError) as err:
            print(f"FAIL: cannot scan {arg}: {err}", file=sys.stderr)
            fail = True
    if scanned == 0:
        print("FAIL: no files scanned", file=sys.stderr)
        fail = True
    if not fail:
        print(f"PASS: {scanned} file(s), no RFC 8032 test seeds")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

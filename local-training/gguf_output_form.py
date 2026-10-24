# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""The output form a linguist GGUF declares (0017 L3b, ROADMAP 13e). Stdlib only.

A linguist GGUF carries the string metadata key `sidged.linguist.output`, `compact` or `full`
(absent means full), inside the weights, so the SHA-256 that pins them (0011 R8) covers it.
release_gate.sh stamps each GGUF it exports from the run manifest's `target_format` and checks
the served form against it; scripts/serve-local-linguist.sh --workspace sets `model.output` from it.

Stamping rewrites the header (pairs and tensor infos) with the key added or replaced, pads to the
file's alignment and copies the tensor data unchanged; tensor offsets are relative to the data
section, so they stay valid. The file is replaced atomically. The Rust reader the app uses is
runtime/sidged-cli/src/gguf.rs; both refuse the same malformed headers.

Usage: python3 -I gguf_output_form.py read <model.gguf>                  # prints compact or full
       python3 -I gguf_output_form.py stamp (--form F | --manifest M) <model.gguf>...
       python3 -I gguf_output_form.py check --form F <model.gguf>...     # exit 1 on a mismatch
"""
import argparse
import json
import os
import pathlib
import shutil
import struct
import sys
import tempfile

KEY = "sidged.linguist.output"
FORMS = ("compact", "full")

# The limits of the Rust reader.
MAX_HEADER = 64 << 20
MAX_TENSORS = 1 << 20
MAX_PAIRS = 1 << 16
MAX_KEY = 65_535
MAX_STRING = 16 << 20
MAX_ARRAY_ELEMENTS = 1 << 20
MAX_DIMS = 8
# Real files use 32; a larger value pads the rewritten header by that much.
MAX_ALIGNMENT = 1 << 16

STRING, ARRAY, UINT32 = 8, 9, 4
SCALAR_SIZES = {0: 1, 1: 1, 7: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 10: 8, 11: 8, 12: 8}
DEFAULT_ALIGNMENT = 32


class GGUFError(Exception):
    """A malformed, unsupported or implausible GGUF header."""


class Header:
    """The parsed header: pairs as {key: (type, raw value bytes)} in file order."""

    def __init__(self, version, pairs, tensor_infos, alignment, data_offset):
        self.version = version
        self.pairs = pairs
        self.tensor_infos = tensor_infos
        self.alignment = alignment
        self.data_offset = data_offset


class _Reader:
    def __init__(self, stream):
        self.stream = stream
        self.read = 0

    def take(self, n):
        self.read += n
        if self.read > MAX_HEADER:
            raise GGUFError(f"header larger than {MAX_HEADER} bytes")
        data = self.stream.read(n)
        if len(data) != n:
            raise GGUFError("truncated GGUF header")
        return data

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.take(8))[0]

    def string(self, limit=MAX_STRING, what="string length"):
        n = self.u64()
        if n > limit:
            raise GGUFError(f"implausible {what} {n}")
        raw = self.take(n)
        return struct.pack("<Q", n) + raw, raw

    def value(self, kind):
        """The raw bytes of a value of `kind`."""
        if kind in SCALAR_SIZES:
            return self.take(SCALAR_SIZES[kind])
        if kind == STRING:
            return self.string()[0]
        if kind != ARRAY:
            raise GGUFError(f"unknown value type {kind}")
        elem, count = struct.unpack("<IQ", self.take(12))
        if count > MAX_ARRAY_ELEMENTS:
            raise GGUFError(f"implausible array length {count}")
        head = struct.pack("<IQ", elem, count)
        if elem in SCALAR_SIZES:
            return head + self.take(count * SCALAR_SIZES[elem])
        if elem == STRING:
            return head + b"".join(self.string()[0] for _ in range(count))
        if elem == ARRAY:
            raise GGUFError("nested arrays are not a supported value type")
        raise GGUFError(f"unknown value type {elem}")


def parse(path):
    """The header of the GGUF at `path`; tensor data is not read."""
    with open(path, "rb") as stream:
        reader = _Reader(stream)
        if reader.take(4) != b"GGUF":
            raise GGUFError(f"{path}: not a GGUF file (bad magic)")
        version = reader.u32()
        if version not in (2, 3):
            raise GGUFError(f"{path}: unsupported GGUF version {version}")
        tensors, count = reader.u64(), reader.u64()
        if tensors > MAX_TENSORS:
            raise GGUFError(f"{path}: implausible tensor count {tensors}")
        if count > MAX_PAIRS:
            raise GGUFError(f"{path}: implausible key-value count {count}")
        pairs = {}
        for _ in range(count):
            _, raw_key = reader.string(MAX_KEY, "key length")
            try:
                key = raw_key.decode("utf-8")
            except UnicodeDecodeError:
                raise GGUFError(f"{path}: a GGUF key is not UTF-8") from None
            kind = reader.u32()
            if key in pairs:
                raise GGUFError(f"{path}: key {key} appears twice")
            pairs[key] = (kind, reader.value(kind))
        infos = []
        for _ in range(tensors):
            name = reader.string(MAX_KEY, "tensor name length")[0]
            dims = reader.u32()
            if dims > MAX_DIMS:
                raise GGUFError(f"{path}: implausible tensor dimension count {dims}")
            infos.append(name + struct.pack("<I", dims) + reader.take(8 * dims + 12))
        alignment = DEFAULT_ALIGNMENT
        if "general.alignment" in pairs:
            kind, raw = pairs["general.alignment"]
            alignment = struct.unpack("<I", raw)[0] if kind == UINT32 else 0
            if alignment == 0 or alignment & (alignment - 1) or alignment > MAX_ALIGNMENT:
                raise GGUFError(f"{path}: general.alignment must be a power of two uint32 up to {MAX_ALIGNMENT}")
        data_offset = reader.read + (-reader.read % alignment)
        if tensors and os.fstat(stream.fileno()).st_size < data_offset:
            raise GGUFError(f"{path}: truncated before the tensor data")
    return Header(version, pairs, infos, alignment, data_offset)


def read_output(path):
    """`compact` or `full` (also when the key is absent); anything else is refused."""
    pairs = parse(path).pairs
    if KEY not in pairs:
        return "full"
    kind, raw = pairs[KEY]
    if kind != STRING:
        raise GGUFError(f"{path}: key {KEY} is not a string (type {kind})")
    value = raw[8:].decode("utf-8", errors="replace")
    if value not in FORMS:
        raise GGUFError(f'{path}: {KEY} must be "compact" or "full", got {value!r}')
    return value


def stamp(path, form):
    """Set the key to `form`; returns False when the file already says so (left untouched)."""
    if form not in FORMS:
        raise ValueError(f"form must be one of {FORMS}, got {form!r}")
    path = pathlib.Path(path)
    header = parse(path)
    value = (STRING, struct.pack("<Q", len(form)) + form.encode())
    if header.pairs.get(KEY) == value:
        return False
    pairs = dict(header.pairs)
    pairs[KEY] = value
    out = bytearray(b"GGUF" + struct.pack("<IQQ", header.version, len(header.tensor_infos), len(pairs)))
    for key, (kind, raw) in pairs.items():
        name = key.encode()
        out += struct.pack("<Q", len(name)) + name + struct.pack("<I", kind) + raw
    for info in header.tensor_infos:
        out += info
    out += b"\0" * (-len(out) % header.alignment)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as dst, open(path, "rb") as src:
            dst.write(out)
            src.seek(header.data_offset)
            shutil.copyfileobj(src, dst, 1 << 20)
            dst.flush()
            os.fsync(dst.fileno())
        os.chmod(tmp, path.stat().st_mode & 0o7777)
        os.replace(tmp, path)
    except BaseException:
        pathlib.Path(tmp).unlink(missing_ok=True)
        raise
    return True


def form_from_manifest(path):
    """`compact` when the run manifest's target_format says so, else `full`."""
    manifest = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return "compact" if manifest.get("target_format") == "compact" else "full"


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("read").add_argument("gguf")
    stamp_cmd = sub.add_parser("stamp")
    source = stamp_cmd.add_mutually_exclusive_group(required=True)
    source.add_argument("--form", choices=FORMS)
    source.add_argument("--manifest")
    stamp_cmd.add_argument("gguf", nargs="+")
    check = sub.add_parser("check")
    check.add_argument("--form", choices=FORMS, required=True)
    check.add_argument("gguf", nargs="+")
    args = parser.parse_args(argv)
    try:
        if args.command == "read":
            print(read_output(args.gguf))
            return 0
        if args.command == "stamp":
            form = args.form or form_from_manifest(args.manifest)
            for gguf in args.gguf:
                changed = stamp(gguf, form)
                print(f"{gguf}: {KEY} {form}{'' if changed else ' (already)'}")
            return 0
        status = 0
        for gguf in args.gguf:
            declared = read_output(gguf)
            if declared != args.form:
                print(f"{gguf}: declares {KEY} {declared}, served as {args.form}; refused", file=sys.stderr)
                status = 1
        return status
    except (GGUFError, OSError, ValueError) as e:
        print(f"gguf_output_form: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

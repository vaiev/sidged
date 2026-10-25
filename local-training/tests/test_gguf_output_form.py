# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""The output form a linguist GGUF declares (0017 L3b, ROADMAP 13e): release_gate.sh stamps it, the
gate and scripts/serve-local-linguist.sh read it.

Stdlib only; the GGUFs are built here (header, tensor infos and a few data bytes). Run from the repo root:
    $VALIDATE_PY -I -m unittest discover -s local-training/tests -t local-training
"""
import json
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import gguf_output_form  # noqa: E402

SCRIPT = pathlib.Path(gguf_output_form.__file__)
KEY = "vaikor.linguist.output"


def gstr(text):
    data = text.encode()
    return struct.pack("<Q", len(data)) + data


def build(pairs, alignment=None, version=3):
    """A GGUF with `pairs` ((key, type, packed value)), two tensors and their data."""
    kv = list(pairs)
    if alignment is not None:
        kv.insert(0, ("general.alignment", 4, struct.pack("<I", alignment)))
    out = b"GGUF" + struct.pack("<IQQ", version, 2, len(kv))
    for key, kind, value in kv:
        out += gstr(key) + struct.pack("<I", kind) + value
    # Tensor infos: name, n_dims, dims, ggml type (0 = f32), offset relative to the data start.
    out += gstr("a.weight") + struct.pack("<I", 1) + struct.pack("<Q", 3) + struct.pack("<IQ", 0, 0)
    align = alignment or 32
    out += gstr("b.weight") + struct.pack("<I", 2) + struct.pack("<QQ", 1, 2) + struct.pack("<IQ", 0, align)
    out += b"\0" * (-len(out) % align)
    data = bytes(range(12)) + b"\0" * (align - 12) + bytes(range(100, 108))
    return out + data, data


def typical(value=None, alignment=None):
    pairs = [("general.architecture", 8, gstr("qwen3")),
             ("tokenizer.ggml.tokens", 9, struct.pack("<IQ", 8, 2) + gstr("a") + gstr(KEY)),
             ("tokenizer.ggml.scores", 9, struct.pack("<IQ", 6, 2) + struct.pack("<ff", 1.0, -1.0))]
    if value is not None:
        pairs.append((KEY, 8, gstr(value)))
    pairs.append(("general.file_type", 4, struct.pack("<I", 7)))
    return build(pairs, alignment)


class OutputFormTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, data, name="m.gguf"):
        path = self.dir / name
        path.write_bytes(data)
        return path

    def cli(self, *args):
        return subprocess.run([sys.executable, "-I", str(SCRIPT), *map(str, args)],
                              capture_output=True, text=True, check=False)

    def assert_same_tensors(self, before, after, data):
        """Every pair and tensor info of `before` survives, and the data section is byte-equal."""
        old, new = gguf_output_form.parse(before), gguf_output_form.parse(after)
        self.assertEqual(old.version, new.version)
        self.assertEqual(old.tensor_infos, new.tensor_infos)
        self.assertEqual(new.data_offset % new.alignment, 0)
        self.assertEqual(after.read_bytes()[new.data_offset:], data)
        for key, (kind, raw) in old.pairs.items():
            if key != KEY:
                self.assertEqual(new.pairs[key], (kind, raw), key)

    def test_read_follows_the_key_and_absent_means_full(self):
        self.assertEqual(gguf_output_form.read_output(self.write(typical("compact")[0])), "compact")
        self.assertEqual(gguf_output_form.read_output(self.write(typical("full")[0])), "full")
        self.assertEqual(gguf_output_form.read_output(self.write(typical()[0])), "full")
        result = self.cli("read", self.write(typical("compact")[0]))
        self.assertEqual((result.returncode, result.stdout), (0, "compact\n"))

    def test_bad_values_types_and_headers_are_refused(self):
        for value in ("Compact", "", "v0.2"):
            with self.assertRaisesRegex(gguf_output_form.GGUFError, KEY):
                gguf_output_form.read_output(self.write(typical(value)[0]))
        wrong_type = build([(KEY, 4, struct.pack("<I", 1))])[0]
        with self.assertRaisesRegex(gguf_output_form.GGUFError, "not a string"):
            gguf_output_form.read_output(self.write(wrong_type))
        twice = build([(KEY, 8, gstr("full")), (KEY, 8, gstr("compact"))])[0]
        with self.assertRaisesRegex(gguf_output_form.GGUFError, "twice"):
            gguf_output_form.read_output(self.write(twice))
        with self.assertRaisesRegex(gguf_output_form.GGUFError, "magic"):
            gguf_output_form.read_output(self.write(b"GGUX" + typical()[0][4:]))
        for version in (1, 4):
            with self.assertRaisesRegex(gguf_output_form.GGUFError, "version"):
                gguf_output_form.read_output(self.write(build([], version=version)[0]))
        data = typical("compact")[0]
        header_end = gguf_output_form.parse(self.write(data)).data_offset
        for cut in (0, 3, 10, 30, header_end - 70):
            with self.assertRaises(gguf_output_form.GGUFError, msg=cut):
                gguf_output_form.read_output(self.write(data[:cut]))
        huge = b"GGUF" + struct.pack("<IQQ", 3, 0, 2**40)
        with self.assertRaisesRegex(gguf_output_form.GGUFError, "key-value count"):
            gguf_output_form.read_output(self.write(huge))
        huge_array = build([("t", 9, struct.pack("<IQ", 8, 2**40))])[0]
        with self.assertRaisesRegex(gguf_output_form.GGUFError, "array length"):
            gguf_output_form.read_output(self.write(huge_array))
        result = self.cli("read", self.write(typical("v0.2")[0]))
        self.assertEqual(result.returncode, 2)
        self.assertIn(KEY, result.stderr)

    def test_stamp_adds_or_replaces_the_key_and_keeps_the_weights(self):
        for alignment in (None, 64):
            original, data = typical(alignment=alignment)
            before = self.write(original, "before.gguf")
            path = self.write(original)
            self.assertTrue(gguf_output_form.stamp(path, "compact"))
            self.assertEqual(gguf_output_form.read_output(path), "compact")
            self.assert_same_tensors(before, path, data)
            self.assertEqual(len(gguf_output_form.parse(path).pairs), len(gguf_output_form.parse(before).pairs) + 1)
            # Stamping the same form again leaves the file alone; another form replaces the value.
            stamped = path.read_bytes()
            self.assertFalse(gguf_output_form.stamp(path, "compact"))
            self.assertEqual(path.read_bytes(), stamped)
            self.assertTrue(gguf_output_form.stamp(path, "full"))
            self.assertEqual(gguf_output_form.read_output(path), "full")
            self.assert_same_tensors(before, path, data)
            self.assertEqual(len(gguf_output_form.parse(path).pairs), len(gguf_output_form.parse(before).pairs) + 1)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["before.gguf", "m.gguf"])

    def test_stamp_refuses_an_unknown_form_and_a_malformed_file(self):
        path = self.write(typical()[0])
        with self.assertRaises(ValueError):
            gguf_output_form.stamp(path, "v0.2")
        bad = self.write(b"GGUF" + struct.pack("<I", 9), "bad.gguf")
        with self.assertRaises(gguf_output_form.GGUFError):
            gguf_output_form.stamp(bad, "compact")
        self.assertEqual(bad.read_bytes(), b"GGUF" + struct.pack("<I", 9))

    def test_an_implausible_alignment_is_refused_before_anything_is_allocated(self):
        # Zero tensors, one pair: general.alignment = 2^31 would pad the stamped header by 2 GiB.
        huge = (b"GGUF" + struct.pack("<IQQ", 3, 0, 1) + gstr("general.alignment")
                + struct.pack("<II", 4, 2**31))
        path = self.write(huge)
        for call in (gguf_output_form.read_output, lambda p: gguf_output_form.stamp(p, "compact")):
            with self.assertRaisesRegex(gguf_output_form.GGUFError, "alignment"):
                call(path)
        self.assertEqual(path.read_bytes(), huge)

    def test_the_gate_stamps_from_the_manifest_and_checks_the_served_form(self):
        manifest = self.dir / "manifest.json"
        manifest.write_text(json.dumps({"target_format": "compact"}))
        self.assertEqual(gguf_output_form.form_from_manifest(manifest), "compact")
        for other in ({"target_format": "full"}, {"target_format": None}, {}):
            manifest.write_text(json.dumps(other))
            self.assertEqual(gguf_output_form.form_from_manifest(manifest), "full")
        manifest.write_text(json.dumps({"target_format": "compact"}))
        first, second = self.write(typical()[0], "q8_0.gguf"), self.write(typical("full")[0], "q4.gguf")
        result = self.cli("stamp", "--manifest", manifest, first, second)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([gguf_output_form.read_output(p) for p in (first, second)], ["compact", "compact"])
        self.assertEqual(self.cli("check", "--form", "compact", first).returncode, 0)
        mismatch = self.cli("check", "--form", "full", first)
        self.assertEqual(mismatch.returncode, 1)
        self.assertIn("compact", mismatch.stderr)
        self.assertEqual(self.cli("stamp", "--form", "v0.2", first).returncode, 2)


class GateTest(unittest.TestCase):
    """release_gate.sh with a fake llama.cpp: it stamps every export and stops before building or
    serving when the blind split's form differs from the declared one (a fake cargo would fail)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name)
        self.run_dir, self.llama, self.bin = root / "run", root / "llama", root / "bin"
        for d in (self.run_dir / "merged", self.llama / "build" / "bin", self.bin):
            d.mkdir(parents=True)
        fixture = root / "exported.gguf"
        fixture.write_bytes(typical()[0])
        (self.llama / "convert_hf_to_gguf.py").write_text(
            "import shutil, sys\n"
            f"shutil.copy({str(fixture)!r}, sys.argv[sys.argv.index('--outfile') + 1])\n")
        for name, body in ((self.llama / "build" / "bin" / "llama-quantize", 'cp "$1" "$2"'),
                           (self.bin / "cargo", "echo cargo must not run >&2; exit 99")):
            name.write_text(f"#!/bin/sh\n{body}\n")
            name.chmod(0o755)
        self.blind = root / "blind.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    def gate(self, blind_v, target_format=None):
        content = json.dumps({"v": blind_v, "lang": "de", "intent": None, "slots": {}})
        self.blind.write_text(json.dumps({"messages": [{}, {}, {"content": content}]}) + "\n")
        if target_format is not None:
            (self.run_dir / "manifest.json").write_text(json.dumps({"target_format": target_format}))
        env = dict(os.environ, VAIKOR_LLAMA=str(self.llama), PYTHON=sys.executable,
                   PATH=f"{self.bin}:{os.environ['PATH']}")
        return subprocess.run(["bash", str(SCRIPT.parent / "release_gate.sh"), str(self.run_dir), str(self.blind)],
                              capture_output=True, text=True, env=env, timeout=120, check=False)

    def forms(self):
        return [gguf_output_form.read_output(self.run_dir / f"vaikor-linguist-{q}.gguf")
                for q in ("f16", "q8_0", "q4_k_m")]

    def test_a_compact_run_served_full_is_refused(self):
        result = self.gate("0.1", "compact")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("declare", result.stderr)
        self.assertEqual(self.forms(), ["compact"] * 3)

    def test_a_run_without_manifest_is_full_and_refused_for_a_compact_split(self):
        result = self.gate("0.2")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn("cargo must not run", result.stderr)
        self.assertEqual(self.forms(), ["full"] * 3)


class ServeTest(unittest.TestCase):
    """scripts/serve-local-linguist.sh --workspace sets model.output from the key, with a fake llama-server."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name)
        self.toolchain, self.workspace, self.runtime = root / "toolchain", root / "workspace", root / "xdg"
        server = self.toolchain / "llama.cpp" / "build" / "bin" / "llama-server"
        for d in (server.parent, self.workspace, self.runtime):
            d.mkdir(parents=True)
        self.started = root / "started"
        server.write_text(f'#!/bin/sh\necho "$@" > {self.started}\n')
        server.chmod(0o755)
        (self.workspace / "manifest.json").write_text("{}")
        self.config = self.workspace / "config.json"
        self.config.write_text(json.dumps({"timezone": "Europe/Zurich",
                                           "model": {"endpoint": "unix:/old", "output": "compact"}}))
        self.model = root / "m.gguf"

    def tearDown(self):
        self.tmp.cleanup()

    def serve(self, value):
        self.model.write_bytes(typical(value)[0])
        env = dict(os.environ, VAIKOR_TOOLCHAIN=str(self.toolchain), XDG_RUNTIME_DIR=str(self.runtime))
        script = SCRIPT.parent.parent / "scripts" / "serve-local-linguist.sh"
        return subprocess.run(["bash", str(script), str(self.model), "--workspace", str(self.workspace)],
                              capture_output=True, text=True, env=env, timeout=60, check=False)

    def test_the_workspace_gets_the_declared_form(self):
        result = self.serve("compact")
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(self.config.read_text())
        self.assertEqual(config["model"]["output"], "compact")
        self.assertTrue(config["model"]["endpoint"].endswith("/vaikor/linguist.sock"))
        self.assertEqual(config["timezone"], "Europe/Zurich")
        self.assertTrue(self.started.exists())

    def test_an_absent_key_removes_a_stale_compact_setting(self):
        result = self.serve(None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("output", json.loads(self.config.read_text())["model"])

    def test_an_unknown_form_is_not_served(self):
        before = self.config.read_text()
        result = self.serve("v0.2")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(KEY, result.stderr)
        self.assertEqual(self.config.read_text(), before)
        self.assertFalse(self.started.exists())


if __name__ == "__main__":
    unittest.main()

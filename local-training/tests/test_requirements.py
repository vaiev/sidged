# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Offline contract for the generated, hashed training lock."""
import pathlib
import re
import shlex
import unittest

HERE = pathlib.Path(__file__).resolve().parent.parent
PINS = {
    "torch": "2.7.0+cu128",  # CUDA 12.8 build (Blackwell sm_120)
    "torchvision": "0.22.0+cu128",
    "unsloth": "2025.6.2",
    "unsloth-zoo": "2025.6.1",
}
PIN = re.compile(r"([A-Za-z0-9_.-]+)==([0-9][A-Za-z0-9.+-]*)")


def norm(name):
    """PEP 503 name normalisation (unsloth_zoo == unsloth-zoo)."""
    return re.sub(r"[-_.]+", "-", name).lower()


HASH = re.compile(r"--hash=sha256:[0-9a-fA-F]{64}")


def active_lines(path):
    return [line.strip() for line in path.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


class RequirementsTest(unittest.TestCase):
    def input_pins(self):
        path = HERE / "requirements.in"
        self.assertTrue(path.is_file(), "requirements.in must contain top-level pins")
        pins = {}
        for line in active_lines(path):
            match = PIN.fullmatch(line)
            self.assertIsNotNone(match, line)
            self.assertNotIn(norm(match[1]), pins, "duplicate input pin")
            pins[norm(match[1])] = match[2]
        return pins

    def test_input_has_compatible_pins(self):
        pins = self.input_pins()
        for name, version in PINS.items():
            self.assertEqual(pins.get(name), version, name)
        if "torchaudio" in pins:
            self.assertEqual(pins["torchaudio"], "2.7.0")
        self.assertTrue({"xformers", "triton"}.isdisjoint(pins))

    def test_lock_has_hash_continuations_for_every_pin(self):
        lines = active_lines(HERE / "requirements.lock")
        self.assertTrue(lines, "lock must not be empty")
        pins = {}
        index = 0
        while index < len(lines):
            line = lines[index]
            self.assertTrue(line.endswith("\\"), "pin needs hash continuation: " + line)
            match = PIN.fullmatch(line[:-1].rstrip())
            self.assertIsNotNone(match, line)
            self.assertNotIn(norm(match[1]), pins, "duplicate lock pin")
            pins[norm(match[1])] = match[2]
            index += 1
            while True:
                self.assertLess(index, len(lines), "missing hash continuation")
                line = lines[index]
                continued = line.endswith("\\")
                self.assertIsNotNone(HASH.fullmatch(line[:-1].rstrip() if continued else line), line)
                index += 1
                if not continued:
                    break
        inputs = self.input_pins()
        for name in PINS:
            self.assertEqual(pins.get(name), inputs.get(name), name)

    def test_setup_requires_hashes_and_cu128_extra_index(self):
        text = (HERE / "setup_gpu_cu128.sh").read_text()
        commands = [shlex.split(line) for line in text.replace("\\\n", " ").splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
        installs = [cmd for cmd in commands if cmd[:4] == ["python", "-m", "pip", "install"]]
        locked = [cmd for cmd in installs if "-r" in cmd]
        self.assertEqual(len(locked), 1)
        cmd = locked[0]
        self.assertIn("--require-hashes", cmd)
        self.assertEqual(cmd[cmd.index("-r") + 1], "$here/requirements.lock")
        self.assertIn("--extra-index-url", cmd)
        # The approved wheel index is shared with the existing setup contract.
        if __package__:
            from .test_dataset import CU128_INDEX
        else:
            from test_dataset import CU128_INDEX
        self.assertEqual(cmd[cmd.index("--extra-index-url") + 1], CU128_INDEX)
        self.assertEqual(len(installs), 1, "all packages must use the hashed lock")

    def test_lock_header_matches_readme_regeneration_command(self):
        readme = (HERE / "README.md").read_text()
        command = next(line for line in readme.splitlines() if line.startswith("uv pip compile "))
        header = (HERE / "requirements.lock").read_text().splitlines()[1]
        self.assertEqual(header.removeprefix("#").strip(), command)

    def test_readme_describes_the_hashed_lock_and_dependencies(self):
        text = (HERE / "README.md").read_text()
        for stale in ("unhashed placeholder", "current placeholder", "no extra-index", "adamw_torch (no bitsandbytes)"):
            self.assertNotIn(stale, text)
        self.assertIn("bitsandbytes and xformers", text)
        self.assertIn("unsloth dependencies", text)

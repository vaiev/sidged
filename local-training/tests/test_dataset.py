# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Tests for the local training data, validator and manifest (turnkey WP f).

Stdlib only, no GPU, no model download, no training. Run from the repo root:
    python3 -I -m unittest discover -s local-training/tests -t local-training
"""
import copy
import json
import pathlib
import re
import tempfile
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
# Model 0's trainer is archived with the other demo trainers.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "experimental"))

import make_dataset
import train_edge_llm
import validate_dataset
import write_manifest

CU128_INDEX = "https://download.pytorch.org/whl/cu128"

HERE = pathlib.Path(__file__).resolve().parent.parent


def sample(component="TaskList", route="local-ui", props=None, user="Plan my afternoon"):
    call = {"component": component, "route": route, "props": props if props is not None else {"items": ["a"]}}
    return {
        "messages": [
            {"role": "system", "content": make_dataset.SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": json.dumps(call, sort_keys=True)},
        ]
    }


class ValidatorTest(unittest.TestCase):
    def refused(self, record, needle):
        errors = validate_dataset.check_record(record)
        self.assertTrue(errors, f"accepted: {record}")
        self.assertTrue(any(needle in e for e in errors), f"{needle!r} not in {errors}")

    def test_a_valid_record_passes(self):
        self.assertEqual(validate_dataset.check_record(sample()), [])

    def test_only_the_five_registry_components(self):
        self.assertEqual(
            validate_dataset.COMPONENTS,
            {"TaskList", "CountdownWidget", "NoteEditor", "WebResult", "CloudCallTrace"},
        )
        for name in ["SwarmManager", "TrustedApprovalSheet", "Shell", ""]:
            self.refused(sample(component=name), "component")

    def test_only_the_three_ratified_routes(self):
        self.assertEqual(validate_dataset.ROUTES, {"local-ui", "worker-tool", "cloud:grok"})
        for route in ["cloud:openai", "cloud:anthropic", "swarm", "LOCAL-UI", ""]:
            self.refused(sample(route=route), "route")

    def test_no_residency_approval_or_grant_fields_anywhere(self):
        for key in ["residency", "approval", "approved", "grant", "grants", "capability_token",
                    "signature", "consent", "trusted"]:
            self.refused(sample(props={"items": ["a"], key: "CH-EGRESS-GATED"}), "forbidden key")
            nested = sample(props={"items": [{key: True}]})
            self.refused(nested, "forbidden key")
        record = sample()
        call = json.loads(record["messages"][2]["content"])
        call["residency"] = "CH"
        record["messages"][2]["content"] = json.dumps(call)
        self.refused(record, "forbidden key")

    def test_ip_literals_and_pii_are_refused(self):
        self.refused(sample(user="connect VM 192.168.1.20:8091"), "ipv4")
        self.refused(sample(user="node at fd00::1 please"), "ipv6")
        self.refused(sample(props={"items": ["mail anna@example.org"]}), "email")
        self.refused(sample(user="key sk-abcdefghijklmnopqrstuv"), "secret")
        self.refused(sample(user="call +41 79 123 45 67"), "phone")
        self.refused(sample(user="pay CH93 0076 2011 6238 5295 7"), "iban")

    def test_structure_is_strict(self):
        record = sample()
        record["messages"][2]["content"] = "not json"
        self.refused(record, "JSON")
        record = sample()
        record["messages"][0]["role"] = "assistant"
        self.refused(record, "roles")
        record = sample()
        record["extra"] = 1
        self.refused(record, "keys")
        record = sample()
        call = json.loads(record["messages"][2]["content"])
        call["code"] = "rm -rf /"
        record["messages"][2]["content"] = json.dumps(call)
        self.refused(record, "keys")


class DatasetTest(unittest.TestCase):
    def test_generated_data_is_valid_and_covers_every_component_and_route(self):
        records = make_dataset.build(seed=42, per_template=3)
        self.assertTrue(records)
        components, routes = set(), set()
        for record in records:
            self.assertEqual(validate_dataset.check_record(record), [], record)
            call = json.loads(record["messages"][2]["content"])
            components.add(call["component"])
            routes.add(call["route"])
        self.assertEqual(components, validate_dataset.COMPONENTS)
        self.assertEqual(routes, validate_dataset.ROUTES)

    def test_generation_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = pathlib.Path(tmp, "a.jsonl")
            b = pathlib.Path(tmp, "b.jsonl")
            make_dataset.write(a, seed=7, per_template=2)
            make_dataset.write(b, seed=7, per_template=2)
            self.assertEqual(a.read_bytes(), b.read_bytes())
            self.assertEqual(validate_dataset.check_file(a), [])

    def test_system_prompt_names_only_registry_components(self):
        self.assertNotIn("SwarmManager", make_dataset.SYSTEM_PROMPT)
        self.assertIn("/no_think", make_dataset.SYSTEM_PROMPT)


class ManifestTest(unittest.TestCase):
    REV = "0123456789abcdef0123456789abcdef01234567"

    def inputs(self, tmp):
        data = pathlib.Path(tmp, "data.jsonl")
        data.write_text('{"x":1}\n')
        return dict(
            base_model="Qwen/Qwen3-0.6B",
            revision=self.REV,
            dataset=data,
            scripts=[HERE / "make_dataset.py", HERE / "experimental" / "train_edge_llm.py"],
            hyperparameters=train_edge_llm.HYPERPARAMETERS,
            gguf=None,
        )

    def test_manifest_is_deterministic_and_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = write_manifest.build(**self.inputs(tmp))
            second = write_manifest.build(**self.inputs(tmp))
            self.assertEqual(write_manifest.dumps(first), write_manifest.dumps(second))
            self.assertEqual(first["base_model"]["id"], "Qwen/Qwen3-0.6B")
            self.assertEqual(first["base_model"]["revision"], self.REV)
            self.assertEqual(first["base_model"]["licence"], "Apache-2.0")
            self.assertEqual(first["dataset"]["digest"]["alg"], "sha-256")
            self.assertEqual(len(first["scripts"]), 2)
            self.assertEqual(first["hyperparameters"]["lora_r"], 32)
            self.assertIsNone(first["model"]["weights"])
            text = write_manifest.dumps(first)
            self.assertNotRegex(text, r"\d{4}-\d{2}-\d{2}T")  # no timestamps
            self.assertNotIn("residency", text)

    def test_gguf_digest_and_licences(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.inputs(tmp)
            gguf = pathlib.Path(tmp, "m.gguf")
            gguf.write_bytes(b"GGUF")
            args["gguf"] = gguf
            manifest = write_manifest.build(**args)
            weights = manifest["model"]["weights"]
            self.assertEqual(manifest["model"]["format"], "gguf")
            self.assertEqual(weights[0]["digest"]["alg"], "sha-256")
            self.assertRegex(weights[0]["digest"]["value"], r"^[A-Za-z0-9_-]{43}$")
            args["base_model"] = "google/functiongemma-270m-it"
            self.assertEqual(write_manifest.build(**args)["base_model"]["licence"], "Gemma Terms of Use")

    def test_revision_must_be_a_commit_and_base_model_known(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.inputs(tmp)
            for bad in ["main", "v1", self.REV[:-1]]:
                args["revision"] = bad
                with self.assertRaises(ValueError):
                    write_manifest.build(**args)
            args["revision"] = self.REV
            args["base_model"] = "some/other-model"
            with self.assertRaises(ValueError):
                write_manifest.build(**args)


class ConsentAndSetupTest(unittest.TestCase):
    def test_training_needs_the_flag_and_a_typed_confirmation(self):
        with self.assertRaises(SystemExit):
            train_edge_llm.require_consent(flag=False, ask=lambda _: "TRAIN", tty=True)
        with self.assertRaises(SystemExit):
            train_edge_llm.require_consent(flag=True, ask=lambda _: "yes", tty=True)
        with self.assertRaises(SystemExit):
            train_edge_llm.require_consent(flag=True, ask=lambda _: "TRAIN", tty=False)
        train_edge_llm.require_consent(flag=True, ask=lambda _: "TRAIN", tty=True)

    def test_hyperparameters_are_bf16_lora_without_4bit(self):
        h = train_edge_llm.HYPERPARAMETERS
        self.assertEqual((h["lora_r"], h["lora_alpha"], h["precision"]), (32, 64, "bf16"))
        self.assertFalse(h["load_in_4bit"])

    def test_setup_uses_stable_cu128_wheels_only(self):
        text = (HERE / "setup_gpu_cu128.sh").read_text()
        self.assertIn("--extra-index-url " + CU128_INDEX, text)
        for bad in ["nightly", "--pre", "git+", "| sh", "| bash"]:
            self.assertNotIn(bad, text)

    def test_no_timing_claims_in_the_readme(self):
        text = (HERE / "README.md").read_text()
        self.assertIsNone(re.search(r"<\s*\d+\s*(min|minutes|s|sec)\b", text))


if __name__ == "__main__":
    unittest.main()

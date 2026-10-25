# Copyright 2026 The Selfkin Standards contributors
# Copyright 2026 VAIEV
# Provenance: adapted from https://github.com/selfkin/standards (see NOTICE).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for the Vaikor schemas, examples, and validator.

Run from the repository root:
  python -m unittest discover -s spec/validate -v
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate  # noqa: E402

FORBIDDEN_DASHES = ("\u2014", "\u2013")
TEXT_SUFFIXES = {".json", ".md", ".py", ".yml", ".yaml", ".txt"}


class SchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schemas = validate.load_schemas()
        cls.registry = validate.build_registry(cls.schemas)

    def test_schema_files_are_well_formed(self):
        self.assertEqual(validate.check_schema_files(self.schemas), [])

    def test_valid_examples_pass(self):
        for path in validate.example_files():
            if path.name.endswith(".invalid.json"):
                continue
            with self.subTest(example=path.name):
                problems = validate.validate_document(
                    validate.load_json(path), validate.schema_for_example(path), self.schemas, self.registry
                )
                self.assertEqual(problems, [], f"{path.name} should be valid")

    def test_invalid_examples_fail(self):
        for path in validate.example_files():
            if not path.name.endswith(".invalid.json"):
                continue
            with self.subTest(example=path.name):
                problems = validate.validate_document(
                    validate.load_json(path), validate.schema_for_example(path), self.schemas, self.registry
                )
                self.assertNotEqual(problems, [], f"{path.name} should be invalid")

    def test_every_schema_has_valid_and_invalid_examples(self):
        files = [p.name for p in validate.example_files()]
        for name in validate.SCHEMA_NAMES:
            with self.subTest(schema=name):
                mine = [f for f in files if validate.schema_for_example(Path(f)) == name]
                self.assertTrue(any(not f.endswith(".invalid.json") for f in mine), f"no valid example for {name}")
                self.assertTrue(any(f.endswith(".invalid.json") for f in mine), f"no invalid example for {name}")

    def test_invalid_examples_are_explained(self):
        readme = (validate.EXAMPLE_DIR / "README.md").read_text(encoding="utf-8")
        for path in validate.example_files():
            if path.name.endswith(".invalid.json"):
                with self.subTest(example=path.name):
                    self.assertIn(f"`{path.name}`", readme, "explain every invalid example in examples/README.md")

    def test_unknown_residency_tag_syntax(self):
        tag_schema = {"$ref": "common.schema.json#/$defs/residencyTag"}
        tag_schema["$id"] = validate.ID_PREFIX + "test-tag.schema.json"
        from jsonschema import Draft202012Validator

        checker = Draft202012Validator(tag_schema, registry=self.registry)
        for good in ("CH", "EU", "CH-EU", "x-home-only", "x-" + "a" * 62):
            self.assertTrue(checker.is_valid(good), good)
        # Vaikor L7: owner-defined tags have at most 64 characters in total.
        for bad in ("ch", "EU-CH", "Switzerland", "x-", "", "x-" + "a" * 63):
            self.assertFalse(checker.is_valid(bad), bad)

    def test_map_over_is_a_ref_to_a_whole_output(self):
        # VKR-L3 R6, R4a: `over` names an earlier step's whole output; `field` is for arguments.
        validator = validate.make_validator("plan", self.schemas, self.registry)

        def plan(over):
            return {"v": "0.1", "steps": [
                {"id": "free", "kind": "call", "capability": "tag:vaikor.com,2026:capability:calendar.free_slots",
                 "args": {"range": {"lit": "next_week"}}},
                {"id": "each", "kind": "map", "over": over, "bound": 2,
                 "capability": "tag:vaikor.com,2026:capability:calendar.free_slots",
                 "args": {"range": {"item": True}, "note": {"ref": "free", "field": "slots"}}},
            ]}

        self.assertTrue(validator.is_valid(plan({"ref": "free"})))
        for bad in ({"ref": "free", "field": "slots"}, {"lit": "x"}, {"item": True}):
            self.assertFalse(validator.is_valid(plan(bad)), bad)


def registry_codes(name: str) -> list[str]:
    """First-column codes of every table row in registries/<name>."""
    codes = []
    for line in (validate.REPO / "spec" / "registries" / name).read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\| `([^`]+)` \|", line)
        if match:
            codes.append(match.group(1))
    return codes


class EgressResidencyTests(unittest.TestCase):
    """VKR-L1 R8 v0.2: egress capabilities need explicit residency."""

    base = {"effects": ["egress"], "data_classes": ["query.text"], "consequential": True}

    def test_missing_or_empty_residency_fails(self):
        for residency in (None, {"tags": []}):
            d = dict(self.base)
            if residency is not None:
                d["residency"] = residency
            self.assertTrue(any("R8a" in p for p in validate.check_capability_descriptor(d)))

    def test_unrestricted_only_alone(self):
        ok = dict(self.base, residency={"tags": ["unrestricted"]})
        bad = dict(self.base, residency={"tags": ["unrestricted", "CH"]})
        self.assertEqual(validate.check_capability_descriptor(ok), [])
        self.assertTrue(any("R8b" in p for p in validate.check_capability_descriptor(bad)))


class RegistryTests(unittest.TestCase):
    """Registries and schemas must list the same codes."""

    @classmethod
    def setUpClass(cls):
        cls.common = validate.load_schemas()["common"]["$defs"]

    def test_refusal_reasons_match(self):
        enum = self.common["refusalReason"]["anyOf"][0]["enum"]
        self.assertEqual(sorted(registry_codes("refusal-reasons.md")), sorted(enum))

    def test_vkr_intents_and_domains_match(self):
        codes = registry_codes("intents.md")
        reserved = [c for c in codes if c.startswith("vkr.")]
        domains = [c for c in codes if not c.startswith("vkr.")]
        self.assertEqual(sorted(reserved), sorted(self.common["intent"]["anyOf"][0]["enum"]))
        pattern = self.common["intent"]["anyOf"][1]["pattern"]
        self.assertEqual(sorted(domains), sorted(re.match(r"^\^\(([^)]*)\)", pattern).group(1).split("|")))

    def test_effects_match(self):
        enum = validate.load_schemas()["capability-descriptor"]["properties"]["effects"]["items"]["enum"]
        self.assertEqual(sorted(registry_codes("effects.md")), sorted(enum))

    def test_data_classes_match(self):
        pattern = self.common["dataClass"]["pattern"]
        classes = re.match(r"^\^\(\(([^)]*)\)", pattern).group(1).split("|")
        self.assertEqual(sorted(registry_codes("data-classes.md")), sorted(classes))

    def test_residency_tags_match(self):
        enum = self.common["residencyTag"]["anyOf"][0]["enum"]
        self.assertEqual(sorted(registry_codes("residency.md")), sorted(enum))


class TimeServerDemoTests(unittest.TestCase):
    """The mcp-server-time overlay matches VKR-L1 and the published tool names."""

    def test_annotated_tools_are_valid_capabilities(self):
        demo = validate.load_json(validate.REPO / "docs/demo/mcp-server-time/annotated-tools.json")
        schemas = validate.load_schemas()
        registry = validate.build_registry(schemas)
        for tool in demo["tools"]:
            descriptor = tool["_meta"]["com.vaikor/capability"]
            with self.subTest(tool=tool["name"]):
                self.assertEqual(descriptor["id"].rsplit(":", 1)[-1], tool["name"])
                self.assertEqual(tool["inputSchema"], descriptor["input_schema"])
                problems = validate.validate_document(descriptor, "capability-descriptor", schemas, registry)
                self.assertEqual(problems, [])
                if descriptor["effects"] == ["read"]:
                    self.assertTrue(tool["annotations"]["readOnlyHint"])
                    self.assertFalse(tool["annotations"]["openWorldHint"])


class IntentCatalogTests(unittest.TestCase):
    """The intent catalog the runtime embeds is the one the companion linguist trains on."""

    def test_runtime_intent_catalog_is_valid(self):
        catalog = validate.load_json(validate.REPO / "runtime/vaikor-cli/assets/intent-catalog.json")
        schemas = validate.load_schemas()
        registry = validate.build_registry(schemas)
        self.assertEqual(validate.validate_document(catalog, "intent-catalog", schemas, registry), [])

    def test_every_intent_capability_has_a_descriptor(self):
        intents = validate.load_json(validate.REPO / "runtime/vaikor-cli/assets/intent-catalog.json")
        capabilities = validate.load_json(validate.REPO / "runtime/vaikor-cli/assets/capability-catalog.json")
        known = {descriptor["id"] for descriptor in capabilities}
        for entry in intents["intents"]:
            for capability in entry["capabilities"]:
                with self.subTest(intent=entry["intent"], capability=capability):
                    self.assertIn(capability, known)

    def test_runtime_capability_catalog_is_valid(self):
        catalog = validate.load_json(validate.REPO / "runtime/vaikor-cli/assets/capability-catalog.json")
        schemas = validate.load_schemas()
        registry = validate.build_registry(schemas)
        for descriptor in catalog:
            with self.subTest(capability=descriptor["id"]):
                self.assertEqual(validate.validate_document(descriptor, "capability-descriptor", schemas, registry), [])

    def test_missing_slot_and_placeholder_rules(self):
        envelope = validate.load_json(validate.EXAMPLE_DIR / "linguist-envelope.gsw-missing-slot.json")
        envelope["slots"]["time"] = "tomorrow"
        self.assertIn("slot time is both given and missing", validate.check_linguist_envelope(envelope))
        envelope = validate.load_json(validate.EXAMPLE_DIR / "linguist-envelope.en-complete.json")
        envelope["canonical_intent_en"] = "Remind me about {subject}"
        self.assertTrue(validate.check_linguist_envelope(envelope))


class LinguistProposalTests(unittest.TestCase):
    """The compact linguist proposal (0017 L3a): v0.2 carries only v, lang, intent, slots and then."""

    @classmethod
    def setUpClass(cls):
        cls.schemas = validate.load_schemas()
        cls.registry = validate.build_registry(cls.schemas)

    def problems(self, document):
        return validate.validate_document(document, "linguist-proposal", self.schemas, self.registry)

    def test_the_proposal_schema_is_registered(self):
        self.assertIn("linguist-proposal", validate.SCHEMA_NAMES)

    def test_the_shared_compact_fixture_proposals_are_valid(self):
        fixture = validate.load_json(validate.REPO / "runtime/vaikor-cli/tests/fixtures/linguist-prompt-compact.json")
        for vector in fixture["proposals"]:
            with self.subTest(utterance=vector["utterance"]):
                self.assertEqual(self.problems(vector["proposal"]), [])

    def test_every_derived_member_and_a_full_envelope_are_refused(self):
        proposal = validate.load_json(validate.EXAMPLE_DIR / "linguist-proposal.gsw-missing-slot.json")
        envelope = validate.load_json(validate.EXAMPLE_DIR / "linguist-envelope.gsw-missing-slot.json")
        for key in ("missing_slots", "clarification_needed", "clarification_question_local",
                    "canonical_intent_en", "suggested_route", "required_data_classes", "residency"):
            with self.subTest(key=key):
                self.assertTrue(self.problems(dict(proposal, **{key: envelope.get(key, ["CH"])})))
        self.assertTrue(self.problems(envelope))
        self.assertTrue(self.problems(dict(envelope, v="0.2")))
        for key in ("v", "lang", "intent", "slots"):
            with self.subTest(missing=key):
                self.assertTrue(self.problems({k: v for k, v in proposal.items() if k != key}))


class SemanticTests(unittest.TestCase):
    def test_resource_coverage(self):
        self.assertTrue(validate.resource_covers("urn:a:b/*", "urn:a:b/c"))
        self.assertTrue(validate.resource_covers("urn:a:b", "urn:a:b"))
        self.assertFalse(validate.resource_covers("urn:a:b", "urn:a:b/c"))
        self.assertFalse(validate.resource_covers("urn:a:b/*", "urn:a:bc"))
        self.assertFalse(validate.resource_covers("urn:x:a/*", "urn:x:a/"))
        self.assertFalse(validate.resource_covers("urn:x:a/*", "urn:x:a/../b"))
        self.assertFalse(validate.resource_covers("urn:x:a/*", "urn:x:a/%2e%2e/b"))
        self.assertTrue(validate.resource_covers("urn:x:a/*", "urn:x:a/b/c"))

    def test_money_is_compared_exactly(self):
        # As floats both amounts are 1.0, so the widening went unnoticed.
        parent = {"action": "pay", "resource": "urn:x", "constraints": {"max_amount": {"amount": "1", "currency": "CHF"}}}
        child = {"action": "pay", "resource": "urn:x",
                 "constraints": {"max_amount": {"amount": "1.0000000000000001", "currency": "CHF"}}}
        self.assertFalse(validate.right_covered(child, parent))
        budget_parent = {"budget": {"money": {"amount": "0.3", "currency": "CHF"}}}
        budget_child = {"budget": {"money": {"amount": "0.30000000000000001", "currency": "CHF"}}}
        self.assertEqual(len(validate.budget_problems(budget_child, budget_parent)), 1)
        self.assertEqual(validate.budget_problems(budget_parent, budget_parent), [])

    def test_impossible_timestamp_is_a_problem_not_a_crash(self):
        schemas = validate.load_schemas()
        registry = validate.build_registry(schemas)
        document = validate.load_json(validate.EXAMPLE_DIR / "capability-token.root.json")
        document["exp"] = "2026-02-30T00:00:00Z"
        problems = validate.validate_document(document, "capability-token", schemas, registry)
        self.assertTrue(problems)

    def test_egress_without_network_is_a_problem(self):
        manifest = {"data_classes": ["calendar.events"], "egress": [{"data_classes": ["calendar.events"]}],
                    "resources": {"network": False}}
        self.assertIn("egress is declared but resources.network is false", validate.check_module_manifest(manifest))

    def test_schema_without_id_fails_clearly(self):
        with self.assertRaises(ValueError):
            validate.build_registry({"broken": {"title": "x"}})

    def test_dropping_a_parent_constraint_widens(self):
        parent = {"action": "pay", "resource": "urn:x", "constraints": {"max_uses": 2}}
        child = {"action": "pay", "resource": "urn:x"}
        self.assertFalse(validate.right_covered(child, parent))


class RepositoryStyleTests(unittest.TestCase):
    def test_no_em_or_en_dashes(self):
        roots = [validate.REPO / "spec" / d for d in ("schemas", "examples", "validate", "registries", "test-vectors")]
        for root in roots:
            paths = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
            for path in paths:
                if path.suffix not in TEXT_SUFFIXES:
                    continue
                with self.subTest(file=str(path.relative_to(validate.REPO))):
                    text = path.read_text(encoding="utf-8")
                    for dash in FORBIDDEN_DASHES:
                        self.assertNotIn(dash, text)


if __name__ == "__main__":
    unittest.main()

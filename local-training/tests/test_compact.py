# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Compact v0.2 linguist proposals and catalog-constrained decoding (ROADMAP 13e B, 0017 L3a, L8).

No GPU, no model, no training. The decoding-schema test needs `jsonschema` (the validate venv,
spec/validate/requirements.txt); the data side stays stdlib only. Run from the repo root:
    $VALIDATE_PY -I -m unittest discover -s local-training/tests -t local-training
"""
import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import core_bridge  # noqa: E402
import eval_linguist  # noqa: E402
import linguist  # noqa: E402
import make_dataset_linguist  # noqa: E402
import validate_dataset_linguist  # noqa: E402

FIXTURES = linguist.HERE.parent / "runtime" / "sidged-cli" / "tests" / "fixtures"
SIZES = {"train": (2, 1.0), "dev": (2, 1.0), "blind": (2, 1.0)}


def assistant(record):
    return json.loads(record["messages"][2]["content"])


def with_assistant(record, proposal):
    changed = json.loads(json.dumps(record))
    changed["messages"][2]["content"] = json.dumps(proposal, ensure_ascii=False)
    return changed


class CompactContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = linguist.load_catalog()
        cls.fixture = json.loads((FIXTURES / "linguist-prompt-compact.json").read_text(encoding="utf-8"))
        cls.full = json.loads((FIXTURES / "linguist-prompt.json").read_text(encoding="utf-8"))

    def test_compact_prompt_bytes_from_the_core_match_the_fixture(self):
        prompt = self.fixture["prompt"]
        system, user = core_bridge.render_prompt(prompt["utterance"], prompt["intent_ids"], compact=True)
        self.assertEqual(system, prompt["system"])
        self.assertEqual(user, prompt["user"])
        # The v0.1 prompt stays what it was.
        full = self.full["prompt"]
        self.assertEqual(core_bridge.render_prompt(full["utterance"], full["intent_ids"]),
                         (full["system"], full["user"]))

    def test_fixture_proposals_derive_the_fixture_envelopes(self):
        for vector in self.fixture["proposals"]:
            proposal = vector["proposal"]
            with self.subTest(utterance=vector["utterance"]):
                self.assertEqual(linguist.check_proposal(self.catalog, proposal), [])
                self.assertEqual(linguist.derive_proposal(self.catalog, proposal), vector["expected"])
                self.assertEqual(linguist.compact(vector["expected"], self.catalog), proposal)

    def test_a_compact_proposal_with_any_other_member_is_refused(self):
        good = self.fixture["proposals"][0]["proposal"]
        envelope = self.fixture["proposals"][0]["expected"]
        for key in ("missing_slots", "clarification_needed", "canonical_intent_en", "suggested_route",
                    "required_data_classes", "residency", "approval"):
            with self.subTest(key=key):
                self.assertTrue(linguist.check_proposal(self.catalog, dict(good, **{key: envelope.get(key, True)})))
        self.assertTrue(linguist.check_proposal(self.catalog, envelope))
        self.assertTrue(linguist.check_proposal(self.catalog, dict(good, v="0.1")))
        self.assertTrue(linguist.check_proposal(self.catalog, {k: v for k, v in good.items() if k != "slots"}))
        self.assertTrue(linguist.check_proposal(self.catalog, dict(good, intent="x.unknown")))
        self.assertTrue(linguist.check_proposal(self.catalog, dict(good, slots={"place": "home"})))
        composition = self.fixture["proposals"][2]["proposal"]
        follow_up = dict(composition["then"][0], missing_slots=[])
        self.assertTrue(linguist.check_proposal(self.catalog, dict(composition, then=[follow_up])))

    def test_slot_values_and_follow_up_slots_are_checked(self):
        base = {"v": "0.2", "lang": "en", "intent": "timer.set", "missing": [], "slots": {"duration": "5 minutes"}}
        composed = {"v": "0.2", "lang": "en", "intent": "task.summarize", "missing": [],
                    "slots": {"source": "the report"},
                    "then": [{"intent": "messaging.send", "slots": {"recipient": "Lea"}}]}
        self.assertEqual(linguist.check_proposal(self.catalog, base), [])
        self.assertEqual(linguist.check_proposal(self.catalog, dict(base, slots={"duration": "5" * 512})), [])
        bad = {
            "over-long slot": dict(base, slots={"duration": "5" * 513}),
            "empty slot": dict(base, slots={"duration": ""}),
            "blank slot": dict(base, slots={"duration": "  "}),
            "control character": dict(base, slots={"duration": "5\nminutes"}),
            "non-string slot": dict(base, slots={"duration": 5}),
            "slots not an object": dict(base, slots=[]),
            "follow-up slots a list": dict(composed, then=[{"intent": "messaging.send", "slots": []}]),
            "follow-up over-long slot": dict(composed, then=[{"intent": "messaging.send",
                                                               "slots": {"recipient": "L" * 513}}]),
            "follow-up empty slot": dict(composed, then=[{"intent": "messaging.send", "slots": {"recipient": ""}}]),
            "follow-up intent not a string": dict(composed, then=[{"intent": None, "slots": {}}]),
            "missing slot also given": dict(base, missing=["duration"]),
            "required slot neither given nor missing": dict(base, slots={}),
            "missing not a list": dict(base, missing="duration"),
            "slots out of grammar order": {"v": "0.2", "lang": "en", "intent": "files.find", "missing": [],
                                           "slots": {"folder": "Documents", "query": "plan.odt"}},
        }
        for name, proposal in bad.items():
            with self.subTest(case=name):
                self.assertTrue(linguist.check_proposal(self.catalog, proposal), proposal)

    def test_compact_keeps_the_key_order_the_model_learns(self):
        envelope = self.fixture["proposals"][2]["expected"]
        text = linguist.dumps(linguist.compact(envelope, self.catalog))
        self.assertEqual(list(json.loads(text)), ["v", "lang", "intent", "missing", "slots", "then"])
        self.assertTrue(text.startswith('{"v": "0.2", "lang": "gsw", "intent": "task.summarize"'), text)


class CompactDatasetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = linguist.load_catalog()
        cls.book = linguist.load_json(linguist.PHRASEBOOK_PATH)
        cls.splits = make_dataset_linguist.build_splits(cls.catalog, cls.book, 7, SIZES, fmt="compact")

    def test_compact_records_are_valid_and_carry_only_the_proposal(self):
        kinds = set()
        for split, (records, _meta) in self.splits.items():
            errors = validate_dataset_linguist.check_records(self.catalog, records)
            for record, found in zip(records, errors):
                self.assertEqual(found, [], record)
                proposal = assistant(record)
                self.assertEqual([k for k in proposal if k != "then"], list(linguist.PROPOSAL_KEYS))
                self.assertEqual(record["messages"][0]["content"], self.compact_system)
                envelope = linguist.derive_proposal(self.catalog, proposal)
                kinds.add(eval_linguist.case_kind(proposal))
                self.assertEqual(linguist.compact(envelope, self.catalog), proposal)
        self.assertEqual(kinds, {"composition", "intent-null", "missing-slot", "complete"})

    @property
    def compact_system(self):
        return core_bridge.render_prompt("x", None, compact=True)[0]

    def test_full_and_compact_data_hold_the_same_targets(self):
        full = make_dataset_linguist.build_splits(self.catalog, self.book, 7, SIZES)
        for split in make_dataset_linguist.SPLITS:
            with self.subTest(split=split):
                full_records, compact_records = full[split][0], self.splits[split][0]
                self.assertEqual(len(full_records), len(compact_records))
                for a, b in zip(full_records, compact_records):
                    self.assertEqual(a["messages"][1], b["messages"][1])
                    self.assertEqual(linguist.compact(assistant(a), self.catalog), assistant(b))

    def test_the_validator_refuses_mixed_forms_and_extra_members(self):
        record = self.splits["train"][0][0]
        proposal = assistant(record)
        bad = with_assistant(record, dict(proposal, missing_slots=[]))
        self.assertTrue(validate_dataset_linguist.check_record(self.catalog, bad))
        bad = with_assistant(record, dict(proposal, residency=["CH"]))
        self.assertTrue(any("forbidden key" in e for e in validate_dataset_linguist.check_record(self.catalog, bad)))
        # A full envelope under the compact instruction (or the reverse) is not a runtime record.
        envelope = linguist.derive_proposal(self.catalog, proposal)
        errors = validate_dataset_linguist.check_record(self.catalog, with_assistant(record, envelope))
        self.assertTrue(any("system prompt" in e for e in errors), errors)
        # Slot values the Core would refuse are not training targets (0017 L4).
        for slots in ({name: "x" * 513 for name in proposal["slots"]} or {"x": "y"}, []):
            errors = validate_dataset_linguist.check_record(self.catalog, with_assistant(record, dict(proposal, slots=slots)))
            self.assertTrue(errors, slots)
        reordered = {k: proposal[k] for k in ("lang", "v", "intent", "missing", "slots")}
        errors = validate_dataset_linguist.check_record(self.catalog, with_assistant(record, reordered))
        self.assertTrue(any("in order" in e for e in errors), errors)

    def test_the_command_line_writes_compact_splits(self):
        quiet = contextlib.ExitStack()
        quiet.enter_context(contextlib.redirect_stdout(io.StringIO()))
        quiet.enter_context(contextlib.redirect_stderr(io.StringIO()))
        with quiet, tempfile.TemporaryDirectory() as tmp:
            code = make_dataset_linguist.main(["--out-dir", tmp, "--seed", "3", "--per-cell", "1",
                                               "--eval-per-cell", "1", "--format", "compact"])
            self.assertEqual(code, 0)
            for split in make_dataset_linguist.SPLITS:
                path = pathlib.Path(tmp, f"linguist_{split}.jsonl")
                self.assertEqual(validate_dataset_linguist.check_file(self.catalog, path), [])
                first = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
                self.assertEqual(assistant(first)["v"], linguist.PROPOSAL_V)
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                make_dataset_linguist.main(["--out-dir", "x", "--format", "v0.2"])

    def test_recorded_compact_replies_score_through_the_core(self):
        records = self.splits["dev"][0][:4]
        results = eval_linguist.score_completions(records, [r["messages"][2]["content"] for r in records])
        for result in results:
            self.assertTrue(result["core_accepts"], result)
            self.assertEqual(result["corrections"], [], result)
            self.assertTrue(result["semantic_ok"], result)
        metrics = eval_linguist.aggregate(results, records, [{} for _ in records])
        self.assertEqual(metrics["all"]["semantic_ok"], 1.0)

    def test_the_gate_serves_the_form_the_split_was_built_for(self):
        compact = self.splits["blind"][0]
        self.assertEqual(eval_linguist.split_form(compact), "compact")
        full = make_dataset_linguist.build_splits(self.catalog, self.book, 7, SIZES)["blind"][0]
        self.assertEqual(eval_linguist.split_form(full), "full")
        with self.assertRaises(SystemExit):
            eval_linguist.split_form(compact[:1] + full[:1])
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp, "config.json")
            config.write_text(json.dumps({"model": {"endpoint": "tcp:127.0.0.1:1", "output": "compact"}}))
            self.assertEqual(eval_linguist.config_form(config), "compact")
            config.write_text(json.dumps({"model": {"endpoint": "tcp:127.0.0.1:1"}}))
            self.assertEqual(eval_linguist.config_form(config), "full")


class DecodingSchemaTest(unittest.TestCase):
    """0017 L8: the schema the runtime sends admits every proposal the generator makes, and no other."""

    @classmethod
    def setUpClass(cls):
        import jsonschema
        cls.catalog = linguist.load_catalog()
        book = linguist.load_json(linguist.PHRASEBOOK_PATH)
        request = core_bridge.render_prompts([("x", None)], compact=True)[0]["request"]
        cls.response_format = request["response_format"]
        cls.validator = jsonschema.Draft202012Validator(cls.response_format["json_schema"]["schema"])
        cls.proposals = [assistant(r) for split in make_dataset_linguist.SPLITS
                         for r in make_dataset_linguist.build(cls.catalog, book, split, 5, 3, fmt="compact")]

    def test_the_request_names_llama_server_json_schema(self):
        self.assertEqual(set(self.response_format), {"type", "json_schema"})
        self.assertEqual(self.response_format["type"], "json_schema")
        self.assertEqual(set(self.response_format["json_schema"]), {"schema"})
        import jsonschema
        jsonschema.Draft202012Validator.check_schema(self.response_format["json_schema"]["schema"])

    def test_every_generated_proposal_validates(self):
        self.assertTrue(any(p.get("then") for p in self.proposals))
        self.assertTrue(any(p["intent"] is None for p in self.proposals))
        for proposal in self.proposals:
            errors = list(self.validator.iter_errors(proposal))
            self.assertEqual(errors, [], proposal)

    def test_foreign_intents_slots_long_values_and_undeclared_compositions_fail(self):
        base = {"v": "0.2", "lang": "en", "intent": "timer.set", "missing": [], "slots": {"duration": "5 minutes"}}
        composed = {"v": "0.2", "lang": "en", "intent": "task.summarize", "missing": [],
                    "slots": {"source": "the report"},
                    "then": [{"intent": "messaging.send", "slots": {"recipient": "Lea"}}]}
        self.assertTrue(self.validator.is_valid(base))
        self.assertTrue(self.validator.is_valid(composed))
        bad = {
            "foreign intent": dict(base, intent="payments.transfer"),
            "foreign slot": dict(base, slots={"duration": "5 minutes", "recipient": "Lea"}),
            "slot of another intent": dict(base, intent="task.note"),
            "over-long slot": dict(base, slots={"duration": "5" * 513}),
            "empty slot": dict(base, slots={"duration": ""}),
            "non-string slot": dict(base, slots={"duration": 5}),
            "foreign locale": dict(base, lang="fr"),
            "v0.1": dict(base, v="0.1"),
            "derived member": dict(base, missing_slots=[]),
            "residency": dict(base, residency=["CH"]),
            "undeclared composition": dict(base, then=[{"intent": "messaging.send", "slots": {}}]),
            "composition in reverse": {"v": "0.2", "lang": "en", "intent": "messaging.send",
                                       "missing": ["topic"], "slots": {"recipient": "Lea"},
                                       "then": [{"intent": "task.summarize", "slots": {}}]},
            "three follow-ups": dict(composed, then=composed["then"] * 3),
            "two follow-ups not declared": dict(composed, then=composed["then"] * 2),
            "empty then": dict(composed, then=[]),
            "follow-up extra member": dict(composed, then=[dict(composed["then"][0], missing_slots=[])]),
            "follow-up foreign slot": dict(composed, then=[{"intent": "messaging.send",
                                                             "slots": {"source": "x"}}]),
            "null intent with slots": dict(base, intent=None),
            "missing slot also given": dict(base, missing=["duration"]),
            "required slot neither given nor missing": dict(base, slots={}),
            "null intent with then": {"v": "0.2", "lang": "en", "intent": None, "missing": [], "slots": {},
                                      "then": composed["then"]},
        }
        for name, proposal in bad.items():
            with self.subTest(case=name):
                self.assertFalse(self.validator.is_valid(proposal), proposal)


if __name__ == "__main__":
    unittest.main()

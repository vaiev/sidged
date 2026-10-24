# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Tests for the companion linguist (Model -1) contract, data and validator.

Stdlib only, no GPU, no model download, no training. Run from the repo root:
    python3 -I -m unittest discover -s local-training/tests -t local-training
"""
import json
import pathlib
import random
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import chat_split  # noqa: E402
import core_bridge  # noqa: E402
import linguist  # noqa: E402
import make_dataset_linguist  # noqa: E402
import validate_dataset_linguist  # noqa: E402

FIXTURE = linguist.HERE.parent / "runtime" / "sidged-cli" / "tests" / "fixtures" / "linguist-prompt.json"


def frame_slots(frame):
    return set(linguist.PLACEHOLDER.findall(frame))


class ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = linguist.load_catalog()
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_prompt_bytes_from_the_core_match_the_runtime_fixture(self):
        prompt = self.fixture["prompt"]
        system, user = core_bridge.render_prompt(prompt["utterance"], prompt["intent_ids"])
        self.assertEqual(system, prompt["system"])
        self.assertEqual(user, prompt["user"])

    def test_composition_derivation_matches_the_runtime_fixture(self):
        for vector in self.fixture["derive_then"]:
            then = [(f["intent"], f["slots"]) for f in vector["then"]]
            envelope = linguist.derive_with_then(self.catalog, vector["lang"], vector["intent"], vector["slots"], then)
            self.assertEqual(envelope, vector["expected"])
            self.assertEqual(linguist.check_envelope(self.catalog, envelope), [])

    def test_derivation_matches_the_runtime_fixture(self):
        for vector in self.fixture["derive"]:
            with self.subTest(vector=vector["expected"]["canonical_intent_en"]):
                envelope = linguist.derive_envelope(self.catalog, vector["lang"], vector["intent"], vector["slots"])
                self.assertEqual(envelope, vector["expected"])
                self.assertEqual(list(envelope), list(linguist.ENVELOPE_KEYS))

    def test_missing_slots_follow_catalog_order_and_ask_the_first(self):
        envelope = linguist.derive_envelope(self.catalog, "gsw", "messaging.send", {})
        self.assertEqual(envelope["missing_slots"], ["recipient", "topic"])
        self.assertTrue(envelope["clarification_needed"])
        self.assertEqual(envelope["suggested_route"], "clarify")
        entry = linguist.intents_by_id(self.catalog)["messaging.send"]
        self.assertEqual(envelope["clarification_question_local"],
                         entry["slots_schema"]["properties"]["recipient"]["x-ask"]["gsw"])

    def test_optional_slot_never_triggers_clarification(self):
        envelope = linguist.derive_envelope(self.catalog, "en", "task.code", {"description": "a CSV parser"})
        self.assertFalse(envelope["clarification_needed"])
        self.assertEqual(envelope["suggested_route"], "swarm-worker")

    def test_core_rejects_inconsistent_proposals(self):
        good = linguist.derive_envelope(self.catalog, "de", "scheduling.remind", {"subject": "the laundry"})
        self.assertEqual(linguist.check_envelope(self.catalog, good), [])
        for key, value in [("clarification_needed", False), ("missing_slots", []),
                           ("suggested_route", "edge-local"), ("required_data_classes", []),
                           ("intent", "x.unknown")]:
            bad = dict(good, **{key: value})
            with self.subTest(key=key):
                self.assertTrue(linguist.check_envelope(self.catalog, bad))
        self.assertTrue(linguist.check_envelope(self.catalog, dict(good, residency=["CH"])))
        self.assertTrue(linguist.check_envelope(self.catalog, dict(good, slots={"place": "home"})))

    def test_unknown_locale_and_intent_are_errors(self):
        with self.assertRaises(ValueError):
            linguist.derive_envelope(self.catalog, "fr", None, {})
        with self.assertRaises(ValueError):
            linguist.derive_envelope(self.catalog, "en", "x.unknown", {})


class PhrasebookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = linguist.load_catalog()
        cls.book = linguist.load_json(linguist.PHRASEBOOK_PATH)

    def test_every_catalog_intent_has_frames_in_every_locale(self):
        self.assertEqual(set(self.book["intents"]), set(linguist.intents_by_id(self.catalog)))
        for entry in self.catalog["intents"]:
            book = self.book["intents"][entry["intent"]]
            properties = entry["slots_schema"]["properties"]
            self.assertEqual(set(book["pools"]), set(properties), entry["intent"])
            for pools in book["pools"].values():
                for pool in pools:
                    self.assertIn(pool, self.book["pools"])
            for lang in self.catalog["locales"]:
                for key in ("frames", "eval_frames"):
                    with self.subTest(intent=entry["intent"], lang=lang, key=key):
                        self.assertTrue(book[key][lang])
                        for frame in book[key][lang]:
                            self.assertLessEqual(frame_slots(frame), set(properties), frame)

    def test_frames_cover_complete_and_each_missing_required_slot(self):
        for entry in self.catalog["intents"]:
            required = set(entry["slots_schema"]["required"])
            for lang in self.catalog["locales"]:
                frames = self.book["intents"][entry["intent"]]["frames"][lang]
                with self.subTest(intent=entry["intent"], lang=lang):
                    self.assertTrue(any(required <= frame_slots(f) for f in frames), "no complete frame")
                    for slot in required:
                        self.assertTrue(any(slot not in frame_slots(f) for f in frames), f"{slot} never missing")

    def test_eval_frames_are_never_trained_on(self):
        for name, book in self.book["intents"].items():
            for lang in self.catalog["locales"]:
                with self.subTest(intent=name, lang=lang):
                    self.assertFalse(set(book["frames"][lang]) & set(book["eval_frames"][lang]))

    def test_pools_speak_every_locale(self):
        for name, entries in self.book["pools"].items():
            langs = set()
            for entry in entries:
                langs |= set(self.catalog["locales"]) if isinstance(entry, str) else set(entry) - {"canonical"}
            with self.subTest(pool=name):
                self.assertEqual(langs, set(self.catalog["locales"]))


class DatasetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = linguist.load_catalog()
        cls.book = linguist.load_json(linguist.PHRASEBOOK_PATH)

    def test_generated_splits_are_valid_and_cover_every_case(self):
        for split in make_dataset_linguist.SPLITS:
            records = make_dataset_linguist.build(self.catalog, self.book, split, 7, 4, ["isch scho guet so"])
            intents, langs, kinds = set(), set(), set()
            for record in records:
                self.assertEqual(validate_dataset_linguist.check_record(self.catalog, record), [], record)
                envelope = json.loads(record["messages"][2]["content"])
                intents.add(envelope["intent"])
                langs.add(envelope["lang"])
                kinds.add("null" if envelope["intent"] is None else
                          "missing" if envelope["missing_slots"] else "complete")
            with self.subTest(split=split):
                self.assertEqual(langs, set(self.catalog["locales"]))
                self.assertEqual(kinds, {"null", "missing", "complete"})
                if split == "train":
                    self.assertEqual(intents - {None}, set(linguist.intents_by_id(self.catalog)))

    def test_generation_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = pathlib.Path(tmp, "a.jsonl"), pathlib.Path(tmp, "b.jsonl")
            first = make_dataset_linguist.write(a, make_dataset_linguist.build(self.catalog, self.book, "train", 3, 2))
            second = make_dataset_linguist.write(b, make_dataset_linguist.build(self.catalog, self.book, "train", 3, 2))
            self.assertEqual(first, second)
            self.assertEqual(validate_dataset_linguist.check_file(self.catalog, a), [])

    def test_validator_refuses_core_fields_pii_and_foreign_intents(self):
        record = make_dataset_linguist.build(self.catalog, self.book, "train", 5, 1)[0]
        envelope = json.loads(record["messages"][2]["content"])
        for mutate, needle in [
            (lambda e: e.update(residency=["CH"]), "keys"),
            (lambda e: e.update(approval=True), "forbidden key"),
            (lambda e: e.update(intent="x.unknown"), "unknown intent"),
        ]:
            changed = dict(envelope)
            mutate(changed)
            bad = json.loads(json.dumps(record))
            bad["messages"][2]["content"] = json.dumps(changed)
            errors = validate_dataset_linguist.check_record(self.catalog, bad)
            self.assertTrue(any(needle in e for e in errors), (needle, errors))
        bad = json.loads(json.dumps(record))
        bad["messages"][1]["content"] = bad["messages"][1]["content"].rsplit("\nUtterance: ", 1)[0] + \
            "\nUtterance: call +41 79 123 45 67"
        self.assertTrue(any("phone" in e for e in validate_dataset_linguist.check_record(self.catalog, bad)))
        bad = json.loads(json.dumps(record))
        bad["messages"][1]["content"] = "Catalog:\n- made.up | x\nUtterance: hi"
        self.assertTrue(any("catalog subset" in e for e in validate_dataset_linguist.check_record(self.catalog, bad)))
        bad = json.loads(json.dumps(record))
        bad["messages"][0]["content"] += " "
        self.assertTrue(any("system prompt" in e for e in validate_dataset_linguist.check_record(self.catalog, bad)))

    def test_out_of_catalog_utterances_become_intent_null(self):
        records = make_dataset_linguist.build(self.catalog, self.book, "train", 11, 20)
        for record in records:
            envelope = json.loads(record["messages"][2]["content"])
            if envelope["intent"] is not None:
                self.assertIn(f"- {envelope['intent']} |", record["messages"][1]["content"])

    def test_chat_negatives_drop_requests_pii_and_excluded_terms(self):
        lines = ["isch scho guet so, mir gseh üs",
                 "chasch mer morn schriibe wenn bisch da",
                 "mini nummere isch +41 79 123 45 67 u so",
                 "ig bi hüt bim zzexcludedterm gsi",
                 "isch scho guet so, mir gseh üs",
                 "hi"]
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp, "chat.txt")
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            terms = pathlib.Path(tmp, "terms.txt")
            terms.write_text("# test\nzzexcluded\n", encoding="utf-8")
            exclude = make_dataset_linguist.load_exclude_terms(terms)
            kept = make_dataset_linguist.chat_negatives(path, 10, random.Random("chat"), exclude)
            self.assertEqual(kept, ["isch scho guet so, mir gseh üs"])
            self.assertEqual(make_dataset_linguist.chat_negatives(path, 10, random.Random("chat"), exclude, 1), [])


class DialectTreeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = json.loads(make_dataset_linguist.LEXICON_PATH.read_text(encoding="utf-8"))
        cls.lexicon = make_dataset_linguist.load_lexicon()
        cls.book = linguist.load_json(linguist.PHRASEBOOK_PATH)

    def test_every_node_has_forms_in_every_region(self):
        for name, entry in self.raw["nodes"].items():
            for region in make_dataset_linguist.REGIONS:
                with self.subTest(node=name, region=region):
                    self.assertTrue(entry[region])
                    self.assertEqual(len(entry[region]), len(set(entry[region])))

    def test_frames_name_only_known_nodes_and_only_in_swiss_german(self):
        texts = [(lang, f) for book in self.book["intents"].values() for key in ("frames", "eval_frames")
                 for lang, frames in book[key].items() for f in frames]
        texts += [(lang, f) for lang, phrases in self.book["unmatched"].items() for f in phrases]
        for lang, text in texts:
            for node in make_dataset_linguist.NODE.findall(text):
                with self.subTest(text=text):
                    self.assertEqual(lang, "gsw")
                    self.assertIn(node, self.raw["nodes"])

    def test_one_utterance_speaks_one_region(self):
        rng = random.Random(7)
        text = "<nicht> <mal> <kannst_du> <wegen>"
        for region in make_dataset_linguist.REGIONS:
            for _ in range(20):
                words = make_dataset_linguist.realize(text, region, self.lexicon, rng).lower().split()
                forms = [self.raw["nodes"][n][region] for n in ("nicht", "mal", "kannst_du", "wegen")]
                self.assertEqual(len(words), 4)
                for word, allowed in zip(words, forms):
                    self.assertIn(word, [f.lower() for f in allowed], region)

    def test_walk_covers_every_leaf_before_repeating(self):
        cell = make_dataset_linguist.leaves(["<schreib> {recipient}", "Schick e Nachricht"], "gsw")
        self.assertEqual(len(cell), 4)
        self.assertIn(("Schick e Nachricht", "gen"), cell)
        order = make_dataset_linguist.walk(cell, 9, random.Random(3))
        self.assertEqual(set(order[:4]), set(cell))
        self.assertEqual(set(order[4:8]), set(cell))

    def test_eval_meta_names_the_region_of_each_record(self):
        catalog = linguist.load_catalog()
        records, meta = make_dataset_linguist.build(catalog, self.book, "blind", 1, 2, (), 1.5, self.lexicon,
                                                    with_meta=True)
        self.assertEqual(len(records), len(meta))
        langs = {json.loads(r["messages"][2]["content"])["lang"] for r, m in zip(records, meta)
                 if m["region"] in make_dataset_linguist.REGIONS}
        self.assertEqual(langs, {"gsw"})
        self.assertTrue({"be", "zh", "bs"} <= {m["region"] for m in meta})


class ProbeTest(unittest.TestCase):
    def test_probes_are_never_training_or_eval_text(self):
        book = linguist.load_json(linguist.PHRASEBOOK_PATH)
        lexicon = make_dataset_linguist.load_lexicon()
        catalog = linguist.load_catalog()
        probes = json.loads((linguist.HERE / "linguist_probes.json").read_text(encoding="utf-8"))["probes"]
        intents = set(linguist.intents_by_id(catalog))
        texts = {f for b in book["intents"].values() for key in ("frames", "eval_frames")
                 for frames in b[key].values() for f in frames}
        texts |= {f for phrases in book["unmatched"].values() for f in phrases}
        texts |= {f for c in book.get("compositions", []) for key in ("frames", "eval_frames")
                  for frames in c[key].values() for f in frames}
        raw = json.loads(make_dataset_linguist.LEXICON_PATH.read_text(encoding="utf-8"))["nodes"]

        def expand(text, region):
            # every realization of a slot-free text in one region
            match = make_dataset_linguist.NODE.search(text)
            if not match:
                return [text]
            out = []
            for form in raw[match.group(1)][region]:
                form = form[:1].upper() + form[1:] if match.start() == 0 else form
                out += expand(text[:match.start()] + form + text[match.end():], region)
            return out

        realized = {u.lower() for t in texts if "{" not in t
                    for r in make_dataset_linguist.REGIONS for u in expand(t, r)}
        self.assertTrue(lexicon)
        for probe in probes:
            with self.subTest(probe=probe["u"]):
                self.assertTrue(probe["intent"] is None or probe["intent"] in intents)
                self.assertNotIn(probe["u"], texts)
                self.assertNotIn(probe["u"].lower(), realized)


class ChatSplitTest(unittest.TestCase):
    def test_messages_become_pseudonymous_single_utterances(self):
        lines = [
            "01.02.24, 10:00 - Ana: isch scho guet. mir gseh üs morn",
            "01.02.24, 10:01 - Ben: <Medien ausgeschlossen>",
            "01.02.24, 10:02 - Ana: lueg mau https://example.org",
            "01.02.24, 10:03 - Ben: i ha ke zit hüt",
            "zweiti zile vo de nachricht",
            "01.02.24, 10:04 - Ana hat die Gruppe verlassen",
        ]
        other = ["02.02.24, 09:00 - Ana: hoi zäme, wie geits?"]
        with tempfile.TemporaryDirectory() as tmp:
            a, b = pathlib.Path(tmp, "a.txt"), pathlib.Path(tmp, "b.txt")
            a.write_text("\n".join(lines) + "\n", encoding="utf-8")
            b.write_text("\n".join(other) + "\n", encoding="utf-8")
            rows, stats = chat_split.split_chats([str(a), str(b)], None)
        texts = [(r["speaker"], r["text"]) for r in rows]
        self.assertIn(("owner", "isch scho guet."), texts)
        self.assertIn(("owner", "mir gseh üs morn"), texts)
        self.assertIn(("peer", "i ha ke zit hüt"), texts)
        self.assertIn(("peer", "zweiti zile vo de nachricht"), texts)
        self.assertFalse(any("http" in t or "Medien" in t for _, t in texts))
        self.assertFalse(any("Ana" in json.dumps(r) or "Ben" in json.dumps(r) for r in rows))
        self.assertEqual(stats["chats"], 2)


if __name__ == "__main__":
    unittest.main()


class ReleaseGateTest(unittest.TestCase):
    """ROADMAP 13e part A: splits that measure generalisation, scored by the Core."""

    SIZES = {"train": (3, 1.0), "dev": (2, 1.0), "blind": (2, 1.0)}

    @classmethod
    def setUpClass(cls):
        cls.catalog = linguist.load_catalog()
        cls.book = linguist.load_json(linguist.PHRASEBOOK_PATH)

    def build(self, sizes=None, negatives=None):
        return make_dataset_linguist.build_splits(self.catalog, self.book, 11, sizes or self.SIZES, negatives)

    def test_no_normalised_utterance_is_in_two_splits(self):
        # The same chat line, varied in case, spacing and punctuation, offered to every split.
        line = "Isch   scho guet so, merci!"
        variants = {"blind": [line], "dev": [line.lower()], "train": [line.upper().replace(",", "")]}
        splits = self.build(negatives=variants)
        seen = {}
        for split, (records, _meta) in splits.items():
            for record in records:
                key = make_dataset_linguist.normalise(make_dataset_linguist._utterance(record))
                self.assertIn(seen.setdefault(key, split), (split,), f"{key!r} in {seen[key]} and {split}")
        self.assertEqual(seen[make_dataset_linguist.normalise(line)], "blind")

    def test_the_blind_split_does_not_depend_on_train_or_dev_settings(self):
        small = self.build()
        large = self.build({"train": (6, 1.0), "dev": (4, 1.0), "blind": (2, 1.0)})
        self.assertEqual(small["blind"][0], large["blind"][0])

    def test_a_frozen_blind_split_is_kept_and_excluded_from_train_and_dev(self):
        frozen = self.build()
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "linguist_blind.jsonl"
            make_dataset_linguist.write(path, frozen["blind"][0])
            make_dataset_linguist.meta_path(path).write_text(
                "".join(json.dumps(m) + "\n" for m in frozen["blind"][1]), encoding="utf-8")
            # Other data settings and a phrasebook with one family fewer: the blind split stays the frozen one.
            book = json.loads(json.dumps(self.book))
            book["intents"]["messaging.send"]["frames"]["en"].pop(0)
            for fmt in make_dataset_linguist.FORMATS:
                with self.subTest(fmt=fmt):
                    splits = make_dataset_linguist.build_splits(
                        self.catalog, book, 12, {"train": (6, 1.0), "dev": (4, 1.0), "blind": (3, 1.0)},
                        fmt=fmt, frozen_blind=path)
                    blind, meta = splits["blind"]
                    self.assertEqual(meta, frozen["blind"][1])
                    utterances = [make_dataset_linguist._utterance(r) for r in blind]
                    self.assertEqual(utterances, [make_dataset_linguist._utterance(r) for r in frozen["blind"][0]])
                    if fmt == "full":
                        self.assertEqual(blind, frozen["blind"][0])
                    else:
                        self.assertEqual([linguist.derive_proposal(self.catalog, json.loads(r["messages"][2]["content"]))
                                          for r in blind],
                                         [json.loads(r["messages"][2]["content"]) for r in frozen["blind"][0]])
                    held = {make_dataset_linguist.normalise(u) for u in utterances}
                    for split in ("train", "dev"):
                        leaked = [u for u in map(make_dataset_linguist._utterance, splits[split][0])
                                  if make_dataset_linguist.normalise(u) in held]
                        self.assertEqual(leaked, [], split)

    def test_dev_and_blind_prompts_show_the_whole_catalog(self):
        ids = set(linguist.intents_by_id(self.catalog))
        splits = self.build()
        for split in make_dataset_linguist.HELD_OUT:
            for record in splits[split][0]:
                prompt = record["messages"][0]["content"] + record["messages"][1]["content"]
                missing = {i for i in ids if i not in prompt}
                self.assertEqual(missing, set(), f"{split}: prompt omits {sorted(missing)}")

    def test_the_core_refuses_a_completion_that_adds_a_core_field(self):
        record = self.build()["dev"][0][0]
        expected = json.loads(record["messages"][2]["content"])
        good = json.dumps(expected, ensure_ascii=False)
        bad = dict(expected, residency="CH")
        utterance = make_dataset_linguist._utterance(record)
        ok, refused = core_bridge.score([
            {"utterance": utterance, "completion": good, "expected": expected},
            {"utterance": utterance, "completion": json.dumps(bad, ensure_ascii=False), "expected": expected},
        ])
        self.assertTrue(ok["core_accepts"], ok)
        self.assertFalse(refused["core_accepts"], refused)
        self.assertTrue(ok["legacy_effective"], ok)
        # The old metric could not see the refusal: that is why it no longer gates a release.
        self.assertTrue(refused["legacy_effective"], refused)

    def test_trainers_seed_before_the_adapter_is_created(self):
        for name in ("train_companion_linguist.py", "experimental/train_edge_llm.py",
                     "experimental/train_planner_think.py"):
            text = (linguist.HERE / name).read_text(encoding="utf-8")
            with self.subTest(trainer=name):
                self.assertLess(text.index("seed_everything("), text.index("get_peft_model(model"))


class TrainingTimeEvalTest(unittest.TestCase):
    """evaluate() without a model: generation is replaced by recorded replies."""

    def test_evaluate_scores_recorded_replies_and_reports(self):
        import train_companion_linguist as trainer
        catalog = linguist.load_catalog()
        book = linguist.load_json(linguist.PHRASEBOOK_PATH)
        records, meta = make_dataset_linguist.build_splits(
            catalog, book, 5, ReleaseGateTest.SIZES)["dev"]
        records, meta = records[:3], meta[:3]
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp, "dev.jsonl")
            make_dataset_linguist.write(path, records)
            make_dataset_linguist.meta_path(path).write_text(
                "".join(json.dumps(m) + "\n" for m in meta), encoding="utf-8")
            replies = [r["messages"][2]["content"] for r in records]
            original = trainer.generate
            trainer.generate = lambda out, recs, device: (replies, {"seconds": 1.0, "tokens_per_second": 1.0})
            try:
                report = trainer.evaluate(path, tmp, device="cpu")
            finally:
                trainer.generate = original
        self.assertEqual(report["record_count"], 3)
        self.assertEqual(report["metrics"]["all"]["core_accepted"], 1.0)


class ProbeVerdictTest(unittest.TestCase):
    def test_a_probe_fails_when_the_clarification_is_wrong(self):
        import probe_linguist
        result = {"core_accepts": True, "semantic_ok": True, "clarification_ok": False, "intent_ok": True,
                  "kept": {"intent": "timer.set", "clarification_needed": True}, "invented_slots": [],
                  "missing_slots": [], "wrong_slots": [], "extra_followups": [], "missing_followups": []}
        ok, why = probe_linguist.verdict(result)
        self.assertFalse(ok)
        self.assertIn("asks back", why)

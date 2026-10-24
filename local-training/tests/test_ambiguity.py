# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Utterances German and Swiss German write the same (ROADMAP 13e): the gate accepts either language.

Stdlib only, no GPU, no model, no owner data. Run from the repo root:
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

import annotate_langs  # noqa: E402
import eval_linguist  # noqa: E402
import linguist  # noqa: E402
import make_dataset_linguist  # noqa: E402

SIZES = {"train": (2, 1.0), "dev": (2, 1.0), "blind": (2, 1.0)}


class AmbiguityRuleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = linguist.load_catalog()
        cls.book = linguist.load_json(linguist.PHRASEBOOK_PATH)
        cls.lexicon = make_dataset_linguist.load_lexicon()

    def langs(self, utterance, lang, intent, slots, then=()):
        envelope = linguist.derive_with_then(self.catalog, lang, intent, slots, then)
        return make_dataset_linguist.record_langs(self.book, self.lexicon, utterance, envelope)

    def test_a_string_both_generators_write_for_the_same_target_takes_either_language(self):
        find = {"query": "report.pdf", "folder": "Documents"}
        # de and gsw eval frame "Such {query} in {folder}"; the record's own language comes first.
        self.assertEqual(self.langs("Such report.pdf in Documents", "de", "files.find", find), ["de", "gsw"])
        self.assertEqual(self.langs("such report.pdf in Documents!", "gsw", "files.find", find), ["gsw", "de"])
        # "Hallo, " is a German greeting the Swiss German generator never writes.
        self.assertEqual(self.langs("Hallo, such report.pdf in Documents", "de", "files.find", find), ["de"])
        # Another target: the Swiss German generator writes the words, but not for this folder.
        self.assertEqual(self.langs("Such report.pdf in Downloads", "de", "files.find", find), ["de"])
        self.assertEqual(self.langs("Finde report.pdf", "de", "files.find", {"query": "report.pdf"}), ["de"])
        # English is never in the set: the rule is about German and Swiss German only.
        self.assertEqual(self.langs("Find report.pdf", "gsw", "files.find", {"query": "report.pdf"}), ["gsw"])
        self.assertEqual(self.langs("Find report.pdf", "en", "files.find", {"query": "report.pdf"}), ["en"])

    def test_unmatched_phrases_and_lexicon_forms_count(self):
        def langs(book, lexicon, utterance, lang, intent, slots):
            envelope = linguist.derive_envelope(self.catalog, lang, intent, slots)
            return make_dataset_linguist.record_langs(book, lexicon, utterance, envelope)

        find = {"query": "report.pdf", "folder": "Documents"}
        utterance = "Such report.pdf im Ordner Documents"
        # Without the literal Swiss German frame, "<such> {query} im Ordner {folder}" still writes it
        # through the lexicon form "such"; a lexicon without that form does not.
        book = json.loads(json.dumps(self.book))
        book["intents"]["files.find"]["frames"]["gsw"].remove("Such {query} im Ordner {folder}")
        self.assertEqual(langs(book, self.lexicon, utterance, "de", "files.find", find), ["de", "gsw"])
        lexicon = {name: {region: ([f for f in forms if f != "such"] or forms, weights)
                          for region, (forms, weights) in regions.items()}
                   for name, regions in self.lexicon.items()}
        self.assertEqual(langs(book, lexicon, utterance, "de", "files.find", find), ["de"])
        # Intent null: the other language's unmatched phrases.
        book["unmatched"]["gsw"].append("Mach das")
        self.assertEqual(langs(book, self.lexicon, "mach das!", "de", None, {}), ["de", "gsw"])
        self.assertEqual(langs(book, self.lexicon, "Mach das", "gsw", None, {}), ["gsw", "de"])
        self.assertEqual(langs(self.book, self.lexicon, "Mach das", "de", None, {}), ["de"])
        self.assertEqual(self.langs("Hoi zäme", "gsw", None, {}), ["gsw"])

    def test_the_decision_depends_on_nothing_but_the_record_and_the_phrasebook(self):
        records, meta = make_dataset_linguist.build(self.catalog, self.book, "blind", 3, 3, (), 1.0, self.lexicon,
                                                    with_meta=True)
        again = make_dataset_linguist.annotate(self.book, self.lexicon, records)
        self.assertEqual([m["langs"] for m in meta], again)
        for record, m in zip(records, meta):
            target = json.loads(record["messages"][2]["content"])
            self.assertEqual(m["langs"][0], target["lang"])
            self.assertTrue(set(m["langs"]) <= {"de", "gsw"} or m["langs"] == [target["lang"]], m)


class AnnotateBlindTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = linguist.load_catalog()
        cls.book = linguist.load_json(linguist.PHRASEBOOK_PATH)

    def test_every_split_carries_langs_and_training_targets_keep_one_language(self):
        splits = make_dataset_linguist.build_splits(self.catalog, self.book, 7, SIZES)
        for split, (records, meta) in splits.items():
            for record, m in zip(records, meta):
                target = json.loads(record["messages"][2]["content"])
                self.assertIsInstance(target["lang"], str)
                self.assertEqual(m["langs"][0], target["lang"], split)

    def test_an_annotated_blind_split_keeps_its_record_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()):
                written = make_dataset_linguist.write_splits(tmp, self.catalog, self.book, 7, SIZES)
            path = written["blind"][0]
            data = path.read_bytes()
            sidecar = make_dataset_linguist.meta_path(path)
            built = [json.loads(line) for line in sidecar.read_text(encoding="utf-8").splitlines()]
            # A sidecar written before this member existed.
            old = [{k: v for k, v in m.items() if k != "langs"} for m in built]
            sidecar.write_text("".join(json.dumps(m, ensure_ascii=False) + "\n" for m in old), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(annotate_langs.main([str(path)]), 0)
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual([json.loads(line) for line in sidecar.read_text(encoding="utf-8").splitlines()], built)
            # A sidecar that does not belong to the split is refused and left alone.
            sidecar.write_text("".join(json.dumps(m) + "\n" for m in old[:-1]), encoding="utf-8")
            with self.assertRaises(SystemExit):
                annotate_langs.main([str(path)])
            self.assertEqual(len(sidecar.read_text(encoding="utf-8").splitlines()), len(old) - 1)
            self.assertEqual(path.read_bytes(), data)


class GateExpectationTest(unittest.TestCase):
    def test_the_gate_expects_the_sidecar_langs_and_reports_the_strict_number(self):
        catalog = linguist.load_catalog()
        envelope = linguist.derive_envelope(catalog, "de", "files.find", {"query": "report.pdf", "folder": "Documents"})
        record = {"messages": [{"role": "system", "content": "s"},
                               {"role": "user", "content": "x\nUtterance: Such report.pdf in Documents"},
                               {"role": "assistant", "content": linguist.dumps(envelope)}]}
        records, meta = [record, record], [{"region": None, "langs": ["de", "gsw"]}] * 2
        replies = [linguist.dumps(envelope), linguist.dumps(dict(envelope, lang="gsw"))]
        results = eval_linguist.score_completions(records, replies, meta)
        self.assertEqual([r["semantic_ok"] for r in results], [True, True])
        self.assertEqual([r["lang_strict_ok"] for r in results], [True, False])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            report = eval_linguist.report("t", results, records, meta)
        self.assertEqual(report["metrics"]["all"]["semantic_ok"], 1.0)
        self.assertEqual(report["metrics"]["all"]["semantic_ok_lang_strict"], 0.5)
        self.assertIn("lang_strict", out.getvalue())
        # Buckets keep the language the record was generated in.
        self.assertIn("lang:de", report["metrics"])
        # Without a sidecar the expectation is the target's own language.
        self.assertEqual([r["semantic_ok"] for r in eval_linguist.score_completions(records, replies)],
                         [True, False])


class EnvelopeSlotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = linguist.load_catalog()

    def test_check_envelope_refuses_what_check_proposal_refuses(self):
        for value in ("x" * 513, "a\u0007b", "line\nbreak", "  "):
            envelope = linguist.derive_envelope(self.catalog, "en", "task.note", {"content": value})
            with self.subTest(value=value[:12]):
                self.assertNotEqual(linguist.check_envelope(self.catalog, envelope), [])
                self.assertNotEqual(linguist.check_proposal(self.catalog, linguist.compact(envelope, self.catalog)), [])
        then = linguist.derive_with_then(self.catalog, "en", "task.summarize", {"source": "report.pdf"},
                                         [("messaging.send", {"recipient": "x" * 513})])
        self.assertNotEqual(linguist.check_envelope(self.catalog, then), [])
        ok = linguist.derive_envelope(self.catalog, "en", "task.note", {"content": "x" * 512})
        self.assertEqual(linguist.check_envelope(self.catalog, ok), [])

    def test_generated_full_data_passes_the_stricter_check(self):
        splits = make_dataset_linguist.build_splits(self.catalog, linguist.load_json(linguist.PHRASEBOOK_PATH), 3,
                                                    SIZES)
        for split, (records, _meta) in splits.items():
            for record in records:
                target = json.loads(record["messages"][2]["content"])
                self.assertEqual(linguist.check_envelope(self.catalog, target), [], split)


if __name__ == "__main__":
    unittest.main()

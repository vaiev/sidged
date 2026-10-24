# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""check_published.py: a published copy of the spec passes only when it is this commit's."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import check_published
import validate


class PublishedSpec(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        for part in check_published.PARTS:
            shutil.copytree(validate.SPEC / part, self.dir / part)

    def problems(self):
        return check_published.check(self.dir)

    def test_an_exact_copy_passes(self):
        self.assertEqual(self.problems(), [])

    def test_a_changed_byte_fails(self):
        path = self.dir / "schemas" / "plan.schema.json"
        path.write_bytes(path.read_bytes() + b"\n")
        self.assertIn("schemas/plan.schema.json: differs from this commit", self.problems())

    def test_a_missing_or_extra_file_fails(self):
        (self.dir / "registries" / "effects.md").unlink()
        (self.dir / "schemas" / "extra.schema.json").write_text("{}")
        problems = self.problems()
        self.assertIn("registries/effects.md: missing", problems)
        self.assertIn("schemas/extra.schema.json: not in this commit", problems)

    def test_a_wrong_id_or_an_unresolvable_ref_fails(self):
        path = self.dir / "schemas" / "refusal.schema.json"
        schema = json.loads(path.read_text())
        schema["$id"] = "https://example.org/refusal.schema.json"
        schema["properties"]["broken"] = {"$ref": "nowhere.schema.json"}
        path.write_text(json.dumps(schema))
        problems = self.problems()
        self.assertTrue(any("refusal: $id must be" in p for p in problems), problems)
        self.assertTrue(any("$ref nowhere.schema.json does not resolve" in p for p in problems), problems)

    def test_a_missing_directory_fails(self):
        shutil.rmtree(self.dir / "schemas")
        self.assertIn("schemas/: missing or empty", self.problems())


if __name__ == "__main__":
    unittest.main()

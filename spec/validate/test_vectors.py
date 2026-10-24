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
"""Run the shared conformance test vectors in test-vectors/ against the validator.

The validator implements the static operations (resource-covers, token-check,
envelope-check, residency-destination, residency-tag-syntax, session-check without signature
verification), and skips every vector that lists requires. It returns problems, not refusal codes,
so it compares accept or refuse only, and skips the other operations
(signatures, residency regions, and receive), which need a runtime. A sequence
vector runs only if the validator supports every step; it keeps no state
between steps because none of its operations has state.

Failures of normative vectors fail the tests. Failures of provisional vectors
(an interim reading of an open issue) are printed but never fail.

Run from the repository root:
  python -m unittest discover -s spec/validate -v   # with the other tests
  python spec/validate/test_vectors.py --summary    # summary only
"""

from __future__ import annotations

import base64
import json
import re
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate  # noqa: E402

VECTOR_DIR = validate.REPO / "spec" / "test-vectors"
VECTOR_SCHEMA = VECTOR_DIR / "vector.schema.json"
KEY_FILE = VECTOR_DIR / "keys" / "rfc8032-test-keys.json"
REGISTRY = validate.REPO / "spec" / "registries" / "refusal-reasons.md"


def suite_version() -> str:
    """The suite version. test-vectors/VERSION is its only source; vector files carry none."""
    return (VECTOR_DIR / "VERSION").read_text(encoding="utf-8").strip()


def vector_files() -> list[Path]:
    return sorted(p for p in VECTOR_DIR.rglob("*.json") if p != VECTOR_SCHEMA and p.parent.name != "keys")


def load_vectors() -> list[tuple[Path, dict]]:
    return [(path, vector) for path in vector_files() for vector in validate.load_json(path)["vectors"]]


def registered_reasons() -> set[str]:
    return set(re.findall(r"^\| `([a-z-]+)` \|", REGISTRY.read_text(encoding="utf-8"), re.MULTILINE))


class Runner:
    """Runs one vector against the validator. Returns 'pass', 'fail', or 'skip'."""

    def __init__(self):
        self.schemas, self.registry = validate.load_checked()
        tag_schema = {"$ref": validate.ID_PREFIX + "common.schema.json#/$defs/residencyTag"}
        self.tag_validator = Draft202012Validator(tag_schema, registry=self.registry, format_checker=FormatChecker())

    def outcome(self, document, schema: str) -> dict:
        problems = validate.validate_document(document, schema, self.schemas, self.registry)
        return {"result": "refuse" if problems else "accept"}

    def actual(self, operation: str, data: dict):
        if operation == "resource-covers":
            return {"value": validate.resource_covers(data["right"], data["resource"])}
        if operation == "capability-check":
            return self.outcome(data["descriptor"], "capability-descriptor")
        if operation == "plan-check":
            problems = validate.validate_document(data["plan"], "plan", self.schemas, self.registry)
            if not problems:
                problems = validate.check_plan_run(data)
            return {"result": "refuse" if problems else "accept"}
        if operation == "token-check":
            return self.outcome(data["token"], "capability-token")
        if operation == "envelope-check":
            return self.outcome(data["envelope"], "envelope")
        if operation == "residency-destination":
            problems = validate.residency_destination(data.get("tags"), data["destination"])
            return {"result": "refuse" if problems else "accept"}
        if operation == "approval-binding":
            return {"value": validate.approval_binding(data["request"], data["line"])}
        if operation == "egress-check":
            result, reason = validate.egress_check(data)
            return {"result": result, "reason": reason}
        if operation == "residency-tag-syntax":
            return {"value": self.tag_validator.is_valid(data["tag"])}
        if operation == "session-check":
            problems = validate.check_session(data["envelope"], data["core_kid"], self.schemas, self.registry)
            return {"result": "refuse" if problems else "accept"}
        return None

    @staticmethod
    def matches(expected: dict, actual: dict) -> bool:
        if "value" in expected:
            return actual == expected
        # The validator has no refusal codes and runs nothing, so only result is compared.
        if "result" in expected and actual.get("result") != expected["result"]:
            return False
        if "reason" in actual:  # only runners that report codes (egress-check)
            if actual["reason"] is None:
                return "reason" not in expected
            if "reason" not in expected:
                return False  # a refusal vector must name its reason
            want = expected["reason"]
            return actual["reason"] in (want if isinstance(want, list) else [want])
        return True

    def run(self, vector: dict) -> tuple[str, object]:
        if vector.get("requires"):
            return "skip", None  # the validator verifies no signatures and has no jcs
        if vector.get("kind") == "sequence":
            steps = vector["steps"]
        else:
            steps = [vector]
        results = []
        for step in steps:
            actual = self.actual(step["operation"], step["input"])
            if actual is None:
                return "skip", None
            results.append(actual)
            if not self.matches(step["expected"], actual):
                return "fail", results if len(steps) > 1 else actual
        return "pass", results if len(steps) > 1 else results[0]


class VectorFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = validate.load_json(VECTOR_SCHEMA)
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)
        cls.vectors = load_vectors()

    def test_files_exist(self):
        self.assertTrue(vector_files(), "no vector files found")

    def test_files_match_the_vector_schema(self):
        for path in vector_files():
            with self.subTest(file=str(path.relative_to(validate.REPO))):
                errors = [e.message for e in self.validator.iter_errors(validate.load_json(path))]
                self.assertEqual(errors, [])

    def test_schema_keeps_single_and_sequence_shapes_apart(self):
        single = {"id": "x.y.001", "spec": [{"doc": "L6", "section": "A5"}], "status": "normative",
                  "operation": "envelope-check", "input": {}, "expected": {"result": "accept"}}
        step = {"operation": "receive", "now": "2026-10-09T08:11:00Z", "input": {}, "expected": {"executed": False}}
        sequence = {"id": "x.y.002", "kind": "sequence", "spec": single["spec"], "status": "normative",
                    "state": {}, "steps": [step]}
        wrap = lambda vector: {"category": "envelope", "description": "d", "vectors": [vector]}
        self.assertTrue(self.validator.is_valid(wrap(single)))
        self.assertTrue(self.validator.is_valid(wrap(sequence)))
        self.assertFalse(self.validator.is_valid(wrap({**sequence, "input": {}})))
        self.assertFalse(self.validator.is_valid(wrap({**single, "steps": [step]})))
        self.assertFalse(self.validator.is_valid(wrap({**sequence, "steps": [{**step, "expected": {"reason": "replayed"}}]})))

    def test_open_issue_is_free_text(self):
        vector = {"id": "x.y.001", "spec": [{"doc": "L6", "section": "A5"}], "status": "provisional",
                  "operation": "envelope-check", "input": {}, "expected": {"result": "accept"}}
        wrap = lambda open_issue: {"category": "envelope", "description": "d",
                                   "vectors": [{**vector, "open_issue": open_issue}]}
        self.assertTrue(self.validator.is_valid(wrap("Whether a repeat is refused is still open.")))
        self.assertFalse(self.validator.is_valid(wrap("")))

    def test_version_is_semver(self):
        self.assertRegex(suite_version(), r"^[0-9]+\.[0-9]+\.[0-9]+$")

    def test_readme_states_the_version(self):
        readme = (VECTOR_DIR / "README.md").read_text(encoding="utf-8")
        match = re.search(r"current suite version is `([^`]+)`", readme)
        self.assertIsNotNone(match, "test-vectors/README.md must say: The current suite version is `X.Y.Z`")
        self.assertEqual(match.group(1), suite_version(), "test-vectors/README.md and VERSION disagree")

    def test_files_carry_no_suite_version(self):
        for path in vector_files():
            with self.subTest(file=str(path.relative_to(validate.REPO))):
                self.assertFalse("suite" in validate.load_json(path), "the suite version lives only in test-vectors/VERSION")

    def test_ids_are_unique(self):
        ids = [vector["id"] for _, vector in self.vectors]
        self.assertEqual(len(ids), len(set(ids)), "duplicate vector ids")

    def test_reasons_are_registered(self):
        reasons = registered_reasons()
        for _, vector in self.vectors:
            for expected in [step["expected"] for step in vector.get("steps", [])] or [vector["expected"]]:
                reason = expected.get("reason")
                for code in [reason] if isinstance(reason, str) else reason or []:
                    with self.subTest(vector=vector["id"]):
                        self.assertIn(code, reasons)

    def test_sequence_steps_are_in_time_order(self):
        for _, vector in self.vectors:
            times = [validate.parse_time(step["now"]) for step in vector.get("steps", [])]
            with self.subTest(vector=vector["id"]):
                self.assertEqual(times, sorted(times))

    def test_keys_are_the_rfc_8032_test_keys(self):
        keys = validate.load_json(KEY_FILE)
        self.assertIs(keys["test_only"], True)
        self.assertIn("RFC 8032, section 7.1", keys["source"])
        names = {key["name"] for key in keys["keys"]}
        for _, vector in self.vectors:
            for data in [step["input"] for step in vector.get("steps", [])] or [vector["input"]]:
                for field in ("key", "public_key"):
                    if field in data:
                        with self.subTest(vector=vector["id"]):
                            self.assertIn(data[field], names)



    def test_signature_vectors_match_rfc8785_and_ed25519(self):
        """Renamed payloads keep honest JCS and Ed25519 results.

        validate.py still does not check signatures. This test does, so a rename
        cannot leave a normative signature vector pointing at the old bytes.
        """
        import rfc8785
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

        keys = validate.load_json(KEY_FILE)
        secret = {item["name"]: bytes.fromhex(item["secret_key_hex"]) for item in keys["keys"]}
        public = {item["name"]: bytes.fromhex(item["public_key_hex"]) for item in keys["keys"]}

        def signing_input(obj: dict) -> bytes:
            body = {key: item for key, item in obj.items() if key != "sig"}
            return rfc8785.dumps(body)

        def decode(value: str) -> bytes:
            pad = "=" * ((4 - len(value) % 4) % 4)
            return base64.urlsafe_b64decode(value + pad)

        for _, vector in self.vectors:
            operation = vector.get("operation")
            with self.subTest(vector=vector["id"]):
                if operation == "jcs-signing-input":
                    got = signing_input(vector["input"]["object"]).decode("utf-8")
                    self.assertEqual(got, vector["expected"]["value"])
                elif operation == "ed25519-sign":
                    key = Ed25519PrivateKey.from_private_bytes(secret[vector["input"]["key"]])
                    message = bytes.fromhex(vector["input"]["message_hex"])
                    self.assertEqual(key.sign(message).hex(), vector["expected"]["value"])
                elif operation == "sign":
                    key = Ed25519PrivateKey.from_private_bytes(secret[vector["input"]["key"]])
                    raw = key.sign(signing_input(vector["input"]["object"]))
                    got = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
                    self.assertEqual(got, vector["expected"]["value"])
                elif operation == "verify":
                    key = Ed25519PublicKey.from_public_bytes(public[vector["input"]["public_key"]])
                    ok = True
                    try:
                        key.verify(decode(vector["input"]["object"]["sig"]["value"]), signing_input(vector["input"]["object"]))
                    except (InvalidSignature, ValueError):
                        ok = False
                    self.assertEqual("accept" if ok else "refuse", vector["expected"]["result"])

    def test_accepted_receive_steps_are_valid_envelopes(self):
        schemas, registry = validate.load_checked()
        for _, vector in self.vectors:
            for step in vector.get("steps", []):
                if step["operation"] == "receive" and step["expected"].get("result", "accept") == "accept":
                    with self.subTest(vector=vector["id"], now=step["now"]):
                        problems = validate.validate_document(step["input"]["envelope"], "envelope", schemas, registry)
                        self.assertEqual(problems, [])


class VectorRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = Runner()
        cls.vectors = load_vectors()

    def test_normative_vectors(self):
        for _, vector in self.vectors:
            if vector["status"] != "normative":
                continue
            with self.subTest(vector=vector["id"]):
                status, actual = self.runner.run(vector)
                self.assertNotEqual(status, "fail", f"expected {vector.get('expected', vector.get('steps'))}, got {actual}")

    def test_provisional_vectors_are_reported(self):
        for _, vector in self.vectors:
            if vector["status"] == "provisional":
                status, actual = self.runner.run(vector)
                if status == "fail":
                    print(f"\n  provisional {vector['id']} ({vector['open_issue']}): expected {vector.get('expected', 'see steps')}, "
                          f"got {actual}", end="", file=sys.stderr)


def summary() -> int:
    runner = Runner()
    totals: dict[tuple[str, str], int] = {}
    failed = []
    for path, vector in load_vectors():
        status, actual = runner.run(vector)
        key = (str(path.relative_to(VECTOR_DIR)), status)
        totals[key] = totals.get(key, 0) + 1
        if status == "fail":
            expected = [step["expected"] for step in vector["steps"]] if "steps" in vector else vector["expected"]
            failed.append(f"{vector['id']} [{vector['status']}]: expected {expected}, got {actual}")
    for (name, status), count in sorted(totals.items()):
        print(f"{name:40} {status:5} {count}")
    for line in failed:
        print("FAIL  " + line)
    normative_failures = [line for line in failed if "[normative]" in line]
    print(f"\nsuite {suite_version()}: {sum(totals.values())} vectors, {len(failed)} failed ({len(normative_failures)} normative)")
    return 1 if normative_failures else 0


if __name__ == "__main__":
    if "--summary" in sys.argv:
        sys.exit(summary())
    unittest.main()

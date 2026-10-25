#!/usr/bin/env python3
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Check a published copy of the Vaikor spec against this commit.

A site that serves the schemas and registries (vaikor.com/spec/) fetches them into a
directory with `schemas/` and `registries/` and runs this check on it:

  python spec/validate/check_published.py <published-dir>

It passes only when the published copy is exactly this commit's spec:
  1. every schema and registry file of this commit is there, byte for byte, and nothing else;
  2. every schema is a valid JSON Schema 2020-12 whose $id is
     https://vaikor.com/spec/schemas/<name>.schema.json;
  3. every $ref resolves within the published schemas, with no network access;
  4. every example under spec/examples validates (or fails, for *.invalid.json) against the
     published schemas exactly as against the repository's.

Exit status 0 when everything holds, 1 otherwise.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate  # noqa: E402

PARTS = {"schemas": "*.json", "registries": "*.md"}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compare_files(published: Path) -> list[str]:
    """Problems where the published files differ from this commit's."""
    problems = []
    for part, pattern in PARTS.items():
        ours = {p.name: p for p in sorted((validate.SPEC / part).glob(pattern))}
        theirs = {p.name: p for p in sorted((published / part).glob(pattern))} if (published / part).is_dir() else {}
        if not theirs:
            problems.append(f"{part}/: missing or empty")
            continue
        for name in sorted(ours.keys() - theirs.keys()):
            problems.append(f"{part}/{name}: missing")
        for name in sorted(theirs.keys() - ours.keys()):
            problems.append(f"{part}/{name}: not in this commit")
        for name in sorted(ours.keys() & theirs.keys()):
            if digest(ours[name]) != digest(theirs[name]):
                problems.append(f"{part}/{name}: differs from this commit")
    return problems


def refs(node):
    """Every $ref value in a schema."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from refs(item)


def check_refs(schemas: dict[str, dict], registry) -> list[str]:
    """Problems where a $ref does not resolve within the published schemas."""
    problems = []
    for name, schema in schemas.items():
        resolver = registry.resolver(base_uri=schema.get("$id", ""))
        for ref in sorted(set(refs(schema))):
            try:
                resolver.lookup(ref)
            except Exception as exc:  # noqa: BLE001 - any unresolvable reference is a problem
                problems.append(f"{name}: $ref {ref} does not resolve ({type(exc).__name__})")
    return problems


def check_examples(schemas: dict[str, dict], registry) -> list[str]:
    """Problems where an example's outcome differs from what its file name expects."""
    problems = []
    files = validate.example_files()
    if not files:
        problems.append("no examples found")
    for path in files:
        name = validate.schema_for_example(path)
        expect_valid = not path.name.endswith(".invalid.json")
        try:
            found = validate.validate_document(validate.load_json(path), name, schemas, registry)
        except Exception as exc:  # noqa: BLE001 - an unresolvable reference while validating
            problems.append(f"{path.relative_to(validate.REPO)}: cannot be validated ({type(exc).__name__})")
            continue
        if (not found) != expect_valid:
            expectation = "valid" if expect_valid else "invalid"
            problems.append(f"{path.relative_to(validate.REPO)}: expected {expectation} against the published schemas")
    return problems


def check(published: Path) -> list[str]:
    problems = compare_files(published)
    schemas = validate.load_schemas(published / "schemas") if (published / "schemas").is_dir() else {}
    schema_problems = validate.check_schema_files(schemas)
    try:
        registry = validate.build_registry(schemas)
    except ValueError as exc:
        return problems + schema_problems + [str(exc)]
    schema_problems += check_refs(schemas, registry)
    problems += schema_problems
    # Examples say something only about schemas that are sound themselves.
    if not schema_problems:
        problems += check_examples(schemas, registry)
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("published", type=Path, help="directory with the published schemas/ and registries/")
    args = parser.parse_args(argv)
    problems = check(args.published)
    for problem in problems:
        print(f"FAIL  {problem}")
    print(f"published spec: {'OK' if not problems else f'{len(problems)} problem(s)'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
